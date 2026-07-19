package server

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"quicdiver/internal/server/auth"
	"quicdiver/internal/server/db"
)

// Пути установки узла.
//
// Оба обслуживаются ВИТРИНОЙ НА TCP, а не HTTP/3-муксом: скрипт установки
// исполняется на голой машине, где есть только curl, а curl HTTP/3 не умеет.
// Витрина уже слушает тот же порт и тем же сертификатом, поэтому отдельного
// порта (то есть отдельного маркера при пробинге) не появляется.
const (
	// InstallPath отдаёт готовый скрипт установки узла.
	InstallPath = "/qd-install"
	// NodeBinaryPath раздаёт бинарь узла — тот самый, которым работает мастер.
	//
	// Так по сети расходится ОДНА версия: разъехавшиеся версии узлов дают
	// баги, которые невозможно воспроизвести, потому что никто не помнит, где
	// какая сборка.
	NodeBinaryPath = "/qd-node-binary"
)

// installHandlers — обработчики установки для витрины TCP.
//
// Без токена оба отдают витрину: посторонний не должен даже знать, что здесь
// что-то есть, — иначе путь установки становится указателем «тут не сайт».
func installHandlers(cfg Config, site http.Handler) map[string]http.Handler {
	return map[string]http.Handler{
		InstallPath:    guardByToken(cfg, site, serveInstallScript(cfg)),
		NodeBinaryPath: guardByToken(cfg, site, serveNodeBinary()),
	}
}

// guardByToken пускает дальше только по admin- или node-токену.
//
// Витрина живёт вне QUIC-сессии, поэтому сессионной авторизации здесь нет —
// токен предъявляется заголовком на каждый запрос.
func guardByToken(cfg Config, site http.Handler, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			site.ServeHTTP(w, r)
			return
		}
		hash := auth.Hash(auth.TokenFromRequest(r))
		info, err := store.Lookup(r.Context(), hash)
		if err == nil && (info.Role == auth.RoleAdmin || info.Role == auth.RoleNode) {
			next.ServeHTTP(w, r)
			return
		}
		// Токен самого узла тоже годится: обновляющийся узел предъявляет свой.
		if _, err := store.NodeByTokenHash(r.Context(), hash); err == nil {
			next.ServeHTTP(w, r)
			return
		}
		site.ServeHTTP(w, r)
	})
}

// serveNodeBinary отдаёт исполняемый файл, которым работает этот узел.
func serveNodeBinary() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		self, err := os.Executable()
		if err != nil {
			http.Error(w, "не найти свой бинарь: "+err.Error(), http.StatusInternalServerError)
			return
		}
		f, err := os.Open(self)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()

		w.Header().Set("Content-Type", "application/octet-stream")
		if st, err := f.Stat(); err == nil {
			w.Header().Set("Content-Length", fmt.Sprint(st.Size()))
		}
		if _, err := io.Copy(w, f); err != nil {
			log.Printf("раздача бинаря узла: %v", err)
		}
	})
}

// installRequest — что нужно знать, чтобы собрать скрипт.
type installRequest struct {
	node   db.Node
	token  string // node-токен устанавливаемого узла
	master db.Node
	dns    string
	pool   string
}

// serveInstallScript отдаёт shell-скрипт, ставящий узел в сеть.
//
// Раньше добавление узла означало обход машины руками: скопировать бинарь,
// написать unit, не забыть флаги, зарегистрировать узел на мастере. Каждый шаг
// — место для опечатки, а половина ошибок вылезала только под нагрузкой.
//
// Токен узла подставляется в скрипт: он выдаётся один раз при регистрации и
// иначе его пришлось бы переносить вручную. Поэтому и сам скрипт — секрет: он
// отдаётся только по admin-токену и по TLS.
func serveInstallScript(cfg Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store, ok := sqliteOf(cfg.Store)
		if !ok {
			http.Error(w, "хранилище не поддерживает реестр узлов", http.StatusNotImplemented)
			return
		}
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		token := strings.TrimSpace(r.URL.Query().Get("token"))
		if id == "" || token == "" {
			http.Error(w, "нужны ?id= и ?token= (выдаются при POST /qd-admin/nodes)",
				http.StatusBadRequest)
			return
		}
		node, err := store.NodeByID(r.Context(), id)
		if err != nil {
			http.Error(w, "узел не найден в реестре: "+id, http.StatusNotFound)
			return
		}
		// Токен обязан принадлежать именно этому узлу: иначе установленный узел
		// не смог бы представиться, а ошибка вылезла бы только на первом стуке.
		if auth.Hash(token) != node.TokenHash {
			http.Error(w, "токен не от этого узла", http.StatusBadRequest)
			return
		}

		state, err := store.ClusterState(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		master := db.Node{ID: cfg.NodeID, Addr: cfg.Authority, SNI: cfg.NodeID}
		if state.MasterID != "" && state.MasterID != cfg.NodeID {
			if m, err := store.NodeByID(r.Context(), state.MasterID); err == nil {
				master = m
			}
		}

		dns := "udp://8.8.8.8:53"
		if cfg.Resolver != nil {
			if up := cfg.Resolver.Settings().Upstream; up != "" {
				dns = dnsFlagValue(up)
			}
		}
		script := installScript(installRequest{
			node: node, token: token, master: master, dns: dns,
			pool: poolForNode(cfg),
		})
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = io.WriteString(w, script)
	})
}

// dnsFlagValue приводит upstream резолвера к виду, который понимает флаг -dns.
//
// Резолвер показывает plain-транспорт как "plain://host:port", а флаг ждёт
// "udp://". Разошлись эти два написания молча: узел ставился, падал на разборе
// флага и уходил в перезапуск — а установщик рапортовал об успехе.
func dnsFlagValue(upstream string) string {
	if rest, ok := strings.CutPrefix(upstream, "plain://"); ok {
		return "udp://" + rest
	}
	return upstream
}

// withPort дополняет адрес портом по умолчанию.
//
// В реестре адрес мастера может лежать без порта (узел запущен с -authority без
// него). Передать такой в -master значит уронить новый узел на разборе адреса.
func withPort(addr, def string) string {
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, def)
}

// poolForNode — пул адресов клиентов для нового узла.
//
// Тот же, что у мастера: адреса живут внутри туннеля и наружу не выходят, а
// разные пулы на узлах только мешали бы читать логи.
func poolForNode(cfg Config) string {
	if cfg.Pool.IsValid() {
		return cfg.Pool.String()
	}
	return "10.7.0.0/16"
}

// installScript собирает текст скрипта.
//
// Пишется на sh, а не на bash: на голой Debian/Ubuntu-машине sh есть всегда, а
// установка узла — первое, что там запускается.
func installScript(req installRequest) string {
	masterAddr := withPort(req.master.Addr, "443")
	if masterAddr == "" {
		masterAddr = withPort(req.master.ID, "443")
	}
	masterSNI := req.master.Authority()
	// Порт узла берём из его адреса в реестре: админ мог поставить нестандартный
	// (например 27015 — под DPI это выглядит игрой, а не прокси).
	listen := ":443"
	if _, port, err := net.SplitHostPort(req.node.Addr); err == nil && port != "" {
		listen = ":" + port
	}

	return fmt.Sprintf(`#!/bin/sh
# Установка узла QUIC Diver «%[1]s».
#
# Скрипт выдан мастером сети и содержит СЕКРЕТ (node-токен этого узла) —
# не выкладывать и не пересылать.
#
# Запуск на чистой машине (Debian/Ubuntu, root):
#   sh install-%[1]s.sh
set -e

NODE_ID='%[1]s'
NODE_TOKEN='%[2]s'
MASTER_ADDR='%[3]s'
MASTER_SNI='%[4]s'
LISTEN='%[5]s'
POOL='%[6]s'
DNS='%[7]s'

DIR=/opt/quic-diver
BIN="$DIR/qd-server"
DB="$DIR/node.db"
UNIT=/etc/systemd/system/qd-node.service

[ "$(id -u)" = 0 ] || { echo "нужен root" >&2; exit 1; }
command -v curl >/dev/null || { echo "нужен curl" >&2; exit 1; }

echo "== ставлю узел $NODE_ID (мастер $MASTER_ADDR) =="
mkdir -p "$DIR"

# Бинарь берём у мастера: по сети должна ходить ОДНА версия, иначе узлы
# разъезжаются и баги перестают воспроизводиться.
#
# Проверку сертификата НЕ отключаем по умолчанию: сюда качается исполняемый
# файл, который тут же запускается от root, — подменивший его получит машину
# целиком. Если у мастера самоподписанный сертификат (стенд), это осознанно
# включается QD_INSECURE=1.
echo "-- качаю бинарь с мастера"
MASTER_HOST=$(echo "$MASTER_ADDR" | cut -d: -f1)
INSECURE=""
if [ "${QD_INSECURE:-0}" = "1" ]; then
	echo "   ВНИМАНИЕ: проверка сертификата мастера отключена (QD_INSECURE=1)."
	echo "   Так можно только на своём стенде: бинарь запускается от root."
	INSECURE="-k"
fi
curl -fsS --tlsv1.2 $INSECURE -o "$BIN.new" \
	-H "X-Qd-Token: $NODE_TOKEN" \
	--resolve "$MASTER_SNI:%[8]s:$MASTER_HOST" \
	"https://$MASTER_SNI:%[8]s%[9]s" || {
		echo "не скачался бинарь с мастера." >&2
		echo "Если у мастера самоподписанный сертификат — QD_INSECURE=1 sh $0" >&2
		exit 1; }
[ -s "$BIN.new" ] || { echo "мастер отдал пустой файл" >&2; rm -f "$BIN.new"; exit 1; }
chmod +x "$BIN.new"
mv "$BIN.new" "$BIN"

# Юнит переживает перезагрузку, Restart=always поднимает узел после падения.
# LimitNOFILE — на узле тысячи одновременных стримов, дефолт 1024 кончится
# в первый же час под нагрузкой.
echo "-- пишу systemd-юнит"
cat > "$UNIT" <<UNITEOF
[Unit]
Description=QUIC Diver node ($NODE_ID)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -listen $LISTEN -authority $NODE_ID -pool $POOL -db $DB \
	-node-token $NODE_TOKEN -master $MASTER_ADDR -master-sni $MASTER_SNI -dns $DNS
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNITEOF
chmod 600 "$UNIT"

systemctl daemon-reload
systemctl enable --now qd-node

# Проверяем, что узел ДЕЙСТВИТЕЛЬНО поднялся, а не ушёл в цикл перезапуска.
# Restart=always маскирует ошибку конфигурации: сервис числится «запущенным»,
# хотя падает каждые три секунды, — и установщик отрапортовал бы об успехе.
echo "-- проверяю, что узел держится"
sleep 6
if ! systemctl is-active --quiet qd-node || \
   [ "$(systemctl show qd-node -p NRestarts --value)" -gt 1 ]; then
	echo >&2
	echo "УЗЕЛ НЕ ПОДНЯЛСЯ. Последние строки журнала:" >&2
	journalctl -u qd-node -n 20 --no-pager >&2
	exit 1
fi

cat <<DONE

== готово ==
Узел поднят. Реестр сети, клиентов и admin-токен он заберёт у мастера сам —
первая репликация проходит сразу, дальше раз в 15 минут.

TLS сейчас самоподписанный. Для боевого узла положите сертификат и добавьте
в юнит ($UNIT):
    -cert /etc/letsencrypt/live/$NODE_ID/fullchain.pem \\
    -key  /etc/letsencrypt/live/$NODE_ID/privkey.pem
затем: systemctl daemon-reload && systemctl restart qd-node

Проверить, что мастер увидел узел живым:
    qdadmin -server <мастер> -token <admin> -nodes
DONE
`, req.node.ID, req.token, masterAddr, masterSNI, listen, req.pool, req.dns,
		portOf(masterAddr), NodeBinaryPath)
}

// portOf — порт из host:port (по умолчанию 443).
func portOf(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	return "443"
}
