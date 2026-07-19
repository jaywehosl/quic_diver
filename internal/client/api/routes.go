package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"quicdiver/internal/client/config"
	"quicdiver/internal/client/notify"
	"quicdiver/internal/client/routing"
	"quicdiver/internal/server/auth"
)

var errNoQuit = errors.New("выключение не поддержано этой сборкой")

// get/post/rw — методы, которые эндпоинт принимает. Явно, а не «любой»:
// изменяющая операция на GET прошла бы мимо защиты от чужих страниц.
func get(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	})
}

func post(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	})
}

func rw(read, write http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			read(w, r)
		case http.MethodPut, http.MethodPost:
			write(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// compileRules собирает набор правил из настроек.
func compileRules(cfg config.Config) (*routing.Ruleset, error) {
	rules, err := routing.ParseRules(strings.Join(cfg.Routing.Rules, "\n"))
	if err != nil {
		return nil, err
	}
	def := cfg.Routing.Default
	if def == "" {
		def = "direct"
	}
	return routing.Compile(rules, def), nil
}

// testRequest — что проверяем.
type testRequest struct {
	// Host — домен или IP. Домен важнее: правила чаще пишут по доменам.
	Host string `json:"host"`
	Port uint16 `json:"port,omitempty"`
	// Process — имя процесса для per-app правил.
	Process string `json:"process,omitempty"`
}

// testResult — куда пойдёт трафик и почему.
type testResult struct {
	// Out — метка выхода: direct | <узел> | auto:<тег>.
	Out string `json:"out"`
	// Rule — номер СТРОКИ в редакторе (с 1); 0 — не сработало ни одно правило.
	//
	// Именно строки, а не порядковый номер правила: человек смотрит в тот же
	// текст, где есть комментарии и пустые строки, и «правило №2» отправило бы
	// его не туда.
	Rule int `json:"rule"`
	// RuleText — само правило, как оно записано.
	RuleText string `json:"rule_text,omitempty"`
	// Default — сработал выход по умолчанию, а не правило.
	Default bool `json:"default"`
	// Note — что стоит знать о результате.
	Note string `json:"note,omitempty"`
}

// testRule отвечает, куда пойдёт трафик к указанному адресу.
//
// Главная фича панели. Правила матчатся по порядку, первое совпавшее
// выигрывает, и «почему трафик пошёл не туда» иначе выясняется экспериментом на
// живом трафике. Здесь ответ виден сразу и с указанием правила.
func (d Deps) testRule(w http.ResponseWriter, r *http.Request) {
	var req testRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	req.Host = strings.TrimSpace(req.Host)
	if req.Host == "" {
		fail(w, http.StatusBadRequest, errors.New("нужен host: домен или IP"))
		return
	}
	cfg := d.Config.Get()
	rs, err := compileRules(cfg)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}

	port := req.Port
	if port == 0 {
		port = 443
	}
	flow := routing.Flow{Process: req.Process}
	// Адрес и домен — разные условия правил. Ввели IP — заполняем адрес; ввели
	// домен — домен, а адрес оставляем нулевым, иначе правило по подсети
	// сработало бы на пустышке.
	if ip, err := netip.ParseAddr(req.Host); err == nil {
		flow.Dst = netip.AddrPortFrom(ip, port)
	} else {
		flow.Domain = req.Host
		flow.Dst = netip.AddrPortFrom(netip.Addr{}, port)
	}

	out, idx := rs.Explain(flow)
	res := testResult{Out: out, Default: idx < 0}
	if idx >= 0 {
		if line, text, ok := ruleSource(cfg.Routing.Rules, idx); ok {
			res.Rule, res.RuleText = line, text
		}
	}
	// Про per-app честно предупреждаем: правило принимается, но имя процесса в
	// живом трафике сейчас не определяется, и на практике оно не сработает.
	if req.Process == "" && usesProcessRules(cfg) {
		res.Note = "правила по процессу пока не срабатывают на живом трафике: имя процесса не определяется"
	}
	writeJSON(w, res)
}

// ruleSource находит строку редактора, породившую правило №idx.
//
// Прямое обращение по индексу здесь неверно: комментарии и пустые строки
// правилами не становятся, поэтому нумерация набора и нумерация строк
// расходятся. Наступали на это вживую — тестер уверенно показывал соседнее
// правило, и доверие к нему было бы потеряно с первого же раза.
func ruleSource(lines []string, idx int) (line int, text string, ok bool) {
	n := 0
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		if n == idx {
			return i + 1, l, true
		}
		n++
	}
	return 0, "", false
}

func usesProcessRules(cfg config.Config) bool {
	for _, r := range cfg.Routing.Rules {
		if strings.HasPrefix(strings.TrimSpace(r), "proc:") {
			return true
		}
	}
	return false
}

// exits отдаёт выходы, доступные клиенту: их публикует узел.
//
// Через управляющую связь, а не через туннель перехвата: список нужен ДО
// подключения — иначе правило пришлось бы писать вслепую.
func (d Deps) exits(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
		"https://"+d.nodeAuthority()+"/qd-exits", nil)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	rsp, err := d.Control.Do(r.Context(), req)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	defer rsp.Body.Close()
	relay(w, rsp)
}

// proxy передаёт запрос в admin-API узла как есть.
//
// Панель управления сервером живёт на клиенте (так в ТЗ), а admin-API — на
// узле за QUIC, куда браузеру хода нет. Дублировать здесь каждый эндпоинт
// значило бы обновлять два места при любой правке API узла.
//
// Админ-токен берётся из заголовка запроса панели и НЕ хранится у клиента:
// он вводится в панели на время сеанса. Записать его в конфиг значило бы
// положить ключ от всей сети рядом с клиентским токеном.
func (d Deps) proxy(w http.ResponseWriter, r *http.Request) {
	adminToken := r.Header.Get(auth.HeaderToken)
	if adminToken == "" {
		fail(w, http.StatusUnauthorized, errors.New("нужен админ-токен"))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/node")
	if path == "" || path[0] != '/' {
		fail(w, http.StatusBadRequest, errors.New("пустой путь"))
		return
	}
	target := "https://" + d.nodeAuthority() + path
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, strings.NewReader(string(body)))
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	req.Header.Set(auth.HeaderToken, adminToken)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}

	rsp, err := d.Control.Do(r.Context(), req)
	if err != nil {
		fail(w, http.StatusBadGateway, err)
		return
	}
	defer rsp.Body.Close()
	relay(w, rsp)
}

// relay переносит ответ узла в ответ панели.
func relay(w http.ResponseWriter, rsp *http.Response) {
	if ct := rsp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(rsp.StatusCode)
	_, _ = io.Copy(w, rsp.Body)
}

// nodeAuthority — куда адресовать запросы к узлу.
func (d Deps) nodeAuthority() string {
	cfg := d.Config.Get()
	if len(cfg.Node.Entries) == 0 {
		return "node.invalid"
	}
	return cfg.Node.Entries[0].Authority()
}

// --- уведомления ---

// noticesView — уведомления и счётчик непрочитанных.
//
// Счётчик отдельно от списка: трей рисует иконку по нему и не должен разбирать
// весь список ради одного числа.
type noticesView struct {
	Unread int            `json:"unread"`
	Items  []notify.Event `json:"items"`
}

func (d Deps) listNotices(w http.ResponseWriter, r *http.Request) {
	if d.Notices == nil {
		writeJSON(w, noticesView{Items: []notify.Event{}})
		return
	}
	items := d.Notices.List()
	if items == nil {
		items = []notify.Event{}
	}
	writeJSON(w, noticesView{Unread: d.Notices.Unread(), Items: items})
}

// readNotices помечает прочитанным одно уведомление или все, либо очищает список.
type readRequest struct {
	// ID — что пометить прочитанным; 0 — все.
	ID int64 `json:"id"`
	// Clear — убрать список целиком.
	Clear bool `json:"clear"`
}

func (d Deps) readNotices(w http.ResponseWriter, r *http.Request) {
	if d.Notices == nil {
		fail(w, http.StatusNotImplemented, errors.New("уведомления не подключены"))
		return
	}
	var req readRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
	if req.Clear {
		d.Notices.Clear()
	} else {
		d.Notices.MarkRead(req.ID)
	}
	d.listNotices(w, r)
}
