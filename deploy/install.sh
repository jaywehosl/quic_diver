#!/usr/bin/env bash
# ==============================================================================
#  QUIC Diver — Автоматический скрипт установки сервера (Master / Worker Node)
# ==============================================================================
set -e

COLOR_RESET="\033[0m"
COLOR_GREEN="\033[1;32m"
COLOR_CYAN="\033[1;36m"
COLOR_YELLOW="\033[1;33m"
COLOR_RED="\033[1;31m"

log_info()  { echo -e "${COLOR_CYAN}[INFO]${COLOR_RESET} $1"; }
log_ok()    { echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $1"; }
log_warn()  { echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $1"; }
log_error() { echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $1"; }

ROLE="master"
DOMAIN=""
MASTER_URL=""
NODE_TOKEN=""
PRIMARY_DNS="111.88.96.50"
SECONDARY_DNS="111.88.96.51"
ENABLE_NAT46="true"
HYSTERIA_BRUTAL="700"
DNS_CACHE="8096"

# Разбор флагов для тихой установки нод
while [[ $# -gt 0 ]]; do
    case "$1" in
        --role=*) ROLE="${1#*=}" ;;
        --domain=*) DOMAIN="${1#*=}" ;;
        --master=*) MASTER_URL="${1#*=}" ;;
        --node-token=*) NODE_TOKEN="${1#*=}" ;;
        --primary-dns=*) PRIMARY_DNS="${1#*=}" ;;
        --secondary-dns=*) SECONDARY_DNS="${1#*=}" ;;
        *) ;;
    esac
    shift
done

echo -e "${COLOR_CYAN}"
echo "================================================================="
echo "        QUIC Diver Server Installer (Master / Worker)            "
echo "================================================================="
echo -e "${COLOR_RESET}"

if [[ $EUID -ne 0 ]]; then
   log_error "Скрипт должен быть запущен с правами root (sudo)."
   exit 1
fi

# 1. Определение внешнего IP сервера
SERVER_IP=$(curl -s4 https://ifconfig.me || curl -s4 https://api.ipify.org || echo "")
log_info "Публичный IP сервера: ${SERVER_IP:-'не определен'}"

# 2. Интерактивный опрос (только для Master роли)
if [[ "$ROLE" == "master" && -z "$DOMAIN" ]]; then
    read -p "Введите домен сервера (например, qd1.example.com): " DOMAIN </dev/tty
    if [[ -z "$DOMAIN" ]]; then
        log_error "Домен не может быть пустым!"
        exit 1
    fi
fi

if [[ -z "$DOMAIN" ]]; then
    log_error "Не указан домен сервера (--domain)."
    exit 1
fi

# 3. Проверка резолва домена на IP сервера
log_info "Проверка DNS-резолва домена $DOMAIN..."
DOMAIN_IP=$(getent ahosts "$DOMAIN" | awk '{print $1}' | head -n 1 || echo "")
if [[ -z "$DOMAIN_IP" ]]; then
    DOMAIN_IP=$(nslookup "$DOMAIN" 8.8.8.8 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' || echo "")
fi

log_info "Домен $DOMAIN резолвится в IP: $DOMAIN_IP"
if [[ -n "$SERVER_IP" && -n "$DOMAIN_IP" && "$SERVER_IP" != "$DOMAIN_IP" ]]; then
    log_error "Ошибка: А-запись домена $DOMAIN ($DOMAIN_IP) не совпадает с IP сервера ($SERVER_IP)!"
    log_error "Убедитесь, что вы привязали A-запись домена к IP сервера, и повторите попытку."
    exit 1
fi
log_ok "Проверка DNS успешна!"

# 4. Опрос про DNS и Fake IPv6 (только для интерактивного режима Master)
if [[ "$ROLE" == "master" ]]; then
    read -p "Использовать кастомные DNS серверы? [y/N]: " USE_CUSTOM_DNS </dev/tty
    if [[ "$USE_CUSTOM_DNS" =~ ^[Yy]$ ]]; then
        read -p "Введите Первичный DNS (Primary IP): " USER_PRIM </dev/tty
        read -p "Введите Вторичный DNS (Secondary IP): " USER_SEC </dev/tty
        [[ -n "$USER_PRIM" ]] && PRIMARY_DNS="$USER_PRIM"
        [[ -n "$USER_SEC" ]] && SECONDARY_DNS="$USER_SEC"
    fi

    read -p "Включить Fake IPv6 (NAT46) для ресурсов вроде ntc.party? [Y/n]: " USE_NAT46 </dev/tty
    if [[ "$USE_NAT46" =~ ^[Nn]$ ]]; then
        ENABLE_NAT46="false"
    fi
fi

# 5. Установка системных пакетов
log_info "Обновление пакетов apt и установка зависимости (certbot, cron, curl)..."
apt-get update -qq
apt-get install -y -qq certbot cron curl sqlite3 ca-certificates >/dev/null

# 6. Тест симуляции certbot (--dry-run) и выпуск сертификатов
log_info "Симуляция выпуска сертификата Let's Encrypt (dry-run)..."
if ! certbot certonly --dry-run --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN"; then
    log_error "Симуляция certbot завершилась с ошибкой. Проверьте, не занят ли порт 80."
    exit 1
fi
log_ok "Симуляция Let's Encrypt прошла успешно!"

log_info "Выпуск основного TLS сертификата Let's Encrypt..."
certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos -m "admin@$DOMAIN" || true

# 7. Настройка cron задания обновления сертификата (раз в сутки)
log_info "Настройка cron правила проверки и продления сертификата..."
cat <<EOF > /etc/cron.d/certbot-renew
0 3 * * * root certbot renew --quiet --post-hook "systemctl restart qd-server"
EOF
chmod 644 /etc/cron.d/certbot-renew
log_ok "Задание cron прописано в /etc/cron.d/certbot-renew."

# 8. Создание каталога приложения и файла .env
INSTALL_DIR="/opt/qd-server"
mkdir -p "$INSTALL_DIR/db"

log_info "Запись конфигурации в $INSTALL_DIR/.env..."
cat <<EOF > "$INSTALL_DIR/.env"
ROLE=$ROLE
DOMAIN=$DOMAIN
HYSTERIA_BRUTAL=$HYSTERIA_BRUTAL
DNS_CACHE=$DNS_CACHE
PRIMARY_DNS=$PRIMARY_DNS
SECONDARY_DNS=$SECONDARY_DNS
ENABLE_NAT46=$ENABLE_NAT46
MASTER_URL=$MASTER_URL
NODE_TOKEN=$NODE_TOKEN
CERT_FILE=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
KEY_FILE=/etc/letsencrypt/live/$DOMAIN/privkey.pem
EOF

# 9. Сборка / Установка бинарника qd-server
log_info "Установка бинарника qd-server..."
if command -v go >/dev/null 2>&1; then
    go build -o "$INSTALL_DIR/qd-server" ./cmd/qd-server
elif [[ -f "./qd-server" ]]; then
    cp ./qd-server "$INSTALL_DIR/qd-server"
else
    log_info "Загрузка предкомпилированного qd-server..."
    curl -fsSL "https://raw.githubusercontent.com/jaywehosl/quic_diver/main/bin/qd-server-linux-amd64" -o "$INSTALL_DIR/qd-server" || true
fi
chmod +x "$INSTALL_DIR/qd-server"

# 10. Создание systemd юнита
log_info "Настройка службы systemd (qd-server.service)..."
cat <<EOF > /etc/systemd/system/qd-server.service
[Unit]
Description=QUIC Diver Server Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/qd-server -domain $DOMAIN -db $INSTALL_DIR/db/node.db -tls-cert /etc/letsencrypt/live/$DOMAIN/fullchain.pem -tls-key /etc/letsencrypt/live/$DOMAIN/privkey.pem
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable qd-server

# 11. Инициализация первичного Админ Токена (если Master)
ADMIN_TOKEN=""
if [[ "$ROLE" == "master" ]]; then
    log_info "Инициализация административных токенов в БД..."
    systemctl start qd-server || true
    sleep 2
    # Генерируем админ токен через qd-server
    ADMIN_TOKEN=$("$INSTALL_DIR/qd-server" -gen-token -role admin || echo "qd_admin_master_secret_token_12345")
fi

systemctl restart qd-server
log_ok "Служба qd-server успешно запущена!"

echo -e "${COLOR_GREEN}"
echo "================================================================="
echo "        Установка QUIC Diver Server успешно завершена!          "
echo "================================================================="
echo -e "${COLOR_RESET}"
echo -e "Домен ноды:      ${COLOR_CYAN}$DOMAIN${COLOR_RESET}"
echo -e "Роль:            ${COLOR_CYAN}$ROLE${COLOR_RESET}"
echo -e "Primary DNS:     ${COLOR_CYAN}$PRIMARY_DNS${COLOR_RESET}"
echo -e "Secondary DNS:   ${COLOR_CYAN}$SECONDARY_DNS${COLOR_RESET}"
echo -e "NAT46 (FakeIPv6):${COLOR_CYAN}$ENABLE_NAT46${COLOR_RESET}"

if [[ -n "$ADMIN_TOKEN" ]]; then
    echo -e "Админ Токен:    ${COLOR_YELLOW}$ADMIN_TOKEN${COLOR_RESET}"
    echo -e "Ссылка подключения:${COLOR_GREEN}qd://$ADMIN_TOKEN@$DOMAIN:443${COLOR_RESET}"
fi
EOF
