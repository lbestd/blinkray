#!/usr/bin/env bash
# Blinkray one-shot installer.
#
# Usage (on the VPS, after `git clone`):
#   cd blinkray && ./install.sh
#
# Re-elevates itself with sudo if not run as root. Idempotent: safe to
# re-run (won't touch an existing password / env file).
#
# The very first run relocates the checkout to /opt/blinkray regardless of
# where it was cloned: systemd changes into WorkingDirectory as the
# unprivileged blinkray user (not as root), so cloning into e.g. /root
# (mode 700) makes that chdir fail with "Permission denied" no matter what
# we chown inside the checkout — /opt is 755 by convention, so this class
# of bug can't happen there. After the first run, keep working straight out
# of /opt/blinkray (git pull && ./install.sh there).
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E bash "$0" "$@"
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/blinkray"

log()  { echo -e "\033[1;32m==>\033[0m $*"; }
warn() { echo -e "\033[1;33m!!\033[0m $*" >&2; }

if [ "$REPO_DIR" != "$INSTALL_DIR" ]; then
  log "Переношу проект в ${INSTALL_DIR} (права зависимого от пользователя каталога вроде /root ломают запуск сервиса)"
  mkdir -p "$INSTALL_DIR"
  cp -a "${REPO_DIR}/." "${INSTALL_DIR}/"
  exec bash "${INSTALL_DIR}/install.sh" "$@"
fi

SCRIPT_DIR="$INSTALL_DIR"
PANEL_USER="blinkray"
XRAY_USER="xray"
XRAY_BIN="/usr/local/bin/xray"
XRAY_SERVICE_NAME="xray"
ENV_FILE="/etc/blinkray.env"
SUDOERS_FILE="/etc/sudoers.d/blinkray"
PANEL_SERVICE_FILE="/etc/systemd/system/blinkray.service"
XRAY_SERVICE_FILE="/etc/systemd/system/${XRAY_SERVICE_NAME}.service"
DATA_DIR="${SCRIPT_DIR}/data"

log "Устанавливаю системные зависимости"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  # needrestart on Ubuntu/Debian pops up an interactive "restart services?"
  # dialog mid-install that looks exactly like a hang over SSH — silence it.
  export NEEDRESTART_MODE=a
  export NEEDRESTART_SUSPEND=1
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv openssl curl unzip ca-certificates >/dev/null
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y -q python3 python3-pip openssl curl unzip
elif command -v yum >/dev/null 2>&1; then
  yum install -y -q python3 python3-pip openssl curl unzip
else
  warn "Неизвестный пакетный менеджер — убедитесь, что установлены python3, python3-venv, openssl, curl, unzip"
fi

log "Создаю системных пользователей"
id -u "$XRAY_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$XRAY_USER"
id -u "$PANEL_USER" >/dev/null 2>&1 || useradd --system --home "$SCRIPT_DIR" --shell /usr/sbin/nologin "$PANEL_USER"
usermod -d "$SCRIPT_DIR" "$PANEL_USER"
usermod -aG "$PANEL_USER" "$XRAY_USER"

if [ -x "$XRAY_BIN" ] && [ "${FORCE_XRAY_INSTALL:-0}" != "1" ]; then
  log "xray-core уже установлен: $("$XRAY_BIN" version | head -1)"
elif [ -f "${SCRIPT_DIR}/vendor/xray" ]; then
  log "Устанавливаю xray-core из vendor/xray"
  install -m 755 "${SCRIPT_DIR}/vendor/xray" "$XRAY_BIN"
else
  log "Скачиваю последний релиз xray-core с GitHub"
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64|amd64) ASSET="Xray-linux-64.zip" ;;
    aarch64|arm64) ASSET="Xray-linux-arm64-v8a.zip" ;;
    armv7l|armv7) ASSET="Xray-linux-arm32-v7a.zip" ;;
    *) warn "Неизвестная архитектура $ARCH. Положите бинарь xray-core в ${SCRIPT_DIR}/vendor/xray и перезапустите скрипт."; exit 1 ;;
  esac
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  curl -fsSL -o "${TMP_DIR}/xray.zip" "https://github.com/XTLS/Xray-core/releases/latest/download/${ASSET}"
  unzip -qo "${TMP_DIR}/xray.zip" -d "$TMP_DIR"
  install -m 755 "${TMP_DIR}/xray" "$XRAY_BIN"
  rm -rf "$TMP_DIR"
  trap - EXIT
fi

log "Настраиваю виртуальное окружение Python"
if [ ! -d "${SCRIPT_DIR}/venv" ]; then
  python3 -m venv "${SCRIPT_DIR}/venv"
fi
"${SCRIPT_DIR}/venv/bin/pip" install -q --upgrade pip
"${SCRIPT_DIR}/venv/bin/pip" install -q -r "${SCRIPT_DIR}/requirements.txt"

log "Настраиваю каталоги и права"
mkdir -p "$DATA_DIR"
chown -R "${PANEL_USER}:${PANEL_USER}" "$SCRIPT_DIR"
chmod 750 "$DATA_DIR"
chmod g+rx "$SCRIPT_DIR"

# PANEL_PASSWORD / PANEL_HOST / PANEL_PORT are sticky (kept across re-runs if
# already set); PANEL_DATA_DIR/XRAY_BIN/XRAY_CONFIG_PATH are always
# rewritten to match the current install location — an old env file with
# stale absolute paths (e.g. from a checkout that later got relocated) is
# exactly what caused "Permission denied: /root/blinkray/data" here before.
_env_get() {
  local key="$1" default="$2"
  if [ -f "$ENV_FILE" ]; then
    local val
    val="$(grep -m1 "^${key}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2-)"
    if [ -n "$val" ]; then echo "$val"; return; fi
  fi
  echo "$default"
}

GENERATED_PASSWORD=""
EXISTING_PASSWORD="$(_env_get PANEL_PASSWORD "")"
if [ -n "$EXISTING_PASSWORD" ]; then
  PASSWORD="$EXISTING_PASSWORD"
elif [ -n "${PANEL_PASSWORD:-}" ]; then
  PASSWORD="$PANEL_PASSWORD"
else
  PASSWORD="$(openssl rand -base64 18 | tr -d '=+/')"
  GENERATED_PASSWORD="$PASSWORD"
fi
PANEL_HOST_VAL="$(_env_get PANEL_HOST 0.0.0.0)"
PANEL_PORT_VAL="$(_env_get PANEL_PORT 10077)"

log "Пишу $ENV_FILE (пароль/хост/порт сохраняю, если уже были заданы; пути пересчитываю под ${SCRIPT_DIR})"
cat > "$ENV_FILE" <<EOF
PANEL_PASSWORD=${PASSWORD}
PANEL_HOST=${PANEL_HOST_VAL}
PANEL_PORT=${PANEL_PORT_VAL}
PANEL_DATA_DIR=${DATA_DIR}
XRAY_BIN=${XRAY_BIN}
XRAY_CONFIG_PATH=${DATA_DIR}/xray/config.json
XRAY_SERVICE_NAME=${XRAY_SERVICE_NAME}
EOF
chmod 600 "$ENV_FILE"
chown "${PANEL_USER}:${PANEL_USER}" "$ENV_FILE"

log "Настраиваю sudoers (право панели управлять xray.service без пароля)"
cat > "$SUDOERS_FILE" <<EOF
Cmnd_Alias BLINKRAY_XRAY = /usr/bin/systemctl start ${XRAY_SERVICE_NAME}.service, \\
    /usr/bin/systemctl stop ${XRAY_SERVICE_NAME}.service, \\
    /usr/bin/systemctl restart ${XRAY_SERVICE_NAME}.service, \\
    /usr/bin/systemctl enable ${XRAY_SERVICE_NAME}.service, \\
    /usr/bin/systemctl disable ${XRAY_SERVICE_NAME}.service

${PANEL_USER} ALL=(root) NOPASSWD: BLINKRAY_XRAY
EOF
chmod 440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" >/dev/null

log "Пишу systemd unit'ы"
cat > "$PANEL_SERVICE_FILE" <<EOF
[Unit]
Description=Blinkray VLESS panel
After=network.target

[Service]
Type=simple
User=${PANEL_USER}
Group=${PANEL_USER}
WorkingDirectory=${SCRIPT_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=${SCRIPT_DIR}/venv/bin/python3 ${SCRIPT_DIR}/app.py
Restart=on-failure
RestartSec=2
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

cat > "$XRAY_SERVICE_FILE" <<EOF
[Unit]
Description=Xray VLESS server (managed by Blinkray)
After=network.target

[Service]
Type=simple
User=${XRAY_USER}
Group=${XRAY_USER}
ExecStart=${XRAY_BIN} run -c ${DATA_DIR}/xray/config.json
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

log "Перечитываю systemd и запускаю панель"
systemctl daemon-reload
systemctl enable --now blinkray.service

sleep 1
if systemctl is-active --quiet blinkray.service; then
  log "Панель запущена"
else
  warn "Панель не запустилась, смотрите: journalctl -u blinkray -n 50"
fi

IP="$(curl -fs -4 --max-time 3 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"

echo
echo "========================================================"
echo " Blinkray установлен"
echo " Панель:  https://${IP:-<IP-сервера>}:10077"
if [ -n "$GENERATED_PASSWORD" ]; then
  echo " Пароль:  ${GENERATED_PASSWORD}"
  echo " (сохранён в ${ENV_FILE}, поменять — отредактируйте PANEL_PASSWORD и"
  echo "  выполните: systemctl restart blinkray)"
fi
echo "========================================================"
echo
echo "Дальше: откройте панель в браузере (сертификат самоподписной —"
echo "браузер предупредит, это нормально), в разделе «Настройки подключения»"
echo "укажите публичный адрес/порт/SNI и сохраните, затем нажмите «Запустить»"
echo "в разделе «Сервер»."
