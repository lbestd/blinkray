import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PANEL_DATA_DIR", str(BASE_DIR / "data"))).resolve()

PANEL_CERT_DIR = DATA_DIR / "panel-cert"
APK_DIR = DATA_DIR / "apk"
XRAY_DIR = DATA_DIR / "xray"

SETTINGS_FILE = DATA_DIR / "settings.json"
CLIENTS_FILE = DATA_DIR / "clients.json"
SECRET_FILE = DATA_DIR / "secret.key"
STATS_FILE = DATA_DIR / "stats.json"

XRAY_LOG_DIR = XRAY_DIR / "logs"
XRAY_ACCESS_LOG = XRAY_LOG_DIR / "access.log"

PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "10077"))
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD")
SESSION_TTL = int(os.environ.get("PANEL_SESSION_TTL", str(30 * 24 * 3600)))

# install.sh writes PANEL_PASSWORD into this systemd EnvironmentFile; when
# the password is changed from the web UI we rewrite it here too, so the
# new password survives a restart and not just the running process.
PANEL_ENV_FILE = Path(os.environ.get("PANEL_ENV_FILE", "/etc/blinkray.env"))

# Path to the xray binary and the config file it is launched with (via
# systemd). Defaults keep everything self-contained under DATA_DIR so the
# panel never needs write access outside of its own directory; point
# XRAY_CONFIG_PATH at the same file xray.service's ExecStart uses.
XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG_PATH = Path(os.environ.get("XRAY_CONFIG_PATH", str(XRAY_DIR / "config.json")))
XRAY_CERT_DIR = Path(os.environ.get("XRAY_CERT_DIR", str(XRAY_DIR / "certs")))
XRAY_SERVICE_NAME = os.environ.get("XRAY_SERVICE_NAME", "xray")

APK_MAX_SIZE = int(os.environ.get("PANEL_APK_MAX_SIZE", str(300 * 1024 * 1024)))


def ensure_dirs():
    for d in (DATA_DIR, PANEL_CERT_DIR, APK_DIR, XRAY_DIR, XRAY_CERT_DIR, XRAY_CONFIG_PATH.parent, XRAY_LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # Pre-create the access log owned by the panel user with group-write, so
    # xray-core (running as its own system user, only a *member* of this
    # process's group — see install.sh) can open and append to it without
    # needing to own it or the directory. If xray had to create the file
    # itself it would land 644 (owner-only write), and the panel wouldn't be
    # able to truncate it when rotating (see stats.py).
    if not XRAY_ACCESS_LOG.exists():
        XRAY_ACCESS_LOG.touch()
    XRAY_ACCESS_LOG.chmod(0o664)


def require_password():
    if not PANEL_PASSWORD:
        raise SystemExit(
            "PANEL_PASSWORD env var is required (password for logging into the panel)."
        )


def _update_env_file(key: str, value: str) -> None:
    """Best-effort rewrite of one KEY=value line in PANEL_ENV_FILE. A no-op
    if that file doesn't exist (e.g. local dev run without systemd) — the
    caller is responsible for updating the in-process value regardless."""
    if not PANEL_ENV_FILE.exists():
        return
    lines = PANEL_ENV_FILE.read_text().splitlines()
    prefix = f"{key}="
    found = False
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            lines[i] = f"{key}={value}"
            found = True
            break
    if not found:
        lines.append(f"{key}={value}")
    PANEL_ENV_FILE.write_text("\n".join(lines) + "\n")


def update_panel_password(new_password: str) -> None:
    global PANEL_PASSWORD
    PANEL_PASSWORD = new_password
    _update_env_file("PANEL_PASSWORD", new_password)
