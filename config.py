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

PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "10077"))
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD")
SESSION_TTL = int(os.environ.get("PANEL_SESSION_TTL", str(30 * 24 * 3600)))

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
    for d in (DATA_DIR, PANEL_CERT_DIR, APK_DIR, XRAY_DIR, XRAY_CERT_DIR, XRAY_CONFIG_PATH.parent):
        d.mkdir(parents=True, exist_ok=True)


def require_password():
    if not PANEL_PASSWORD:
        raise SystemExit(
            "PANEL_PASSWORD env var is required (password for logging into the panel)."
        )
