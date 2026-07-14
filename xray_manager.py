"""Everything that touches the xray-core server: its config file, the
client (user) list, the systemd service, and building vless:// links.

Two inbound modes are supported, matching the two setups documented for
this server (see GUIDE.md): "ws_tls" (VLESS+WebSocket+TLS, self-signed
cert, needs allowInsecure — works even when WS traffic must look like
ordinary HTTPS) and "reality" (VLESS+TCP+REALITY — no certificate at all,
harder to fingerprint, the currently recommended default)."""
import json
import secrets
import subprocess
import uuid
from urllib.parse import quote

import config
import certgen

DEFAULT_SETTINGS = {
    "mode": "ws_tls",        # "ws_tls" or "reality"
    "public_host": "",       # IP or domain clients connect to, e.g. 185.114.72.195
    "port": 443,
    "fingerprint": "chrome",  # client-side uTLS fingerprint, used by both modes
    "autostart": True,

    # ws_tls mode
    "ws_path": "/ms",
    "sni": "www.microsoft.com",  # camouflage SNI presented in the TLS handshake
    "allow_insecure": True,      # needed by clients since the cert is self-signed

    # reality mode
    "reality_dest": "www.microsoft.com:443",   # real site xray proxies the handshake to
    "reality_server_name": "www.microsoft.com",  # SNI clients present / server expects
    "reality_private_key": "",   # generated on first apply, then kept stable
    "reality_public_key": "",
    "reality_short_id": "",
}


# ---------------------------------------------------------------- settings

def load_settings() -> dict:
    if config.SETTINGS_FILE.exists():
        data = json.loads(config.SETTINGS_FILE.read_text())
        merged = dict(DEFAULT_SETTINGS)
        merged.update(data)
        return merged
    return dict(DEFAULT_SETTINGS)


def save_settings(settings: dict) -> None:
    config.SETTINGS_FILE.write_text(json.dumps(settings, indent=2, ensure_ascii=False))


# ----------------------------------------------------------------- clients

def load_clients() -> list[dict]:
    if config.CLIENTS_FILE.exists():
        return json.loads(config.CLIENTS_FILE.read_text())
    return []


def save_clients(clients: list[dict]) -> None:
    config.CLIENTS_FILE.write_text(json.dumps(clients, indent=2, ensure_ascii=False))


def add_client(name: str) -> dict:
    import time
    clients = load_clients()
    client = {
        "id": str(uuid.uuid4()),
        "name": name.strip() or "client",
        "enabled": True,
        "created_at": int(time.time()),
    }
    clients.append(client)
    save_clients(clients)
    return client


def delete_client(client_id: str) -> None:
    clients = [c for c in load_clients() if c["id"] != client_id]
    save_clients(clients)


def toggle_client(client_id: str) -> None:
    clients = load_clients()
    for c in clients:
        if c["id"] == client_id:
            c["enabled"] = not c["enabled"]
    save_clients(clients)


def rename_client(client_id: str, new_name: str) -> bool:
    new_name = new_name.strip()
    if not new_name:
        return False
    clients = load_clients()
    found = False
    for c in clients:
        if c["id"] == client_id:
            c["name"] = new_name
            found = True
    if found:
        save_clients(clients)
    return found


# ------------------------------------------------------------- vless links

def reality_server_names(settings: dict) -> list[str]:
    """reality_server_name is stored as a comma-separated string so a
    REALITY inbound can camouflage as more than one SNI (xray-core's
    realitySettings.serverNames accepts a list)."""
    raw = settings.get("reality_server_name", "") or ""
    return [s.strip() for s in raw.split(",") if s.strip()]


def build_vless_link(client: dict, settings: dict) -> str:
    mode = settings.get("mode", "ws_tls")
    if mode == "reality":
        names = reality_server_names(settings)
        params = {
            "encryption": "none",
            "security": "reality",
            "type": "tcp",
            "flow": "xtls-rprx-vision",
            "pbk": settings.get("reality_public_key", ""),
            "sni": names[0] if names else "",
            "sid": settings.get("reality_short_id", ""),
            "fp": settings.get("fingerprint", "chrome"),
        }
    else:
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "path": settings["ws_path"],
            "sni": settings["sni"],
            "fp": settings.get("fingerprint", "chrome"),
        }
        if settings.get("allow_insecure", True):
            params["allowInsecure"] = "1"

    query = "&".join(f"{k}={quote(str(v), safe='')}" for k, v in params.items())
    name = quote(client["name"], safe="")
    host = settings["public_host"]
    port = settings["port"]
    return f"vless://{client['id']}@{host}:{port}?{query}#{name}"


# --------------------------------------------------------- xray config.json

def xray_cert_paths():
    return config.XRAY_CERT_DIR / "xray.crt", config.XRAY_CERT_DIR / "xray.key"


def build_xray_config(settings: dict, clients: list[dict]) -> dict:
    mode = settings.get("mode", "ws_tls")
    enabled = [c for c in clients if c.get("enabled", True)]

    if mode == "reality":
        vless_clients = [
            {"id": c["id"], "email": c["name"], "flow": "xtls-rprx-vision", "level": 0}
            for c in enabled
        ]
        stream_settings = {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "dest": settings["reality_dest"],
                "serverNames": reality_server_names(settings),
                "privateKey": settings["reality_private_key"],
                "shortIds": [settings["reality_short_id"]],
            },
        }
    else:
        cert_path, key_path = xray_cert_paths()
        vless_clients = [
            {"id": c["id"], "email": c["name"], "level": 0}
            for c in enabled
        ]
        stream_settings = {
            "network": "ws",
            "security": "tls",
            "tlsSettings": {
                "certificates": [
                    {"certificateFile": str(cert_path), "keyFile": str(key_path)}
                ],
            },
            "wsSettings": {"path": settings["ws_path"]},
        }

    return {
        "log": {"loglevel": "warning", "access": str(config.XRAY_ACCESS_LOG)},
        "inbounds": [
            {
                "tag": "vless-in",
                "listen": "0.0.0.0",
                "port": settings["port"],
                "protocol": "vless",
                "settings": {
                    "clients": vless_clients,
                    "decryption": "none",
                },
                "streamSettings": stream_settings,
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            }
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
    }


def write_xray_config(cfg: dict) -> None:
    config.XRAY_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.XRAY_CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))


def ensure_xray_cert(settings: dict) -> bool:
    cert_path, key_path = xray_cert_paths()
    sans = [settings["sni"]]
    if settings.get("public_host"):
        sans.append(settings["public_host"])
    # key_mode=0640: xray-core runs as its own system user (not the panel's
    # user) and only reads this key via shared group membership, so it can't
    # be owner-only 0600 like the panel's own HTTPS key.
    return certgen.ensure_self_signed_cert(cert_path, key_path, cn=settings["sni"], sans=sans, key_mode=0o640)


def generate_reality_keypair() -> tuple[str, str]:
    ok, out = _run([config.XRAY_BIN, "x25519"])
    if not ok:
        raise RuntimeError(f"failed to generate x25519 keypair: {out}")
    private_key = public_key = ""
    for line in out.splitlines():
        if line.startswith("PrivateKey:"):
            private_key = line.split(":", 1)[1].strip()
        elif "PublicKey" in line:
            public_key = line.split(":", 1)[1].strip()
    if not private_key or not public_key:
        raise RuntimeError(f"could not parse xray x25519 output: {out!r}")
    return private_key, public_key


def public_key_from_private(private_key: str) -> str:
    """Derive the REALITY public key from an already-existing private key —
    used when importing a hand-written config.json (see tools/import_xray_config.py)
    so a pre-existing deployment's key doesn't get silently replaced."""
    ok, out = _run([config.XRAY_BIN, "x25519", "-i", private_key])
    if not ok:
        raise RuntimeError(f"failed to derive public key: {out}")
    for line in out.splitlines():
        if "PublicKey" in line:
            return line.split(":", 1)[1].strip()
    raise RuntimeError(f"could not parse xray x25519 -i output: {out!r}")


def ensure_reality_keys(settings: dict) -> bool:
    """Generate & persist the REALITY x25519 keypair + short id once; kept
    stable across re-applies so previously issued client links stay valid."""
    changed = False
    if not settings.get("reality_private_key") or not settings.get("reality_public_key"):
        private_key, public_key = generate_reality_keypair()
        settings["reality_private_key"] = private_key
        settings["reality_public_key"] = public_key
        changed = True
    if not settings.get("reality_short_id"):
        settings["reality_short_id"] = secrets.token_hex(8)
        changed = True
    if changed:
        save_settings(settings)
    return changed


def rotate_reality_keys(settings: dict) -> None:
    settings["reality_private_key"] = ""
    settings["reality_public_key"] = ""
    settings["reality_short_id"] = ""
    ensure_reality_keys(settings)


def validate_config() -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [config.XRAY_BIN, "run", "-test", "-c", str(config.XRAY_CONFIG_PATH)],
            capture_output=True, text=True, timeout=15,
        )
    except FileNotFoundError:
        return False, f"xray binary not found at {config.XRAY_BIN}"
    except subprocess.TimeoutExpired:
        return False, "xray -test timed out"
    ok = result.returncode == 0
    output = (result.stdout + result.stderr).strip()
    return ok, output


def apply_config() -> tuple[bool, str]:
    """Regenerate the xray cert/keys + config.json from current
    settings/clients, validate it, and return (ok, message). Does not
    restart the service."""
    settings = load_settings()
    if settings.get("mode", "ws_tls") == "reality":
        ensure_reality_keys(settings)
    else:
        ensure_xray_cert(settings)
    cfg = build_xray_config(settings, load_clients())
    write_xray_config(cfg)
    ok, output = validate_config()
    return ok, output


# --------------------------------------------------------------- systemctl

def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except FileNotFoundError as e:
        return False, str(e)
    except subprocess.TimeoutExpired:
        return False, f"timed out: {' '.join(cmd)}"
    ok = result.returncode == 0
    output = (result.stdout + result.stderr).strip()
    return ok, output


def _systemctl(*args: str) -> tuple[bool, str]:
    return _run(["sudo", "-n", "systemctl", *args, config.XRAY_SERVICE_NAME])


def service_status() -> dict:
    active_ok, active_out = _run(["systemctl", "is-active", config.XRAY_SERVICE_NAME])
    enabled_ok, enabled_out = _run(["systemctl", "is-enabled", config.XRAY_SERVICE_NAME])
    return {
        "active": active_out.strip() if active_out else ("active" if active_ok else "inactive"),
        "enabled": enabled_out.strip() if enabled_out else ("enabled" if enabled_ok else "disabled"),
        "running": active_out.strip() == "active",
    }


def start_service() -> tuple[bool, str]:
    return _systemctl("start")


def stop_service() -> tuple[bool, str]:
    return _systemctl("stop")


def restart_service() -> tuple[bool, str]:
    return _systemctl("restart")


def set_autostart(enabled: bool) -> tuple[bool, str]:
    return _systemctl("enable" if enabled else "disable")


def xray_version() -> str:
    ok, out = _run([config.XRAY_BIN, "version"])
    return out.splitlines()[0] if ok and out else "unknown"
