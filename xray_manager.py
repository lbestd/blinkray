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
    "server_name": "",       # shown to clients — used as the profile's display
                              # name (remarks) in the JSON config, so imported
                              # entries aren't a bare timestamp in v2rayNG
    "client_link_token": "",  # secret path segment for /c/<token> — lets
                               # clients reach the picker/guide without the
                               # panel password (see ensure_client_link_token)
    "public_host": "",       # IP or domain clients connect to, e.g. 185.114.72.195
    "port": 443,
    "fingerprint": "chrome",  # client-side uTLS fingerprint, used by both modes
    "autostart": True,

    # ws_tls mode
    "ws_path": "/ms",
    "sni": "www.microsoft.com",  # camouflage SNI presented in the TLS handshake
    "allow_insecure": True,      # needed by clients since the cert is self-signed
    "mtls_enabled": False,       # require a per-client CA-signed cert (see ca_cert_paths)

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


# --------------------------------------------------------- client link token

def ensure_client_link_token(settings: dict) -> bool:
    """Generate the secret /c/<token> path segment once, if missing. Kept in
    settings.json like the REALITY keys, so it survives restarts."""
    if settings.get("client_link_token"):
        return False
    settings["client_link_token"] = secrets.token_urlsafe(24)
    save_settings(settings)
    return True


def rotate_client_link_token(settings: dict) -> None:
    """Invalidate the current client link (e.g. after it leaked) and issue a
    fresh one."""
    settings["client_link_token"] = secrets.token_urlsafe(24)
    save_settings(settings)


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


def build_client_json_config(client: dict, settings: dict) -> dict:
    """A full, standalone xray client config for this client (ws_tls mode
    only). Newer xray-core releases (confirmed against the 26.2.6 build
    running in production) hard-reject any config containing the old
    "allowInsecure" field — it was removed in favor of pinning the server's
    self-signed leaf cert by its SHA-256 fingerprint instead, so that's what
    we embed here (verified end-to-end against the live server: a real xray
    client using this exact field connected and proxied traffic
    successfully, while allowInsecure made it refuse to even start). A plain
    vless:// link has no field for this pin (or for a client certificate),
    so this JSON config is the only reliable way to hand over a working
    profile — import it in v2rayNG via "Import config from file/clipboard".
    When mTLS is enabled, the client's own CA-signed cert/key are embedded
    inline as PEM text too (requires ensure_client_cert to have run first);
    otherwise the connection relies on the VLESS UUID alone, same as before.

    The top-level "routing" key below is a no-op (no rules) but must be
    present: v2rayNG's clipboard-paste import only recognizes a pasted blob
    as a custom config at all if it contains "inbounds", "outbounds" *and*
    "routing" — confirmed by reading its parseCustomConfigServer() source.
    Without it the paste is silently ignored (looks like a generic import
    error), even though the config itself is otherwise fully valid.

    "remarks" sets the profile's display name in v2rayNG's server list —
    read from CustomFmt.parse(): it uses fullConfig.remarks if present, else
    falls back to the current timestamp, which is what clients were seeing
    (a bare number like "1785584568599") before this field existed."""
    cert_path, _ = xray_cert_paths()
    server_name = settings.get("server_name", "").strip()
    remarks = f"{server_name} — {client['name']}" if server_name else client["name"]
    tls_settings = {
        "serverName": settings["sni"],
        "fingerprint": settings.get("fingerprint", "chrome"),
        "pinnedPeerCertSha256": certgen.cert_sha256_fingerprint(cert_path),
    }
    if settings.get("mtls_enabled"):
        client_cert_path, client_key_path = client_cert_paths(client["id"])
        tls_settings["certificates"] = [{
            "certificate": client_cert_path.read_text().strip().splitlines(),
            "key": client_key_path.read_text().strip().splitlines(),
        }]
    return {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "protocol": "socks", "listen": "127.0.0.1", "port": 10808,
             "settings": {"udp": True}},
            {"tag": "http", "protocol": "http", "listen": "127.0.0.1", "port": 10809},
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": settings["public_host"],
                        "port": settings["port"],
                        "users": [{"id": client["id"], "encryption": "none"}],
                    }]
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "tls",
                    "tlsSettings": tls_settings,
                    "wsSettings": {"path": settings["ws_path"]},
                },
            },
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []},
    }


# --------------------------------------------------------- xray config.json

def xray_cert_paths():
    return config.XRAY_CERT_DIR / "xray.crt", config.XRAY_CERT_DIR / "xray.key"


def ca_cert_paths():
    return config.XRAY_CERT_DIR / "ca.crt", config.XRAY_CERT_DIR / "ca.key"


def client_cert_paths(client_id: str):
    d = config.XRAY_CERT_DIR / "clients"
    return d / f"{client_id}.crt", d / f"{client_id}.key"


def ensure_ca() -> bool:
    ca_cert, ca_key = ca_cert_paths()
    return certgen.ensure_ca(ca_cert, ca_key, key_mode=0o600)


def ensure_client_cert(client: dict) -> bool:
    """Generate this client's mTLS cert/key, signed by our CA, if missing.
    Requires the CA to already exist (see ensure_ca / apply_config)."""
    ca_cert, ca_key = ca_cert_paths()
    cert_path, key_path = client_cert_paths(client["id"])
    return certgen.ensure_signed_cert(cert_path, key_path, cn=client["name"],
                                       ca_cert_path=ca_cert, ca_key_path=ca_key, key_mode=0o600)


def delete_client_cert(client_id: str) -> None:
    cert_path, key_path = client_cert_paths(client_id)
    cert_path.unlink(missing_ok=True)
    key_path.unlink(missing_ok=True)


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
        certificates = [{"certificateFile": str(cert_path), "keyFile": str(key_path)}]
        tls_settings = {"certificates": certificates}
        if mode == "ws_tls" and settings.get("mtls_enabled"):
            ca_cert, _ = ca_cert_paths()
            # "usage": "verify" tells xray to use this cert only to validate
            # the client cert presented during the handshake, not to serve
            # it — the server still presents its own leaf cert above.
            certificates.append({"certificateFile": str(ca_cert), "usage": "verify"})
            tls_settings["verifyClientCertificate"] = True
        stream_settings = {
            "network": "ws",
            "security": "tls",
            "tlsSettings": tls_settings,
            "wsSettings": {"path": settings["ws_path"]},
        }

    return {
        "log": {"loglevel": "warning", "access": str(config.XRAY_ACCESS_LOG)},
        # Local gRPC StatsService (127.0.0.1 only) — per-client byte
        # counters, read and reset every minute by stats.py via
        # `xray api statsquery`. Users are keyed by "email" (= client name).
        "api": {
            "tag": "api",
            "listen": f"127.0.0.1:{config.XRAY_API_PORT}",
            "services": ["StatsService"],
        },
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True},
        },
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


def query_traffic(reset: bool = True) -> tuple[bool, dict | str]:
    """Read (and by default reset) xray's byte counters. Returns
    (True, {"users": {email: {"up", "down"}}, "inbound": {"up", "down"}})
    or (False, error text) — e.g. when the running config predates the
    "api"/"stats" sections (re-apply the config + restart xray to fix)."""
    cmd = [config.XRAY_BIN, "api", "statsquery", f"--server=127.0.0.1:{config.XRAY_API_PORT}"]
    if reset:
        cmd.append("-reset")
    ok, out = _run(cmd, timeout=10)
    if not ok:
        return False, out
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return False, f"unparseable statsquery output: {out[:200]!r}"
    users: dict[str, dict] = {}
    inbound = {"up": 0, "down": 0}
    for item in data.get("stat") or []:
        parts = str(item.get("name", "")).split(">>>")
        if len(parts) != 4 or parts[2] != "traffic":
            continue
        kind, name, _, direction = parts
        # protobuf JSON renders int64 as a string, and omits zero values.
        value = int(item.get("value") or 0)
        key = "up" if direction == "uplink" else "down"
        if kind == "user":
            users.setdefault(name, {"up": 0, "down": 0})[key] += value
        elif kind == "inbound" and name == "vless-in":
            inbound[key] += value
    return True, {"users": users, "inbound": inbound}


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
        if settings.get("mtls_enabled"):
            ensure_ca()
    cfg = build_xray_config(settings, load_clients())
    write_xray_config(cfg)
    ok, output = validate_config()
    return ok, output


# --------------------------------------------------------------- systemctl

def _run(cmd: list[str], timeout: int = 20) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as e:
        return False, str(e)
    except subprocess.TimeoutExpired:
        return False, f"timed out: {' '.join(cmd)}"
    ok = result.returncode == 0
    output = (result.stdout + result.stderr).strip()
    return ok, output


def _unit_name() -> str:
    # sudo matches the command line it's given *literally* against the
    # sudoers rule — it has no idea "xray" and "xray.service" name the same
    # systemd unit the way systemctl itself does. install.sh's sudoers rule
    # always spells out the full "xray.service", so every sudo'd systemctl
    # call here must too, or `-n` fails with "a password is required" even
    # though `sudo -l` shows a matching NOPASSWD entry.
    name = config.XRAY_SERVICE_NAME
    return name if name.endswith(".service") else f"{name}.service"


def _systemctl(*args: str) -> tuple[bool, str]:
    return _run(["sudo", "-n", "systemctl", *args, _unit_name()])


def service_status() -> dict:
    active_ok, active_out = _run(["systemctl", "is-active", _unit_name()])
    enabled_ok, enabled_out = _run(["systemctl", "is-enabled", _unit_name()])
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


# ------------------------------------------------------------- self-update

def current_version() -> dict:
    """Local git HEAD, read straight from the checkout — no network call,
    safe to run on every dashboard load."""
    ok, out = _run(["git", "-C", str(config.BASE_DIR), "log", "-1", "--format=%h|%s|%ci"])
    if not ok or not out:
        return {"hash": "unknown", "message": "", "date": ""}
    h, _, rest = out.partition("|")
    msg, _, date = rest.partition("|")
    return {"hash": h, "message": msg, "date": date}


def _update_script() -> str:
    return str(config.BASE_DIR / "tools" / "self_update.sh")


def check_for_update() -> tuple[bool, str]:
    """git fetch + compare against origin/main. Runs via sudo as root (see
    install.sh's BLINKRAY_UPDATE rule) because the panel's own unprivileged
    user has no GitHub credentials of its own — only root's, set up
    out-of-band on each server, actually reach the private repo."""
    return _run(["sudo", "-n", _update_script(), "check"], timeout=60)


def apply_update() -> tuple[bool, str]:
    """git reset --hard origin/main + reinstall requirements + restart the
    panel — see tools/self_update.sh for the actual steps (also root, same
    reason as check_for_update). The restart happens in the background a
    second after this returns, so the caller gets to send its HTTP response
    first instead of being killed mid-request."""
    return _run(["sudo", "-n", _update_script(), "apply"], timeout=120)
