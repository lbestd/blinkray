#!/usr/bin/env python3
"""One-shot importer: reads an existing, hand-written xray inbound
config.json (VLESS+REALITY or VLESS+WS+TLS — the two shapes Blinkray itself
understands) and writes it into Blinkray's settings.json/clients.json.

Called by install.sh before it takes over an already-running xray.service,
so a pre-existing deployment's keys and clients survive the handover
instead of getting silently replaced by an empty config on first restart.

Usage: import_xray_config.py <path-to-existing-config.json> [public_host]
Exit code 0 + config.json regenerated & validated on success, non-zero and
no changes to settings/clients on any failure (unrecognized shape, missing
fields, etc.) — callers should treat a non-zero exit as "did not import,
leave the takeover for the human to sort out by hand".
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import xray_manager as xm  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: import_xray_config.py <config.json> [public_host]", file=sys.stderr)
        return 1

    src_path = Path(sys.argv[1])
    public_host = sys.argv[2] if len(sys.argv) > 2 else ""

    cfg = json.loads(src_path.read_text())
    inbounds = cfg.get("inbounds") or []
    if not inbounds:
        print("no inbounds in source config — nothing to import", file=sys.stderr)
        return 1
    inbound = inbounds[0]
    if inbound.get("protocol") != "vless":
        print(f"first inbound protocol is {inbound.get('protocol')!r}, not vless — refusing to import", file=sys.stderr)
        return 1

    stream = inbound.get("streamSettings", {})
    security = stream.get("security")
    port = inbound.get("port", 443)
    raw_clients = inbound.get("settings", {}).get("clients", [])
    if not raw_clients:
        print("source config has no clients — refusing to import", file=sys.stderr)
        return 1

    settings = xm.load_settings()
    if public_host:
        settings["public_host"] = public_host
    settings["port"] = port

    if security == "reality":
        rs = stream.get("realitySettings", {})
        required = ("dest", "serverNames", "privateKey", "shortIds")
        missing = [k for k in required if not rs.get(k)]
        if missing:
            print(f"realitySettings missing {missing} — refusing to import", file=sys.stderr)
            return 1
        settings["mode"] = "reality"
        settings["reality_dest"] = rs["dest"]
        settings["reality_server_name"] = ", ".join(rs["serverNames"])
        settings["reality_private_key"] = rs["privateKey"]
        settings["reality_short_id"] = rs["shortIds"][0]
        settings["reality_public_key"] = xm.public_key_from_private(rs["privateKey"])
    elif security == "tls":
        ts = stream.get("tlsSettings", {})
        ws = stream.get("wsSettings", {})
        settings["mode"] = "ws_tls"
        settings["ws_path"] = ws.get("path") or settings.get("ws_path", "/ms")
        if ts.get("serverName"):
            settings["sni"] = ts["serverName"]
        settings["allow_insecure"] = bool(ts.get("allowInsecure", True))
    else:
        print(f"unsupported streamSettings.security {security!r} — refusing to import", file=sys.stderr)
        return 1

    now = int(time.time())
    clients = [
        {
            "id": c["id"],
            "name": c.get("email") or f"imported-{c['id'][:8]}",
            "enabled": True,
            "created_at": now,
        }
        for c in raw_clients
        if c.get("id")
    ]
    if not clients:
        print("no client entries had an id — refusing to import", file=sys.stderr)
        return 1

    # Only touch disk once everything above parsed cleanly.
    xm.save_settings(settings)
    xm.save_clients(clients)

    ok, out = xm.apply_config()
    print(out)
    if not ok:
        print("imported settings failed xray -test validation — check output above", file=sys.stderr)
        return 1

    print(f"imported {len(clients)} client(s), mode={settings['mode']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
