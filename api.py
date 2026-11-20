"""Machine-readable API for a central dashboard that manages several
Blinkray servers from one place. Everything under /api/v1/ is
authenticated by a Bearer token (see auth.api_token), not the panel
password/session cookie.

Deliberately narrow: status/stats (read), xray service control,
self-update, and (as of 2026-11-20) creating/deleting individual VLESS
clients — enough for a central dashboard to provision one real client per
subscription-client per server, without needing the full panel password.
Settings (mode, REALITY keys, etc.) are still changed only from this
panel's own UI.
"""
import asyncio
import time
from datetime import datetime, timezone

from aiohttp import web

import stats
import xray_manager

to_thread = asyncio.to_thread

API_VERSION = 1


def _client_summary(raw: dict, clients: list[dict]) -> list[dict]:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    by_name = {c["name"]: c for c in clients}
    names = list(by_name) + [n for n in raw if n not in by_name]
    result = []
    for name in names:
        entry = raw.get(name, {})
        c = by_name.get(name)
        result.append({
            "name": name,
            "known": c is not None,  # False = stats for a deleted/renamed client
            "enabled": bool(c.get("enabled", True)) if c else False,
            "conns_total": entry.get("count", 0),
            "conns_today": entry.get("daily", {}).get(today, 0),
            "up": entry.get("up", 0),
            "down": entry.get("down", 0),
            "bytes_today": entry.get("daily_bytes", {}).get(today, 0),
            "last_seen": entry.get("last_seen"),
            "last_traffic_at": entry.get("last_traffic_at"),
            "last_ip": entry.get("last_ip", ""),
        })
    return result


async def status(request: web.Request) -> web.Response:
    settings = xray_manager.load_settings()
    clients = xray_manager.load_clients()
    service, xray_ver, version = await asyncio.gather(
        to_thread(xray_manager.service_status),
        to_thread(xray_manager.xray_version),
        to_thread(xray_manager.current_version),
    )
    st = stats.load_stats()
    return web.json_response({
        "api_version": API_VERSION,
        "time": time.time(),
        "panel": {"version": version},
        "xray": {"version": xray_ver, **service},
        "server": {
            "name": settings.get("server_name", ""),
            "mode": settings.get("mode", "ws_tls"),
            "public_host": settings.get("public_host", ""),
            "port": settings.get("port"),
        },
        "clients": {
            "total": len(clients),
            "enabled": sum(1 for c in clients if c.get("enabled", True)),
        },
        "stats": {
            "updated_at": st.get("updated_at"),
            "last_traffic_at": st.get("last_traffic_at"),
            "traffic_api": st.get("traffic_api"),
            "hourly": st.get("hourly", {}),
            "clients": _client_summary(st.get("clients", {}), clients),
        },
    })


async def xray_action(request: web.Request) -> web.Response:
    action = request.match_info["action"]
    if action == "start":
        ok, out = await to_thread(xray_manager.start_service)
    elif action == "stop":
        ok, out = await to_thread(xray_manager.stop_service)
    elif action == "restart":
        ok, out = await to_thread(xray_manager.restart_service)
    elif action == "apply":
        # Regenerate config.json from settings/clients (also enables the
        # traffic counters on servers whose config predates them), validate,
        # and only restart xray if validation passed.
        ok, out = await to_thread(xray_manager.apply_config)
        if ok:
            ok, restart_out = await to_thread(xray_manager.restart_service)
            out = "\n".join(x for x in (out, restart_out) if x)
    else:
        raise web.HTTPNotFound(text=f"unknown action {action!r}")
    return web.json_response({"ok": ok, "output": out})


async def update_check(request: web.Request) -> web.Response:
    ok, out = await to_thread(xray_manager.check_for_update)
    return web.json_response({"ok": ok, "output": out.strip()})


async def update_apply(request: web.Request) -> web.Response:
    ok, out = await to_thread(xray_manager.apply_update)
    return web.json_response({"ok": ok, "output": out.strip()})


async def clients_add(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except ValueError:
        raise web.HTTPBadRequest(text="bad json")
    name = str((body or {}).get("name", "")).strip()
    if not name:
        raise web.HTTPBadRequest(text="name required")

    client = await to_thread(xray_manager.add_client, name)
    ok, out = await to_thread(xray_manager.apply_config)
    if not ok:
        # Client is saved either way (matches the UI's clients_add
        # behaviour) — report the config problem, don't silently drop it.
        return web.json_response({"ok": False, "error": f"конфиг не прошёл проверку: {out}",
                                   "client_id": client["id"]})
    if (await to_thread(xray_manager.service_status))["running"]:
        await to_thread(xray_manager.restart_service)

    settings = xray_manager.load_settings()
    link = xray_manager.build_vless_link(client, settings)
    return web.json_response({"ok": True, "client_id": client["id"], "link": link})


async def clients_delete(request: web.Request) -> web.Response:
    client_id = request.match_info["client_id"]
    await to_thread(xray_manager.delete_client, client_id)
    await to_thread(xray_manager.delete_client_cert, client_id)
    ok, out = await to_thread(xray_manager.apply_config)
    if ok and (await to_thread(xray_manager.service_status))["running"]:
        await to_thread(xray_manager.restart_service)
    return web.json_response({"ok": ok, "output": out if not ok else ""})


async def clients_link(request: web.Request) -> web.Response:
    """Current vless:// link for an existing client, under whatever mode
    the server is running right now. Needed because the link depends on
    settings (mode, REALITY keys, xhttp_path, ...) that change independently
    of the client itself — e.g. after switching the server's mode, every
    existing client's link changes even though no client was added/removed."""
    client_id = request.match_info["client_id"]
    client = next((c for c in xray_manager.load_clients() if c["id"] == client_id), None)
    if not client:
        raise web.HTTPNotFound(text="client not found")
    settings = xray_manager.load_settings()
    return web.json_response({"ok": True, "client_id": client_id,
                               "link": xray_manager.build_vless_link(client, settings)})


def setup_api_routes(app: web.Application) -> None:
    app.router.add_get("/api/v1/status", status)
    app.router.add_post("/api/v1/xray/{action}", xray_action)
    app.router.add_post("/api/v1/update/check", update_check)
    app.router.add_post("/api/v1/update/apply", update_apply)
    app.router.add_post("/api/v1/clients", clients_add)
    app.router.add_post("/api/v1/clients/{client_id}/delete", clients_delete)
    app.router.add_get("/api/v1/clients/{client_id}/link", clients_link)
