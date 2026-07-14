from urllib.parse import quote

from aiohttp import web

import config
import templates
import xray_manager
import certgen


def _redirect_with_flash(msg: str, level: str = "ok") -> web.HTTPFound:
    return web.HTTPFound(f"/?flash={quote(msg)}&level={level}")


async def dashboard(request: web.Request) -> web.Response:
    status = xray_manager.service_status()
    settings = xray_manager.load_settings()
    clients = xray_manager.load_clients()
    links = {c["id"]: xray_manager.build_vless_link(c, settings) for c in clients}

    cert_path, _ = xray_manager.xray_cert_paths()
    fingerprint = certgen.cert_sha256_fingerprint(cert_path) if cert_path.exists() else "нет сертификата — сохраните настройки"

    apk_path = _apk_path()
    apk_info = {"name": apk_path.name, "size": apk_path.stat().st_size} if apk_path else None

    html = templates.dashboard_page(
        status=status,
        settings=settings,
        clients=clients,
        links=links,
        xray_ver=xray_manager.xray_version(),
        apk_info=apk_info,
        flash=request.query.get("flash"),
        flash_level=request.query.get("level", "ok"),
        cert_fingerprint=fingerprint,
    )
    return web.Response(text=html, content_type="text/html")


# --------------------------------------------------------------- server control

async def server_start(request: web.Request) -> web.Response:
    ok, out = xray_manager.start_service()
    return _redirect_with_flash("Сервер запущен" if ok else f"Ошибка запуска: {out}", "ok" if ok else "error")


async def server_stop(request: web.Request) -> web.Response:
    ok, out = xray_manager.stop_service()
    return _redirect_with_flash("Сервер остановлен" if ok else f"Ошибка остановки: {out}", "ok" if ok else "error")


async def server_restart(request: web.Request) -> web.Response:
    ok, out = xray_manager.restart_service()
    return _redirect_with_flash("Сервер перезапущен" if ok else f"Ошибка перезапуска: {out}", "ok" if ok else "error")


async def server_autostart(request: web.Request) -> web.Response:
    data = await request.post()
    enable = data.get("enable") == "1"
    ok, out = xray_manager.set_autostart(enable)
    msg = ("Автозапуск включён" if enable else "Автозапуск выключен") if ok else f"Ошибка: {out}"
    return _redirect_with_flash(msg, "ok" if ok else "error")


# ------------------------------------------------------------------- settings

async def update_settings(request: web.Request) -> web.Response:
    data = await request.post()
    settings = xray_manager.load_settings()
    try:
        port = int(data.get("port", settings["port"]))
    except ValueError:
        return _redirect_with_flash("Некорректный порт", "error")

    mode = data.get("mode")
    if mode not in ("reality", "ws_tls"):
        return _redirect_with_flash("Некорректный режим", "error")

    settings["mode"] = mode
    settings["public_host"] = str(data.get("public_host", "")).strip()
    settings["port"] = port
    settings["fingerprint"] = str(data.get("fingerprint", "chrome")).strip() or "chrome"

    settings["ws_path"] = str(data.get("ws_path", settings["ws_path"])).strip() or "/ms"
    settings["sni"] = str(data.get("sni", settings["sni"])).strip() or settings["sni"]
    settings["allow_insecure"] = data.get("allow_insecure") is not None

    settings["reality_dest"] = str(data.get("reality_dest", settings["reality_dest"])).strip() or settings["reality_dest"]
    settings["reality_server_name"] = str(data.get("reality_server_name", settings["reality_server_name"])).strip() or settings["reality_server_name"]

    xray_manager.save_settings(settings)

    ok, out = xray_manager.apply_config()
    if not ok:
        return _redirect_with_flash(f"Конфиг сохранён, но не прошёл проверку xray: {out}", "error")

    status = xray_manager.service_status()
    if status["running"]:
        restarted, rout = xray_manager.restart_service()
        if not restarted:
            return _redirect_with_flash(f"Настройки сохранены, но перезапуск не удался: {rout}", "error")
        return _redirect_with_flash("Настройки сохранены и применены (сервер перезапущен)")
    return _redirect_with_flash("Настройки сохранены и применены")


async def rotate_reality_keys(request: web.Request) -> web.Response:
    settings = xray_manager.load_settings()
    if settings.get("mode") != "reality":
        return _redirect_with_flash("Сначала переключитесь в режим REALITY", "error")
    xray_manager.rotate_reality_keys(settings)

    ok, out = xray_manager.apply_config()
    if not ok:
        return _redirect_with_flash(f"Ключи перегенерированы, но конфиг не прошёл проверку: {out}", "error")
    if xray_manager.service_status()["running"]:
        xray_manager.restart_service()
    return _redirect_with_flash("Ключи REALITY перегенерированы — старые ссылки клиентов больше не работают")


# ------------------------------------------------------------------- clients

async def clients_add(request: web.Request) -> web.Response:
    data = await request.post()
    name = str(data.get("name", "")).strip()
    if not name:
        return _redirect_with_flash("Укажите имя клиента", "error")
    xray_manager.add_client(name)
    ok, out = xray_manager.apply_config()
    if not ok:
        return _redirect_with_flash(f"Клиент добавлен, но конфиг не прошёл проверку: {out}", "error")
    if xray_manager.service_status()["running"]:
        xray_manager.restart_service()
    return _redirect_with_flash(f"Клиент «{name}» добавлен")


async def clients_delete(request: web.Request) -> web.Response:
    client_id = request.match_info["client_id"]
    xray_manager.delete_client(client_id)
    xray_manager.apply_config()
    if xray_manager.service_status()["running"]:
        xray_manager.restart_service()
    return _redirect_with_flash("Клиент удалён")


async def clients_toggle(request: web.Request) -> web.Response:
    client_id = request.match_info["client_id"]
    xray_manager.toggle_client(client_id)
    xray_manager.apply_config()
    if xray_manager.service_status()["running"]:
        xray_manager.restart_service()
    return _redirect_with_flash("Статус клиента изменён")


# ----------------------------------------------------------------------- apk

def _apk_path():
    files = list(config.APK_DIR.glob("*.apk"))
    return files[0] if files else None


async def apk_upload(request: web.Request) -> web.Response:
    reader = await request.multipart()
    field = await reader.next()
    if field is None or field.name != "apk":
        return _redirect_with_flash("Файл не выбран", "error")

    filename = field.filename or "v2rayNG.apk"
    if not filename.lower().endswith(".apk"):
        return _redirect_with_flash("Нужен файл .apk", "error")

    for old in config.APK_DIR.glob("*.apk"):
        old.unlink()

    dest = config.APK_DIR / filename
    size = 0
    with open(dest, "wb") as f:
        while True:
            chunk = await field.read_chunk(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > config.APK_MAX_SIZE:
                f.close()
                dest.unlink(missing_ok=True)
                return _redirect_with_flash("Файл слишком большой", "error")
            f.write(chunk)

    return _redirect_with_flash(f"Файл {filename} загружен")


async def apk_download(request: web.Request) -> web.Response:
    path = _apk_path()
    if not path:
        raise web.HTTPNotFound(text="apk не загружен")
    return web.FileResponse(
        path,
        headers={"Content-Disposition": f'attachment; filename="{path.name}"'},
    )


async def apk_delete(request: web.Request) -> web.Response:
    path = _apk_path()
    if path:
        path.unlink()
    return _redirect_with_flash("Файл удалён")


async def healthz(request: web.Request) -> web.Response:
    return web.Response(text="ok")


def setup_routes(app: web.Application):
    app.router.add_get("/", dashboard)
    app.router.add_get("/healthz", healthz)

    app.router.add_post("/server/start", server_start)
    app.router.add_post("/server/stop", server_stop)
    app.router.add_post("/server/restart", server_restart)
    app.router.add_post("/server/autostart", server_autostart)

    app.router.add_post("/settings", update_settings)
    app.router.add_post("/settings/rotate-reality", rotate_reality_keys)

    app.router.add_post("/clients/add", clients_add)
    app.router.add_post("/clients/{client_id}/delete", clients_delete)
    app.router.add_post("/clients/{client_id}/toggle", clients_toggle)

    app.router.add_post("/apk/upload", apk_upload)
    app.router.add_get("/apk/download", apk_download)
    app.router.add_post("/apk/delete", apk_delete)

    app.router.add_static("/static", str((config.BASE_DIR / "static")), name="static")
