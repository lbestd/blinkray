"""Password login with a signed, stateless session cookie.

No extra dependencies: the session cookie is `<expiry>.<hmac-sha256>`,
signed with a random secret persisted on disk. No password or session
state is ever stored client-side beyond the expiry timestamp.
"""
import hmac
import hashlib
import os
import time

from aiohttp import web

import config
import templates

SESSION_COOKIE = "vless_panel_session"

PUBLIC_PATHS = {"/login", "/healthz"}


def _load_secret() -> bytes:
    if config.SECRET_FILE.exists():
        return config.SECRET_FILE.read_bytes()
    secret = os.urandom(32)
    config.SECRET_FILE.write_bytes(secret)
    config.SECRET_FILE.chmod(0o600)
    return secret


_SECRET = None


def _secret() -> bytes:
    global _SECRET
    if _SECRET is None:
        _SECRET = _load_secret()
    return _SECRET


def _sign(expiry: int) -> str:
    msg = str(expiry).encode()
    return hmac.new(_secret(), msg, hashlib.sha256).hexdigest()


def make_session_value() -> str:
    expiry = int(time.time()) + config.SESSION_TTL
    return f"{expiry}.{_sign(expiry)}"


def is_valid_session(value: str | None) -> bool:
    if not value or "." not in value:
        return False
    expiry_s, sig = value.split(".", 1)
    if not expiry_s.isdigit():
        return False
    expiry = int(expiry_s)
    if expiry < time.time():
        return False
    return hmac.compare_digest(_sign(expiry), sig)


@web.middleware
async def auth_middleware(request: web.Request, handler):
    if request.path in PUBLIC_PATHS or request.path.startswith("/static/"):
        return await handler(request)

    cookie = request.cookies.get(SESSION_COOKIE)
    if not is_valid_session(cookie):
        if request.path.startswith("/api/"):
            raise web.HTTPUnauthorized(text="Not authenticated")
        raise web.HTTPFound("/login")
    return await handler(request)


async def login_get(request: web.Request) -> web.Response:
    error = request.query.get("error")
    return web.Response(text=templates.login_page(error), content_type="text/html")


async def login_post(request: web.Request) -> web.Response:
    data = await request.post()
    password = data.get("password", "")
    if not config.PANEL_PASSWORD or not hmac.compare_digest(str(password), config.PANEL_PASSWORD):
        raise web.HTTPFound("/login?error=1")

    resp = web.HTTPFound("/")
    resp.set_cookie(
        SESSION_COOKIE,
        make_session_value(),
        max_age=config.SESSION_TTL,
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    raise resp


async def logout_post(request: web.Request) -> web.Response:
    resp = web.HTTPFound("/login")
    resp.del_cookie(SESSION_COOKIE)
    raise resp


def setup_auth_routes(app: web.Application):
    app.router.add_get("/login", login_get)
    app.router.add_post("/login", login_post)
    app.router.add_post("/logout", logout_post)
