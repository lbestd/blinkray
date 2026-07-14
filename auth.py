"""Password login with a signed, stateless session cookie.

No extra dependencies: the session cookie is `<expiry>.<hmac-sha256>`,
signed with a random secret persisted on disk. No password or session
state is ever stored client-side beyond the expiry timestamp.
"""
import hmac
import hashlib
import os
import time
from urllib.parse import quote

from aiohttp import web

import config
import templates

SESSION_COOKIE = "vless_panel_session"

PUBLIC_PATHS = {"/login", "/healthz"}

# Login brute-force protection, in-memory (per-process) — same idea as the
# fail2ban jail this project already runs for SSH: too many wrong passwords
# from one IP within a window earns that IP a temporary ban. Resets on
# panel restart, which is fine for a low-traffic personal admin panel.
LOGIN_MAX_ATTEMPTS = int(os.environ.get("PANEL_LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_WINDOW_SECONDS = int(os.environ.get("PANEL_LOGIN_WINDOW_SECONDS", "300"))
LOGIN_BAN_SECONDS = int(os.environ.get("PANEL_LOGIN_BAN_SECONDS", "900"))

_login_failures: dict[str, list[float]] = {}
_login_banned_until: dict[str, float] = {}


def _client_ip(request: web.Request) -> str:
    return request.remote or "unknown"


def _login_blocked(ip: str) -> int:
    """Returns remaining ban seconds, or 0 if not currently banned."""
    until = _login_banned_until.get(ip)
    if until and until > time.time():
        return int(until - time.time())
    return 0


def _record_login_failure(ip: str) -> None:
    now = time.time()
    attempts = [t for t in _login_failures.get(ip, []) if now - t < LOGIN_WINDOW_SECONDS]
    attempts.append(now)
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        _login_banned_until[ip] = now + LOGIN_BAN_SECONDS
        _login_failures.pop(ip, None)
    else:
        _login_failures[ip] = attempts


def _clear_login_failures(ip: str) -> None:
    _login_failures.pop(ip, None)
    _login_banned_until.pop(ip, None)


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


def rotate_secret() -> None:
    """Invalidate every outstanding session cookie immediately — called
    after a password change so a stolen old cookie stops working too."""
    global _SECRET
    secret = os.urandom(32)
    config.SECRET_FILE.write_bytes(secret)
    config.SECRET_FILE.chmod(0o600)
    _SECRET = secret


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
    notice = request.query.get("notice")
    return web.Response(text=templates.login_page(error, notice), content_type="text/html")


async def login_post(request: web.Request) -> web.Response:
    ip = _client_ip(request)
    banned_for = _login_blocked(ip)
    if banned_for:
        minutes = max(1, banned_for // 60)
        msg = f"Слишком много неудачных попыток входа. Попробуйте снова через {minutes} мин."
        raise web.HTTPFound(f"/login?error={quote(msg)}")

    data = await request.post()
    password = data.get("password", "")
    if not config.PANEL_PASSWORD or not hmac.compare_digest(str(password), config.PANEL_PASSWORD):
        _record_login_failure(ip)
        raise web.HTTPFound(f"/login?error={quote('Неверный пароль')}")

    _clear_login_failures(ip)
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
