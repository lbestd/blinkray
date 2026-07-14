import logging
import ssl

from aiohttp import web

import config
import certgen
import auth
import routes
import stats


def create_app() -> web.Application:
    config.require_password()
    config.ensure_dirs()

    app = web.Application(middlewares=[auth.auth_middleware])
    auth.setup_auth_routes(app)
    routes.setup_routes(app)
    app.on_startup.append(stats.start)
    app.on_cleanup.append(stats.stop)
    return app


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = create_app()

    cert_path = config.PANEL_CERT_DIR / "panel.crt"
    key_path = config.PANEL_CERT_DIR / "panel.key"
    cn = config.PANEL_HOST if config.PANEL_HOST not in ("0.0.0.0", "") else "blinkray.local"
    created = certgen.ensure_self_signed_cert(cert_path, key_path, cn=cn, sans=[cn, "localhost", "127.0.0.1"])
    if created:
        logging.info("Generated self-signed panel certificate at %s", cert_path)

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(str(cert_path), str(key_path))

    logging.info("Starting Blinkray panel on https://%s:%s", config.PANEL_HOST, config.PANEL_PORT)
    web.run_app(app, host=config.PANEL_HOST, port=config.PANEL_PORT, ssl_context=ssl_ctx)


if __name__ == "__main__":
    main()
