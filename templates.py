"""Tiny HTML templating with plain f-strings (no Jinja2 dependency).
All user-controlled values are passed through html.escape()."""
from html import escape
from urllib.parse import quote

PAGE_HEAD = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
"""

PAGE_TAIL = """
</body>
</html>
"""


def _flash_html(flash: str | None, level: str) -> str:
    if not flash:
        return ""
    cls = "flash flash-error" if level == "error" else "flash flash-ok"
    return f'<div class="{cls}">{escape(flash)}</div>'


def login_page(error: str | None) -> str:
    err_html = '<div class="flash flash-error">Неверный пароль</div>' if error else ""
    body = f"""
<div class="login-wrap">
  <form class="login-box" method="post" action="/login">
    <h1>Blinkray</h1>
    {err_html}
    <input type="password" name="password" placeholder="Пароль" autofocus required>
    <button type="submit">Войти</button>
  </form>
</div>
"""
    return PAGE_HEAD.format(title="Вход — Blinkray") + body + PAGE_TAIL


def _status_badge(running: bool) -> str:
    if running:
        return '<span class="badge badge-on">работает</span>'
    return '<span class="badge badge-off">остановлен</span>'


def _autostart_badge(enabled: str) -> str:
    on = enabled == "enabled"
    label = "включён" if on else "выключен"
    cls = "badge-on" if on else "badge-off"
    return f'<span class="badge {cls}">автозапуск: {label}</span>'


def _client_row(client: dict, link: str) -> str:
    cid = escape(client["id"])
    name = escape(client["name"])
    enabled = client.get("enabled", True)
    state_label = "включён" if enabled else "выключен"
    state_cls = "badge-on" if enabled else "badge-off"
    toggle_label = "Выключить" if enabled else "Включить"
    return f"""
<tr>
  <td>{name}</td>
  <td><code class="uuid">{cid}</code></td>
  <td><span class="badge {state_cls}">{state_label}</span></td>
  <td class="link-cell">
    <input type="text" readonly value="{escape(link)}" onclick="this.select()">
    <button type="button" class="btn btn-small" onclick="copyLink(this)">Копировать</button>
  </td>
  <td class="actions">
    <form method="post" action="/clients/{cid}/toggle" class="inline-form">
      <button type="submit" class="btn btn-small">{toggle_label}</button>
    </form>
    <form method="post" action="/clients/{cid}/delete" class="inline-form" onsubmit="return confirm('Удалить клиента {name}?')">
      <button type="submit" class="btn btn-small btn-danger">Удалить</button>
    </form>
  </td>
</tr>
"""


def _mode_info_block(settings: dict, cert_fingerprint: str) -> str:
    if settings.get("mode") == "reality":
        pubkey = settings.get("reality_public_key") or ""
        short_id = settings.get("reality_short_id") or ""
        if not pubkey:
            return '<p class="muted">Ключи REALITY будут сгенерированы при первом сохранении настроек.</p>'
        return f"""
<p class="muted">Public key: <code>{escape(pubkey)}</code></p>
<p class="muted">Short ID: <code>{escape(short_id)}</code></p>
<form method="post" action="/settings/rotate-reality" class="inline-form" onsubmit="return confirm('Перегенерировать ключи REALITY? Старые ссылки клиентов перестанут работать.')">
  <button type="submit" class="btn btn-small btn-danger">Перегенерировать ключи</button>
</form>
"""
    return f'<p class="muted">SHA-256 отпечаток сертификата xray: <code>{escape(cert_fingerprint)}</code></p>'


def dashboard_page(*, status: dict, settings: dict, clients: list, links: dict,
                    xray_ver: str, apk_info: dict | None, flash: str | None,
                    flash_level: str, cert_fingerprint: str) -> str:
    running = status["running"]
    mode = settings.get("mode", "ws_tls")
    rows = "".join(_client_row(c, links[c["id"]]) for c in clients) or \
        '<tr><td colspan="5" class="empty">Пока нет клиентов</td></tr>'
    reality_display = "" if mode == "reality" else "display:none;"
    ws_tls_display = "" if mode == "ws_tls" else "display:none;"

    apk_block = ""
    if apk_info:
        size_mb = apk_info["size"] / 1024 / 1024
        apk_block = f"""
<p>Текущий файл: <strong>{escape(apk_info['name'])}</strong> ({size_mb:.1f} МБ)</p>
<a class="btn" href="/apk/download">Скачать v2rayNG.apk</a>
<form method="post" action="/apk/delete" class="inline-form" onsubmit="return confirm('Удалить загруженный apk?')">
  <button type="submit" class="btn btn-danger">Удалить файл</button>
</form>
"""
    else:
        apk_block = "<p class=\"muted\">Файл v2rayNG ещё не загружен.</p>"

    body = f"""
<header class="topbar">
  <h1>Blinkray</h1>
  <form method="post" action="/logout"><button type="submit" class="btn btn-small">Выйти</button></form>
</header>

{_flash_html(flash, flash_level)}

<section class="card">
  <h2>Сервер</h2>
  <p>{_status_badge(running)} {_autostart_badge(status['enabled'])}</p>
  <p class="muted">xray: {escape(xray_ver)}</p>
  <div class="btn-row">
    <form method="post" action="/server/start" class="inline-form"><button type="submit" class="btn" {"disabled" if running else ""}>Запустить</button></form>
    <form method="post" action="/server/stop" class="inline-form" onsubmit="return confirm('Остановить VLESS сервер?')"><button type="submit" class="btn btn-danger" {"disabled" if not running else ""}>Остановить</button></form>
    <form method="post" action="/server/restart" class="inline-form"><button type="submit" class="btn">Перезапустить</button></form>
    <form method="post" action="/server/autostart" class="inline-form">
      <input type="hidden" name="enable" value="{'0' if status['enabled']=='enabled' else '1'}">
      <button type="submit" class="btn btn-small">{'Выключить автозапуск' if status['enabled']=='enabled' else 'Включить автозапуск'}</button>
    </form>
  </div>
</section>

<section class="card">
  <h2>Настройки подключения</h2>
  <form method="post" action="/settings" class="settings-form">
    <div class="mode-switch full-row">
      <label class="radio"><input type="radio" name="mode" value="reality" {"checked" if mode == "reality" else ""} onchange="toggleMode(this.value)"> VLESS + REALITY</label>
      <label class="radio"><input type="radio" name="mode" value="ws_tls" {"checked" if mode == "ws_tls" else ""} onchange="toggleMode(this.value)"> VLESS + WS + TLS</label>
    </div>

    <label>Публичный адрес сервера (IP или домен)
      <input type="text" name="public_host" value="{escape(settings['public_host'])}" placeholder="1.2.3.4" required>
    </label>
    <label>Порт
      <input type="number" name="port" value="{settings['port']}" min="1" max="65535" required>
    </label>
    <label>Fingerprint (uTLS)
      <input type="text" name="fingerprint" value="{escape(settings.get('fingerprint', 'chrome'))}" required>
    </label>

    <div id="fields-reality" class="mode-fields full-row" style="{reality_display}">
      <label>Camouflage-домен (dest, host:port)
        <input type="text" name="reality_dest" value="{escape(settings.get('reality_dest', ''))}" placeholder="www.microsoft.com:443">
      </label>
      <label>SNI / serverName
        <input type="text" name="reality_server_name" value="{escape(settings.get('reality_server_name', ''))}" placeholder="www.microsoft.com">
      </label>
    </div>

    <div id="fields-ws_tls" class="mode-fields full-row" style="{ws_tls_display}">
      <label>WebSocket путь
        <input type="text" name="ws_path" value="{escape(settings['ws_path'])}">
      </label>
      <label>SNI (маскировочный домен)
        <input type="text" name="sni" value="{escape(settings['sni'])}">
      </label>
      <label class="checkbox">
        <input type="checkbox" name="allow_insecure" {"checked" if settings.get('allow_insecure', True) else ""}>
        allowInsecure (нужно для самоподписного сертификата)
      </label>
    </div>

    <button type="submit" class="btn">Сохранить и применить</button>
  </form>
  {_mode_info_block(settings, cert_fingerprint)}
</section>

<script>
function toggleMode(mode) {{
  document.getElementById('fields-reality').style.display = mode === 'reality' ? '' : 'none';
  document.getElementById('fields-ws_tls').style.display = mode === 'ws_tls' ? '' : 'none';
}}
</script>

<section class="card">
  <h2>Клиенты</h2>
  <form method="post" action="/clients/add" class="add-client-form">
    <input type="text" name="name" placeholder="Имя клиента" required>
    <button type="submit" class="btn">Добавить клиента</button>
  </form>
  <table class="clients-table">
    <thead><tr><th>Имя</th><th>UUID</th><th>Статус</th><th>Ссылка (для v2rayNG)</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>

<section class="card">
  <h2>Пакет v2rayNG</h2>
  <form method="post" action="/apk/upload" enctype="multipart/form-data" class="apk-form">
    <input type="file" name="apk" accept=".apk" required>
    <button type="submit" class="btn">Загрузить apk</button>
  </form>
  {apk_block}
</section>

<script>
function copyLink(btn) {{
  const input = btn.previousElementSibling;
  input.select();
  navigator.clipboard.writeText(input.value).then(() => {{
    const old = btn.textContent;
    btn.textContent = 'Скопировано!';
    setTimeout(() => btn.textContent = old, 1200);
  }});
}}
</script>
"""
    return PAGE_HEAD.format(title="Blinkray") + body + PAGE_TAIL
