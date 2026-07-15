"""Tiny HTML templating with plain f-strings (no Jinja2 dependency).
All user-controlled values are passed through html.escape()."""
from datetime import datetime
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
<script>
// Strip ?flash=...&level=...&error=...&notice=... from the address bar once
// shown, so refreshing (F5) re-requests the clean URL instead of re-showing
// a stale message — and never resubmits the action that produced it (every
// action already redirects here via POST-Redirect-GET, this just tidies up
// what's left in the bar afterwards).
if (window.location.search) {
  window.history.replaceState({}, document.title, window.location.pathname);
}
</script>
</body>
</html>
"""


def _flash_html(flash: str | None, level: str) -> str:
    if not flash:
        return ""
    cls = "flash flash-error" if level == "error" else "flash flash-ok"
    return f'<div class="{cls}">{escape(flash)}</div>'


def login_page(error: str | None, notice: str | None = None) -> str:
    err_html = f'<div class="flash flash-error">{escape(error)}</div>' if error else ""
    notice_html = f'<div class="flash flash-ok">{escape(notice)}</div>' if notice else ""
    body = f"""
<div class="login-wrap">
  <form class="login-box" method="post" action="/login">
    <h1>Blinkray</h1>
    {err_html}
    {notice_html}
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


def _client_card(client: dict, link: str, mtls: bool = False) -> str:
    cid = escape(client["id"])
    name = escape(client["name"])
    enabled = client.get("enabled", True)
    state_label = "включён" if enabled else "выключен"
    state_cls = "badge-on" if enabled else "badge-off"
    toggle_label = "Выключить" if enabled else "Включить"
    if mtls:
        # A plain vless:// link has nowhere to carry a client certificate,
        # so once mTLS is required for this client the link alone can't
        # authenticate — copy the full JSON config instead (v2rayNG's
        # "Import from Clipboard" accepts a pasted config, not just a
        # share-link) so copy-paste still works, and keep a file-download
        # alternative alongside it.
        copy_button = (
            f'<button type="button" class="btn" '
            f'onclick="copyCertConfig(this, \'/clients/{cid}/cert\')" '
            f'title="Копирует JSON-конфиг с сертификатом — обычная ссылка тут не подключится">'
            f'Копировать</button>'
        )
        cert_button = f'<a class="btn btn-small" href="/clients/{cid}/cert" title="Скачать тот же конфиг файлом">Сертификат</a>'
    else:
        copy_button = '<button type="button" class="btn" onclick="copyLink(this)">Копировать</button>'
        cert_button = ""
    return f"""
<div class="client-card">
  <div class="client-header">
    <div class="client-name-view" id="name-view-{cid}">
      <strong>{name}</strong>
      <button type="button" class="btn-icon" onclick="editName('{cid}')" title="Переименовать">&#9998;</button>
      <span class="badge {state_cls}">{state_label}</span>
    </div>
    <form method="post" action="/clients/{cid}/rename" class="inline-form rename-form" id="name-edit-{cid}" style="display:none;">
      <input type="text" name="name" value="{name}" class="rename-input" required>
      <button type="submit" class="btn btn-small">Сохранить</button>
      <button type="button" class="btn btn-small" onclick="cancelEditName('{cid}')">Отмена</button>
    </form>
  </div>
  <div class="client-uuid muted">UUID: <code class="uuid">{cid}</code></div>
  <div class="client-link-row">
    <input type="text" readonly value="{escape(link)}" onclick="this.select()">
    {copy_button}
  </div>
  <div class="actions">
    {cert_button}
    <form method="post" action="/clients/{cid}/toggle" class="inline-form">
      <button type="submit" class="btn btn-small">{toggle_label}</button>
    </form>
    <form method="post" action="/clients/{cid}/delete" class="inline-form" onsubmit="return confirm('Удалить клиента {name}?')">
      <button type="submit" class="btn btn-small btn-danger">Удалить</button>
    </form>
  </div>
</div>
"""


def _format_ts(ts: float | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _stats_row(client: dict, entry: dict | None) -> str:
    name = escape(client["name"])
    if not entry:
        return f"""
<tr>
  <td>{name}</td>
  <td colspan="4" class="muted">ещё не подключался</td>
</tr>
"""
    return f"""
<tr>
  <td>{name}</td>
  <td>{entry['count']}</td>
  <td>{entry['today']}</td>
  <td>{_format_ts(entry['last_seen'])}</td>
  <td><code class="uuid">{escape(entry['last_ip'])}</code></td>
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


def _guide_block(settings: dict, apk_info: dict | None) -> str:
    mtls = settings.get("mode") == "ws_tls" and settings.get("mtls_enabled", False)

    if apk_info:
        step1 = """
    <p>Откройте эту страницу панели <strong>прямо на телефоне</strong> (в браузере телефона), пролистайте вниз до раздела «Пакет v2rayNG» и нажмите кнопку <strong>«Скачать v2rayNG.apk»</strong>. Файл скачается в папку «Загрузки».</p>
"""
    else:
        step1 = """
    <p>Установите приложение <strong>v2rayNG</strong> — на телефоне откройте Google Play, найдите «v2rayNG» и нажмите «Установить». Если Google Play недоступен — попросите того, кто настраивал сервер, прислать вам apk-файл, и переходите сразу к шагу 2.</p>
"""

    if mtls:
        import_step = """
    <p><strong>а)</strong> На этой странице (с телефона или компьютера — не важно) откройте раздел «Клиенты» ниже и найдите свою карточку.</p>
    <p><strong>б)</strong> Нажмите кнопку <strong>«Копировать»</strong> напротив своего имени — она скопирует в буфер обмена ваш личный конфиг с сертификатом. Если ссылку/конфиг копируете с телефона — на нём и открывайте v2rayNG дальше. Если копировали с компьютера — нажмите вместо этого кнопку <strong>«Сертификат»</strong>, она скачает файл, который нужно перекинуть на телефон (например, через Telegram «Избранное» или почту самому себе).</p>
    <p><strong>в)</strong> В v2rayNG нажмите «+» в правом верхнем углу.</p>
    <p><strong>г)</strong> Если копировали через «Копировать» — выберите пункт <strong>«Импорт конфигурации из буфера обмена»</strong> (Import config from Clipboard). Если скачивали файл через «Сертификат» — выберите <strong>«Импорт конфигурации из файла»</strong> (Import config from file) и укажите скачанный файл.</p>
    <p class="muted">Обычная короткая ссылка вида vless://... для вас не подойдёт — в этом режиме сервер проверяет у каждого личный сертификат, а ссылка его не содержит.</p>
"""
    else:
        import_step = """
    <p><strong>а)</strong> На этой странице откройте раздел «Клиенты» ниже, найдите свою карточку и нажмите кнопку <strong>«Копировать»</strong> — скопируется ваша личная ссылка подключения (начинается с vless://).</p>
    <p><strong>б)</strong> Если копировали с компьютера, а телефон другой — перешлите эту ссылку себе на телефон (например, через Telegram «Избранное» или почту).</p>
    <p><strong>в)</strong> Откройте v2rayNG на телефоне, нажмите «+» в правом верхнем углу, выберите <strong>«Импорт конфигурации из буфера обмена»</strong> (Import config from Clipboard). Приложение само найдёт скопированную ссылку.</p>
"""

    return f"""
<ol class="guide-steps">
  <li>
    <strong>Скачайте и установите приложение v2rayNG.</strong>
{step1}
  </li>
  <li>
    <strong>Разрешите установку (если ставили через apk-файл, а не Google Play).</strong>
    <p>При открытии скачанного файла телефон покажет предупреждение «Установка заблокирована» или «Небезопасный файл». Нажмите «Настройки» → включите «Разрешить установку из этого источника» → вернитесь назад и нажмите «Установить».</p>
  </li>
  <li>
    <strong>Получите и добавьте свой личный конфиг сервера.</strong>
{import_step}
  </li>
  <li>
    <strong>Выберите сервер в списке.</strong>
    <p>В v2rayNG появится новая строка с названием сервера — нажмите на неё один раз, слева появится отметка (кружок/галочка), что означает «выбран как активный».</p>
  </li>
  <li>
    <strong>Включите VPN.</strong>
    <p>Нажмите большую круглую кнопку с буквой «V» внизу экрана.</p>
  </li>
  <li>
    <strong>Разрешите Android создать VPN-подключение.</strong>
    <p>Появится системное окно «Запрос на подключение» / «VPN connection request» — это стандартное окно самого Android, а не наше приложение. Нажмите «ОК» / «Разрешить». Оно появляется только при первом включении.</p>
  </li>
  <li>
    <strong>Проверьте, что всё работает.</strong>
    <p>Кнопка «V» станет зелёной и покажет «Подключено» и счётчик трафика, а вверху экрана телефона в строке состояния появится значок ключа (VPN). Дополнительно можно открыть браузер и зайти на 2ip.ru — показанный там IP-адрес должен отличаться от обычного.</p>
  </li>
  <li>
    <strong>Чтобы выключить VPN</strong> — снова откройте v2rayNG и нажмите ту же круглую кнопку «V».
  </li>
</ol>
<p class="muted"><strong>Если не подключается:</strong> проверьте, что дата и время на телефоне выставлены автоматически и верны (для сертификатов это критично); убедитесь, что сервер запущен в разделе «Сервер» выше на этой странице; попробуйте скопировать ссылку/конфиг заново — возможно, скопировалась не полностью.</p>
"""


def dashboard_page(*, status: dict, settings: dict, clients: list, links: dict,
                    client_stats: dict, xray_ver: str, apk_info: dict | None, flash: str | None,
                    flash_level: str, cert_fingerprint: str) -> str:
    running = status["running"]
    mode = settings.get("mode", "ws_tls")
    mtls = mode == "ws_tls" and settings.get("mtls_enabled", False)
    cards = "".join(_client_card(c, links[c["id"]], mtls) for c in clients) or \
        '<p class="muted empty">Пока нет клиентов</p>'
    stats_rows = "".join(_stats_row(c, client_stats.get(c["id"])) for c in clients) or \
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
  <div class="btn-row" style="margin:0;">
    <button type="button" class="btn btn-small" onclick="toggleGuide()">Инструкция</button>
    <form method="post" action="/logout" class="inline-form"><button type="submit" class="btn btn-small">Выйти</button></form>
  </div>
</header>

{_flash_html(flash, flash_level)}

<section class="card" id="guide" style="display:none;">
  <h2>Как подключиться с телефона</h2>
  {_guide_block(settings, apk_info)}
</section>

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
      <label>SNI / serverNames (через запятую, если несколько)
        <input type="text" name="reality_server_name" value="{escape(settings.get('reality_server_name', ''))}" placeholder="www.microsoft.com, www.bing.com">
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
      <label class="checkbox">
        <input type="checkbox" name="mtls_enabled" {"checked" if settings.get('mtls_enabled', False) else ""}>
        Требовать клиентский сертификат (mTLS)
      </label>
      <p class="muted full-row">При включении у каждого клиента в таблице ниже появится кнопка «Сертификат» — готовый JSON-конфиг с его личным сертификатом для импорта в v2rayNG (вместо обычной ссылки).</p>
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
  <div class="clients-list">{cards}</div>
</section>

<section class="card">
  <h2>Статистика подключений</h2>
  <div class="table-scroll">
    <table class="clients-table">
      <thead><tr><th>Имя</th><th>Всего</th><th>Сегодня</th><th>Последний раз</th><th>Последний IP</th></tr></thead>
      <tbody>{stats_rows}</tbody>
    </table>
  </div>
  <p class="muted">Обновляется раз в минуту из access-лога xray.</p>
</section>

<section class="card">
  <h2>Пакет v2rayNG</h2>
  <form method="post" action="/apk/upload" enctype="multipart/form-data" class="apk-form">
    <input type="file" name="apk" accept=".apk" required>
    <button type="submit" class="btn">Загрузить apk</button>
  </form>
  {apk_block}
</section>

<section class="card">
  <h2>Пароль от панели</h2>
  <form method="post" action="/account/password" class="settings-form">
    <label>Текущий пароль
      <input type="password" name="current_password" required>
    </label>
    <label>Новый пароль
      <input type="password" name="new_password" minlength="8" required>
    </label>
    <label>Повторите новый пароль
      <input type="password" name="new_password2" minlength="8" required>
    </label>
    <button type="submit" class="btn">Сменить пароль</button>
  </form>
  <p class="muted">После смены пароля все текущие сессии (включая эту) слетят — придётся войти заново.</p>
</section>

<script>
function copyLink(btn) {{
  const input = btn.closest('.client-link-row').querySelector('input');
  input.select();
  navigator.clipboard.writeText(input.value).then(() => {{
    const old = btn.textContent;
    btn.textContent = 'Скопировано!';
    setTimeout(() => btn.textContent = old, 1200);
  }});
}}

function editName(id) {{
  document.getElementById('name-view-' + id).style.display = 'none';
  const form = document.getElementById('name-edit-' + id);
  form.style.display = 'flex';
  form.querySelector('input').focus();
}}

function cancelEditName(id) {{
  document.getElementById('name-edit-' + id).style.display = 'none';
  document.getElementById('name-view-' + id).style.display = '';
}}

function toggleGuide() {{
  const el = document.getElementById('guide');
  const hidden = el.style.display === 'none';
  el.style.display = hidden ? '' : 'none';
  if (hidden) el.scrollIntoView({{behavior: 'smooth'}});
}}

function copyCertConfig(btn, url) {{
  const old = btn.textContent;
  fetch(url).then(r => r.text()).then(text => navigator.clipboard.writeText(text)).then(() => {{
    btn.textContent = 'Скопировано!';
    setTimeout(() => btn.textContent = old, 1200);
  }}).catch(() => {{
    btn.textContent = 'Ошибка';
    setTimeout(() => btn.textContent = old, 1200);
  }});
}}
</script>
"""
    return PAGE_HEAD.format(title="Blinkray") + body + PAGE_TAIL
