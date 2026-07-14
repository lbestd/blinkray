"""Turns xray-core's access.log into a small per-client stats.json: total
connection count, first/last seen, last source IP, and a per-day count for
the last MAX_DAILY_BUCKETS days. Runs as a background task inside the panel
process (see app.py) — no separate cron job needed.

Every cycle it reads the *whole* access.log and then truncates it in place.
Safe because xray-core opens the file for append (O_APPEND) — every write
seeks to the current end of file regardless of what any other process did
to the file's length in between, so truncating never races a concurrent
write into losing a line. This also keeps the on-disk log bounded without
needing external logrotate config: worst case it grows for one interval.

Clients are identified by the "email" field in the log line, which is the
same string we set from the client's `name` (see xray_manager.build_xray_config).
Renaming a client after it has logged connections starts a fresh entry
under the new name — the old one just stops accumulating, it isn't merged.
"""
import asyncio
import contextlib
import json
import logging
import re
import time
from datetime import datetime, timezone

import config

log = logging.getLogger("blinkray.stats")

PARSE_INTERVAL_SECONDS = 60
MAX_DAILY_BUCKETS = 30

_ACCESS_LINE_RE = re.compile(
    r"^\S+ \S+ from (?P<ip>[^:\s]+):\d+ accepted \S+ \[[^\]]*\] email: (?P<email>.+)$"
)


def load_stats() -> dict:
    if config.STATS_FILE.exists():
        try:
            return json.loads(config.STATS_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_stats(stats: dict) -> None:
    config.STATS_FILE.write_text(json.dumps(stats, indent=2, ensure_ascii=False))


def parse_once() -> int:
    """Fold any new access-log lines into stats.json and truncate the log.
    Returns how many connection events were processed."""
    log_path = config.XRAY_ACCESS_LOG
    if not log_path.exists():
        return 0
    try:
        content = log_path.read_text(errors="replace")
    except OSError as e:
        log.warning("could not read %s: %s", log_path, e)
        return 0
    if not content:
        return 0

    try:
        log_path.write_text("")
    except OSError as e:
        log.warning("could not truncate %s: %s (will re-process these lines next cycle)", log_path, e)

    stats = load_stats()
    clients = stats.setdefault("clients", {})
    now = time.time()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    processed = 0

    for line in content.splitlines():
        m = _ACCESS_LINE_RE.match(line)
        if not m:
            continue
        email = m.group("email").strip()
        if not email:
            continue
        entry = clients.setdefault(email, {
            "count": 0,
            "first_seen": now,
            "last_seen": now,
            "last_ip": "",
            "daily": {},
        })
        entry["count"] += 1
        entry["last_seen"] = now
        entry["last_ip"] = m.group("ip")
        daily = entry.setdefault("daily", {})
        daily[today] = daily.get(today, 0) + 1
        if len(daily) > MAX_DAILY_BUCKETS:
            for old_day in sorted(daily)[: len(daily) - MAX_DAILY_BUCKETS]:
                del daily[old_day]
        processed += 1

    if processed:
        stats["updated_at"] = now
        _save_stats(stats)
    return processed


async def _loop():
    while True:
        try:
            parse_once()
        except Exception:
            log.exception("stats.parse_once failed")
        await asyncio.sleep(PARSE_INTERVAL_SECONDS)


async def start(app):
    app["stats_task"] = asyncio.create_task(_loop())


async def stop(app):
    task = app.get("stats_task")
    if not task:
        return
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
