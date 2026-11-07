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
MAX_HOURLY_BUCKETS = 14 * 24

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


def _client_entry(clients: dict, email: str, now: float) -> dict:
    return clients.setdefault(email, {
        "count": 0,
        "first_seen": now,
        "last_seen": now,
        "last_ip": "",
        "daily": {},
    })


def _trim(buckets: dict, keep: int) -> None:
    if len(buckets) > keep:
        for old in sorted(buckets)[: len(buckets) - keep]:
            del buckets[old]


def _read_access_log() -> str:
    log_path = config.XRAY_ACCESS_LOG
    if not log_path.exists():
        return ""
    try:
        content = log_path.read_text(errors="replace")
    except OSError as e:
        log.warning("could not read %s: %s", log_path, e)
        return ""
    if content:
        try:
            log_path.write_text("")
        except OSError as e:
            log.warning("could not truncate %s: %s (will re-process these lines next cycle)", log_path, e)
    return content


def parse_once() -> int:
    """Fold new access-log lines (connection events) and xray's byte
    counters into stats.json, then truncate the log / reset the counters.
    Returns how many connection events were processed.

    Besides per-client totals, keeps a server-wide "hourly" series
    ({"YYYY-MM-DDTHH": {"conns", "up", "down"}}, UTC, last MAX_HOURLY_BUCKETS
    hours) — that's what the central dashboard uses to show *when* this
    server was actually carrying traffic (e.g. to spot a block)."""
    import xray_manager  # local import: xray_manager imports config too, avoid cycles at load

    content = _read_access_log()
    traffic_ok, traffic = xray_manager.query_traffic(reset=True)

    stats = load_stats()
    clients = stats.setdefault("clients", {})
    hourly = stats.setdefault("hourly", {})
    now = time.time()
    utc = datetime.now(timezone.utc)
    today = utc.strftime("%Y-%m-%d")
    hour = utc.strftime("%Y-%m-%dT%H")
    bucket = hourly.setdefault(hour, {"conns": 0, "up": 0, "down": 0})
    processed = 0

    for line in content.splitlines():
        m = _ACCESS_LINE_RE.match(line)
        if not m:
            continue
        email = m.group("email").strip()
        if not email:
            continue
        entry = _client_entry(clients, email, now)
        entry["count"] += 1
        entry["last_seen"] = now
        entry["last_ip"] = m.group("ip")
        daily = entry.setdefault("daily", {})
        daily[today] = daily.get(today, 0) + 1
        _trim(daily, MAX_DAILY_BUCKETS)
        processed += 1
    bucket["conns"] += processed

    moved = 0
    if traffic_ok:
        for email, t in traffic["users"].items():
            up, down = t["up"], t["down"]
            if not up and not down:
                continue
            entry = _client_entry(clients, email, now)
            entry["up"] = entry.get("up", 0) + up
            entry["down"] = entry.get("down", 0) + down
            entry["last_traffic_at"] = now
            daily_bytes = entry.setdefault("daily_bytes", {})
            daily_bytes[today] = daily_bytes.get(today, 0) + up + down
            _trim(daily_bytes, MAX_DAILY_BUCKETS)
        bucket["up"] += traffic["inbound"]["up"]
        bucket["down"] += traffic["inbound"]["down"]
        moved = traffic["inbound"]["up"] + traffic["inbound"]["down"]
        stats["traffic_api"] = {"ok": True, "error": "", "checked_at": now}
    else:
        stats["traffic_api"] = {"ok": False, "error": str(traffic)[:300], "checked_at": now}

    if processed or moved:
        stats["last_traffic_at"] = now
    _trim(hourly, MAX_HOURLY_BUCKETS)
    stats["updated_at"] = now
    _save_stats(stats)
    return processed


async def _loop():
    while True:
        try:
            await asyncio.to_thread(parse_once)
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
