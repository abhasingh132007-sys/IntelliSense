"""
alert_store.py
---------------
Rolling in-memory store for REAL alerts produced by detection.py.
Same pattern as packet_buffer.py, kept as a separate module since alerts
and raw packets have different shapes and different consumers.

Phase 7 (database.py) will eventually persist these to SQLite instead of
just memory - at that point this module's functions get reimplemented
against the DB, but app.py's calls into it (add_alert / get_alerts)
won't need to change.
"""

from collections import deque
from datetime import datetime
import threading

MAX_ALERTS = 200
_alerts = deque(maxlen=MAX_ALERTS)
_lock = threading.Lock()
_next_id = 1


def add_alert(alert_type, source_ip, severity, description, status="Detected"):
    global _next_id
    with _lock:
        alert = {
            "id": _next_id,
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": alert_type,
            "source_ip": source_ip,
            "severity": severity,
            "status": status,
            "description": description
        }
        _alerts.append(alert)
        _next_id += 1
        return alert


def get_alerts(limit=None):
    with _lock:
        items = list(reversed(_alerts))  # most recent first
    return items[:limit] if limit else items


def get_count():
    with _lock:
        return len(_alerts)


def clear():
    with _lock:
        _alerts.clear()
