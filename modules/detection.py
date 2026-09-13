"""
detection.py
-------------
Rule-based attack detection (no ML - matches the "out of scope" in the
project abstract). Each check tracks per-source-IP activity in a sliding
time window using a deque of timestamps, and fires when a threshold is
crossed within that window.

This module is deliberately standalone - it doesn't know about Scapy,
Flask, or iptables. capture.py feeds it real packets; simulator.py feeds
it synthetic ones. Same detection logic, same guaranteed-accurate
explanations in both modes.

Every check accepts an optional `now` override (defaults to time.time()).
This exists for the Learning Simulator's evasion sandbox: to show what
happens when packets are spread out over more or less time WITHOUT
actually making the Flask request block for real seconds, the simulator
generates synthetic timestamps and passes them in here, rather than
calling time.sleep() between packets.
"""

import time
import threading
from collections import defaultdict, deque

_lock = threading.Lock()

# --- Trackers: source_ip -> deque of recent events (auto-trimmed to window) ---
_port_scan_tracker = defaultdict(deque)   # deque of (timestamp, port)
_dos_tracker = defaultdict(deque)         # deque of timestamps
_icmp_tracker = defaultdict(deque)        # deque of timestamps
_ssh_tracker = defaultdict(deque)         # deque of timestamps

# --- Thresholds ---
PORT_SCAN_WINDOW = 5        # seconds
PORT_SCAN_THRESHOLD = 10    # distinct ports within the window

DOS_WINDOW = 2              # seconds
DOS_THRESHOLD = 50          # TCP packets within the window

ICMP_WINDOW = 2             # seconds
ICMP_THRESHOLD = 30         # ICMP packets within the window

SSH_WINDOW = 5              # seconds
SSH_THRESHOLD = 8           # SYN packets to port 22 within the window

# Maps a simulator-friendly "check name" to its tracker/window/threshold,
# used by get_progress() below.
_CHECK_CONFIG = {
    "port_scan": {"tracker": _port_scan_tracker, "window": PORT_SCAN_WINDOW, "threshold": PORT_SCAN_THRESHOLD, "distinct": True},
    "dos": {"tracker": _dos_tracker, "window": DOS_WINDOW, "threshold": DOS_THRESHOLD, "distinct": False},
    "icmp_flood": {"tracker": _icmp_tracker, "window": ICMP_WINDOW, "threshold": ICMP_THRESHOLD, "distinct": False},
    "ssh_bruteforce": {"tracker": _ssh_tracker, "window": SSH_WINDOW, "threshold": SSH_THRESHOLD, "distinct": False},
}


def _trim(dq, window, now, key_index=None):
    """Drops entries older than `window` seconds from the left of the deque."""
    while dq:
        ts = dq[0][0] if key_index is not None else dq[0]
        if now - ts > window:
            dq.popleft()
        else:
            break


def check_port_scan(src_ip, protocol, port, flags=None, now=None):
    if protocol != "TCP" or port is None or flags != "S":
        return None
    now = now if now is not None else time.time()
    with _lock:
        dq = _port_scan_tracker[src_ip]
        dq.append((now, port))
        _trim(dq, PORT_SCAN_WINDOW, now, key_index=0)

        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
            dq.clear()
            return {
                "type": "Port Scan",
                "source_ip": src_ip,
                "severity": "High",
                "description": f"{len(distinct_ports)} distinct ports contacted within {PORT_SCAN_WINDOW}s"
            }
    return None


def check_dos(src_ip, protocol, port=None, flags=None, now=None):
    if protocol != "TCP":
        return None
    now = now if now is not None else time.time()
    with _lock:
        dq = _dos_tracker[src_ip]
        dq.append(now)
        _trim(dq, DOS_WINDOW, now)

        if len(dq) >= DOS_THRESHOLD:
            count = len(dq)
            dq.clear()
            return {
                "type": "DoS Attempt",
                "source_ip": src_ip,
                "severity": "Critical",
                "description": f"{count} TCP packets within {DOS_WINDOW}s - high rate of requests detected"
            }
    return None


def check_icmp_flood(src_ip, protocol, port=None, flags=None, now=None):
    if protocol != "ICMP":
        return None
    now = now if now is not None else time.time()
    with _lock:
        dq = _icmp_tracker[src_ip]
        dq.append(now)
        _trim(dq, ICMP_WINDOW, now)

        if len(dq) >= ICMP_THRESHOLD:
            count = len(dq)
            dq.clear()
            return {
                "type": "ICMP Flood",
                "source_ip": src_ip,
                "severity": "High",
                "description": f"{count} ICMP echo requests within {ICMP_WINDOW}s"
            }
    return None


def check_ssh_bruteforce(src_ip, protocol, port=None, flags=None, now=None):
    """
    SIMPLIFIED PROXY, not real brute-force detection. A real implementation
    needs to know whether each login attempt actually FAILED, which means
    parsing /var/log/auth.log - SSH traffic is encrypted, so Scapy can only
    see that a connection to port 22 happened, not whether it succeeded.
    """
    if protocol != "TCP" or port != 22 or flags != "S":
        return None
    now = now if now is not None else time.time()
    with _lock:
        dq = _ssh_tracker[src_ip]
        dq.append(now)
        _trim(dq, SSH_WINDOW, now)

        if len(dq) >= SSH_THRESHOLD:
            count = len(dq)
            dq.clear()
            return {
                "type": "SSH Brute Force",
                "source_ip": src_ip,
                "severity": "Medium",
                "description": f"{count} SSH connection attempts within {SSH_WINDOW}s"
            }
    return None


def analyze(src_ip, protocol, port, flags=None, now=None):
    """
    Runs every check against one packet's info. Returns a list of alert
    dicts (usually empty, occasionally one - rarely more than one at once).
    """
    alerts = []
    for check in (check_port_scan, check_dos, check_icmp_flood, check_ssh_bruteforce):
        result = check(src_ip, protocol, port, flags, now)
        if result:
            alerts.append(result)
    return alerts


def get_progress(check_name, src_ip, now=None):
    """
    Read-only peek at how close src_ip currently is to a given check's
    threshold, WITHOUT mutating any state or triggering detection.
    Used by the Learning Simulator to render a live "X of Y" progress bar.

    Returns (current_count, threshold).
    """
    config = _CHECK_CONFIG.get(check_name)
    if not config:
        return 0, 1

    now = now if now is not None else time.time()
    with _lock:
        dq = config["tracker"][src_ip]
        _trim(dq, config["window"], now, key_index=0 if config["distinct"] else None)
        if config["distinct"]:
            current = len({p for _, p in dq})
        else:
            current = len(dq)
        return current, config["threshold"]