"""
detection.py
-------------
Rule-based attack detection (no ML - matches the "out of scope" in the
project abstract). Each check tracks per-source-IP activity in a sliding
time window using a deque of timestamps, and fires when a threshold is
crossed within that window.

This module is deliberately standalone - it doesn't know about Scapy,
Flask, or iptables. capture.py feeds it (src_ip, protocol, port, flags)
from real packets; simulator.py feeds it the exact same shape of data
from FAKE packets. Same detection logic, same guaranteed-accurate
explanations in both modes.
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


def _trim(dq, window, now, key_index=None):
    """Drops entries older than `window` seconds from the left of the deque."""
    while dq:
        ts = dq[0][0] if key_index is not None else dq[0]
        if now - ts > window:
            dq.popleft()
        else:
            break


def check_port_scan(src_ip, protocol, port, flags=None):
    # Only bare SYN packets are real scan probes. SYN-ACK/ACK/RST are
    # replies (e.g. the monitored host answering each probed port) - if
    # those were counted too, the host's own replies would look like a
    # scan coming from itself (the false positive seen earlier, where
    # the monitored host's own IP triggered a port-scan alert on its
    # own responses to nmap's probes).
    if protocol != "TCP" or port is None or flags != "S":
        return None
    now = time.time()
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


def check_dos(src_ip, protocol, port=None, flags=None):
    if protocol != "TCP":
        return None
    now = time.time()
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


def check_icmp_flood(src_ip, protocol, port=None, flags=None):
    if protocol != "ICMP":
        return None
    now = time.time()
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


def check_ssh_bruteforce(src_ip, protocol, port=None, flags=None):
    """
    SIMPLIFIED PROXY, not real brute-force detection. A real implementation
    needs to know whether each login attempt actually FAILED, which means
    parsing /var/log/auth.log - SSH traffic is encrypted, so Scapy can only
    see that a connection to port 22 happened, not whether it succeeded.
    This check instead treats a high rate of new SYN connections to port 22
    as a rough stand-in, since a brute-force tool does open many connections
    quickly. Good enough for teaching the CONCEPT in the simulator; not a
    substitute for real auth.log-based detection on production traffic.
    """
    if protocol != "TCP" or port != 22 or flags != "S":
        return None
    now = time.time()
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


def analyze(src_ip, protocol, port, flags=None):
    """
    Runs every check against one packet's info. Returns a list of alert
    dicts (usually empty, occasionally one - rarely more than one at once).
    """
    alerts = []
    for check in (check_port_scan, check_dos, check_icmp_flood, check_ssh_bruteforce):
        result = check(src_ip, protocol, port, flags)
        if result:
            alerts.append(result)
    return alerts