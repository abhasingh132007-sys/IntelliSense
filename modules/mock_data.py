"""
mock_data.py
-------------
Centralized placeholder data for every dashboard page (Alerts, Blocked IPs,
Logs, Live Monitor). This exists so ALL pages read from ONE consistent
source instead of each having its own hardcoded numbers - which matters
because in Phase 4/5 this whole file gets replaced by real queries against
database.py / packet_buffer.py, and every route that imports from here
will keep working without any template changes.
"""

import random
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Alerts - backs the dashboard "Recent Alerts" table AND the full /alerts page
# ---------------------------------------------------------------------------

_ALERT_TEMPLATES = [
    ("Port Scan", "High", "Blocked", "SYN scan detected on port 22"),
    ("Failed Login", "Medium", "Blocked", "Multiple failed login attempts"),
    ("SQL Injection", "High", "Detected", "SQL injection attempt detected"),
    ("DoS Attempt", "Critical", "Blocked", "High rate of requests detected"),
    ("XSS Attack", "Medium", "Detected", "Cross-site scripting attempt"),
    ("ICMP Flood", "High", "Blocked", "Excessive ping requests detected"),
    ("Brute Force", "Medium", "Detected", "Repeated SSH login failures"),
]


def get_alerts(limit=None):
    """
    Returns a list of alert dicts, most recent first.
    Pass `limit` to cap the number returned (e.g. 5 for the dashboard
    overview's "Recent Alerts" widget; None for the full Alerts page).
    """
    alerts = []
    now = datetime.now()
    for i, (a_type, severity, status, desc) in enumerate(_ALERT_TEMPLATES * 2):
        alerts.append({
            "id": i + 1,
            "time": (now - timedelta(seconds=i * 37)).strftime("%H:%M:%S"),
            "type": a_type,
            "source_ip": f"192.168.1.{50 + (i * 7) % 200}",
            "severity": severity,
            "status": status,
            "description": desc
        })
    return alerts[:limit] if limit else alerts


# ---------------------------------------------------------------------------
# Blocked IPs - backs the Blocked IPs page
# ---------------------------------------------------------------------------

def get_blocked_ips():
    now = datetime.now()
    reasons = ["Port Scan", "DoS Attempt", "Brute Force", "ICMP Flood"]
    ips = []
    for i in range(7):
        ips.append({
            "ip": f"192.168.1.{100 + i * 3}",
            "reason": reasons[i % len(reasons)],
            "blocked_at": (now - timedelta(minutes=i * 12)).strftime("%Y-%m-%d %H:%M:%S"),
            "attempts": random.randint(8, 60)
        })
    return ips


# ---------------------------------------------------------------------------
# Logs - backs the Logs page
# ---------------------------------------------------------------------------

def get_logs(limit=50):
    now = datetime.now()
    levels = ["INFO", "WARNING", "ALERT", "INFO", "INFO"]
    messages = [
        "Packet capture started on interface ens33",
        "Detection engine initialized",
        "New connection from 192.168.1.42",
        "Port scan pattern matched - source 192.168.1.105",
        "iptables rule added for 192.168.1.105",
        "Database write: alert logged",
        "Dashboard client connected",
        "Failed SSH login recorded for 192.168.1.203",
    ]
    logs = []
    for i in range(limit):
        logs.append({
            "time": (now - timedelta(seconds=i * 19)).strftime("%Y-%m-%d %H:%M:%S"),
            "level": levels[i % len(levels)],
            "message": messages[i % len(messages)]
        })
    return logs


# ---------------------------------------------------------------------------
# Live packets - backs the Live Monitor page
# ---------------------------------------------------------------------------

def get_live_packets(count=25):
    """
    Simulates what packet_buffer.get_recent_packets() will return once
    Scapy capture is wired in (Phase 3). Randomized each call so the
    Live Monitor page actually feels "live" even before real capture exists.
    """
    protocols = ["TCP", "UDP", "ICMP"]
    now = datetime.now()
    packets = []
    for i in range(count):
        proto = random.choice(protocols)
        packets.append({
            "time": (now - timedelta(milliseconds=i * 250)).strftime("%H:%M:%S.%f")[:-3],
            "src_ip": f"192.168.1.{random.randint(2, 254)}",
            "dst_ip": "192.168.1.10",
            "protocol": proto,
            "port": random.choice([22, 80, 443, 3306, 8080]) if proto != "ICMP" else None,
            "length": random.randint(60, 1500),
            "flags": random.choice(["SYN", "ACK", "SYN-ACK", "FIN", "-"]) if proto == "TCP" else "-"
        })
    return packets
