"""
simulator.py
-------------
Generates synthetic packet sequences for the Learning Simulator and feeds
them through the exact same detection.analyze() used for real captured
traffic (capture.py). Nothing here is actually sent over the network.

Each event now also includes live threshold progress (via
detection.get_progress()), which the frontend renders as a progress bar -
so students watch "6 of 10 ports" climb in real time, not just a final
detected/not-detected result.

simulate_custom() is the evasion sandbox: students choose packet count
and how many seconds to spread them across. Packets are given synthetic
timestamps (via detection.py's `now` override) so a "spread over 10
seconds" run doesn't actually make the HTTP request take 10 real seconds.
"""

import random
import time

from modules import detection

TARGET_IP = "192.168.1.10"

CHECK_NAME_BY_ATTACK = {
    "port_scan": "port_scan",
    "dos": "dos",
    "icmp_flood": "icmp_flood",
    "ssh_bruteforce": "ssh_bruteforce",
}


def _random_attacker_ip():
    return f"203.0.113.{random.randint(2, 254)}"


def _run_sequence(packets, check_name, synthetic_times=None):
    attacker_ip = _random_attacker_ip()
    events = []

    for i, pkt in enumerate(packets):
        now = synthetic_times[i] if synthetic_times else None

        alerts = detection.analyze(
            src_ip=attacker_ip,
            protocol=pkt["protocol"],
            port=pkt.get("port"),
            flags=pkt.get("flags"),
            now=now
        )

        if alerts:
            _, threshold = detection.get_progress(check_name, attacker_ip, now=now)
            progress_current, progress_threshold = threshold, threshold
        else:
            progress_current, progress_threshold = detection.get_progress(check_name, attacker_ip, now=now)

        events.append({
            "step": i + 1,
            "description": pkt["description"],
            "packet": {
                "src_ip": attacker_ip,
                "dst_ip": TARGET_IP,
                "protocol": pkt["protocol"],
                "port": pkt.get("port"),
                "flags": pkt.get("flags") or "-"
            },
            "alert_fired": bool(alerts),
            "alert": alerts[0] if alerts else None,
            "progress": {"current": progress_current, "threshold": progress_threshold}
        })

    return {"attacker_ip": attacker_ip, "target_ip": TARGET_IP, "events": events}


def simulate_port_scan():
    packets = [
        {"protocol": "TCP", "port": p, "flags": "S", "description": f"SYN probe sent to port {p}"}
        for p in range(20, 32)
    ]
    return _run_sequence(packets, "port_scan")


def simulate_dos():
    packets = [
        {"protocol": "TCP", "port": 80, "flags": "S", "description": f"SYN flood packet #{i + 1} to port 80"}
        for i in range(55)
    ]
    return _run_sequence(packets, "dos")


def simulate_icmp_flood():
    packets = [
        {"protocol": "ICMP", "port": None, "flags": None, "description": f"ICMP echo request #{i + 1}"}
        for i in range(35)
    ]
    return _run_sequence(packets, "icmp_flood")


def simulate_ssh_bruteforce():
    packets = [
        {"protocol": "TCP", "port": 22, "flags": "S", "description": f"SSH connection attempt #{i + 1}"}
        for i in range(10)
    ]
    return _run_sequence(packets, "ssh_bruteforce")


SCENARIOS = {
    "port_scan": simulate_port_scan,
    "dos": simulate_dos,
    "icmp_flood": simulate_icmp_flood,
    "ssh_bruteforce": simulate_ssh_bruteforce,
}


def run_scenario(name):
    fn = SCENARIOS.get(name)
    return fn() if fn else None


# ---------------------------------------------------------------------------
# Evasion sandbox - student-configured custom attack
# ---------------------------------------------------------------------------

MAX_CUSTOM_COUNT = 100
MAX_SPREAD_SECONDS = 20

_CUSTOM_BUILDERS = {
    "port_scan": lambda count: [
        {"protocol": "TCP", "port": 20 + i, "flags": "S", "description": f"SYN probe to port {20 + i}"}
        for i in range(count)
    ],
    "dos": lambda count: [
        {"protocol": "TCP", "port": 80, "flags": "S", "description": f"SYN packet #{i + 1} to port 80"}
        for i in range(count)
    ],
    "icmp_flood": lambda count: [
        {"protocol": "ICMP", "port": None, "flags": None, "description": f"ICMP echo request #{i + 1}"}
        for i in range(count)
    ],
    "ssh_bruteforce": lambda count: [
        {"protocol": "TCP", "port": 22, "flags": "S", "description": f"SSH connection attempt #{i + 1}"}
        for i in range(count)
    ],
}


def simulate_custom(attack_type, count, spread_seconds):
    if attack_type not in _CUSTOM_BUILDERS:
        return None

    count = max(1, min(int(count), MAX_CUSTOM_COUNT))
    spread_seconds = max(0, min(float(spread_seconds), MAX_SPREAD_SECONDS))

    packets = _CUSTOM_BUILDERS[attack_type](count)

    base = time.time()
    if spread_seconds == 0 or count == 1:
        synthetic_times = [base] * count
    else:
        step = spread_seconds / (count - 1)
        synthetic_times = [base + (i * step) for i in range(count)]

    check_name = CHECK_NAME_BY_ATTACK[attack_type]
    result = _run_sequence(packets, check_name, synthetic_times=synthetic_times)
    result["config"] = {"attack_type": attack_type, "count": count, "spread_seconds": spread_seconds}
    return result