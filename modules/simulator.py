"""
simulator.py
-------------
Generates synthetic packet sequences for the Learning Simulator and feeds
them through the exact same detection.analyze() used for real captured
traffic (capture.py). Nothing here is actually sent over the network -
these are just Python dicts shaped like what capture.py would have
extracted from a real Scapy packet.

Why this matters: the explanation shown to a student is GUARANTEED to
match real detection behavior, because it's not a hardcoded story - it's
the actual detection engine's real output, replayed step by step.

Each simulation run uses a random source IP from TEST-NET-3
(203.0.113.0/24, RFC 5737) - a block permanently reserved for
documentation/examples and guaranteed never to be a real routable
address. A fresh random IP per run also avoids two students running a
scenario at the same time from sharing (and corrupting) each other's
detection.py tracking state.
"""

import random

from modules import detection

TARGET_IP = "192.168.1.10"


def _random_attacker_ip():
    return f"203.0.113.{random.randint(2, 254)}"


def _run_sequence(packets):
    """
    packets: list of dicts with protocol/port/flags/description.
    Feeds each one through detection.analyze(), building a step-by-step
    timeline the frontend can animate through.
    """
    attacker_ip = _random_attacker_ip()
    events = []

    for i, pkt in enumerate(packets):
        alerts = detection.analyze(
            src_ip=attacker_ip,
            protocol=pkt["protocol"],
            port=pkt.get("port"),
            flags=pkt.get("flags")
        )
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
            "alert": alerts[0] if alerts else None
        })

    return {"attacker_ip": attacker_ip, "target_ip": TARGET_IP, "events": events}


def simulate_port_scan():
    packets = [
        {"protocol": "TCP", "port": p, "flags": "S", "description": f"SYN probe sent to port {p}"}
        for p in range(20, 32)
    ]
    return _run_sequence(packets)


def simulate_dos():
    packets = [
        {"protocol": "TCP", "port": 80, "flags": "S", "description": f"SYN flood packet #{i + 1} to port 80"}
        for i in range(55)
    ]
    return _run_sequence(packets)


def simulate_icmp_flood():
    packets = [
        {"protocol": "ICMP", "port": None, "flags": None, "description": f"ICMP echo request #{i + 1}"}
        for i in range(35)
    ]
    return _run_sequence(packets)


def simulate_ssh_bruteforce():
    packets = [
        {"protocol": "TCP", "port": 22, "flags": "S", "description": f"SSH connection attempt #{i + 1}"}
        for i in range(10)
    ]
    return _run_sequence(packets)


SCENARIOS = {
    "port_scan": simulate_port_scan,
    "dos": simulate_dos,
    "icmp_flood": simulate_icmp_flood,
    "ssh_bruteforce": simulate_ssh_bruteforce,
}


def run_scenario(name):
    """Returns None for an unknown scenario name - caller should 404."""
    fn = SCENARIOS.get(name)
    return fn() if fn else None