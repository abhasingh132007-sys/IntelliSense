"""
capture.py
-----------
Real packet capture using Scapy. Replaces mock_data.get_live_packets()
as the actual source of truth once this is running.

Requires root privileges (raw sockets) - run the app with sudo, e.g.:
    sudo $(which python3) app.py

Runs sniff() in a background daemon thread so it never blocks Flask's
own request handling. Wraps everything in try/except so a permissions
error or missing interface doesn't crash the whole app - it just logs
a warning and the dashboard silently keeps showing an empty/stale buffer
instead of mock data (a deliberate choice: better to show "no data yet"
than to silently fall back to fake numbers once this module is wired in).
"""

import threading
import socket
from datetime import datetime

from modules import packet_buffer, detection, database

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _get_own_ip():
    """
    Figures out this machine's own IP address on the active route, without
    actually sending any traffic (UDP connect() just picks the outbound
    interface/route - no packet is sent for a UDP "connection").
    Used to exclude the monitored host's own traffic from detection, so
    its own replies (SYN-ACK/RST answering a scan) don't get miscounted
    as an attack coming from itself.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


_OWN_IP = _get_own_ip()


def _extract_summary(pkt):
    """Pulls out a small JSON-safe dict from a raw Scapy packet object."""
    if IP not in pkt:
        return None

    if TCP in pkt:
        proto = "TCP"
        port = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif UDP in pkt:
        proto = "UDP"
        port = pkt[UDP].dport
        flags = "-"
    elif ICMP in pkt:
        proto = "ICMP"
        port = None
        flags = "-"
    else:
        proto = "Other"
        port = None
        flags = "-"

    return {
        "time": datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3],
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": proto,
        "port": port,
        "length": len(pkt),
        "flags": flags
    }


def _process_packet(pkt):
    summary = _extract_summary(pkt)
    if not summary:
        return

    packet_buffer.add_packet(summary)

    # Skip detection for packets the monitored host sent itself (e.g. its
    # own SYN-ACK/RST replies answering a scan). Without this, the host's
    # own replies get miscounted as an attack coming from itself - this
    # was the "detecting its own IP" bug.
    if _OWN_IP and summary["src_ip"] == _OWN_IP:
        return

    # Phase 4/D: run detection on this packet's info. A fired alert becomes
    # a real incident with status 'New' - it enters the SOC Analyst's queue
    # rather than being auto-blocked, matching the escalation workflow
    # (Analyst investigates -> Administrator approves -> firewall blocks).
    fired_alerts = detection.analyze(
        src_ip=summary["src_ip"],
        protocol=summary["protocol"],
        port=summary["port"],
        flags=summary["flags"]
    )
    for alert in fired_alerts:
        org_id = database.get_default_org_id()
        if org_id:
            database.create_incident(
                org_id=org_id,
                attack_type=alert["type"],
                source_ip=alert["source_ip"],
                severity=alert["severity"],
                description=alert["description"],
                destination_ip=summary["dst_ip"]
            )


def start_capture(interface="ens37"):
    """
    Starts sniffing in a background thread. Call once, at app startup.
    interface: change to match your Ubuntu VM's actual NIC name (`ip a` to check).
    """
    if not SCAPY_AVAILABLE:
        print("[capture] Scapy not installed - skipping real packet capture.")
        return

    def _run():
        try:
            if SCAPY_AVAILABLE:
                from scapy.all import get_if_list
                available = get_if_list()
                print(f"[capture] Available interfaces on this machine: {available}")
                if interface not in available:
                    print(f"[capture] WARNING: '{interface}' is not in the list above. "
                          f"Update start_capture(interface=...) in app.py to one of the names shown.")

            print(f"[capture] Starting Scapy sniff on interface: {interface}")
            print(f"[capture] Own IP detected as: {_OWN_IP or 'unknown - self-traffic filtering disabled'}")
            sniff(iface=interface, prn=_process_packet, store=False)
        except PermissionError:
            print("[capture] Permission denied - Scapy needs root. Run with sudo.")
        except OSError as e:
            print(f"[capture] Could not open interface '{interface}': {e}")
        except Exception as e:
            print(f"[capture] Unexpected error, capture stopped: {e}")

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
