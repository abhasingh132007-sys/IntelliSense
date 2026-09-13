"""
learning_content.py
---------------------
Content for the Learning Modules hub - the general cybersecurity education
section, separate from the attack simulator. Each module has ordered
sections (text, image placeholder, video placeholder, or a chart spec),
followed by a quiz (see quiz_data.py's MODULE_QUIZZES, keyed the same way).

Images/videos are placeholders for now - swap the placeholder sections
for real asset URLs once you have them, the template doesn't need to change.
"""

MODULES = [
    {
        "key": "intro_networking",
        "title": "Introduction to Networking",
        "icon": "🌐",
        "color": "#3b82f6",
        "summary": "IP addresses, ports, and how TCP/UDP actually move data.",
        "sections": [
            {"type": "text", "heading": "What is an IP Address?",
             "body": "Every device on a network has an IP address - a unique identifier "
                      "that lets other devices know where to send data. Think of it like a "
                      "postal address, but for computers. IPv4 addresses look like 192.168.1.10."},
            {"type": "image", "caption": "How a packet travels from source to destination"},
            {"type": "text", "heading": "Ports: One Address, Many Doors",
             "body": "An IP address gets data to the right DEVICE, but a port number gets it "
                      "to the right SERVICE on that device. Port 22 is SSH, port 80 is HTTP, "
                      "port 443 is HTTPS. This is exactly what a port scan is probing for."},
            {"type": "chart", "chart_type": "bar", "heading": "Common Ports and Their Services",
             "labels": ["21", "22", "80", "443", "3306"],
             "values": [1, 1, 1, 1, 1],
             "tooltips": ["FTP", "SSH", "HTTP", "HTTPS", "MySQL"]},
            {"type": "text", "heading": "TCP vs UDP",
             "body": "TCP is connection-oriented: it establishes a handshake (SYN, SYN-ACK, ACK) "
                      "before sending data and guarantees delivery order. UDP just sends packets "
                      "with no handshake and no guarantee - faster, but less reliable. This is "
                      "exactly the SYN flag our detection engine looks for in a port scan."},
            {"type": "video", "caption": "Watching a TCP handshake happen packet by packet"}
        ]
    },
    {
        "key": "understanding_idps",
        "title": "Understanding IDS & IPS",
        "icon": "🛡️",
        "color": "#22c55e",
        "summary": "The difference between detecting and preventing, and how roles collaborate.",
        "sections": [
            {"type": "text", "heading": "Detection vs Prevention",
             "body": "An Intrusion Detection System (IDS) watches traffic and raises alerts. "
                      "An Intrusion Prevention System (IPS) goes further - it can actively block "
                      "traffic. IntelliSense does both: detection.py identifies threats, "
                      "prevention.py can block them via iptables."},
            {"type": "image", "caption": "IntelliSense's detect - escalate - approve - block pipeline"},
            {"type": "text", "heading": "Why Have a Human Approve Actions?",
             "body": "Fully automatic blocking risks false positives taking down legitimate traffic. "
                      "IntelliSense's SOC Analyst investigates and recommends; the Administrator "
                      "reviews and approves before anything actually gets blocked - a real-world "
                      "pattern used in professional security operations centers."},
            {"type": "video", "caption": "A SOC Analyst investigating and escalating a live incident"}
        ]
    },
    {
        "key": "common_attacks",
        "title": "Common Network Attacks",
        "icon": "🎯",
        "color": "#ef4444",
        "summary": "Port scans, DoS floods, and brute-force login attempts explained.",
        "sections": [
            {"type": "text", "heading": "Port Scanning: Reconnaissance",
             "body": "Before attacking, attackers often scan for open ports to find running "
                      "services and known vulnerabilities. It's not damaging by itself, but it's "
                      "usually the first step of a larger attack."},
            {"type": "chart", "chart_type": "doughnut", "heading": "Attack Types We Detect",
             "labels": ["Port Scan", "DoS Attempt", "ICMP Flood", "SSH Brute Force"],
             "values": [35, 25, 20, 20],
             "colors": ["#3b82f6", "#ef4444", "#06b6d4", "#f59e0b"]},
            {"type": "text", "heading": "Denial of Service (DoS)",
             "body": "A DoS attack floods a target with traffic or requests until it can't "
                      "respond to legitimate users. Our detection engine watches for an abnormal "
                      "RATE of packets from one source, regardless of which port."},
            {"type": "text", "heading": "Brute Force Login Attempts",
             "body": "Automated tools try many username/password combinations rapidly, hoping "
                      "one works. Real detection needs to see actual failed logins (from server "
                      "logs); our simulator uses a simplified connection-rate proxy instead."},
            {"type": "video", "caption": "Running an ICMP flood and watching the alert fire"}
        ]
    },
    {
        "key": "firewalls_prevention",
        "title": "Firewalls & Prevention",
        "icon": "🔥",
        "color": "#f59e0b",
        "summary": "How iptables actually blocks traffic at the kernel level.",
        "sections": [
            {"type": "text", "heading": "What a Firewall Actually Does",
             "body": "A firewall is a set of rules the operating system checks against every "
                      "packet. iptables (on Linux) organizes these rules into chains - INPUT for "
                      "incoming traffic, OUTPUT for outgoing, FORWARD for routed traffic."},
            {"type": "image", "caption": "The iptables INPUT chain evaluating an incoming packet"},
            {"type": "text", "heading": "DROP vs REJECT",
             "body": "DROP silently discards a packet - the sender gets no response at all, "
                      "learning nothing. REJECT sends back an error, confirming something is "
                      "listening. IntelliSense uses DROP for exactly this reason."},
            {"type": "text", "heading": "From Approval to Firewall Rule",
             "body": "When an Administrator approves an incident, prevention.py runs "
                      "iptables -A INPUT -s <ip> -j DROP - turning a human decision into a "
                      "real kernel-level block, instantly."},
            {"type": "video", "caption": "Watching a live iptables block happen after approval"}
        ]
    }
]


def get_module(key):
    return next((m for m in MODULES if m["key"] == key), None)


def get_all_modules():
    return MODULES