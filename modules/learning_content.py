"""
learning_content.py
---------------------
Content for the Learning Modules hub - text/image/example/chart sections,
each followed by a quiz (see quiz_data.py's MODULE_QUIZZES, keyed the same
way). No video sections - theory, references, and worked examples only.
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
            {"type": "example", "icon": "💻",
             "heading": "Example: Looking at a real connection",
             "body": "When your browser loads a website, it opens a TCP connection FROM your "
                      "computer's IP on a random high port (e.g. 51342) TO the server's IP on "
                      "port 443 (HTTPS). Try it yourself: run `netstat -an` on your machine and "
                      "look for lines showing ESTABLISHED connections - you'll see exactly this "
                      "src-IP:port -> dst-IP:port pattern.",
             "caption": "netstat output showing active connections by IP:port pairs"},
            {"type": "chart", "chart_type": "bar", "heading": "Common Ports and Their Services",
             "labels": ["21", "22", "80", "443", "3306"],
             "values": [1, 1, 1, 1, 1],
             "tooltips": ["FTP", "SSH", "HTTP", "HTTPS", "MySQL"]},
            {"type": "text", "heading": "TCP vs UDP",
             "body": "TCP is connection-oriented: it establishes a handshake (SYN, SYN-ACK, ACK) "
                      "before sending data and guarantees delivery order. UDP just sends packets "
                      "with no handshake and no guarantee - faster, but less reliable. This is "
                      "exactly the SYN flag our detection engine looks for in a port scan."}
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
            {"type": "example", "icon": "🔍",
             "heading": "Example: A real escalation in IntelliSense",
             "body": "A port scan from 203.0.113.50 is detected. It appears on the SOC Analyst's "
                      "dashboard with status 'New'. The Analyst opens it, writes the note "
                      "\"10 ports scanned in 5s, no legitimate reason found\", recommends "
                      "\"Block source IP\", and escalates. The Administrator sees it under "
                      "'Escalated Incidents', reviews the note, and clicks Approve - only then "
                      "does prevention.py actually run the iptables command.",
             "caption": "The incident's status field moving through New → Investigating → Escalated → Action Taken"},
            {"type": "text", "heading": "Auto-Block for Repeat Offenders",
             "body": "When the same source IP crosses a per-attack-type threshold within a short "
                      "time window (e.g. 5 Port Scan incidents within 2 minutes), IntelliSense "
                      "blocks it immediately instead of waiting for manual review - while still "
                      "notifying both the Analyst and Administrator, so no action is ever silent."}
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
            {"type": "example", "icon": "⌨️",
             "heading": "Example: Running a real port scan",
             "body": "On Kali Linux, `sudo nmap -sS 192.168.1.10` sends a bare SYN packet to "
                      "each of the top 1000 ports. Our own simulator does exactly this same "
                      "pattern synthetically - 10+ distinct ports contacted within 5 seconds "
                      "is what detection.py's check_port_scan() looks for.",
             "caption": "nmap -sS output listing open/closed/filtered ports"},
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
            {"type": "example", "icon": "🔑",
             "heading": "Example: hydra brute-forcing SSH",
             "body": "`hydra -l admin -P wordlist.txt ssh://192.168.1.10` tries every password "
                      "in wordlist.txt against the 'admin' account. Each attempt opens a new "
                      "TCP connection to port 22 - 8 or more within 5 seconds is what our "
                      "simplified check_ssh_bruteforce() proxy watches for.",
             "caption": "hydra output showing rapid login attempts against SSH"}
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
            {"type": "example", "icon": "🚫",
             "heading": "Example: Checking a block yourself",
             "body": "After IntelliSense blocks an IP, run `sudo iptables -L INPUT -n` on the "
                      "Ubuntu server - you'll see a line like `DROP  all  --  203.0.113.50  "
                      "0.0.0.0/0`. From that point on, every packet from that IP is silently "
                      "discarded before it ever reaches your application.",
             "caption": "iptables -L INPUT -n showing an active DROP rule"}
        ]
    }
]


def get_module(key):
    return next((m for m in MODULES if m["key"] == key), None)


def get_all_modules():
    return MODULES