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
        "summary": "IP addresses, ports, the OSI model, and how TCP/UDP actually move data.",
        "sections": [
            {"type": "text", "heading": "What is an IP Address?",
             "body": "Every device on a network has an IP address - a unique identifier "
                     "that lets other devices know where to send data. IPv4 addresses use a 32-bit "
                     "structure (e.g., 192.168.1.10), while IPv6 uses a 128-bit structure to solve "
                     "address exhaustion. IP addresses operate at Layer 3 (Network Layer) of the OSI model."},
            {"type": "text", "heading": "Subnets and Routing",
             "body": "IP addresses are split into a 'Network' portion and a 'Host' portion using a "
                     "Subnet Mask (like 255.255.255.0 or /24). If a destination IP is outside your local "
                     "subnet, your machine forwards the packet to the Default Gateway (usually your router), "
                     "which determines the next hop."},
            {"type": "text", "heading": "Ports: One Address, Many Doors",
             "body": "While an IP gets data to the right DEVICE, a port (operating at Layer 4 - Transport) "
                     "gets it to the right SERVICE. There are 65,535 total ports. Ports 0-1023 are 'Well-Known' "
                     "(e.g., 22 for SSH, 80 for HTTP). Ports 1024-49151 are 'Registered', and 49152-65535 are "
                     "'Ephemeral' (temporary ports used by your browser to receive data)."},
            {"type": "example", "icon": "💻",
             "heading": "Example: Looking at a real connection",
             "body": "When your browser loads a website, it opens a TCP connection FROM your "
                     "computer's IP on a random high ephemeral port (e.g., 51342) TO the server's IP on "
                     "port 443 (HTTPS). Try running `netstat -an` on your machine and look for ESTABLISHED "
                     "connections to see this src-IP:port -> dst-IP:port pattern.",
             "caption": "netstat output showing active connections by IP:port pairs"},
            {"type": "chart", "chart_type": "bar", "heading": "Common Ports and Their Services",
             "height": 220, 
             "labels": ["21 (FTP)", "22 (SSH)", "53 (DNS)", "80 (HTTP)", "443 (HTTPS)", "3306 (MySQL)"],
             "values": [1, 1, 1, 1, 1, 1],
             "tooltips": ["File Transfer Protocol", "Secure Shell", "Domain Name System", "Web Traffic", "Secure Web Traffic", "Database"]},
            {"type": "text", "heading": "TCP vs UDP",
             "body": "TCP (Transmission Control Protocol) is connection-oriented. It guarantees delivery, "
                     "order, and error-checking via a 3-way handshake (SYN -> SYN-ACK -> ACK). UDP (User "
                     "Datagram Protocol) is connectionless. It simply fires packets at the target without "
                     "checking if they arrive. UDP is used for live video or gaming where speed beats reliability."},
            {"type": "example", "icon": "🤝",
             "heading": "Example: The TCP 3-Way Handshake",
             "body": "1. Client sends a SYN (Synchronize) packet.\n"
                     "2. Server replies with SYN-ACK (Synchronize-Acknowledge).\n"
                     "3. Client replies with ACK (Acknowledge).\n\n"
                     "Attackers abuse this by sending thousands of SYN packets but never replying with the final ACK. "
                     "This leaves the server waiting with open connections, leading to a SYN Flood DoS attack."}
        ]
    },
    {
        "key": "understanding_idps",
        "title": "Understanding IDS & IPS",
        "icon": "🛡️",
        "color": "#22c55e",
        "summary": "Detection methodologies, false positives, and how SOC teams collaborate.",
        "sections": [
            {"type": "text", "heading": "Detection vs Prevention",
             "body": "An Intrusion Detection System (IDS) is passive; it watches traffic and raises alerts "
                     "(like a security camera). An Intrusion Prevention System (IPS) is active; it sits inline "
                     "and can actively drop malicious traffic (like a security guard). IntelliSense bridges both: "
                     "detection.py identifies threats, and prevention.py dynamically blocks them."},
            {"type": "image", "caption": "IntelliSense's detect - escalate - approve - block pipeline"},
            {"type": "text", "heading": "Detection Methodologies",
             "body": "1. Signature-Based: Looks for specific patterns or hashes of known malware (like an antivirus). "
                     "Fast, but fails against new (zero-day) attacks.\n"
                     "2. Anomaly-Based: Establishes a baseline of 'normal' traffic. If traffic spikes unpredictably "
                     "(like a sudden flood of ICMP packets), it raises an alert. Great for catching new attacks, "
                     "but generates more false positives."},
            {"type": "text", "heading": "The False Positive Problem",
             "body": "A 'False Positive' is when the IDS flags legitimate traffic as an attack. A 'False Negative' "
                     "is when a real attack slips through undetected. Security engineers must constantly tune "
                     "thresholds to balance these two. A system tuned too aggressively will block real users."},
            {"type": "text", "heading": "Why Have a Human Approve Actions?",
             "body": "Fully automatic blocking risks false positives taking down legitimate business traffic. "
                     "In professional SOCs, Tier 1 Analysts investigate the alerts and recommend action. "
                     "Tier 2/3 Administrators review and approve the block. This human-in-the-loop architecture "
                     "prevents automated systems from accidentally isolating the company network."},
            {"type": "example", "icon": "🔍",
             "heading": "Example: A real escalation in IntelliSense",
             "body": "A port scan from 203.0.113.50 is detected. It appears on the SOC Analyst's "
                     "dashboard with status 'New'. The Analyst notes \"15 ports scanned in 2s, no known business need\", "
                     "recommends \"Block IP\", and escalates. The Administrator reviews it and clicks Approve. "
                     "Only then does the IPS alter the firewall.",
             "caption": "Incident lifecycle: New → Investigating → Escalated → Action Taken"},
            {"type": "text", "heading": "Auto-Block for Repeat Offenders",
             "body": "To counter high-speed attacks (like DoS), human review is too slow. IntelliSense uses "
                     "dynamic per-attack-type thresholds. If a single IP triggers 3 DoS alerts in 60 seconds, "
                     "the system bypasses the Analyst and automatically injects a firewall drop rule to save the server."}
        ]
    },
    {
        "key": "common_attacks",
        "title": "Common Network Attacks",
        "icon": "🎯",
        "color": "#ef4444",
        "summary": "Reconnaissance, volumetric floods, and credential brute-forcing explained.",
        "sections": [
            {"type": "text", "heading": "Port Scanning: Reconnaissance",
             "body": "Attackers don't strike blindly; they map the network first. Port scanning reveals which "
                     "services are running, hinting at potential vulnerabilities (e.g., finding an outdated FTP "
                     "server on port 21). Scanning isn't intrinsically damaging, but it is the precursor to a breach."},
            {"type": "example", "icon": "⌨️",
             "heading": "Example: Running a real port scan",
             "body": "On Kali Linux, `sudo nmap -sS 192.168.1.10` executes a 'Stealth SYN Scan'. It sends a SYN "
                     "packet, waits for the server's SYN-ACK, but immediately sends a RST (Reset) instead of finishing "
                     "the handshake. This prevents the target server from logging a full connection, but IntelliSense "
                     "detects the rapid sequence of partial handshakes across multiple ports.",
             "caption": "nmap output revealing network topology and open services"},
            {"type": "chart", "chart_type": "doughnut", "heading": "Common Attack Distribution in Enterprise Networks",
             "height": 200,
             "labels": ["Reconnaissance (Scans)", "Volumetric (DoS)", "Credential Attacks", "Exploitation"],
             "values": [40, 25, 20, 15],
             "colors": ["#3b82f6", "#ef4444", "#f59e0b", "#06b6d4"]},
            {"type": "text", "heading": "Denial of Service (DoS) & DDoS",
             "body": "DoS attacks aim to exhaust the target's resources (CPU, RAM, or bandwidth). A volumetric DoS "
                     "floods the target with sheer garbage data. A Distributed DoS (DDoS) uses thousands of compromised "
                     "devices (a botnet) to launch the flood simultaneously, making IP-based blocking highly difficult."},
            {"type": "text", "heading": "ICMP Floods (Ping of Death / Smurf)",
             "body": "ICMP (Internet Control Message Protocol) is used for network diagnostics (like 'ping'). "
                     "Attackers can flood a server with ICMP Echo Requests faster than it can reply, consuming bandwidth. "
                     "More advanced versions spoof the source IP, reflecting traffic off third-party servers to amplify the attack."},
            {"type": "text", "heading": "Brute Force & Credential Stuffing",
             "body": "Brute Force relies on trying thousands of password combinations rapidly. Credential Stuffing "
                     "is a smarter variant that uses lists of known compromised passwords from previous data breaches. "
                     "IntelliSense detects these by tracking the anomalous RATE of connection attempts on authentication ports (like 22)."},
            {"type": "example", "icon": "🔑",
             "heading": "Example: hydra brute-forcing SSH",
             "body": "`hydra -l admin -P wordlist.txt ssh://192.168.1.10` tries every password in wordlist.txt "
                     "against the 'admin' account. Our detection engine proxy watches for >8 connections within 5 seconds "
                     "to flag this automated behavior without needing access to the encrypted SSH application logs."}
        ]
    },
    {
        "key": "firewalls_prevention",
        "title": "Firewalls & Prevention",
        "icon": "🔥",
        "color": "#f59e0b",
        "summary": "Kernel-level packet filtering, stateful inspection, and iptables architecture.",
        "sections": [
            {"type": "text", "heading": "What a Firewall Actually Does",
             "body": "A firewall is the network's bouncer. It intercepts every incoming and outgoing packet "
                     "and evaluates it against an ordered list of rules. If a packet matches a rule, the firewall "
                     "executes the target action (Accept, Drop, Reject). If no rules match, it falls back to the "
                     "Default Policy (which should always be 'Drop' in secure environments)."},
            {"type": "text", "heading": "Stateless vs Stateful Firewalls",
             "body": "A 'Stateless' firewall only looks at isolated packets (IPs and Ports). A 'Stateful' firewall "
                     "(like iptables) tracks the entire conversation. It knows if an incoming packet is a response "
                     "to an internal request you initiated, allowing it through dynamically without requiring a permanent open port."},
            {"type": "image", "caption": "The Linux netfilter/iptables architecture (INPUT, OUTPUT, FORWARD)"},
            {"type": "text", "heading": "Understanding iptables Chains",
             "body": "1. INPUT: Handles packets destined for the server itself (e.g., someone viewing your website).\n"
                     "2. OUTPUT: Handles packets generated by the server going out to the internet.\n"
                     "3. FORWARD: Handles packets being routed THROUGH the server to another network (used in VPNs or routers)."},
            {"type": "text", "heading": "DROP vs REJECT",
             "body": "REJECT explicitly tells the attacker the connection is forbidden by sending an ICMP Error packet back. "
                     "DROP silently discards the packet into a black hole. Security best practice dictates using DROP "
                     "for malicious traffic, as it wastes the attacker's time waiting for a timeout and hides network topology."},
            {"type": "text", "heading": "From Approval to Firewall Rule",
             "body": "When an Administrator approves an incident in IntelliSense, the backend converts that decision "
                     "into a system command. The Python `subprocess` module executes `iptables -A INPUT -s <attacker_ip> -j DROP`. "
                     "The `-A` appends the rule to the end of the INPUT chain, blocking the attacker at the OS kernel level."},
            {"type": "example", "icon": "🚫",
             "heading": "Example: Checking a block yourself",
             "body": "After IntelliSense blocks an IP, run `sudo iptables -L INPUT -n` on your Ubuntu VM. "
                     "You will see a line like:\n`DROP   all  --  203.0.113.50   0.0.0.0/0`\n"
                     "This means all traffic protocols from 203.0.113.50 destined for anywhere (0.0.0.0/0) on this server "
                     "will be silently dropped. To undo this, you would use the `-D` (Delete) flag.",
             "caption": "Viewing active DROP rules in the netfilter firewall"}
        ]
    }
]


def get_module(key):
    return next((m for m in MODULES if m["key"] == key), None)


def get_all_modules():
    return MODULES

