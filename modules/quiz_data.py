"""
quiz_data.py
-------------
Two separate quiz banks:
1. SIMULATION_QUIZZES - short quiz shown right after running a simulator
   scenario, testing what the student just watched happen (specific
   numbers/behavior from that scenario).
2. MODULE_QUIZZES - quizzes at the end of each Learning Module, testing
   general conceptual understanding (not tied to a live simulation run).

Each question: {"question", "options": [...], "correct": index, "explanation"}
"""

SIMULATION_QUIZZES = {
    "port_scan": [
        {
            "question": "How many distinct ports need to be contacted within the time window to trigger a Port Scan alert?",
            "options": ["3 ports", "10 ports", "50 ports", "100 ports"],
            "correct": 1,
            "explanation": "detection.py's PORT_SCAN_THRESHOLD is 10 distinct ports within a 5-second window."
        },
        {
            "question": "Why does the detection engine only count bare SYN packets, not SYN-ACK or RST replies?",
            "options": [
                "SYN-ACK packets are encrypted",
                "Counting replies would make the monitored host's own responses look like a scan on itself",
                "SYN packets are faster to process",
                "There is no difference, all TCP flags are counted"
            ],
            "correct": 1,
            "explanation": "This was a real bug we fixed - replies (SYN-ACK/RST) come FROM the monitored host, so counting them caused false self-detection."
        },
        {
            "question": "What happens to packets sent AFTER the threshold is crossed and the alert fires?",
            "options": [
                "They are automatically blocked",
                "The tracker resets, so a fresh scan would need to start counting again",
                "They are logged but ignored",
                "The system crashes"
            ],
            "correct": 1,
            "explanation": "check_port_scan() calls dq.clear() after firing, preventing the same scan from re-triggering on every subsequent packet."
        }
    ],
    "dos": [
        {
            "question": "What does the DoS check actually measure?",
            "options": [
                "Number of distinct destination ports",
                "Number of TCP packets from one source within a short window, regardless of port",
                "The size of each packet",
                "Whether the source IP is on a blocklist"
            ],
            "correct": 1,
            "explanation": "check_dos() tracks raw TCP packet RATE per source IP - 50+ packets within 2 seconds - unlike port scan which tracks distinct ports."
        },
        {
            "question": "How is a DoS pattern different from a Port Scan pattern at the packet level?",
            "options": [
                "DoS uses UDP only",
                "DoS hits ONE port repeatedly at high volume; Port Scan hits MANY ports at moderate volume",
                "They are detected identically",
                "DoS only uses ICMP"
            ],
            "correct": 1,
            "explanation": "This scenario sent 55 SYN packets all to port 80 - high rate, single target - the signature of a flood, not reconnaissance."
        }
    ],
    "icmp_flood": [
        {
            "question": "What protocol does an ICMP flood use?",
            "options": ["TCP", "UDP", "ICMP (ping)", "HTTP"],
            "correct": 2,
            "explanation": "ICMP is the protocol behind the `ping` command - a flood of echo requests can exhaust bandwidth/processing."
        },
        {
            "question": "How many ICMP packets within how many seconds trigger this alert?",
            "options": ["10 packets / 10s", "30 packets / 2s", "5 packets / 1s", "100 packets / 5s"],
            "correct": 1,
            "explanation": "ICMP_THRESHOLD = 30 packets within ICMP_WINDOW = 2 seconds."
        }
    ],
    "ssh_bruteforce": [
        {
            "question": "Why is SSH brute-force detection in this project a 'simplified proxy' rather than fully accurate?",
            "options": [
                "SSH is not a real protocol",
                "SSH traffic is encrypted, so packet capture alone can't tell if a login attempt succeeded or failed",
                "Scapy cannot see SSH traffic at all",
                "It doesn't matter, this check is 100% accurate"
            ],
            "correct": 1,
            "explanation": "Real brute-force detection needs to parse /var/log/auth.log for actual failed-login events - packet capture only sees that connections happened, not their outcome."
        },
        {
            "question": "What does this simplified check actually count instead?",
            "options": [
                "Failed password attempts from the auth log",
                "The rate of new SYN connections to port 22",
                "The length of each SSH session",
                "The username being used"
            ],
            "correct": 1,
            "explanation": "It treats a high rate of new connection attempts to port 22 as a rough stand-in for brute-forcing, since real brute-force tools open many connections quickly."
        }
    ]
}


MODULE_QUIZZES = {
    "intro_networking": [
        {
            "question": "What does an IP address identify on a network?",
            "options": ["A specific file", "A device's location on the network", "A username", "A firewall rule"],
            "correct": 1,
            "explanation": "An IP address is the network-layer identifier that lets devices find and send data to each other."
        },
        {
            "question": "Which layer of the OSI model do IP addresses belong to?",
            "options": ["Application", "Network", "Physical", "Session"],
            "correct": 1,
            "explanation": "IP addressing and routing happen at the Network layer (Layer 3)."
        },
        {
            "question": "What's the main difference between TCP and UDP?",
            "options": [
                "TCP is connection-oriented and reliable; UDP is connectionless and faster but unreliable",
                "There is no difference",
                "UDP is always encrypted",
                "TCP only works over the internet, UDP only works on local networks"
            ],
            "correct": 0,
            "explanation": "TCP establishes a connection and guarantees delivery order; UDP just sends packets without those guarantees, trading reliability for speed."
        }
    ],
    "understanding_idps": [
        {
            "question": "What's the difference between an IDS and an IPS?",
            "options": [
                "They are the same thing",
                "IDS only detects and alerts; IPS can also actively block/prevent",
                "IDS is hardware, IPS is software",
                "IPS is older technology than IDS"
            ],
            "correct": 1,
            "explanation": "Intrusion Detection Systems (IDS) observe and alert; Intrusion Prevention Systems (IPS) can also take action, like blocking traffic."
        },
        {
            "question": "In IntelliSense's design, who has the authority to approve a firewall block?",
            "options": ["Any logged-in user", "Only the SOC Analyst", "Only the Administrator", "It happens automatically with no human involved"],
            "correct": 2,
            "explanation": "The SOC Analyst investigates and recommends; only the Administrator can approve the action that actually blocks an IP via iptables."
        }
    ],
    "common_attacks": [
        {
            "question": "What is the goal of a port scan?",
            "options": [
                "To crash the target immediately",
                "To discover which services/ports are open on a target",
                "To steal a password",
                "To encrypt the target's files"
            ],
            "correct": 1,
            "explanation": "Port scanning is reconnaissance - finding open doors before deciding how to attack, not an attack in itself."
        },
        {
            "question": "What does DoS stand for, and what's its goal?",
            "options": [
                "Denial of Service - overwhelm a system so legitimate users can't use it",
                "Data on Screen - display stolen data",
                "Domain of Security - a type of firewall",
                "Delay of Signal - slow down a network"
            ],
            "correct": 0,
            "explanation": "A Denial of Service attack floods a target with traffic/requests until it can't respond to real users."
        },
        {
            "question": "Why do attackers use brute-force against SSH instead of guessing once?",
            "options": [
                "They only get one guess normally",
                "Automated tools can try thousands of username/password combinations quickly, hoping one works",
                "SSH requires brute force by design",
                "It's not actually about passwords"
            ],
            "correct": 1,
            "explanation": "Brute-forcing relies on speed and volume - trying many combinations fast, hoping to hit a weak or reused password."
        }
    ],
    "firewalls_prevention": [
        {
            "question": "What does iptables actually do when IntelliSense 'blocks' an IP?",
            "options": [
                "Deletes the attacker's files",
                "Adds a rule telling the Linux kernel to DROP packets from that source IP",
                "Sends a warning email to the attacker",
                "Disconnects the entire network"
            ],
            "correct": 1,
            "explanation": "block_ip() in prevention.py runs `iptables -A INPUT -s <ip> -j DROP`, which silently discards packets from that source."
        },
        {
            "question": "Why does IntelliSense use DROP instead of REJECT?",
            "options": [
                "DROP is faster to type",
                "DROP silently discards packets with no response, giving the attacker less information than REJECT's error reply",
                "REJECT doesn't work in iptables",
                "There is no difference"
            ],
            "correct": 1,
            "explanation": "REJECT sends back an error response, confirming to the attacker that something is listening. DROP gives no feedback at all - better for security."
        }
    ]
}


def get_simulation_quiz(scenario_key):
    return SIMULATION_QUIZZES.get(scenario_key, [])


def get_module_quiz(module_key):
    return MODULE_QUIZZES.get(module_key, [])