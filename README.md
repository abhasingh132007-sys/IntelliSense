# IntelliSense

Intelligent Network Intrusion Detection, Prevention and Learning Platform.

A role-based cybersecurity platform combining real-time intrusion detection
with an educational Learning Simulator. SOC Analysts investigate live
network traffic and escalate confirmed threats; Administrators review and
approve prevention actions; Students explore guided attack scenarios using
the same detection engine.

## Features

- **Live packet capture** via Scapy, analyzing real network traffic
- **Rule-based detection** for port scans, DoS floods, and ICMP floods
- **Incident escalation workflow** — Analyst investigates → escalates → Administrator approves/rejects
- **Role-based dashboards** for Administrator and SOC Analyst
- **Learning Simulator** for students, using the same detection logic on safely generated traffic
- **SQLite persistence** for organizations, users, incidents, and reports

## Tech Stack

- **Backend:** Python, Flask
- **Packet capture:** Scapy
- **Database:** SQLite
- **Frontend:** HTML, CSS, vanilla JS, Chart.js
- **Firewall (planned):** iptables

## Setup

```bash
# Clone the repo
git clone <your-repo-url>
cd IntelliSense

# Create and activate a virtual environment
python3 -m venv scapy_env
source scapy_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run (needs sudo for Scapy's raw packet capture)
sudo $(which python3) app.py
```

Visit `http://localhost:5000` in your browser. The database is created and
seeded automatically on first run.

## Demo Credentials

| Portal | Organization | Username | Password |
|---|---|---|---|
| Organization | ABC Technologies | `admin` | `intellisense123` |
| Organization | ABC Technologies | `analyst1` | `analyst123` |
| Student | — | `student` | `student123` |

**Change these before any real deployment** — see `modules/database.py`'s
seed data.

## Project Structure

```
IntelliSense/
├── app.py                  # Flask routes and app entry point
├── modules/
│   ├── auth.py              # Session-based auth, role decorators
│   ├── database.py          # SQLite schema and queries
│   ├── capture.py           # Scapy packet sniffing
│   ├── detection.py         # Rule-based attack detection
│   └── mock_data.py         # Placeholder data (being phased out)
├── templates/               # Jinja2 templates
├── static/
│   ├── css/                 # Dark theme (dashboards) + light theme (login pages)
│   ├── js/                  # Dashboard charts, network animation, etc.
│   └── img/logo.svg         # Brand logo
└── requirements.txt
```

## Status

Actively in development. See open issues / project board for what's next.

## License

Academic project - license TBD.
