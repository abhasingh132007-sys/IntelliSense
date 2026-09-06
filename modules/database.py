"""
database.py
------------
Real persistent storage using SQLite, replacing both the in-memory
mock_data.py placeholders AND the single hardcoded auth.py account.

Schema (matches the Organization/Student portal design):
- organizations: one row per org
- users: belongs to an org (nullable for students), has a role
- incidents: alerts that flow through the investigation/escalation lifecycle
- reports: requested/prepared/submitted between roles

This intentionally uses Python's built-in sqlite3 - no extra dependency,
and matches what the project abstract scoped (SQLite for development).
"""

import sqlite3
import os
from datetime import datetime
from werkzeug.security import generate_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "intellisense.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # lets us access columns by name, e.g. row["username"]
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Creates all tables if they don't exist yet, and seeds one demo org + users."""
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS organizations (
        org_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE
    );

    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER,                          -- NULL for students (no org)
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('administrator', 'soc_analyst', 'student')),
        FOREIGN KEY (org_id) REFERENCES organizations(org_id)
    );

    CREATE TABLE IF NOT EXISTS incidents (
        incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        attack_type TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        destination_ip TEXT,
        severity TEXT NOT NULL CHECK(severity IN ('Low', 'Medium', 'High', 'Critical')),
        status TEXT NOT NULL DEFAULT 'New'
            CHECK(status IN ('New', 'Investigating', 'Escalated', 'Action Taken', 'Resolved')),
        description TEXT,
        notes TEXT,                              -- SOC Analyst's investigation notes
        recommendation TEXT,                     -- SOC Analyst's recommended action
        analyst_id INTEGER,                      -- who investigated it
        administrator_id INTEGER,                -- who resolved/approved it
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(org_id),
        FOREIGN KEY (analyst_id) REFERENCES users(user_id),
        FOREIGN KEY (administrator_id) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS reports (
        report_id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        requested_by INTEGER NOT NULL,
        assigned_to INTEGER NOT NULL,
        report_type TEXT NOT NULL,
        summary TEXT,
        analysis TEXT,
        recommendation TEXT,
        status TEXT NOT NULL DEFAULT 'Requested'
            CHECK(status IN ('Requested', 'Submitted', 'Reviewed')),
        created_at TEXT NOT NULL,
        FOREIGN KEY (org_id) REFERENCES organizations(org_id),
        FOREIGN KEY (requested_by) REFERENCES users(user_id),
        FOREIGN KEY (assigned_to) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS notifications (
        notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    );
    """)
    conn.commit()

    # Seed one demo organization + one user per role, only if empty
    cur.execute("SELECT COUNT(*) FROM organizations")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO organizations (name) VALUES (?)", ("ABC Technologies",))
        org_id = cur.lastrowid

        seed_users = [
            (org_id, "admin", "intellisense123", "administrator"),
            (org_id, "analyst1", "analyst123", "soc_analyst"),
            (None, "student", "student123", "student"),
        ]
        for org, username, password, role in seed_users:
            cur.execute(
                "INSERT INTO users (org_id, username, password_hash, role) VALUES (?, ?, ?, ?)",
                (org, username, generate_password_hash(password), role)
            )
        conn.commit()
        print("[database] Seeded demo organization + 3 users (admin/analyst1/student).")

    conn.close()


# ---------------------------------------------------------------------------
# User / auth queries
# ---------------------------------------------------------------------------

def get_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_org_name(org_id):
    if not org_id:
        return None
    conn = get_connection()
    row = conn.execute("SELECT name FROM organizations WHERE org_id = ?", (org_id,)).fetchone()
    conn.close()
    return row["name"] if row else None


def get_default_org_id():
    """
    Returns the first organization's id. There's only one demo org for now
    (multi-org support would need capture.py to know which org's network
    it's monitoring - out of scope per your abstract, which targets one
    organization's network per deployment).
    """
    conn = get_connection()
    row = conn.execute("SELECT org_id FROM organizations ORDER BY org_id LIMIT 1").fetchone()
    conn.close()
    return row["org_id"] if row else None


# ---------------------------------------------------------------------------
# Incident queries (Phase D/E - used once escalation workflow is built)
# ---------------------------------------------------------------------------

def create_incident(org_id, attack_type, source_ip, severity, description, destination_ip=None):
    conn = get_connection()
    now = datetime.now().isoformat(timespec="seconds")
    cur = conn.execute(
        """INSERT INTO incidents (org_id, attack_type, source_ip, destination_ip, severity,
           status, description, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'New', ?, ?, ?)""",
        (org_id, attack_type, source_ip, destination_ip, severity, description, now, now)
    )
    conn.commit()
    incident_id = cur.lastrowid
    conn.close()
    return incident_id


def get_incidents(org_id, status=None):
    conn = get_connection()
    if status:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE org_id = ? AND status = ? ORDER BY created_at DESC",
            (org_id, status)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE org_id = ? ORDER BY created_at DESC",
            (org_id,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_incident(incident_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def count_incidents_by_status(org_id, status):
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) as c FROM incidents WHERE org_id = ? AND status = ?",
        (org_id, status)
    ).fetchone()
    conn.close()
    return row["c"]


def list_organization_names():
    conn = get_connection()
    rows = conn.execute("SELECT name FROM organizations ORDER BY name").fetchall()
    conn.close()
    return [r["name"] for r in rows]


def update_incident(incident_id, **fields):
    """Generic updater - pass any column=value pairs, e.g. status='Escalated'."""
    if not fields:
        return
    fields["updated_at"] = datetime.now().isoformat(timespec="seconds")
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [incident_id]

    conn = get_connection()
    conn.execute(f"UPDATE incidents SET {set_clause} WHERE incident_id = ?", values)
    conn.commit()
    conn.close()
