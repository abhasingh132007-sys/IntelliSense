"""
IntelliSense - Intelligent Network Intrusion Detection, Prevention and Learning Platform
Main Flask Application Entry Point

Role-based architecture:
    /                       -> portal selection (Organization vs Student)
    /organization/login     -> org name + username + password
    /student/login          -> username + password (no org)
    /admin/dashboard         -> Administrator (role_required)
    /analyst/dashboard       -> SOC Analyst (role_required)
    /simulator               -> Student (role_required)
    /incident/<id>            -> shared investigate/escalate/approve page,
                                 behavior branches on the logged-in user's role
"""

from flask import Flask, render_template, jsonify, redirect, url_for, request, session, Response
import json

from modules import mock_data, capture, packet_buffer, detection, database, auth, prevention

app = Flask(__name__)
app.config['SECRET_KEY'] = 'intellisense-dev-key-change-in-production'

database.init_db()


# ---------------------------------------------------------------------------
# Portal selection + auth
# ---------------------------------------------------------------------------

@app.route('/', methods=['GET', 'POST'])
def home():
    """
    Organization Login is now the app's entry point - no separate
    portal-selector page. This single route handles both showing the
    page (GET) and processing the login form (POST).
    """
    if auth.current_user():
        return redirect(url_for('role_home', role=session['role']))

    error = None
    if request.method == 'POST':
        org_name = request.form.get('org_name', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = auth.verify_login(username, password)
        if (user and user.get('role') in ('administrator', 'soc_analyst')
                and database.get_org_name(user.get('org_id')) == org_name):
            auth.login_user_session(user)
            return redirect(url_for('role_home', role=user['role']))
        error = "Invalid organization, username, or password."

    return render_template('organization_login.html', error=error)


@app.route('/organization/login')
def organization_login():
    """Old URL, kept as a redirect so any existing links/bookmarks still work."""
    return redirect(url_for('home'))


@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    """Student login: username + password, no organization involved."""
    if auth.current_user():
        return redirect(url_for('role_home', role=session['role']))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = auth.verify_login(username, password)
        if user and user.get('role') == 'student':
            auth.login_user_session(user)
            return redirect(url_for('simulator'))
        error = "Invalid username or password."

    return render_template('student_login.html', error=error)


@app.route('/home/<role>')
def role_home(role):
    """
    Central redirect target used by auth.role_required() when a logged-in
    user with the WRONG role hits a page - sends them to their own home
    instead of a raw 403. Also used right after login.
    """
    if role == 'administrator':
        return redirect(url_for('admin_dashboard'))
    if role == 'soc_analyst':
        return redirect(url_for('analyst_dashboard'))
    if role == 'student':
        return redirect(url_for('simulator'))
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    """Clears the session and sends the user back to the portal selection page."""
    session.clear()
    return redirect(url_for('home'))


# ---------------------------------------------------------------------------
# Administrator dashboard
# ---------------------------------------------------------------------------

@app.route('/admin/dashboard')
@auth.role_required('administrator')
def admin_dashboard():
    user = auth.current_user()
    org_id = user['org_id']

    stats = get_admin_stats(org_id)
    escalated = database.get_incidents(org_id, status='Escalated')

    return render_template(
        'admin_dashboard.html',
        current_mode='ADMINISTRATOR',
        stats=stats,
        escalated_incidents=escalated,
        username=user['username']
    )


def get_admin_stats(org_id):
    real_packets = packet_buffer.get_total_count()
    new_count = database.count_incidents_by_status(org_id, 'New')
    escalated_count = database.count_incidents_by_status(org_id, 'Escalated')
    resolved_count = database.count_incidents_by_status(org_id, 'Resolved')

    return [
        {"label": "Total Packets", "value": f"{real_packets:,}" if real_packets else "128,567",
         "delta": "12.5%", "delta_dir": "up", "icon": "📦", "bg": "rgba(59,130,246,.15)", "color": "#3b82f6"},
        {"label": "New Incidents", "value": str(new_count), "delta": "-", "delta_dir": "up",
         "icon": "🔔", "bg": "rgba(239,68,68,.15)", "color": "#ef4444"},
        {"label": "Escalated", "value": str(escalated_count), "delta": "-", "delta_dir": "up",
         "icon": "⬆️", "bg": "rgba(245,158,11,.15)", "color": "#f59e0b"},
        {"label": "Resolved", "value": str(resolved_count), "delta": "-", "delta_dir": "down",
         "icon": "✅", "bg": "rgba(34,197,94,.15)", "color": "#22c55e"},
    ]


@app.route('/admin/incident/<int:incident_id>/approve', methods=['POST'])
@auth.role_required('administrator')
def admin_approve_incident(incident_id):
    """
    Administrator approves the SOC Analyst's recommended action.
    Actually calls the Prevention Engine to block the source IP via
    iptables. If the firewall call fails, the incident still gets marked
    approved, but the failure reason is stored in notes.
    """
    user = auth.current_user()
    incident = database.get_incident(incident_id)

    result = prevention.block_ip(incident['source_ip'])

    if result["success"]:
        note_suffix = " (already blocked)" if result["already_blocked"] else " - IP blocked via iptables"
    else:
        note_suffix = f" - FIREWALL BLOCK FAILED: {result['error']}"

    updated_notes = (incident.get('notes') or '') + note_suffix

    database.update_incident(
        incident_id,
        status='Action Taken',
        administrator_id=user['user_id'],
        notes=updated_notes
    )
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/incident/<int:incident_id>/reject', methods=['POST'])
@auth.role_required('administrator')
def admin_reject_incident(incident_id):
    """Administrator sends the incident back to the analyst for more investigation."""
    user = auth.current_user()
    database.update_incident(
        incident_id,
        status='Investigating',
        administrator_id=user['user_id']
    )
    return redirect(url_for('admin_dashboard'))


# ---------------------------------------------------------------------------
# SOC Analyst dashboard
# ---------------------------------------------------------------------------

@app.route('/analyst/dashboard')
@auth.role_required('soc_analyst')
def analyst_dashboard():
    user = auth.current_user()
    org_id = user['org_id']

    new_incidents = database.get_incidents(org_id, status='New')
    investigating = database.get_incidents(org_id, status='Investigating')

    return render_template(
        'analyst_dashboard.html',
        current_mode='SOC ANALYST',
        new_incidents=new_incidents,
        investigating_incidents=investigating,
        username=user['username']
    )


@app.route('/incident/<int:incident_id>')
@auth.login_required
def incident_detail(incident_id):
    """
    Shared investigate/review page. What actions are available (investigate
    vs approve/reject) is decided in the template based on session role.
    """
    incident = database.get_incident(incident_id)
    if not incident:
        return redirect(url_for('role_home', role=session['role']))
    return render_template('incident_detail.html', incident=incident, current_mode=session['role'].upper())


@app.route('/incident/<int:incident_id>/investigate', methods=['POST'])
@auth.role_required('soc_analyst')
def investigate_incident(incident_id):
    """SOC Analyst submits notes + recommendation and escalates to Administrator."""
    user = auth.current_user()
    notes = request.form.get('notes', '')
    recommendation = request.form.get('recommendation', '')
    severity = request.form.get('severity', '')

    database.update_incident(
        incident_id,
        notes=notes,
        recommendation=recommendation,
        severity=severity,
        status='Escalated',
        analyst_id=user['user_id']
    )
    return redirect(url_for('analyst_dashboard'))


# ---------------------------------------------------------------------------
# Student portal (the existing simulator, now behind student login)
# ---------------------------------------------------------------------------

@app.route('/simulator')
@auth.role_required('student')
def simulator():
    """Learning Simulator - Student portal."""
    return render_template('simulator.html', current_mode='STUDENT')


# ---------------------------------------------------------------------------
# Shared pages (Live Monitor, Alerts, Blocked IPs, Logs) - any logged-in
# organization user (administrator or soc_analyst) can view these
# ---------------------------------------------------------------------------

@app.route('/live-monitor')
@auth.role_required('administrator', 'soc_analyst')
def live_monitor():
    return render_template('live_monitor.html', current_mode=session['role'].upper())


@app.route('/blocked-ips')
@auth.role_required('administrator', 'soc_analyst')
def blocked_ips_page():
    """Reads the REAL blocked IP list from iptables, cross-referenced with incidents."""
    user = auth.current_user()
    real_ips = prevention.list_blocked_ips()

    if real_ips:
        actioned_incidents = database.get_incidents(user['org_id'], status='Action Taken')
        by_ip = {inc['source_ip']: inc for inc in actioned_incidents}

        blocked_ips = []
        for ip in real_ips:
            inc = by_ip.get(ip)
            blocked_ips.append({
                "ip": ip,
                "reason": inc['attack_type'] if inc else "Manually blocked",
                "blocked_at": inc['updated_at'] if inc else "-",
                "attempts": "-"
            })
    else:
        blocked_ips = mock_data.get_blocked_ips()

    return render_template(
        'blocked_ips.html',
        current_mode=session['role'].upper(),
        blocked_ips=blocked_ips
    )


@app.route('/logs')
@auth.role_required('administrator', 'soc_analyst')
def logs_page():
    return render_template(
        'logs.html',
        current_mode=session['role'].upper(),
        logs=mock_data.get_logs()
    )


# ---------------------------------------------------------------------------
# API routes
# ---------------------------------------------------------------------------

@app.route('/api/status')
def api_status():
    return jsonify({"status": "online", "project": "IntelliSense"})


@app.route('/api/traffic-stats')
@auth.api_login_required
def api_traffic_stats():
    return jsonify({
        "labels": ["12:24", "12:24:30", "12:25", "12:25:30", "12:26", "12:26:30", "12:27"],
        "traffic": {
            "incoming": [300, 520, 410, 680, 540, 720, 610],
            "outgoing": [180, 260, 220, 340, 300, 410, 360]
        },
        "alerts_over_time": [10, 35, 18, 42, 25, 38, 20],
        "attack_types": {
            "labels": ["Port Scan", "Failed Login", "DoS Attempt", "SQL Injection", "XSS Attack"],
            "values": [45, 25, 15, 10, 5],
            "colors": ["#3b82f6", "#8b5cf6", "#ef4444", "#f59e0b", "#22c55e"]
        }
    })


@app.route('/api/incidents')
@auth.api_login_required
def api_incidents():
    """Returns this user's org incidents as JSON - used by dashboard polling."""
    user = auth.current_user()
    status = request.args.get('status')
    return jsonify(database.get_incidents(user['org_id'], status=status))


@app.route('/api/live-packets')
@auth.api_login_required
def api_live_packets():
    real_packets = packet_buffer.get_recent_packets()
    if real_packets:
        return jsonify(real_packets)
    return jsonify(mock_data.get_live_packets())


@app.route('/api/blocked-ips/<ip_address>', methods=['DELETE'])
@auth.api_role_required('administrator')
def api_unblock_ip(ip_address):
    """
    Unblocks an IP - Administrator only.
    Now calls the real Prevention Engine.
    """
    result = prevention.unblock_ip(ip_address)
    if result["success"]:
        return jsonify({"status": "unblocked", "ip": ip_address})
    return jsonify({"status": "error", "ip": ip_address, "error": result["error"]}), 500


@app.route('/api/clear-logs', methods=['POST'])
@auth.api_login_required
def api_clear_logs():
    return jsonify({"status": "cleared", "message": "Logs cleared (placeholder - no log table yet)"})


@app.route('/api/export-report')
@auth.api_login_required
def api_export_report():
    user = auth.current_user()
    data = json.dumps(database.get_incidents(user['org_id']), indent=2)
    return Response(
        data, mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=intellisense_report.json'}
    )


if __name__ == '__main__':
    capture.start_capture(interface="ens33")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
