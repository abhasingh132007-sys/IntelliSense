// simulator.js
// -------------
// Fetches a synthetic attack run from /api/simulate/<attack>, which is
// REAL detection.py output (see modules/simulator.py) - not a scripted
// story. This file just paces the display so students can follow along
// packet by packet instead of seeing everything dumped at once.

const attackTitles = {
    port_scan: 'Port Scan',
    dos: 'DoS Attack',
    ssh_bruteforce: 'SSH Brute Force',
    icmp_flood: 'ICMP Flood'
};

document.querySelectorAll('.attack-card').forEach(card => {
    card.addEventListener('click', () => runSimulation(card.dataset.attack));
});

async function runSimulation(attackKey) {
    const box = document.querySelector('#simulation-area');
    const title = attackTitles[attackKey] || attackKey;

    box.innerHTML = `<div class="sim-box"><p style="color:var(--muted);">Generating ${title} traffic and running it through the detection engine...</p></div>`;

    let data;
    try {
        const res = await fetch(`/api/simulate/${attackKey}`);
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        data = await res.json();
    } catch (err) {
        box.innerHTML = `<div class="sim-box"><p style="color:var(--red);">Simulation failed: ${err.message}</p></div>`;
        return;
    }

    box.innerHTML = buildSimLayout(title, data);
    animateEvents(data.events);
}

function buildSimLayout(title, data) {
    return `
    <div class="sim-box">
        <div class="sim-status-line">
            <span class="sim-status-dot" id="sim-status-dot"></span>
            <span id="sim-status-text">Simulating attack from ${data.attacker_ip} &rarr; ${data.target_ip}</span>
        </div>

        <div id="sim-alert-banner" class="sim-alert-banner"></div>

        <div class="sim-layout">
            <div class="sim-packet-log">
                <h4 style="font-size:13px; margin-bottom:8px;">Packets Sent</h4>
                <table class="sim-packet-table">
                    <thead>
                        <tr><th>#</th><th>Protocol</th><th>Port</th><th>Flags</th><th>Description</th></tr>
                    </thead>
                    <tbody id="sim-packet-body"></tbody>
                </table>
            </div>

            <div class="sim-explain">
                <h4 style="font-size:13px; margin-bottom:8px;">What's Happening</h4>
                <div class="sim-step-log" id="sim-step-log"></div>
                <div class="sim-summary" id="sim-summary"></div>
            </div>
        </div>
    </div>`;
}

function animateEvents(events) {
    const packetBody = document.getElementById('sim-packet-body');
    const stepLog = document.getElementById('sim-step-log');
    const banner = document.getElementById('sim-alert-banner');
    const statusDot = document.getElementById('sim-status-dot');
    const statusText = document.getElementById('sim-status-text');

    let i = 0;
    let firstAlert = null;

    // Pace faster for longer sequences (e.g. the 55-packet DoS run) so it
    // doesn't take forever, but slow enough to actually watch on short ones.
    const delay = events.length > 25 ? 35 : 120;

    function step() {
        if (i >= events.length) {
            finish(firstAlert, events.length);
            return;
        }

        const ev = events[i];
        const p = ev.packet;

        const row = document.createElement('tr');
        if (ev.alert_fired) row.className = 'flagged';
        row.innerHTML = `
            <td>${ev.step}</td>
            <td>${p.protocol}</td>
            <td>${p.port ?? '-'}</td>
            <td>${p.flags}</td>
            <td>${ev.description}</td>
        `;
        packetBody.appendChild(row);
        packetBody.scrollTop = packetBody.scrollHeight;

        const logLine = document.createElement('div');
        logLine.textContent = `Step ${ev.step}: ${ev.description}`;
        if (ev.alert_fired) {
            logLine.className = 'hit';
            logLine.textContent += ` -> ALERT: ${ev.alert.type}`;
        }
        stepLog.appendChild(logLine);
        stepLog.scrollTop = stepLog.scrollHeight;

        if (ev.alert_fired && !firstAlert) {
            firstAlert = ev.alert;
            banner.classList.add('visible');
            banner.innerHTML = `
                <h4>🚨 ${ev.alert.type} Detected (${ev.alert.severity})</h4>
                <p>${ev.alert.description}</p>
            `;
        }

        i++;
        setTimeout(step, delay);
    }

    step();

    function finish(alert, totalSteps) {
        statusDot.classList.add('done');
        statusText.textContent = `Simulation complete - ${totalSteps} packets sent`;

        const summary = document.getElementById('sim-summary');
        if (alert) {
            summary.classList.add('visible');
            summary.innerHTML = `
                <strong>✅ Detected.</strong> The detection engine flagged this as
                <strong>${alert.type}</strong> (${alert.severity} severity) after
                ${alert.description.toLowerCase()}. In Real-Time mode, this would appear
                on the SOC Analyst's dashboard for investigation.
            `;
        } else {
            summary.classList.add('visible', 'not-detected');
            summary.innerHTML = `
                <strong>⚠️ Not detected.</strong> This traffic pattern didn't cross the
                detection threshold. Try a scenario with more packets, or look at
                modules/detection.py to see the exact thresholds being checked.
            `;
        }
    }
}