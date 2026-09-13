// simulator.js
// -------------
// Fetches a synthetic attack run from /api/simulate/<attack>, which is
// REAL detection.py output. Animates through it packet by packet with a
// live threshold progress bar, then shows a post-simulation quiz.
// Also wires the Evasion Sandbox.

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
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });

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
    animateEvents(data.events, attackKey);
}

function buildSimLayout(title, data) {
    return `
    <div class="sim-box">
        <div class="sim-status-line">
            <span class="sim-status-dot" id="sim-status-dot"></span>
            <span id="sim-status-text">Simulating attack from ${data.attacker_ip} &rarr; ${data.target_ip}</span>
        </div>

        <div class="sim-progress-wrap">
            <div class="sim-progress-label">
                <span>Detection threshold progress</span>
                <span id="sim-progress-text">0 / -</span>
            </div>
            <div class="sim-progress-track">
                <div class="sim-progress-fill" id="sim-progress-fill"></div>
            </div>
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

        <div id="sim-quiz-container"></div>
    </div>`;
}

function animateEvents(events, attackKey) {
    const packetBody = document.getElementById('sim-packet-body');
    const stepLog = document.getElementById('sim-step-log');
    const banner = document.getElementById('sim-alert-banner');
    const statusDot = document.getElementById('sim-status-dot');
    const statusText = document.getElementById('sim-status-text');
    const progressFill = document.getElementById('sim-progress-fill');
    const progressText = document.getElementById('sim-progress-text');

    let i = 0;
    let firstAlert = null;

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

        if (ev.progress) {
            const pct = Math.min(100, Math.round((ev.progress.current / ev.progress.threshold) * 100));
            progressFill.style.width = pct + '%';
            progressText.textContent = `${ev.progress.current} / ${ev.progress.threshold}`;
            if (ev.alert_fired) progressFill.classList.add('fired');
        }

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
                detection threshold. Try the Evasion Sandbox below to explore why.
            `;
        }

        loadPostSimQuiz(attackKey);
    }
}

async function loadPostSimQuiz(attackKey) {
    const quizContainer = document.getElementById('sim-quiz-container');
    if (!quizContainer) return;

    try {
        const res = await fetch(`/api/quiz/simulation/${attackKey}`);
        const data = await res.json();
        if (!data.questions || data.questions.length === 0) return;

        quizContainer.classList.add('visible');
        quizContainer.innerHTML = `<h4 style="font-size:14px; margin-bottom:10px;">📝 Quick Check</h4>`;
        const quizBody = document.createElement('div');
        quizContainer.appendChild(quizBody);

        IntelliQuiz.render(quizBody, data.questions, {
            itemType: 'simulation',
            itemKey: attackKey,
            onComplete: () => {
                const card = document.querySelector(`.attack-card[data-attack="${attackKey}"]`);
                if (card && !card.querySelector('.completed-badge')) {
                    const badge = document.createElement('span');
                    badge.className = 'completed-badge';
                    badge.textContent = '✓ Done';
                    card.appendChild(badge);
                }
            }
        });
    } catch (err) {
        console.error('Failed to load quiz:', err);
    }
}

// ---------------------------------------------------------------------------
// Evasion Sandbox
// ---------------------------------------------------------------------------

const sandboxCount = document.getElementById('sandbox-count');
const sandboxCountVal = document.getElementById('sandbox-count-val');
const sandboxSpread = document.getElementById('sandbox-spread');
const sandboxSpreadVal = document.getElementById('sandbox-spread-val');
const sandboxRunBtn = document.getElementById('sandbox-run-btn');

if (sandboxCount) {
    sandboxCount.addEventListener('input', () => sandboxCountVal.textContent = sandboxCount.value);
    sandboxSpread.addEventListener('input', () => sandboxSpreadVal.textContent = sandboxSpread.value);

    sandboxRunBtn.addEventListener('click', async () => {
        const attackType = document.getElementById('sandbox-attack').value;
        const count = parseInt(sandboxCount.value, 10);
        const spread = parseFloat(sandboxSpread.value);
        const resultBox = document.getElementById('sandbox-result');

        resultBox.innerHTML = `<p style="color:var(--muted); margin-top:14px;">Running custom pattern: ${count} packets over ${spread}s...</p>`;

        try {
            const res = await fetch('/api/simulate-custom', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attack_type: attackType, count, spread_seconds: spread })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Sandbox run failed');

            const fired = data.events.some(e => e.alert_fired);
            const lastProgress = data.events[data.events.length - 1].progress;

            resultBox.innerHTML = `
                <div style="margin-top:14px; padding:14px; border-radius:10px; ${fired
                    ? 'background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.35);'
                    : 'background:rgba(34,197,94,0.1); border:1px solid rgba(34,197,94,0.35);'}">
                    <strong>${fired ? '🚨 Detected!' : '✅ Evaded detection'}</strong> &mdash;
                    reached ${lastProgress.current} / ${lastProgress.threshold} toward the threshold
                    with ${count} packets spread over ${spread}s.
                    ${fired ? '' : ' Try increasing the packet count or reducing the time spread to trigger detection.'}
                </div>`;
        } catch (err) {
            resultBox.innerHTML = `<p style="color:var(--red); margin-top:14px;">${err.message}</p>`;
        }
    });
}