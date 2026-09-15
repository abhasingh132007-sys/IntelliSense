// simulator.js
// -------------
// Tab switching + a PERSISTENT Live Monitor panel that both the fixed
// attack scenarios and the Evasion Sandbox render into (cleared and
// refilled each run, never appended) - keeps the page a fixed height
// instead of growing with every simulation run.

const attackTitles = {
    port_scan: 'Port Scan',
    dos: 'DoS Attack',
    ssh_bruteforce: 'SSH Brute Force',
    icmp_flood: 'ICMP Flood'
};

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
        btn.classList.add('active');
        document.getElementById(`tab-${btn.dataset.tab}`).classList.remove('hidden');
    });
});

// ---------------------------------------------------------------------------
// Fixed attack scenarios
// ---------------------------------------------------------------------------

document.querySelectorAll('.attack-card-compact .run-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const attackKey = btn.closest('.attack-card-compact').dataset.attack;
        runScenario(attackKey);
    });
});

async function runScenario(attackKey) {
    resetMonitor(`Generating ${attackTitles[attackKey] || attackKey} traffic...`);

    let data;
    try {
        const res = await fetch(`/api/simulate/${attackKey}`);
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        data = await res.json();
    } catch (err) {
        showMonitorError(err.message);
        return;
    }

    animateEvents(data.events, { onFinish: () => loadPostSimQuiz(attackKey) });
}

// ---------------------------------------------------------------------------
// Evasion Sandbox - renders into the SAME persistent panel
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

        resetMonitor(`Running custom pattern: ${count} packets over ${spread}s...`);

        try {
            const res = await fetch('/api/simulate-custom', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attack_type: attackType, count, spread_seconds: spread })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Sandbox run failed');

            animateEvents(data.events, { skipQuiz: true });
        } catch (err) {
            showMonitorError(err.message);
        }
    });
}

// ---------------------------------------------------------------------------
// Persistent Live Monitor panel - shared rendering
// ---------------------------------------------------------------------------

function resetMonitor(statusMessage) {
    const statusEl = document.getElementById('sim-live-status');
    statusEl.textContent = 'Running';
    statusEl.className = 'sim-live-status running';

    document.getElementById('sim-progress-fill').style.width = '0%';
    document.getElementById('sim-progress-fill').classList.remove('fired');
    document.getElementById('sim-progress-text').textContent = '0 / -';

    const banner = document.getElementById('sim-alert-banner');
    banner.classList.remove('visible');
    banner.innerHTML = '';

    document.getElementById('sim-packet-body').innerHTML =
        `<tr><td colspan="5" style="color:var(--muted); text-align:center; padding:16px;">${statusMessage}</td></tr>`;

    document.getElementById('sim-summary').classList.remove('visible', 'not-detected');
    document.getElementById('sim-summary').innerHTML = '';

    const quizContainer = document.getElementById('sim-quiz-container');
    quizContainer.classList.remove('visible');
    quizContainer.innerHTML = '';
}

function showMonitorError(message) {
    document.getElementById('sim-live-status').textContent = 'Error';
    document.getElementById('sim-live-status').className = 'sim-live-status';
    document.getElementById('sim-packet-body').innerHTML =
        `<tr><td colspan="5" style="color:var(--red); text-align:center; padding:16px;">${message}</td></tr>`;
}

function animateEvents(events, opts) {
    opts = opts || {};
    const packetBody = document.getElementById('sim-packet-body');
    const banner = document.getElementById('sim-alert-banner');
    const statusEl = document.getElementById('sim-live-status');
    const progressFill = document.getElementById('sim-progress-fill');
    const progressText = document.getElementById('sim-progress-text');

    packetBody.innerHTML = ''; // clear the "Running..." placeholder row

    let i = 0;
    let firstAlert = null;
    const delay = events.length > 25 ? 30 : 100;

    function step() {
        if (i >= events.length) {
            finish();
            return;
        }

        const ev = events[i];
        const p = ev.packet;

        const row = document.createElement('tr');
        if (ev.alert_fired) row.className = 'flagged';
        row.innerHTML = `
            <td>${ev.step}</td>
            <td>${p.src_ip}</td>
            <td>${p.protocol}</td>
            <td>${p.port ?? '-'}</td>
            <td>${p.flags}</td>
        `;
        packetBody.appendChild(row);
        packetBody.closest('.sim-monitor-scroll').scrollTop = packetBody.closest('.sim-monitor-scroll').scrollHeight;

        if (ev.progress) {
            const pct = Math.min(100, Math.round((ev.progress.current / ev.progress.threshold) * 100));
            progressFill.style.width = pct + '%';
            progressText.textContent = `${ev.progress.current} / ${ev.progress.threshold}`;
            if (ev.alert_fired) progressFill.classList.add('fired');
        }

        if (ev.alert_fired && !firstAlert) {
            firstAlert = ev.alert;
            banner.classList.add('visible');
            banner.innerHTML = `<h4>🚨 ${ev.alert.type} Detected (${ev.alert.severity})</h4><p>${ev.alert.description}</p>`;
        }

        i++;
        setTimeout(step, delay);
    }

    step();

    function finish() {
        const summary = document.getElementById('sim-summary');
        if (firstAlert) {
            statusEl.textContent = 'Detected';
            statusEl.className = 'sim-live-status done';
            summary.classList.add('visible');
            summary.innerHTML = `
                <strong>✅ Detected.</strong> Flagged as <strong>${firstAlert.type}</strong>
                (${firstAlert.severity}) after ${firstAlert.description.toLowerCase()}.
            `;
        } else {
            statusEl.textContent = 'Not Detected';
            statusEl.className = 'sim-live-status';
            summary.classList.add('visible', 'not-detected');
            summary.innerHTML = `<strong>⚠️ Not detected.</strong> This pattern didn't cross the threshold.`;
        }

        if (!opts.skipQuiz && typeof opts.onFinish === 'function') {
            opts.onFinish();
        }
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
        quizContainer.innerHTML = `<h4 style="font-size:13px; margin-bottom:8px;">📝 Quick Check</h4>`;
        const quizBody = document.createElement('div');
        quizContainer.appendChild(quizBody);

        IntelliQuiz.render(quizBody, data.questions, {
            itemType: 'simulation',
            itemKey: attackKey,
            onComplete: () => {
                const card = document.querySelector(`.attack-card-compact[data-attack="${attackKey}"]`);
                if (card && !card.querySelector('.completed-badge')) {
                    const badge = document.createElement('span');
                    badge.className = 'completed-badge';
                    badge.textContent = '✓';
                    card.appendChild(badge);
                }
            }
        });
    } catch (err) {
        console.error('Failed to load quiz:', err);
    }
}