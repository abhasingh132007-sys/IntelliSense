// Handles attack card selection in the Learning Simulator.
// Phase 7 will replace this with real JSON attack templates + packet animation.

const attackInfo = {
    port_scan: {
        title: 'Port Scan',
        steps: [
            'Attacker sends SYN packets to a range of ports on the target IP.',
            'Detection engine counts distinct ports contacted within a short time window.',
            'Threshold exceeded &rarr; flagged as a port scan.',
            'Prevention: attacker IP is added to the firewall block list.'
        ]
    },
    dos: {
        title: 'DoS Attack',
        steps: [
            'Attacker sends a high volume of requests to a single target.',
            'Detection engine tracks request rate per source IP.',
            'Rate exceeds threshold &rarr; flagged as a DoS attempt.',
            'Prevention: traffic from the source IP is rate-limited or dropped.'
        ]
    },
    ssh_bruteforce: {
        title: 'SSH Brute Force',
        steps: [
            'Attacker repeatedly attempts SSH logins with different passwords.',
            'Detection engine counts failed login attempts per IP.',
            'Threshold exceeded &rarr; flagged as brute force.',
            'Prevention: source IP is temporarily banned from SSH access.'
        ]
    },
    icmp_flood: {
        title: 'ICMP Flood',
        steps: [
            'Attacker sends a large number of ICMP echo (ping) requests.',
            'Detection engine monitors ICMP packet rate per source.',
            'Rate exceeds threshold &rarr; flagged as an ICMP flood.',
            'Prevention: ICMP traffic from the source IP is blocked.'
        ]
    }
};

document.querySelectorAll('.attack-card').forEach(card => {
    card.addEventListener('click', () => {
        const key = card.dataset.attack;
        const info = attackInfo[key];
        const box = document.querySelector('#simulation-area .sim-box');

        box.innerHTML = `<p style="color:var(--muted);">Loading simulation for <strong>${info.title}</strong>...</p>`;

        setTimeout(() => {
            box.innerHTML = `
                <h3 style="margin-bottom:14px;">${info.title}</h3>
                ${info.steps.map((s, i) => `
                    <p style="margin-bottom:8px; font-size:13.5px; color:var(--text);">
                        <span style="color:var(--blue); font-weight:600;">Step ${i + 1}:</span> ${s}
                    </p>
                `).join('')}
                <p style="margin-top:12px; font-size:12px; color:var(--muted);">
                    <em>Full packet animation coming in Phase 7.</em>
                </p>
            `;
        }, 400);
    });
});
