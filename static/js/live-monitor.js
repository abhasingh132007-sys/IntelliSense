// Step 7: Live Monitor page.
// Polls /api/live-packets and renders the table. Once Phase 3 wires in
// real Scapy capture, this file needs zero changes - it already just
// consumes whatever the endpoint returns.

let lastCount = 0;

async function refreshLivePackets() {
    try {
        const res = await fetch('/api/live-packets');
        const packets = await res.json();

        const tbody = document.getElementById('live-packets-body');
        tbody.innerHTML = packets.map(p => `
            <tr>
                <td>${p.time}</td>
                <td>${p.src_ip}</td>
                <td>${p.dst_ip}</td>
                <td>${p.protocol}</td>
                <td>${p.port ?? '-'}</td>
                <td>${p.flags ?? '-'}</td>
                <td>${p.length} B</td>
            </tr>
        `).join('');

        // Rough rate estimate just for display - real capture will track this properly
        document.getElementById('packet-rate').textContent = `${packets.length} in buffer`;
    } catch (err) {
        console.error('Failed to load live packets:', err);
    }
}

refreshLivePackets();
setInterval(refreshLivePackets, 1500);
