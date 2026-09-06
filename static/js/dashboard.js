// Polls the /api/alerts endpoint and renders them in the dashboard table.
// In later phases this will connect to the live Scapy-based detection engine.

async function refreshAlerts() {
    try {
        const res = await fetch('/api/alerts');
        const alerts = await res.json();

        const tbody = document.querySelector('#alerts-table tbody');
        tbody.innerHTML = '';

        alerts.forEach(a => {
            const row = document.createElement('tr');
            row.innerHTML = `<td>${a.id}</td><td>${a.type}</td><td>${a.source_ip}</td><td>${a.severity}</td>`;
            tbody.appendChild(row);
        });

        document.getElementById('alert-count').textContent = alerts.length;
    } catch (err) {
        console.error('Failed to fetch alerts:', err);
    }
}

refreshAlerts();
setInterval(refreshAlerts, 5000); // refresh every 5 seconds
