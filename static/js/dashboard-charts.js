/*
  dashboard-charts.js
  --------------------
  Fetches /api/traffic-stats and renders the 3 dashboard charts.
  Deliberately re-fetches and re-renders on an interval so that once
  Phase 4/5 makes the API return real data, this file needs zero changes -
  it already treats the data as dynamic, not a one-time snapshot.
*/

const gridColor = 'rgba(15,23,42,0.06)';
const tickColor = '#6b7280';

let trafficChart, alertsChart, attackDonut;

function baseLineOptions() {
    return {
        plugins: { legend: { labels: { color: tickColor, boxWidth: 10, font: { size: 11 } } } },
        scales: {
            x: { grid: { color: gridColor }, ticks: { color: tickColor, font: { size: 10 } } },
            y: { grid: { color: gridColor }, ticks: { color: tickColor, font: { size: 10 } } }
        },
        animation: { duration: 300 }
    };
}

async function loadTrafficStats() {
    try {
        const res = await fetch('/api/traffic-stats');
        const data = await res.json();
        renderCharts(data);
    } catch (err) {
        console.error('Failed to load traffic stats:', err);
    }
}

function renderCharts(data) {
    // Traffic chart
    if (!trafficChart) {
        trafficChart = new Chart(document.getElementById('trafficChart'), {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [
                    { label: 'Incoming', data: data.traffic.incoming, borderColor: '#3b82f6',
                      backgroundColor: 'rgba(59,130,246,.15)', fill: true, tension: .4, pointRadius: 0 },
                    { label: 'Outgoing', data: data.traffic.outgoing, borderColor: '#8b5cf6',
                      backgroundColor: 'rgba(139,92,246,.1)', fill: true, tension: .4, pointRadius: 0 }
                ]
            },
            options: baseLineOptions()
        });
    } else {
        trafficChart.data.labels = data.labels;
        trafficChart.data.datasets[0].data = data.traffic.incoming;
        trafficChart.data.datasets[1].data = data.traffic.outgoing;
        trafficChart.update();
    }

    // Alerts over time chart
    if (!alertsChart) {
        alertsChart = new Chart(document.getElementById('alertsChart'), {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [{ label: 'Alerts', data: data.alerts_over_time, borderColor: '#ef4444',
                    backgroundColor: 'rgba(239,68,68,.15)', fill: true, tension: .4, pointRadius: 0 }]
            },
            options: baseLineOptions()
        });
    } else {
        alertsChart.data.labels = data.labels;
        alertsChart.data.datasets[0].data = data.alerts_over_time;
        alertsChart.update();
    }

    // Attack types donut chart
    const at = data.attack_types;
    if (!attackDonut) {
        attackDonut = new Chart(document.getElementById('attackDonut'), {
            type: 'doughnut',
            data: {
                labels: at.labels,
                datasets: [{ data: at.values, backgroundColor: at.colors, borderWidth: 0 }]
            },
            options: { plugins: { legend: { display: false } }, cutout: '70%', animation: { duration: 300 } }
        });
    } else {
        attackDonut.data.labels = at.labels;
        attackDonut.data.datasets[0].data = at.values;
        attackDonut.data.datasets[0].backgroundColor = at.colors;
        attackDonut.update();
    }

    // Legend for the donut (built from the same data, not hardcoded)
    const legend = document.getElementById('attack-legend');
    const total = at.values.reduce((a, b) => a + b, 0);
    legend.innerHTML = at.labels.map((label, i) => {
        const pct = total ? Math.round((at.values[i] / total) * 100) : 0;
        return `<div><span class="dot" style="background:${at.colors[i]};"></span>${label} &nbsp;${pct}%</div>`;
    }).join('');
}

loadTrafficStats();
setInterval(loadTrafficStats, 5000); // refresh every 5 seconds
