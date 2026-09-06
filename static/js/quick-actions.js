// Step 6: Quick Actions wiring.
// Clear Logs -> POST /api/clear-logs, Export Report -> downloads /api/export-report

const clearBtn = document.getElementById('btn-clear-logs');
if (clearBtn) {
    clearBtn.addEventListener('click', async () => {
        clearBtn.disabled = true;
        clearBtn.textContent = 'Clearing...';
        try {
            const res = await fetch('/api/clear-logs', { method: 'POST' });
            const data = await res.json();
            clearBtn.textContent = '✅ Cleared';
        } catch (err) {
            clearBtn.textContent = '❌ Failed';
            console.error('Clear logs failed:', err);
        }
        setTimeout(() => {
            clearBtn.disabled = false;
            clearBtn.textContent = '📄 Clear Logs';
        }, 1500);
    });
}

const exportBtn = document.getElementById('btn-export-report');
if (exportBtn) {
    exportBtn.addEventListener('click', () => {
        // Triggers a real file download via the browser - no fetch needed,
        // the server sets Content-Disposition: attachment on this endpoint.
        window.location.href = '/api/export-report';
    });
}
