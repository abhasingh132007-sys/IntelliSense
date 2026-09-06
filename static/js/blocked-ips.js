// Step 8: Blocked IPs page.
// Clicking "Unblock" calls DELETE /api/blocked-ips/<ip> and removes the row.
// PLACEHOLDER: the endpoint just returns success for now - Phase 6 wires
// it to a real prevention.unblock_ip() call against iptables.

document.querySelectorAll('.unblock-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
        const row = btn.closest('tr');
        const ip = row.dataset.ip;

        btn.disabled = true;
        btn.textContent = '...';

        try {
            const res = await fetch(`/api/blocked-ips/${ip}`, { method: 'DELETE' });
            if (res.ok) {
                row.style.opacity = '0.4';
                btn.textContent = 'Unblocked';
            } else {
                btn.textContent = 'Failed';
                btn.disabled = false;
            }
        } catch (err) {
            console.error('Unblock failed:', err);
            btn.textContent = 'Failed';
            btn.disabled = false;
        }
    });
});
