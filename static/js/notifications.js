// notifications.js
// -----------------
// Bell icon dropdown, loaded on every dashboard page. Polls /api/notifications
// every 15s for an updated unread count, and lets the user open the dropdown,
// mark one as read (by clicking it) or mark everything read at once.

(function () {
    const bellBtn = document.getElementById('notif-bell-btn');
    const dropdown = document.getElementById('notif-dropdown');
    const badge = document.getElementById('notif-badge');
    const list = document.getElementById('notif-list');
    const markAllBtn = document.getElementById('notif-mark-all-btn');

    if (!bellBtn) return; // not logged in / bell not rendered on this page

    let isOpen = false;

    function timeAgo(isoString) {
        const diff = (Date.now() - new Date(isoString).getTime()) / 1000;
        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
    }

    async function refresh() {
        try {
            const res = await fetch('/api/notifications');
            const data = await res.json();

            if (data.unread_count > 0) {
                badge.style.display = 'flex';
                badge.textContent = data.unread_count > 9 ? '9+' : data.unread_count;
            } else {
                badge.style.display = 'none';
            }

            if (isOpen) renderList(data.notifications);
        } catch (err) {
            console.error('Failed to load notifications:', err);
        }
    }

    function renderList(notifications) {
        if (!notifications || notifications.length === 0) {
            list.innerHTML = '<p class="notif-empty">No notifications yet.</p>';
            return;
        }
        list.innerHTML = notifications.map(n => `
            <div class="notif-item ${n.is_read ? '' : 'unread'}" data-id="${n.notification_id}">
                ${n.message}
                <span class="notif-time">${timeAgo(n.created_at)}</span>
            </div>
        `).join('');

        list.querySelectorAll('.notif-item.unread').forEach(el => {
            el.addEventListener('click', async () => {
                await fetch(`/api/notifications/${el.dataset.id}/read`, { method: 'POST' });
                el.classList.remove('unread');
                refresh();
            });
        });
    }

    bellBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        isOpen = !isOpen;
        dropdown.style.display = isOpen ? 'flex' : 'none';
        if (isOpen) {
            list.innerHTML = '<p class="notif-empty">Loading...</p>';
            const res = await fetch('/api/notifications');
            const data = await res.json();
            renderList(data.notifications);
        }
    });

    document.addEventListener('click', (e) => {
        if (isOpen && !dropdown.contains(e.target) && e.target !== bellBtn) {
            isOpen = false;
            dropdown.style.display = 'none';
        }
    });

    markAllBtn.addEventListener('click', async () => {
        await fetch('/api/notifications/read-all', { method: 'POST' });
        refresh();
    });

    refresh();
    setInterval(refresh, 15000);
})();