/**
 * dynamic_updates.js
 * Handles real-time updates for badges and counts across the application.
 */
document.addEventListener('DOMContentLoaded', () => {
    function updateCounts() {
        console.log('Fetching dynamic updates...');
        fetch('/api/counts')
            .then(response => {
                if (!response.ok) throw new Error('Network response was not ok');
                return response.json();
            })
            .then(data => {
                if (data.success) {
                    // Update Sidebar Badges
                    updateBadge('badge-notifications', data.notifications);
                    updateBadge('badge-messages', data.messages);
                    updateBadge('badge-friend-requests', data.friend_requests);

                    // Update Friends Dashboard Tabs (if on friends page)
                    updateDashboardCount('count-friends', data.friends);
                    updateDashboardCount('count-friend-requests', data.friend_requests);
                    updateDashboardCount('count-sent-requests', data.sent_requests);
                }
            })
            .catch(error => {
                // Silently fail to avoid console clutter in production, 
                // but logging for now to verify implementation
                console.debug('Count update failed:', error);
            });
    }

    /**
     * Updates a badge element with the given count.
     * Hides the badge if count is 0.
     */
    function updateBadge(id, count) {
        const badge = document.getElementById(id);
        if (badge) {
            if (count > 0) {
                badge.textContent = count;
                badge.style.display = 'flex';

                // Add a subtle animation if the count increased
                const oldCount = parseInt(badge.dataset.oldCount || '0');
                if (count > oldCount) {
                    badge.classList.add('badge-pulse');
                    setTimeout(() => badge.classList.remove('badge-pulse'), 1000);
                }
                badge.dataset.oldCount = count;
            } else {
                badge.style.display = 'none';
                badge.dataset.oldCount = '0';
            }
        }
    }

    /**
     * Updates a generic count element (e.g., in a dashboard tab)
     */
    function updateDashboardCount(id, count) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = count;
        }
    }

    // Initial update
    updateCounts();

    // Poll every 10 seconds for general metrics
    // Chat polling is handled separately and more frequently in chat.html
    setInterval(updateCounts, 10000);
});
