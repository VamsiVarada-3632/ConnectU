/**
 * ConnectU Social Features JavaScript
 * Handles AJAX requests for friend requests, unfriending, etc.
 */

/**
 * Get CSRF token from meta tag
 */
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

/**
 * Send a friend request
 * @param {number} userId - The ID of the user to send a request to
 */
function sendFriendRequest(userId) {
    fetch(`/api/friend-request/send/${userId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                // Update UI
                const btn = document.querySelector(`[onclick="sendFriendRequest('${userId}')"]`);
                if (btn) {
                    btn.innerHTML = 'Request Sent';
                    btn.disabled = true;
                    btn.classList.replace('btn-primary', 'btn-outline');
                }
            } else {
                showNotification(data.error || 'Failed to send request', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('An error occurred', 'error');
        });
}

/**
 * Accept a friend request
 * @param {number} userId - The ID of the user who sent the request
 * @param {number} requestId - The ID of the friendship record
 * @param {number} notificationId - Optional ID of the associated notification
 */
function acceptFriendRequest(userId, requestId, notificationId = null) {
    fetch(`/api/friend-request/accept/${requestId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                // Remove the notification or request card
                const idToRemove = notificationId || requestId;
                const notification = document.getElementById(`notification-${idToRemove}`);
                if (notification) notification.remove();

                const requestCard = document.getElementById(`request-${requestId}`);
                if (requestCard) requestCard.remove();

                // Reload if on friends page to show in "All Friends"
                if (window.location.pathname.includes('/friends')) {
                    window.location.reload();
                }
            } else {
                showNotification(data.error || 'Failed to accept request', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('An error occurred', 'error');
        });
}

/**
 * Reject a friend request
 * @param {number} userId - The ID of the user who sent the request
 * @param {number} requestId - The ID of the friendship record
 * @param {number} notificationId - Optional ID of the associated notification
 */
function rejectFriendRequest(userId, requestId, notificationId = null) {
    fetch(`/api/friend-request/reject/${requestId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                // Remove the notification or request card
                const idToRemove = notificationId || requestId;
                const notification = document.getElementById(`notification-${idToRemove}`);
                if (notification) notification.remove();

                const requestCard = document.getElementById(`request-${requestId}`);
                if (requestCard) requestCard.remove();
            } else {
                showNotification(data.error || 'Failed to reject request', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('An error occurred', 'error');
        });
}

/**
 * Unfriend a user
 * @param {number} userId - The ID of the user to unfriend
 */
function unfriend(userId) {
    if (!confirm('Are you sure you want to remove this friend?')) return;

    fetch(`/api/unfriend/${userId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                // Remove the friend card
                const friendCard = document.getElementById(`friend-card-${userId}`);
                if (friendCard) friendCard.remove();
            } else {
                showNotification(data.error || 'Failed to unfriend', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('An error occurred', 'error');
        });
}

/**
 * Cancel a sent friend request
 * @param {number} requestId - The ID of the friendship record
 */
function cancelFriendRequest(requestId) {
    fetch(`/api/friend-request/cancel/${requestId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        }
    })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showNotification(data.message, 'success');
                const sentRequestCard = document.getElementById(`sent-request-${requestId}`);
                if (sentRequestCard) sentRequestCard.remove();
            } else {
                showNotification(data.error || 'Failed to cancel request', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('An error occurred', 'error');
        });
}

/**
 * Simple notification helper
 */
function showNotification(message, type = 'success') {
    // Check if there's a toast container, if not create one
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.position = 'fixed';
        container.style.bottom = '20px';
        container.style.right = '20px';
        container.style.zIndex = '9999';
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.style.padding = '12px 24px';
    toast.style.marginBottom = '10px';
    toast.style.borderRadius = '8px';
    toast.style.color = '#fff';
    toast.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
    toast.style.transition = 'all 0.3s ease';
    toast.style.backgroundColor = type === 'success' ? '#10b981' : '#ef4444';
    toast.innerText = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}


/**
 * Toggle like for a post
 * @param {number} postId - The ID of the post
 */
function likePost(postId) {
    const btn = document.getElementById(`like-btn-${postId}`);
    if (!btn) return;
    
    // Check if guest (modal is shown by base.html listener)
    if (document.body.classList.contains('user-role-guest')) return;

    fetch(`/api/post/like/${postId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            if (data.action === 'liked') {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
            // Update like count text (assuming it's in a sibling or defined parent)
            const stats = btn.closest('.post-card').querySelector('.post-stats span:first-child');
            if (stats) stats.innerText = `${data.likes_count} likes`;
        } else {
            showNotification(data.error || 'Failed to update like', 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('An error occurred', 'error');
    });
}

/**
 * Toggle comments section visibility
 * @param {number} postId - The ID of the post
 */
function toggleComments(postId) {
    const section = document.getElementById(`comments-${postId}`);
    if (section) {
        section.style.display = section.style.display === 'none' ? 'block' : 'none';
        if (section.style.display === 'block') {
            document.getElementById(`comment-input-${postId}`).focus();
        }
    }
}

/**
 * Submit a new comment
 * @param {number} postId - The ID of the post
 */
function submitComment(postId) {
    const input = document.getElementById(`comment-input-${postId}`);
    const content = input.value.trim();
    if (!content) return;

    fetch(`/api/post/comment/${postId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        },
        body: JSON.stringify({ content: content })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            input.value = '';
            // Append new comment to the list
            const list = document.getElementById(`comments-list-${postId}`);
            const item = document.createElement('div');
            item.className = 'comment-item';
            item.innerHTML = `
                <strong>${data.comment.user_name}</strong>
                <p>${data.comment.content}</p>
                <span class="comment-time">just now</span>
            `;
            list.appendChild(item);
            
            // Update counts
            const stats = input.closest('.post-card').querySelector('.post-stats span:nth-child(2)');
            if (stats) stats.innerText = `${data.comments_count} comments`;
            
            showNotification('Comment posted!', 'success');
        } else {
            showNotification(data.error || 'Failed to post comment', 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('An error occurred', 'error');
    });
}

/**
 * Toggle post options menu
 */
function togglePostMenu(postId) {
    const menu = document.getElementById(`post-menu-${postId}`);
    if (menu) menu.classList.toggle('show');
}

/**
 * Delete a post
 */
function deletePost(postId) {
    if (!confirm('Are you sure you want to delete this post? This action cannot be undone.')) return;

    fetch(`/api/post/delete/${postId}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': getCsrfToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Post deleted successfully', 'success');
            const post = document.getElementById(`post-${postId}`);
            if (post) {
                post.style.opacity = '0';
                post.style.transform = 'scale(0.9)';
                setTimeout(() => post.remove(), 300);
            }
        } else {
            showNotification(data.error || 'Failed to delete post', 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('An error occurred', 'error');
    });
}

// Close dropdowns when clicking outside
window.addEventListener('click', function(e) {
    if (!e.target.closest('.post-options-dropdown')) {
        document.querySelectorAll('.post-dropdown-content.show').forEach(menu => {
            menu.classList.remove('show');
        });
    }
});
