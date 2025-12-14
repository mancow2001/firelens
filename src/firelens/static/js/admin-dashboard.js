/**
 * FireLens Admin - Dashboard JavaScript
 * Handles firewall list management functionality
 */

// Configuration - set from template via window.adminDashboardConfig
let csrfToken = '';
let firewallToDelete = null;

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Load configuration from template
    if (window.adminDashboardConfig) {
        csrfToken = window.adminDashboardConfig.csrfToken || '';
    }

    // Set up modal close on overlay click
    const deleteModal = document.getElementById('deleteModal');
    if (deleteModal) {
        deleteModal.addEventListener('click', function(e) {
            if (e.target === this) {
                closeDeleteModal();
            }
        });
    }
});

/**
 * Show toast notification
 */
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast toast-${type} show`;
    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}

/**
 * Toggle firewall enabled/disabled state
 */
function toggleFirewall(name, currentEnabled) {
    fetch(`/admin/api/firewalls/${encodeURIComponent(name)}/toggle`, {
        method: 'POST',
        credentials: 'include',
        headers: {
            'X-CSRF-Token': csrfToken
        }
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.detail || `HTTP ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        if (data.status === 'ok') {
            showToast(data.message);
            setTimeout(() => location.reload(), 1000);
        } else {
            showToast(data.detail || 'Error toggling firewall', 'error');
        }
    })
    .catch(err => {
        showToast(err.message || 'Error toggling firewall', 'error');
    });
}

/**
 * Show delete confirmation modal
 */
function confirmDelete(name) {
    firewallToDelete = name;
    document.getElementById('deleteFirewallName').textContent = name;
    document.getElementById('deleteModal').classList.add('show');
}

/**
 * Close delete confirmation modal
 */
function closeDeleteModal() {
    document.getElementById('deleteModal').classList.remove('show');
    firewallToDelete = null;
}

/**
 * Delete the firewall
 */
function deleteFirewall() {
    if (!firewallToDelete) return;

    fetch(`/admin/api/firewalls/${encodeURIComponent(firewallToDelete)}`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
            'X-CSRF-Token': csrfToken
        }
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(data => {
                throw new Error(data.detail || `HTTP ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        closeDeleteModal();
        if (data.status === 'ok') {
            showToast(data.message);
            setTimeout(() => location.reload(), 1000);
        } else {
            showToast(data.detail || 'Error deleting firewall', 'error');
        }
    })
    .catch(err => {
        closeDeleteModal();
        showToast(err.message || 'Error deleting firewall', 'error');
    });
}
