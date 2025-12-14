/**
 * FireLens Admin - SSL/TLS JavaScript
 * Handles SSL certificate management functionality
 */

// Configuration - set from template via window.adminSslConfig
let csrfToken = '';

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Load configuration from template
    if (window.adminSslConfig) {
        csrfToken = window.adminSslConfig.csrfToken || '';
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
 * Generate a new self-signed certificate
 */
function generateSelfSigned() {
    if (!confirm('This will generate a new self-signed certificate, replacing any existing certificate. Continue?')) {
        return;
    }

    fetch('/admin/api/ssl/generate', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({ csrf_token: csrfToken })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message);
            setTimeout(() => location.reload(), 1500);
        } else {
            showToast(data.message || 'Error generating certificate', 'error');
        }
    })
    .catch(err => {
        showToast('Error generating certificate', 'error');
    });
}

/**
 * Delete the current certificate
 */
function deleteCertificate() {
    if (!confirm('This will delete the current SSL certificate. A new self-signed certificate will be generated on service restart. Continue?')) {
        return;
    }

    fetch('/admin/api/ssl/certificate', {
        method: 'DELETE',
        credentials: 'include',
        headers: {
            'X-CSRF-Token': csrfToken
        }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message);
            setTimeout(() => location.reload(), 1500);
        } else {
            showToast(data.message || 'Error deleting certificate', 'error');
        }
    })
    .catch(err => {
        showToast('Error deleting certificate', 'error');
    });
}

/**
 * Upload a custom certificate
 */
function uploadCertificate(event) {
    event.preventDefault();

    const certificate = document.getElementById('certificate').value.trim();
    const privateKey = document.getElementById('private_key').value.trim();

    if (!certificate || !privateKey) {
        showToast('Please provide both certificate and private key', 'error');
        return;
    }

    fetch('/admin/api/ssl/upload', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        body: JSON.stringify({
            certificate: certificate,
            private_key: privateKey,
            csrf_token: csrfToken
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message);
            setTimeout(() => location.reload(), 1500);
        } else {
            showToast(data.message || 'Error uploading certificate', 'error');
        }
    })
    .catch(err => {
        showToast('Error uploading certificate', 'error');
    });
}

/**
 * Clear the upload form
 */
function clearForm() {
    document.getElementById('certificate').value = '';
    document.getElementById('private_key').value = '';
}
