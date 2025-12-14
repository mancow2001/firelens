/**
 * FireLens Admin - Certificates JavaScript
 * Handles CA certificate management functionality
 */

// Configuration - set from template via window.adminCertificatesConfig
let csrfToken = '';
let selectedCertId = null;
let certToDelete = null;
let certToDeleteSubject = null;

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Load configuration from template
    if (window.adminCertificatesConfig) {
        csrfToken = window.adminCertificatesConfig.csrfToken || '';
    }

    // Set up drag and drop for upload zone
    const uploadZone = document.getElementById('uploadZone');
    if (uploadZone) {
        uploadZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadZone.classList.add('dragover');
        });
        uploadZone.addEventListener('dragleave', () => {
            uploadZone.classList.remove('dragover');
        });
        uploadZone.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadZone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                document.getElementById('certFile').files = files;
                handleFileSelect(document.getElementById('certFile'));
            }
        });
    }

    // Set up upload form submission
    const uploadForm = document.getElementById('uploadForm');
    if (uploadForm) {
        uploadForm.addEventListener('submit', handleUploadSubmit);
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
 * Show upload modal
 */
function showUploadModal() {
    document.getElementById('uploadModal').classList.add('show');
    document.getElementById('uploadForm').reset();
    document.getElementById('selectedFile').style.display = 'none';
    document.getElementById('uploadResult').style.display = 'none';
}

/**
 * Close upload modal
 */
function closeUploadModal() {
    document.getElementById('uploadModal').classList.remove('show');
}

/**
 * Handle file selection
 */
function handleFileSelect(input) {
    if (input.files && input.files[0]) {
        document.getElementById('selectedFileName').textContent = input.files[0].name;
        document.getElementById('selectedFile').style.display = 'block';
        document.getElementById('uploadResult').style.display = 'none';
    }
}

/**
 * Handle upload form submission
 */
async function handleUploadSubmit(e) {
    e.preventDefault();
    const fileInput = document.getElementById('certFile');
    if (!fileInput.files || !fileInput.files[0]) {
        showToast('Please select a file', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    const uploadBtn = document.getElementById('uploadBtn');
    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Uploading...';

    try {
        const response = await fetch('/admin/api/certificates', {
            method: 'POST',
            body: formData,
            credentials: 'include',
            headers: {
                'X-CSRF-Token': csrfToken
            }
        });

        const result = await response.json();
        const resultDiv = document.getElementById('uploadResult');

        if (response.ok && result.status === 'ok') {
            resultDiv.style.display = 'block';
            resultDiv.style.background = 'rgba(39, 174, 96, 0.1)';
            resultDiv.style.border = '1px solid #27ae60';
            resultDiv.innerHTML = `<strong>Success!</strong> ${result.message}`;

            if (result.warning) {
                resultDiv.innerHTML += `<br><small style="color: var(--text-muted);">${result.warning}</small>`;
            }

            showToast(result.message, 'success');
            setTimeout(() => {
                closeUploadModal();
                location.reload();
            }, 1500);
        } else {
            resultDiv.style.display = 'block';
            resultDiv.style.background = 'rgba(231, 76, 60, 0.1)';
            resultDiv.style.border = '1px solid #e74c3c';
            resultDiv.innerHTML = `<strong>Error:</strong> ${result.message || 'Upload failed'}`;
            showToast(result.message || 'Upload failed', 'error');
        }
    } catch (error) {
        showToast('Upload failed: ' + error.message, 'error');
    } finally {
        uploadBtn.disabled = false;
        uploadBtn.textContent = 'Upload';
    }
}

/**
 * Show certificate detail modal
 */
async function showCertDetail(certId) {
    selectedCertId = certId;
    try {
        const response = await fetch(`/admin/api/certificates/${certId}`, {
            credentials: 'include'
        });
        const cert = await response.json();

        if (cert.status === 'error') {
            showToast(cert.message, 'error');
            return;
        }

        const detailsHtml = `
            <div class="cert-detail-row">
                <span class="cert-detail-label">Subject</span>
                <span class="cert-detail-value">${escapeHtml(cert.subject)}</span>
            </div>
            <div class="cert-detail-row">
                <span class="cert-detail-label">Issuer</span>
                <span class="cert-detail-value">${escapeHtml(cert.issuer)}</span>
            </div>
            <div class="cert-detail-row">
                <span class="cert-detail-label">Valid From</span>
                <span class="cert-detail-value">${cert.not_before.replace('T', ' ').substring(0, 19)}</span>
            </div>
            <div class="cert-detail-row">
                <span class="cert-detail-label">Valid Until</span>
                <span class="cert-detail-value">${cert.not_after.replace('T', ' ').substring(0, 19)}
                    ${cert.is_expired ? '<span class="status-badge status-disabled" style="margin-left: 8px;">Expired</span>' :
                      cert.days_until_expiry <= 30 ? `<span class="status-badge status-stopped" style="margin-left: 8px;">${cert.days_until_expiry} days left</span>` : ''}
                </span>
            </div>
            <div class="cert-detail-row">
                <span class="cert-detail-label">Serial Number</span>
                <span class="cert-detail-value fingerprint">${cert.serial_number}</span>
            </div>
            <div class="cert-detail-row">
                <span class="cert-detail-label">SHA-256</span>
                <span class="cert-detail-value fingerprint">${cert.fingerprint_sha256}</span>
            </div>
            <div class="cert-detail-row">
                <span class="cert-detail-label">SHA-1</span>
                <span class="cert-detail-value fingerprint">${cert.fingerprint_sha1}</span>
            </div>
            <div class="cert-detail-row">
                <span class="cert-detail-label">Is CA</span>
                <span class="cert-detail-value">${cert.is_ca ? 'Yes' : 'No'}</span>
            </div>
            <div class="cert-detail-row">
                <span class="cert-detail-label">Filename</span>
                <span class="cert-detail-value">${escapeHtml(cert.filename)}</span>
            </div>
        `;

        document.getElementById('certDetails').innerHTML = detailsHtml;
        document.getElementById('detailModal').classList.add('show');
    } catch (error) {
        showToast('Failed to load certificate details', 'error');
    }
}

/**
 * Close certificate detail modal
 */
function closeDetailModal() {
    document.getElementById('detailModal').classList.remove('show');
    selectedCertId = null;
}

/**
 * Confirm delete from detail modal
 */
function confirmDeleteFromDetail() {
    closeDetailModal();
    // Get cert info for the confirm dialog
    fetch(`/admin/api/certificates/${selectedCertId}`, { credentials: 'include' })
        .then(r => r.json())
        .then(cert => {
            confirmDelete(selectedCertId, cert.subject);
        });
}

/**
 * Show delete confirmation modal
 */
function confirmDelete(certId, subject) {
    certToDelete = certId;
    certToDeleteSubject = subject;
    document.getElementById('deleteCertSubject').textContent = subject;
    document.getElementById('deleteModal').classList.add('show');
}

/**
 * Close delete confirmation modal
 */
function closeDeleteModal() {
    document.getElementById('deleteModal').classList.remove('show');
    certToDelete = null;
    certToDeleteSubject = null;
}

/**
 * Delete certificate
 */
async function deleteCert() {
    if (!certToDelete) return;

    try {
        const response = await fetch(`/admin/api/certificates/${certToDelete}`, {
            method: 'DELETE',
            credentials: 'include',
            headers: {
                'X-CSRF-Token': csrfToken
            }
        });
        const result = await response.json();

        if (response.ok && result.status === 'ok') {
            showToast('Certificate deleted', 'success');
            closeDeleteModal();
            location.reload();
        } else {
            showToast(result.message || 'Delete failed', 'error');
        }
    } catch (error) {
        showToast('Delete failed: ' + error.message, 'error');
    }
}

/**
 * Download certificate
 */
function downloadCert(certId) {
    window.location.href = `/admin/api/certificates/${certId}/download`;
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
