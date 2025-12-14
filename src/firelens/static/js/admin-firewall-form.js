/**
 * FireLens Admin - Firewall Form JavaScript
 * Handles firewall add/edit form functionality
 */

// Configuration - set from template via window.firewallFormConfig
let isEdit = false;
let firewallName = '';
let originalName = '';
let csrfToken = '';
let interfaceConfigs = [];
let vendorType = 'palo_alto';
let vdom = 'root';

// Duplicate name check state
let nameCheckTimeout = null;
let nameIsDuplicate = false;

// Rename task state
let renameEstimate = null;
let renamePollingInterval = null;

/**
 * Initialize the form on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Load configuration from template
    if (window.firewallFormConfig) {
        isEdit = window.firewallFormConfig.isEdit || false;
        firewallName = window.firewallFormConfig.firewallName || '';
        originalName = window.firewallFormConfig.originalName || '';
        csrfToken = window.firewallFormConfig.csrfToken || '';
        interfaceConfigs = window.firewallFormConfig.interfaceConfigs || [];
        vendorType = window.firewallFormConfig.vendorType || 'palo_alto';
        vdom = window.firewallFormConfig.vdom || 'root';
    }

    // Initialize interface configuration visibility
    toggleInterfaceConfig();

    // Initialize vendor-specific field visibility
    onVendorTypeChange();

    // Render interface table if we have configs
    if (interfaceConfigs.length > 0) {
        renderInterfaceTable();
    }

    // Set up name field listener for duplicate checking
    const nameInput = document.getElementById('name');
    if (nameInput) {
        nameInput.addEventListener('input', function() {
            checkNameChange();
            checkDuplicateName();
        });
    }
});

/**
 * Check if name has changed (for rename warning in edit mode)
 */
function checkNameChange() {
    const nameInput = document.getElementById('name');
    const currentName = nameInput.value.trim();

    if (isEdit && currentName !== originalName && currentName.length > 0) {
        // Fetch rename estimate from server
        checkRenameEstimate(currentName);
    } else {
        hideRenameWarning();
        renameEstimate = null;
    }
}

/**
 * Fetch rename estimate from server
 */
async function checkRenameEstimate(newName) {
    if (!isEdit || !originalName) return;

    try {
        const response = await fetch(`/admin/api/firewalls/${encodeURIComponent(originalName)}/rename-estimate`, {
            credentials: 'include'
        });

        if (!response.ok) return;

        const data = await response.json();
        renameEstimate = data;
        showRenameWarning(data);
    } catch (error) {
        console.error('Error checking rename estimate:', error);
    }
}

/**
 * Show rename warning with estimate
 */
function showRenameWarning(estimate) {
    const warning = document.getElementById('renameWarning');
    if (!warning) return;

    const totalRows = estimate.total_rows.toLocaleString();
    const estTime = estimate.estimated_seconds;

    let message = `Renaming will update ${totalRows} historical records.`;
    if (estTime > 5) {
        message += ` Estimated time: ~${Math.ceil(estTime)} seconds.`;
        message += ` <em>This will run in the background.</em>`;
    }

    warning.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="width: 16px; height: 16px; flex-shrink: 0;">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>${message}</div>
    `;
    warning.style.display = 'flex';
}

/**
 * Hide rename warning
 */
function hideRenameWarning() {
    const warning = document.getElementById('renameWarning');
    if (warning) {
        warning.style.display = 'none';
    }
}

/**
 * Check if firewall name already exists (debounced API call)
 */
function checkDuplicateName() {
    const nameInput = document.getElementById('name');
    const name = nameInput.value.trim();

    // Clear previous timeout
    clearTimeout(nameCheckTimeout);

    // Skip check if empty, invalid format, or same as original in edit mode
    if (!name || (isEdit && name === originalName)) {
        hideDuplicateWarning();
        nameIsDuplicate = false;
        return;
    }

    // Validate format first
    if (!/^[a-zA-Z0-9_]+$/.test(name)) {
        hideDuplicateWarning();
        nameIsDuplicate = false;
        return;
    }

    // Debounce the API call
    nameCheckTimeout = setTimeout(async () => {
        try {
            const response = await fetch(`/admin/api/firewalls/check-name?name=${encodeURIComponent(name)}`, {
                credentials: 'include'
            });
            const data = await response.json();

            if (data.exists) {
                showDuplicateWarning();
                nameIsDuplicate = true;
            } else {
                hideDuplicateWarning();
                nameIsDuplicate = false;
            }
        } catch (error) {
            console.error('Error checking firewall name:', error);
            hideDuplicateWarning();
            nameIsDuplicate = false;
        }
    }, 300);
}

/**
 * Show duplicate name warning
 */
function showDuplicateWarning() {
    let warningEl = document.getElementById('duplicateWarning');
    if (!warningEl) {
        // Create the warning element if it doesn't exist
        const nameInput = document.getElementById('name');
        warningEl = document.createElement('div');
        warningEl.id = 'duplicateWarning';
        warningEl.className = 'rename-warning';
        warningEl.style.background = 'var(--error-bg, #fee2e2)';
        warningEl.style.color = 'var(--error-text, #dc2626)';
        warningEl.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" style="width: 16px; height: 16px; flex-shrink: 0;">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            A firewall with this name already exists.
        `;
        nameInput.parentNode.appendChild(warningEl);
    }
    warningEl.style.display = 'flex';
}

/**
 * Hide duplicate name warning
 */
function hideDuplicateWarning() {
    const warningEl = document.getElementById('duplicateWarning');
    if (warningEl) {
        warningEl.style.display = 'none';
    }
}

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
 * Show error message
 */
function showError(message) {
    const errorEl = document.getElementById('errorMessage');
    errorEl.textContent = message;
    errorEl.classList.add('show');
}

/**
 * Hide error message
 */
function hideError() {
    document.getElementById('errorMessage').classList.remove('show');
}

/**
 * Toggle visibility of interface configuration vs exclusion sections
 */
function toggleInterfaceConfig() {
    const autoDiscover = document.getElementById('auto_discover_interfaces').checked;
    const excludeSection = document.getElementById('excludeSection');
    const configSection = document.getElementById('interfaceConfigSection');

    if (autoDiscover) {
        excludeSection.style.display = 'block';
        configSection.classList.add('hidden');
    } else {
        excludeSection.style.display = 'none';
        configSection.classList.remove('hidden');
    }
}

/**
 * Handle vendor type change - show/hide vendor-specific fields
 */
function onVendorTypeChange() {
    const typeSelect = document.getElementById('type');
    const selectedType = typeSelect ? typeSelect.value : vendorType;
    vendorType = selectedType;

    // Get field elements
    const usernameInput = document.getElementById('username');
    const usernameGroup = document.getElementById('usernameGroup');
    const passwordLabel = document.getElementById('passwordLabel');
    const passwordHelp = document.getElementById('passwordHelp');
    const vdomGroup = document.getElementById('vdomGroup');
    const dpAggregationGroup = document.getElementById('dpAggregationGroup');

    // Reset to defaults first (show username, require it)
    if (usernameGroup) usernameGroup.style.display = 'block';
    if (usernameInput) usernameInput.required = true;
    if (passwordLabel) passwordLabel.innerHTML = 'Password <span class="required">*</span>';
    if (passwordHelp) passwordHelp.textContent = '';
    if (vdomGroup) vdomGroup.style.display = 'none';
    if (dpAggregationGroup) dpAggregationGroup.style.display = 'block';

    // Apply vendor-specific settings
    if (selectedType === 'fortinet') {
        // Fortinet: Hide username entirely, password is API token, show VDOM
        if (usernameGroup) usernameGroup.style.display = 'none';
        if (usernameInput) {
            usernameInput.required = false;
            usernameInput.value = '';
        }
        if (passwordLabel) passwordLabel.innerHTML = 'API Token <span class="required">*</span>';
        if (passwordHelp) passwordHelp.textContent = 'REST API token from FortiGate';
        if (vdomGroup) vdomGroup.style.display = 'block';
        if (dpAggregationGroup) dpAggregationGroup.style.display = 'none';
    } else if (selectedType === 'cisco_firepower') {
        // Cisco Firepower: Hide DP aggregation (not applicable)
        if (dpAggregationGroup) dpAggregationGroup.style.display = 'none';
    }
    // Palo Alto uses all defaults
}

/**
 * Discover interfaces from the firewall
 */
function discoverInterfaces() {
    const host = document.getElementById('host').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const type = document.getElementById('type').value;
    const verify_ssl = document.getElementById('verify_ssl').checked;
    const vdomInput = document.getElementById('vdom');
    const vdomValue = vdomInput ? vdomInput.value : 'root';

    // Fortinet doesn't require username (uses API token)
    const requiresUsername = type !== 'fortinet';
    if (!host || (requiresUsername && !username) || !password) {
        const msg = type === 'fortinet'
            ? 'Please fill in Host and API Token first'
            : 'Please fill in Host, Username, and Password first';
        showToast(msg, 'error');
        return;
    }

    // Show loading state
    const btn = document.querySelector('.btn-discover');
    const btnText = document.getElementById('discoverBtnText');
    const spinner = document.getElementById('discoverSpinner');
    const resultDiv = document.getElementById('discoverResult');

    btn.disabled = true;
    btnText.textContent = 'Discovering...';
    spinner.style.display = 'inline-block';
    resultDiv.className = 'discover-result';
    resultDiv.innerHTML = '';

    fetch('/admin/api/discover-interfaces', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        credentials: 'include',
        body: JSON.stringify({
            host: host,
            username: username,
            password: password,
            type: type,
            verify_ssl: verify_ssl,
            vdom: vdomValue,
            csrf_token: csrfToken
        })
    })
    .then(response => response.json())
    .then(data => {
        btn.disabled = false;
        btnText.textContent = 'Discover Interfaces';
        spinner.style.display = 'none';

        if (data.success) {
            resultDiv.className = 'discover-result success show';
            resultDiv.innerHTML = data.message;

            if (data.interfaces && data.interfaces.length > 0) {
                // Merge discovered interfaces with existing configs
                mergeInterfaceConfigs(data.interfaces);
                renderInterfaceTable();
            }
        } else {
            resultDiv.className = 'discover-result error show';
            resultDiv.innerHTML = data.message;
        }
    })
    .catch(error => {
        btn.disabled = false;
        btnText.textContent = 'Discover Interfaces';
        spinner.style.display = 'none';

        resultDiv.className = 'discover-result error show';
        resultDiv.innerHTML = 'Error: ' + error.message;
    });
}

/**
 * Merge newly discovered interfaces with existing configurations
 */
function mergeInterfaceConfigs(newInterfaces) {
    const existingNames = new Set(interfaceConfigs.map(i => i.name));

    for (const iface of newInterfaces) {
        if (!existingNames.has(iface.name)) {
            interfaceConfigs.push({
                name: iface.name,
                display_name: iface.display_name,
                enabled: true,
                description: ''
            });
        }
    }

    // Sort interfaces by name
    interfaceConfigs.sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Render the interface configuration table
 */
function renderInterfaceTable() {
    const tbody = document.getElementById('interfaceTableBody');
    const table = document.getElementById('interfaceTable');
    const empty = document.getElementById('interfaceEmpty');
    const countEl = document.getElementById('interfaceCount');

    if (interfaceConfigs.length === 0) {
        table.style.display = 'none';
        empty.style.display = 'block';
        countEl.textContent = '';
        return;
    }

    table.style.display = 'table';
    empty.style.display = 'none';

    const enabledCount = interfaceConfigs.filter(i => i.enabled).length;
    countEl.textContent = `${enabledCount} of ${interfaceConfigs.length} interfaces enabled`;

    tbody.innerHTML = '';

    for (let i = 0; i < interfaceConfigs.length; i++) {
        const iface = interfaceConfigs[i];
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>
                <input type="checkbox"
                       ${iface.enabled ? 'checked' : ''}
                       onchange="updateInterfaceEnabled(${i}, this.checked)">
            </td>
            <td class="interface-name">${escapeHtml(iface.name)}</td>
            <td>
                <input type="text"
                       value="${escapeHtml(iface.display_name)}"
                       placeholder="Display name"
                       onchange="updateInterfaceDisplayName(${i}, this.value)">
            </td>
            <td>
                <input type="text"
                       value="${escapeHtml(iface.description || '')}"
                       placeholder="Description (optional)"
                       onchange="updateInterfaceDescription(${i}, this.value)">
            </td>
        `;
        tbody.appendChild(row);
    }

    updateSelectAllState();
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Update interface enabled state
 */
function updateInterfaceEnabled(index, enabled) {
    interfaceConfigs[index].enabled = enabled;
    updateInterfaceCount();
    updateSelectAllState();
}

/**
 * Update interface display name
 */
function updateInterfaceDisplayName(index, name) {
    interfaceConfigs[index].display_name = name;
}

/**
 * Update interface description
 */
function updateInterfaceDescription(index, desc) {
    interfaceConfigs[index].description = desc;
}

/**
 * Update interface count display
 */
function updateInterfaceCount() {
    const countEl = document.getElementById('interfaceCount');
    const enabledCount = interfaceConfigs.filter(i => i.enabled).length;
    countEl.textContent = `${enabledCount} of ${interfaceConfigs.length} interfaces enabled`;
}

/**
 * Toggle all interfaces selection
 */
function toggleSelectAll() {
    const selectAll = document.getElementById('selectAll');
    const checked = selectAll.checked;

    for (let i = 0; i < interfaceConfigs.length; i++) {
        interfaceConfigs[i].enabled = checked;
    }

    renderInterfaceTable();
}

/**
 * Update select all checkbox state
 */
function updateSelectAllState() {
    const selectAll = document.getElementById('selectAll');
    const allEnabled = interfaceConfigs.every(i => i.enabled);
    const someEnabled = interfaceConfigs.some(i => i.enabled);

    selectAll.checked = allEnabled;
    selectAll.indeterminate = someEnabled && !allEnabled;
}

/**
 * Test connection to firewall
 */
function testConnection() {
    const host = document.getElementById('host').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const type = document.getElementById('type').value;
    const verify_ssl = document.getElementById('verify_ssl').checked;
    const vdomInput = document.getElementById('vdom');
    const vdomValue = vdomInput ? vdomInput.value : 'root';

    // Fortinet doesn't require username (uses API token)
    const requiresUsername = type !== 'fortinet';
    if (!host || (requiresUsername && !username) || !password) {
        const msg = type === 'fortinet'
            ? 'Please fill in Host and API Token first'
            : 'Please fill in Host, Username, and Password first';
        showToast(msg, 'error');
        return;
    }

    // Show loading state
    const btn = document.querySelector('.btn-test');
    const btnText = document.getElementById('testBtnText');
    const spinner = document.getElementById('testSpinner');
    const resultDiv = document.getElementById('testResult');

    btn.disabled = true;
    btnText.textContent = 'Testing...';
    spinner.style.display = 'inline-block';
    resultDiv.className = 'test-result';
    resultDiv.innerHTML = '';

    fetch('/admin/api/test-connection', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        credentials: 'include',
        body: JSON.stringify({
            host: host,
            username: username,
            password: password,
            type: type,
            verify_ssl: verify_ssl,
            vdom: vdomValue,
            csrf_token: csrfToken
        })
    })
    .then(response => response.json())
    .then(data => {
        btn.disabled = false;
        btnText.textContent = 'Test Connection';
        spinner.style.display = 'none';

        if (data.success) {
            resultDiv.className = 'test-result success show';
            let html = '<h4>Connection Successful</h4>';
            html += '<p>' + data.message + '</p>';

            if (data.details && Object.keys(data.details).length > 0) {
                html += '<div class="details"><table>';
                if (data.details.hostname) html += '<tr><td>Hostname</td><td>' + data.details.hostname + '</td></tr>';
                if (data.details.model) html += '<tr><td>Model</td><td>' + data.details.model + '</td></tr>';
                if (data.details.serial) html += '<tr><td>Serial</td><td>' + data.details.serial + '</td></tr>';
                if (data.details.sw_version) html += '<tr><td>Software</td><td>' + data.details.sw_version + '</td></tr>';
                if (data.details.uptime) html += '<tr><td>Uptime</td><td>' + data.details.uptime + '</td></tr>';
                html += '</table></div>';
            }
            resultDiv.innerHTML = html;
        } else {
            resultDiv.className = 'test-result error show';
            resultDiv.innerHTML = '<h4>Connection Failed</h4><p>' + data.message + '</p>';
        }
    })
    .catch(error => {
        btn.disabled = false;
        btnText.textContent = 'Test Connection';
        spinner.style.display = 'none';

        resultDiv.className = 'test-result error show';
        resultDiv.innerHTML = '<h4>Error</h4><p>' + error.message + '</p>';
    });
}

/**
 * Submit the firewall form
 */
async function submitForm(event) {
    event.preventDefault();
    hideError();

    // Check for duplicate name
    if (nameIsDuplicate) {
        showError('A firewall with this name already exists. Please choose a different name.');
        return;
    }

    const form = document.getElementById('firewallForm');
    const formData = new FormData(form);
    const newName = formData.get('name').trim();
    const autoDiscover = formData.has('auto_discover_interfaces');

    // Check if this is a rename operation
    if (isEdit && newName !== originalName) {
        // Confirm rename
        const totalRows = renameEstimate ? renameEstimate.total_rows.toLocaleString() : 'unknown';
        if (!confirm(`Are you sure you want to rename this firewall from "${originalName}" to "${newName}"?\n\nThis will update ${totalRows} historical records.`)) {
            return;
        }

        // Use background rename task for rename operations
        try {
            const taskId = await startRenameTask(newName);
            startRenamePolling(taskId, formData, autoDiscover);
            return; // Don't continue with normal form submission
        } catch (error) {
            showError(error.message);
            return;
        }
    }

    // Normal form submission (add or update without rename)
    submitFormData(formData, autoDiscover);
}

/**
 * Start a background rename task
 */
async function startRenameTask(newName) {
    const response = await fetch(`/admin/api/firewalls/${encodeURIComponent(originalName)}/rename`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken
        },
        credentials: 'include',
        body: JSON.stringify({
            new_name: newName,
            csrf_token: csrfToken
        })
    });

    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.detail || 'Failed to start rename');
    }

    return data.task_id;
}

/**
 * Poll rename task status and update progress modal
 */
function startRenamePolling(taskId, formData, autoDiscover) {
    showProgressModal();

    renamePollingInterval = setInterval(async () => {
        try {
            const response = await fetch(`/admin/api/rename-tasks/${taskId}`, {
                credentials: 'include'
            });
            const status = await response.json();

            updateProgressModal(status);

            if (status.status === 'completed') {
                clearInterval(renamePollingInterval);

                // Now update the other firewall settings
                const newName = formData.get('name').trim();

                // Update form data to use new name for the update call
                firewallName = newName;

                // Submit remaining form data to update other settings
                await submitFormData(formData, autoDiscover, newName);

                hideProgressModal();
                showToast('Firewall renamed successfully');
                setTimeout(() => {
                    window.location.href = '/admin';
                }, 1500);
            } else if (status.status === 'failed') {
                clearInterval(renamePollingInterval);
                hideProgressModal();
                showError(status.error_message || 'Rename failed');
            }
        } catch (error) {
            console.error('Error polling rename status:', error);
        }
    }, 1000);
}

/**
 * Show progress modal
 */
function showProgressModal() {
    let modal = document.getElementById('renameProgressModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'renameProgressModal';
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal" style="max-width: 400px;">
                <h3>Renaming Firewall</h3>
                <div class="progress-container" style="margin: 20px 0;">
                    <div class="progress-bar" style="width: 100%; height: 20px; background: var(--bg-secondary); border-radius: 10px; overflow: hidden;">
                        <div id="renameProgressBar" style="height: 100%; background: #3498db; width: 0%; transition: width 0.3s;"></div>
                    </div>
                    <p id="renameProgressText" style="text-align: center; margin-top: 10px; color: var(--text-secondary);">Starting...</p>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    }
    modal.classList.add('show');
}

/**
 * Update progress modal with current status
 */
function updateProgressModal(status) {
    const progressBar = document.getElementById('renameProgressBar');
    const progressText = document.getElementById('renameProgressText');

    if (progressBar && progressText) {
        progressBar.style.width = `${status.progress_percent}%`;

        const tableName = status.current_table ? status.current_table.replace('_', ' ') : '';
        progressText.textContent = `${status.progress_percent}% - Processing ${tableName}...`;
    }
}

/**
 * Hide progress modal
 */
function hideProgressModal() {
    const modal = document.getElementById('renameProgressModal');
    if (modal) {
        modal.classList.remove('show');
    }
}

/**
 * Submit form data to server
 */
async function submitFormData(formData, autoDiscover, overrideName = null) {
    const name = overrideName || formData.get('name').trim();

    // Build JSON data
    // Read checkboxes directly from DOM for reliable boolean values
    const firewallType = formData.get('type');
    const data = {
        name: name,
        host: formData.get('host'),
        username: formData.get('username'),
        password: formData.get('password'),
        type: firewallType,
        enabled: document.getElementById('enabled').checked,
        verify_ssl: document.getElementById('verify_ssl').checked,
        poll_interval: parseInt(formData.get('poll_interval')) || 60,
        dp_aggregation: formData.get('dp_aggregation'),
        interface_monitoring: document.getElementById('interface_monitoring').checked,
        auto_discover_interfaces: autoDiscover,
        exclude_interfaces: formData.get('exclude_interfaces')
    };

    // Add vendor-specific fields
    if (firewallType === 'fortinet') {
        data.vdom = formData.get('vdom') || 'root';
    }

    // Include interface_configs when not using auto-discover
    if (!autoDiscover && interfaceConfigs.length > 0) {
        data.interface_configs = interfaceConfigs;
    }

    // Add CSRF token
    data.csrf_token = csrfToken;

    // Use the override name for the URL if provided (after rename)
    const urlName = overrideName || firewallName;
    const url = isEdit ? `/admin/api/firewalls/${encodeURIComponent(urlName)}` : '/admin/api/firewalls';
    const method = isEdit ? 'PUT' : 'POST';

    try {
        const response = await fetch(url, {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify(data)
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'An error occurred');
        }

        const result = await response.json();

        // Only show toast and redirect if not part of rename flow
        if (!overrideName) {
            showToast(result.message);
            setTimeout(() => {
                window.location.href = '/admin';
            }, 1000);
        }

        return result;
    } catch (err) {
        const message = err.message || 'An error occurred';
        showError(message);
        throw err;
    }
}
