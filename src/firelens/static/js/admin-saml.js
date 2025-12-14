/**
 * FireLens Admin - SAML/SSO JavaScript
 * Handles SAML configuration functionality
 */

/**
 * Copy metadata URL to clipboard
 */
function copyMetadataUrl() {
    const input = document.getElementById('metadataUrl');
    input.select();
    document.execCommand('copy');
    alert('Metadata URL copied to clipboard!');
}

/**
 * Save SAML configuration
 */
async function saveSamlConfig(event) {
    event.preventDefault();

    const form = document.getElementById('samlConfigForm');
    const formData = new FormData(form);

    // Convert to JSON object
    const config = {
        enabled: document.getElementById('samlEnabled').checked,
        idp_entity_id: formData.get('idp_entity_id') || '',
        idp_sso_url: formData.get('idp_sso_url') || '',
        idp_slo_url: formData.get('idp_slo_url') || '',
        idp_x509_cert: formData.get('idp_x509_cert') || '',
        sp_entity_id: formData.get('sp_entity_id') || '',
        sp_acs_url: formData.get('sp_acs_url') || '',
        sp_slo_url: formData.get('sp_slo_url') || '',
        username_attribute: formData.get('username_attribute') || 'email',
        want_assertions_signed: document.getElementById('wantAssertionsSigned').checked,
        want_response_signed: document.getElementById('wantResponseSigned').checked
    };

    try {
        const response = await fetch('/admin/api/saml/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });

        const result = await response.json();

        if (response.ok) {
            showResult('success', 'Configuration saved successfully! The page will reload.');
            setTimeout(() => window.location.reload(), 1500);
        } else {
            showResult('error', result.detail || 'Failed to save configuration');
        }
    } catch (error) {
        showResult('error', 'Error saving configuration: ' + error.message);
    }
}

/**
 * Test SAML configuration
 */
async function testSamlConfig() {
    showResult('', 'Testing configuration...');

    const form = document.getElementById('samlConfigForm');
    const formData = new FormData(form);

    const config = {
        enabled: document.getElementById('samlEnabled').checked,
        idp_entity_id: formData.get('idp_entity_id') || '',
        idp_sso_url: formData.get('idp_sso_url') || '',
        idp_slo_url: formData.get('idp_slo_url') || '',
        idp_x509_cert: formData.get('idp_x509_cert') || '',
        sp_entity_id: formData.get('sp_entity_id') || '',
        sp_acs_url: formData.get('sp_acs_url') || '',
        sp_slo_url: formData.get('sp_slo_url') || '',
        username_attribute: formData.get('username_attribute') || 'email',
        want_assertions_signed: document.getElementById('wantAssertionsSigned').checked,
        want_response_signed: document.getElementById('wantResponseSigned').checked
    };

    try {
        const response = await fetch('/admin/api/saml/test', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });

        const result = await response.json();

        if (response.ok && result.valid) {
            showResult('success', 'Configuration is valid! ' + (result.message || ''));
        } else {
            showResult('error', result.detail || result.message || 'Configuration validation failed');
        }
    } catch (error) {
        showResult('error', 'Error testing configuration: ' + error.message);
    }
}

/**
 * Show result message
 */
function showResult(type, message) {
    const resultDiv = document.getElementById('testResult');
    resultDiv.className = 'test-result' + (type ? ' ' + type : '');
    resultDiv.textContent = message;
    resultDiv.style.display = 'block';
}
