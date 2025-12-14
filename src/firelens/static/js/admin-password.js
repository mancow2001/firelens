/**
 * FireLens Admin - Password JavaScript
 * Handles password change functionality
 */

// Configuration - set from template via window.adminPasswordConfig
let MIN_LENGTH = 12;

/**
 * Initialize on page load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Load configuration from template
    if (window.adminPasswordConfig) {
        MIN_LENGTH = window.adminPasswordConfig.minLength || 12;
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
 * Show error message
 */
function showError(message) {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.textContent = message;
    errorDiv.classList.add('show');
}

/**
 * Hide error message
 */
function hideError() {
    const errorDiv = document.getElementById('errorMessage');
    errorDiv.classList.remove('show');
}

/**
 * Toggle password visibility
 */
function togglePasswordVisibility(inputId, button) {
    const input = document.getElementById(inputId);
    const eyeIcon = button.querySelector('.eye-icon');
    const eyeOffIcon = button.querySelector('.eye-off-icon');

    if (input.type === 'password') {
        input.type = 'text';
        eyeIcon.style.display = 'none';
        eyeOffIcon.style.display = 'block';
    } else {
        input.type = 'password';
        eyeIcon.style.display = 'block';
        eyeOffIcon.style.display = 'none';
    }
}

/**
 * Check password strength
 */
function checkPasswordStrength() {
    const password = document.getElementById('new_password').value;
    const strengthBar = document.getElementById('strengthBar');
    const strengthText = document.getElementById('strengthText');

    // Check each requirement
    const hasLength = password.length >= MIN_LENGTH;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{}|;':",./<>?`~]/.test(password);

    // Update requirement indicators
    document.getElementById('req-length').classList.toggle('met', hasLength);
    document.getElementById('req-upper').classList.toggle('met', hasUpper);
    document.getElementById('req-lower').classList.toggle('met', hasLower);
    document.getElementById('req-digit').classList.toggle('met', hasDigit);
    document.getElementById('req-special').classList.toggle('met', hasSpecial);

    // Calculate strength score
    let score = 0;
    if (hasLength) score++;
    if (hasUpper) score++;
    if (hasLower) score++;
    if (hasDigit) score++;
    if (hasSpecial) score++;

    // Bonus for extra length
    if (password.length >= 16) score++;
    if (password.length >= 20) score++;

    // Update strength meter
    strengthBar.className = 'strength-meter-bar';
    if (password.length === 0) {
        strengthText.textContent = '';
    } else if (score <= 2) {
        strengthBar.classList.add('weak');
        strengthText.textContent = 'Weak';
        strengthText.style.color = '#e74c3c';
    } else if (score <= 4) {
        strengthBar.classList.add('fair');
        strengthText.textContent = 'Fair';
        strengthText.style.color = '#f39c12';
    } else if (score <= 5) {
        strengthBar.classList.add('good');
        strengthText.textContent = 'Good';
        strengthText.style.color = '#3498db';
    } else {
        strengthBar.classList.add('strong');
        strengthText.textContent = 'Strong';
        strengthText.style.color = '#27ae60';
    }

    // Also check password match if confirm field has content
    checkPasswordMatch();
}

/**
 * Check if passwords match
 */
function checkPasswordMatch() {
    const newPassword = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;
    const matchStatus = document.getElementById('matchStatus');

    if (confirmPassword.length === 0) {
        matchStatus.textContent = '';
        return;
    }

    if (newPassword === confirmPassword) {
        matchStatus.textContent = 'Passwords match';
        matchStatus.style.color = '#27ae60';
    } else {
        matchStatus.textContent = 'Passwords do not match';
        matchStatus.style.color = '#e74c3c';
    }
}

/**
 * Handle password change form submission
 */
async function changePassword(event) {
    event.preventDefault();
    hideError();

    const currentPassword = document.getElementById('current_password').value;
    const newPassword = document.getElementById('new_password').value;
    const confirmPassword = document.getElementById('confirm_password').value;

    // Client-side validation
    if (!currentPassword || !newPassword || !confirmPassword) {
        showError('All fields are required');
        return;
    }

    if (newPassword !== confirmPassword) {
        showError('New passwords do not match');
        return;
    }

    // Show loading state
    const submitBtn = document.getElementById('submitBtn');
    const submitText = document.getElementById('submitText');
    const submitSpinner = document.getElementById('submitSpinner');

    submitBtn.disabled = true;
    submitText.style.display = 'none';
    submitSpinner.style.display = 'inline-block';

    try {
        const response = await fetch('/admin/api/password/change', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword,
                confirm_password: confirmPassword
            })
        });

        const data = await response.json();

        if (response.ok && data.status === 'ok') {
            showToast('Password changed successfully');
            // Clear form
            document.getElementById('passwordForm').reset();
            document.getElementById('strengthBar').className = 'strength-meter-bar';
            document.getElementById('strengthText').textContent = '';
            document.getElementById('matchStatus').textContent = '';
            // Reset requirement indicators
            document.querySelectorAll('.password-requirements li').forEach(li => {
                li.classList.remove('met');
            });
        } else {
            showError(data.detail || 'Failed to change password');
        }
    } catch (err) {
        showError('Network error. Please try again.');
    } finally {
        // Reset button state
        submitBtn.disabled = false;
        submitText.style.display = 'inline';
        submitSpinner.style.display = 'none';
    }
}
