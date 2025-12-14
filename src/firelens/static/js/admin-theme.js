/**
 * FireLens Admin Theme Toggle
 * Handles dark mode switching with localStorage persistence
 */

// Initialize theme on page load
function initTheme() {
    const savedTheme = localStorage.getItem('firelens-theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = savedTheme || (systemPrefersDark ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeIcon(theme);
}

// Toggle between light and dark themes
function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('firelens-theme', newTheme);
    updateThemeIcon(newTheme);
}

// Update the theme toggle icon and logo
function updateThemeIcon(theme) {
    const sunIcon = document.getElementById('sunIcon');
    const moonIcon = document.getElementById('moonIcon');
    if (sunIcon && moonIcon) {
        if (theme === 'dark') {
            sunIcon.style.display = 'none';
            moonIcon.style.display = 'block';
        } else {
            sunIcon.style.display = 'block';
            moonIcon.style.display = 'none';
        }
    }

    // Update logo for login page (light logo for light mode, dark logo for dark mode)
    const logoLight = document.getElementById('logoLight');
    const logoDark = document.getElementById('logoDark');
    if (logoLight && logoDark) {
        if (theme === 'dark') {
            logoLight.style.display = 'none';
            logoDark.style.display = 'block';
        } else {
            logoLight.style.display = 'block';
            logoDark.style.display = 'none';
        }
    }
}

// Initialize theme when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTheme);
} else {
    initTheme();
}
