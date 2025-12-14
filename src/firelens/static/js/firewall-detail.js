/**
 * FireLens - Firewall Detail Page JavaScript
 * Handles charts, metrics display, and data fetching for firewall detail view
 */

// Configuration - set from template via window.firewallDetailConfig
let firewallName = '';

// State variables
let charts = {};
let autoRefreshEnabled = true;
let refreshInterval;
let userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
let currentCpuAggregation = 'mean';
let currentInterfaceView = 'both';
let currentInterfaceUnit = 'mbps'; // 'mbps' or 'pps'
let currentCpuView = { mgmt: true, dp: true }; // Track which CPU metrics to show
let selectedInterfaces = [];
let availableInterfaces = [];
let lastFetchedData = [];
let lastFetchedInterfaceData = {};
let lastFetchedSessionStats = [];
let lastFetchedVendorMetrics = [];
let vendorType = 'palo_alto'; // Default, will be set from config

/**
 * Calculate default time range (last 6 hours) in user's local timezone
 */
function getDefaultTimeRange() {
    const now = new Date();
    const sixHoursAgo = new Date(now.getTime() - (6 * 60 * 60 * 1000));

    // Format dates as YYYY-MM-DD for date input
    const formatDate = (date) => {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    };

    // Format times as HH:MM for time input
    const formatTime = (date) => {
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        return `${hours}:${minutes}`;
    };

    return {
        startDate: formatDate(sixHoursAgo),
        startTime: formatTime(sixHoursAgo),
        endDate: formatDate(now),
        endTime: formatTime(now)
    };
}

/**
 * Initialize the page on load
 */
document.addEventListener('DOMContentLoaded', function() {
    // Load configuration from template
    if (window.firewallDetailConfig) {
        firewallName = window.firewallDetailConfig.firewallName || '';
        vendorType = window.firewallDetailConfig.vendorType || 'palo_alto';
    }
    console.log(`Vendor type: ${vendorType}`);

    // Set default time range (last 6 hours in user's timezone)
    const defaults = getDefaultTimeRange();
    document.getElementById('startDate').value = defaults.startDate;
    document.getElementById('startTime').value = defaults.startTime;
    document.getElementById('endDate').value = defaults.endDate;
    document.getElementById('endTime').value = defaults.endTime;

    // Set max points default to 500
    document.getElementById('maxPoints').value = '500';

    console.log('Enhanced interface monitoring dashboard loaded');
    console.log(`User timezone: ${userTimezone}`);
    console.log(`Default time range: ${defaults.startDate} ${defaults.startTime} to ${defaults.endDate} ${defaults.endTime}`);

    // Initialize charts and fetch data
    initCharts();
    refreshData();
    setupAutoRefresh();
});

// Dark Mode Toggle Functionality
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    if (newTheme === 'dark') {
        html.setAttribute('data-theme', 'dark');
    } else {
        html.removeAttribute('data-theme');
    }
    localStorage.setItem('theme', newTheme);
    updateThemeIcon(newTheme);

    // Update chart colors for new theme
    if (typeof updateChartColors === 'function') {
        updateChartColors();
    }
}

// Update theme toggle icon
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
}

// Initialize theme from localStorage on page load
(function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = savedTheme || (systemPrefersDark ? 'dark' : 'light');

    if (theme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    }
    updateThemeIcon(theme);
})();

// Helper function to get theme-aware colors
function getThemeColors() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        gridColor: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)',
        tickColor: isDark ? '#cbd5e0' : '#666',
        textColor: isDark ? '#F4F6F8' : '#333D47'
    };
}

function formatValue(value, decimals = 1) {
    if (value === null || value === undefined) return '--';
    return typeof value === 'number' ? value.toFixed(decimals) : value;
}

function formatTimestamp(timestamp) {
    if (!timestamp) return '--';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function getCpuClass(value) {
    if (value === null || value === undefined) return 'cpu-low';
    if (value > 80) return 'cpu-high';
    if (value > 60) return 'cpu-medium';
    return 'cpu-low';
}

function convertToUserTimezone(utcDatetimeLocal) {
    const localDate = new Date(utcDatetimeLocal);
    return localDate.toISOString();
}

function convertFromUserTimezone(utcDatetime) {
    return new Date(utcDatetime);
}

// Timestamp-based hover synchronization helpers
// Binary search to find closest timestamp index in sorted array
function findClosestTimestampIndex(timestamps, targetTime, toleranceMs = 60000) {
    if (!timestamps || timestamps.length === 0) return -1;

    const targetMs = targetTime.getTime();
    let left = 0;
    let right = timestamps.length - 1;
    let closest = -1;
    let closestDiff = Infinity;

    // Binary search for efficiency
    while (left <= right) {
        const mid = Math.floor((left + right) / 2);
        const midTime = timestamps[mid] instanceof Date ? timestamps[mid].getTime() : new Date(timestamps[mid]).getTime();
        const diff = Math.abs(midTime - targetMs);

        if (diff < closestDiff) {
            closestDiff = diff;
            closest = mid;
        }

        if (midTime < targetMs) {
            left = mid + 1;
        } else if (midTime > targetMs) {
            right = mid - 1;
        } else {
            return mid; // Exact match
        }
    }

    // Return index only if within tolerance
    return closestDiff <= toleranceMs ? closest : -1;
}

// Extract timestamp from chart data point based on chart type
function getTimestampFromChartPoint(chart, dataIndex, datasetIndex = 0) {
    if (!chart || !chart.data || !chart.data.datasets) return null;

    const dataset = chart.data.datasets[datasetIndex];
    if (!dataset || !dataset.data || dataIndex >= dataset.data.length) return null;

    const dataPoint = dataset.data[dataIndex];

    // Handle {x, y} format (interface chart)
    if (dataPoint && typeof dataPoint === 'object' && dataPoint.x) {
        return new Date(dataPoint.x);
    }

    // Handle array format with labels (cpu, session, pbuf charts)
    if (chart.data.labels && dataIndex < chart.data.labels.length) {
        return new Date(chart.data.labels[dataIndex]);
    }

    return null;
}

function toggleInterfaceView(view) {
    currentInterfaceView = view;
    // Only toggle direction buttons, not unit buttons
    ['if-rx', 'if-tx', 'if-both', 'if-total'].forEach(id => {
        document.getElementById(id).classList.remove('active');
    });
    document.getElementById(`if-${view}`).classList.add('active');
    updateInterfaceChart();
    updateInterfaceLegend();
}

function toggleInterfaceUnit(unit) {
    currentInterfaceUnit = unit;
    // Toggle unit buttons
    document.getElementById('if-mbps').classList.remove('active');
    document.getElementById('if-pps').classList.remove('active');
    document.getElementById(`if-${unit}`).classList.add('active');

    // Update chart title
    const title = document.getElementById('interfaceChartTitle');
    title.textContent = unit === 'mbps'
        ? 'Interface Bandwidth (Mbps)'
        : 'Interface Packets (PPS)';

    updateInterfaceChart();
    updateInterfaceLegend();
}

function toggleCpuView(view) {
    if (view === 'both') {
        // Show both
        currentCpuView.mgmt = true;
        currentCpuView.dp = true;
        document.getElementById('cpu-mgmt').classList.add('active');
        document.getElementById('cpu-dp').classList.add('active');
        document.getElementById('cpu-both').classList.add('active');
    } else if (view === 'mgmt') {
        // Toggle management CPU
        currentCpuView.mgmt = !currentCpuView.mgmt;
        document.getElementById('cpu-mgmt').classList.toggle('active');
        // If both are off, this shouldn't be allowed - turn it back on
        if (!currentCpuView.mgmt && !currentCpuView.dp) {
            currentCpuView.mgmt = true;
            document.getElementById('cpu-mgmt').classList.add('active');
        }
        // Update "both" button state
        if (currentCpuView.mgmt && currentCpuView.dp) {
            document.getElementById('cpu-both').classList.add('active');
        } else {
            document.getElementById('cpu-both').classList.remove('active');
        }
    } else if (view === 'dp') {
        // Toggle data plane CPU
        currentCpuView.dp = !currentCpuView.dp;
        document.getElementById('cpu-dp').classList.toggle('active');
        // If both are off, this shouldn't be allowed - turn it back on
        if (!currentCpuView.mgmt && !currentCpuView.dp) {
            currentCpuView.dp = true;
            document.getElementById('cpu-dp').classList.add('active');
        }
        // Update "both" button state
        if (currentCpuView.mgmt && currentCpuView.dp) {
            document.getElementById('cpu-both').classList.add('active');
        } else {
            document.getElementById('cpu-both').classList.remove('active');
        }
    }

    // Update the CPU chart
    updateCpuChart();
}

function toggleInterface(interfaceName) {
    const index = selectedInterfaces.indexOf(interfaceName);
    if (index > -1) {
        selectedInterfaces.splice(index, 1);
    } else {
        selectedInterfaces.push(interfaceName);
    }

    updateInterfaceSelector();
    updateInterfaceChart();
    updateInterfaceLegend();

    // Update current values if this affects totals
    if (lastFetchedData && lastFetchedData.length > 0) {
        updateCurrentValues({
            metrics: lastFetchedData,
            interfaces: lastFetchedInterfaceData,
            sessions: lastFetchedSessionStats,
            vendorMetrics: lastFetchedVendorMetrics
        });
    }
}

function selectAllInterfaces() {
    selectedInterfaces = [...availableInterfaces];
    updateInterfaceSelector();
    updateInterfaceChart();
    updateInterfaceLegend();

    // Update current values
    if (lastFetchedData && lastFetchedData.length > 0) {
        updateCurrentValues({
            metrics: lastFetchedData,
            interfaces: lastFetchedInterfaceData,
            sessions: lastFetchedSessionStats,
            vendorMetrics: lastFetchedVendorMetrics
        });
    }
}

function selectNoInterfaces() {
    selectedInterfaces = [];
    updateInterfaceSelector();
    updateInterfaceChart();
    updateInterfaceLegend();

    // Update current values
    if (lastFetchedData && lastFetchedData.length > 0) {
        updateCurrentValues({
            metrics: lastFetchedData,
            interfaces: lastFetchedInterfaceData,
            sessions: lastFetchedSessionStats,
            vendorMetrics: lastFetchedVendorMetrics
        });
    }
}

function filterInterfaces() {
    const searchTerm = document.getElementById('interfaceSearch').value.toLowerCase();
    const buttons = document.querySelectorAll('#interfaceButtons .interface-btn');

    buttons.forEach(button => {
        const interfaceName = button.dataset.interface.toLowerCase();
        if (interfaceName.includes(searchTerm)) {
            button.style.display = 'inline-block';
        } else {
            button.style.display = 'none';
        }
    });
}

function getInterfaceDisplayName(interfaceName, interfaceConfig) {
    // Try to get display name from configuration
    if (interfaceConfig && interfaceConfig.configured_interfaces) {
        const configuredInterface = interfaceConfig.configured_interfaces.find(
            iface => iface.name === interfaceName
        );
        if (configuredInterface && configuredInterface.display_name) {
            return configuredInterface.display_name;
        }
    }

    // Auto-generate display name if not configured
    return generateDisplayName(interfaceName);
}

function generateDisplayName(interfaceName) {
    const name = interfaceName.toLowerCase();

    if (name.startsWith("ethernet1/1")) return "WAN/Internet";
    if (name.startsWith("ethernet1/2")) return "LAN/Internal";
    if (name.startsWith("ethernet1/3")) return "DMZ";
    if (name.startsWith("ethernet")) {
        const port = name.replace("ethernet", "").replace("1/", "");
        return `Port ${port}`;
    }
    if (name.startsWith("ae")) {
        const num = name.replace("ae", "");
        return `Aggregate ${num}`;
    }
    if (name.startsWith("vlan")) {
        const num = name.replace("vlan", "").replace(".", " ");
        return `VLAN ${num}`;
    }
    if (name.startsWith("tunnel")) {
        return `Tunnel ${name.replace('tunnel.', '')}`;
    }

    // Capitalize first letter for unknown interfaces
    return interfaceName.charAt(0).toUpperCase() + interfaceName.slice(1);
}

function hasInterfaceData(interfaceName) {
    return lastFetchedInterfaceData[interfaceName] &&
           lastFetchedInterfaceData[interfaceName].length > 0;
}

async function fetchMetrics() {
    const startDate = document.getElementById('startDate').value;
    const startTime = document.getElementById('startTime').value;
    const endDate = document.getElementById('endDate').value;
    const endTime = document.getElementById('endTime').value;
    const maxPoints = document.getElementById('maxPoints').value;

    const params = new URLSearchParams();

    if (startDate && startTime) {
        const localStart = `${startDate}T${startTime}:00`;
        const utcStart = convertToUserTimezone(localStart);
        params.append('start_time', utcStart);
    }
    if (endDate && endTime) {
        const localEnd = `${endDate}T${endTime}:59`;
        const utcEnd = convertToUserTimezone(localEnd);
        params.append('end_time', utcEnd);
    }
    if (maxPoints) {
        params.append('limit', maxPoints);
    }

    params.append('user_timezone', userTimezone);

    try {
        // Fetch main metrics
        const metricsResponse = await fetch(`/api/firewall/${firewallName}/metrics?${params}`);
        if (!metricsResponse.ok) {
            throw new Error(`HTTP ${metricsResponse.status}`);
        }
        const metricsData = await metricsResponse.json();
        lastFetchedData = metricsData;

        // Fetch interface configuration first
        const configResponse = await fetch(`/api/firewall/${firewallName}/interface-config`);
        let interfaceConfig = null;
        if (configResponse.ok) {
            interfaceConfig = await configResponse.json();
            window.currentInterfaceConfig = interfaceConfig; // Store globally for access
            console.log('Interface config loaded:', interfaceConfig);
        }

        // Fetch interface metrics
        const interfaceResponse = await fetch(`/api/firewall/${firewallName}/interfaces?${params}`);
        if (interfaceResponse.ok) {
            const interfaceData = await interfaceResponse.json();
            lastFetchedInterfaceData = interfaceData;

            // Update available interfaces from actual data
            const newInterfaces = Object.keys(interfaceData);

            // Sort interfaces for better display
            newInterfaces.sort();

            console.log(`Found ${newInterfaces.length} interfaces with data:`, newInterfaces);

            if (JSON.stringify(availableInterfaces) !== JSON.stringify(newInterfaces)) {
                availableInterfaces = newInterfaces;
                updateInterfaceSelector();

                // Auto-select interfaces based on configuration or smart defaults
                if (selectedInterfaces.length === 0 && availableInterfaces.length > 0) {
                    if (interfaceConfig && interfaceConfig.enabled_interfaces && interfaceConfig.enabled_interfaces.length > 0) {
                        // Prefer enabled interfaces from config for auto-selection
                        selectedInterfaces = interfaceConfig.enabled_interfaces.filter(iface =>
                            availableInterfaces.includes(iface)
                        );
                        console.log(`Auto-selected ${selectedInterfaces.length} enabled interfaces from config`);
                    }

                    // If no config or no enabled interfaces matched, select all interfaces
                    if (selectedInterfaces.length === 0) {
                        // Select all available interfaces by default
                        selectedInterfaces = [...availableInterfaces];
                        console.log(`Auto-selected all ${selectedInterfaces.length} available interfaces`);
                    }
                    updateInterfaceSelector();
                }
            }
        } else {
            console.warn('Interface metrics not available');
            lastFetchedInterfaceData = {};
        }

        // Fetch session statistics
        const sessionResponse = await fetch(`/api/firewall/${firewallName}/sessions?${params}`);
        if (sessionResponse.ok) {
            const sessionData = await sessionResponse.json();
            lastFetchedSessionStats = sessionData;
        } else {
            console.warn('Session statistics not available');
            lastFetchedSessionStats = [];
        }

        // Fetch vendor-specific metrics (Fortinet, etc.)
        const vendorResponse = await fetch(`/api/firewall/${firewallName}/vendor-metrics?${params}`);
        if (vendorResponse.ok) {
            const vendorData = await vendorResponse.json();
            lastFetchedVendorMetrics = vendorData.metrics || [];
            console.log(`Loaded ${lastFetchedVendorMetrics.length} vendor metrics for ${vendorData.vendor_type}`);
        } else {
            console.warn('Vendor metrics not available');
            lastFetchedVendorMetrics = [];
        }

        return {
            metrics: metricsData,
            interfaces: lastFetchedInterfaceData,
            sessions: lastFetchedSessionStats,
            vendorMetrics: lastFetchedVendorMetrics,
            interfaceConfig: interfaceConfig
        };

    } catch (error) {
        console.error('Failed to fetch data:', error);
        document.getElementById('currentValues').innerHTML = '<div class="error">Failed to load data: ' + error.message + '</div>';
        return { metrics: [], interfaces: {}, sessions: [], interfaceConfig: null };
    }
}

function updateInterfaceSelector() {
    const selector = document.getElementById('interfaceSelector');
    if (!selector) return;

    // Preserve existing header and controls, only update buttons and info
    let buttonsContainer = document.getElementById('interfaceButtons');
    let infoContainer = document.getElementById('interfaceInfo');

    if (!buttonsContainer) {
        // Create the structure if it doesn't exist
        selector.innerHTML = `
            <div class="interface-selector-header">
                <span>Select Interfaces to Monitor:</span>
                <div class="interface-selector-controls">
                    <button class="select-all-btn" onclick="selectAllInterfaces()">Select All</button>
                    <button class="select-none-btn" onclick="selectNoInterfaces()">Select None</button>
                </div>
            </div>
            <input type="text" class="interface-search" id="interfaceSearch" placeholder="Search interfaces..." onkeyup="filterInterfaces()">
            <div id="interfaceButtons"></div>
            <div class="interface-info" id="interfaceInfo"></div>
        `;
        buttonsContainer = document.getElementById('interfaceButtons');
        infoContainer = document.getElementById('interfaceInfo');
    }

    buttonsContainer.innerHTML = '';

    if (availableInterfaces.length === 0) {
        buttonsContainer.innerHTML = '<div style="color: #7f8c8d; font-style: italic; width: 100%; text-align: center; padding: 20px;">No interfaces available for monitoring</div>';
        infoContainer.textContent = 'Interface monitoring may not be enabled for this firewall.';
        return;
    }

    // Get interface config if available from global scope
    let interfaceConfig = window.currentInterfaceConfig || null;

    availableInterfaces.forEach(interfaceName => {
        const btn = document.createElement('button');
        btn.className = 'interface-btn';
        btn.dataset.interface = interfaceName;

        // Set display name
        const displayName = getInterfaceDisplayName(interfaceName, interfaceConfig);
        btn.innerHTML = `
            <span>${displayName}</span>
            <small style="display: block; font-size: 0.7em; opacity: 0.8;">${interfaceName}</small>
            <span class="interface-status"></span>
        `;

        btn.onclick = () => toggleInterface(interfaceName);

        // Add visual indicators
        if (selectedInterfaces.includes(interfaceName)) {
            btn.classList.add('active');
        }

        if (hasInterfaceData(interfaceName)) {
            btn.classList.add('has-data');
            btn.title = `${displayName} (${interfaceName}) - Has data available`;
        } else {
            btn.classList.add('no-data');
            btn.title = `${displayName} (${interfaceName}) - No data available`;
        }

        buttonsContainer.appendChild(btn);
    });

    // Update info
    const selectedCount = selectedInterfaces.length;
    const totalCount = availableInterfaces.length;
    const dataCount = availableInterfaces.filter(hasInterfaceData).length;

    let infoText = `${totalCount} interfaces available, ${selectedCount} selected`;
    if (dataCount !== totalCount) {
        infoText += `, ${dataCount} with data`;
    }

    infoContainer.textContent = infoText;

    // Clear search when updating
    const searchInput = document.getElementById('interfaceSearch');
    if (searchInput) {
        searchInput.value = '';
    }
}

function updateCurrentValues(data) {
    // Get latest interface data for display - only from selected interfaces
    let totalInterfaceRx = 0;
    let totalInterfaceTx = 0;
    let interfaceCount = 0;

    selectedInterfaces.forEach(interfaceName => {
        const interfaceDataArray = data.interfaces[interfaceName];
        if (interfaceDataArray && interfaceDataArray.length > 0) {
            const latestInterface = interfaceDataArray[0];
            totalInterfaceRx += latestInterface.rx_mbps || 0;
            totalInterfaceTx += latestInterface.tx_mbps || 0;
            interfaceCount++;
        }
    });

    // Get latest session stats
    let activeSessions = 0;
    if (data.sessions && data.sessions.length > 0) {
        activeSessions = data.sessions[0].active_sessions;
    }

    let currentValuesHtml = '';
    let lastTimestamp = null;

    if (vendorType === 'fortinet') {
        // Fortinet-specific display: CPU, Memory, Interface, Sessions, Setup Rate
        const vendorData = data.vendorMetrics && data.vendorMetrics.length > 0
            ? data.vendorMetrics[0] : null;

        const cpuUsage = vendorData ? vendorData.cpu_usage : null;
        const memoryUsage = vendorData ? vendorData.memory_usage_percent : null;
        const setupRate = vendorData ? vendorData.session_setup_rate : null;
        const npuSessions = vendorData ? vendorData.npu_sessions : null;

        // Try to get CPU from main metrics if not in vendor metrics
        let cpu = null;
        if (data.metrics && data.metrics.length > 0) {
            cpu = data.metrics[0].cpu_usage;
            lastTimestamp = data.metrics[0].timestamp;
        }
        // Override with vendor metrics CPU if available
        if (vendorData && vendorData.cpu_usage !== undefined) {
            cpu = vendorData.cpu_usage;
        }
        if (vendorData && vendorData.timestamp) {
            lastTimestamp = vendorData.timestamp;
        }

        currentValuesHtml = `
            <div class="value-card">
                <div class="value-label">CPU</div>
                <div class="value-number ${getCpuClass(cpu)}">${formatValue(cpu)}</div>
                <div class="value-unit">%</div>
            </div>
            <div class="value-card">
                <div class="value-label">Memory</div>
                <div class="value-number ${getCpuClass(memoryUsage)}">${formatValue(memoryUsage)}</div>
                <div class="value-unit">%</div>
            </div>

            <div class="value-card">
                <div class="value-label">Interface RX (${interfaceCount} Selected)</div>
                <div class="value-number">${formatValue(totalInterfaceRx)}</div>
                <div class="value-unit">Mbps</div>
            </div>
            <div class="value-card">
                <div class="value-label">Interface TX (${interfaceCount} Selected)</div>
                <div class="value-number">${formatValue(totalInterfaceTx)}</div>
                <div class="value-unit">Mbps</div>
            </div>
            <div class="value-card">
                <div class="value-label">Active Sessions</div>
                <div class="value-number">${formatValue(activeSessions, 0)}</div>
                <div class="value-unit">sessions</div>
            </div>
            <div class="value-card">
                <div class="value-label">Setup Rate</div>
                <div class="value-number">${formatValue(setupRate, 1)}</div>
                <div class="value-unit">/s</div>
            </div>
        `;
    } else {
        // Palo Alto display: Mgmt CPU, DP CPU, Interface, Sessions, Packet Buffer
        // CPU/pbuf data now comes from palo_alto_metrics table via vendorMetrics
        const vendorData = data.vendorMetrics && data.vendorMetrics.length > 0
            ? data.vendorMetrics[0] : null;

        if (!vendorData) return;

        lastTimestamp = vendorData.timestamp;
        const mgmtCpu = vendorData.mgmt_cpu;
        const pbufPercent = vendorData.pbuf_util_percent;

        let dpCpu;
        switch(currentCpuAggregation) {
            case 'max':
                dpCpu = vendorData.data_plane_cpu_max;
                break;
            case 'p95':
                dpCpu = vendorData.data_plane_cpu_p95;
                break;
            default:
                dpCpu = vendorData.data_plane_cpu_mean;
        }

        currentValuesHtml = `
            <div class="value-card">
                <div class="value-label">Mgmt CPU</div>
                <div class="value-number ${getCpuClass(mgmtCpu)}">${formatValue(mgmtCpu)}</div>
                <div class="value-unit">%</div>
            </div>
            <div class="value-card">
                <div class="value-label">DP CPU (${currentCpuAggregation.toUpperCase()})</div>
                <div class="value-number ${getCpuClass(dpCpu)}">${formatValue(dpCpu)}</div>
                <div class="value-unit">%</div>
            </div>

            <div class="value-card">
                <div class="value-label">Interface RX (${interfaceCount} Selected)</div>
                <div class="value-number">${formatValue(totalInterfaceRx)}</div>
                <div class="value-unit">Mbps</div>
            </div>
            <div class="value-card">
                <div class="value-label">Interface TX (${interfaceCount} Selected)</div>
                <div class="value-number">${formatValue(totalInterfaceTx)}</div>
                <div class="value-unit">Mbps</div>
            </div>
            <div class="value-card">
                <div class="value-label">Active Sessions</div>
                <div class="value-number">${formatValue(activeSessions, 0)}</div>
                <div class="value-unit">sessions</div>
            </div>
            <div class="value-card">
                <div class="value-label">Packet Buffer</div>
                <div class="value-number ${getCpuClass(pbufPercent)}">${formatValue(pbufPercent)}</div>
                <div class="value-unit">%</div>
            </div>
        `;
    }

    document.getElementById('currentValues').innerHTML = currentValuesHtml;
    if (lastTimestamp) {
        document.getElementById('lastUpdate').textContent = `Last updated: ${formatTimestamp(lastTimestamp)}`;
    }
}

function createChart(canvasId, datasets) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    const themeColors = getThemeColors();

    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: themeColors.gridColor },
                    ticks: { color: themeColors.tickColor }
                },
                x: {
                    type: 'time',
                    time: {
                        displayFormats: {
                            minute: 'HH:mm',
                            hour: 'HH:mm',
                            day: 'MMM dd'
                        }
                    },
                    grid: { color: themeColors.gridColor },
                    ticks: {
                        color: themeColors.tickColor,
                        maxTicksLimit: 10
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    enabled: true,
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        title: function(context) {
                            const date = new Date(context[0].parsed.x);
                            return date.toLocaleString();
                        },
                        // Filter tooltip items to only show data at matching timestamps
                        label: function(context) {
                            const chart = context.chart;
                            const dataPoint = context.raw;

                            // For {x, y} format data (interface chart), verify timestamp matches
                            if (dataPoint && typeof dataPoint === 'object' && dataPoint.x) {
                                // Get the hovered timestamp from the first dataset's point
                                const hoveredX = context.parsed.x;
                                const pointX = new Date(dataPoint.x).getTime();

                                // Only show if within 60 seconds of hovered time
                                const diff = Math.abs(hoveredX - pointX);
                                if (diff > 60000) {
                                    return null; // Hide this item from tooltip
                                }
                            }

                            // Default label format
                            const label = context.dataset.label || '';
                            const value = context.parsed.y;
                            return `${label}: ${value !== null ? value.toFixed(1) : '--'}`;
                        }
                    },
                    // Filter out null labels
                    filter: function(tooltipItem) {
                        return tooltipItem !== null;
                    }
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            onHover: (event, activeElements, chart) => {
                if (activeElements.length > 0) {
                    const dataIndex = activeElements[0].index;
                    const datasetIndex = activeElements[0].datasetIndex;
                    syncChartHover(chart, dataIndex, datasetIndex);
                }
            }
        }
    });

    // Add event listener for mouse leave
    ctx.canvas.addEventListener('mouseleave', () => {
        hideHoverSummary();
    });

    return chart;
}

// Function to update all chart colors when theme changes
function updateChartColors() {
    const themeColors = getThemeColors();

    Object.values(charts).forEach(chart => {
        if (chart && chart.options && chart.options.scales) {
            // Update y-axis colors
            if (chart.options.scales.y) {
                chart.options.scales.y.grid.color = themeColors.gridColor;
                chart.options.scales.y.ticks.color = themeColors.tickColor;
            }
            // Update x-axis colors
            if (chart.options.scales.x) {
                chart.options.scales.x.grid.color = themeColors.gridColor;
                chart.options.scales.x.ticks.color = themeColors.tickColor;
            }
            chart.update('none'); // Update without animation
        }
    });
}

function initCharts() {
    // CPU Chart - vendor-aware datasets
    let cpuDatasets;
    if (vendorType === 'fortinet') {
        // Fortinet: single CPU metric
        cpuDatasets = [
            {
                label: 'CPU (%)',
                data: [],
                borderColor: '#e74c3c',
                backgroundColor: '#e74c3c20',
                fill: false,
                tension: 0.4
            }
        ];
    } else {
        // Palo Alto: separate Mgmt and Data Plane CPU
        cpuDatasets = [
            {
                label: 'Management CPU (%)',
                data: [],
                borderColor: '#e74c3c',
                backgroundColor: '#e74c3c20',
                fill: false,
                tension: 0.4
            },
            {
                label: 'Data Plane CPU - Mean (%)',
                data: [],
                borderColor: '#3498db',
                backgroundColor: '#3498db20',
                fill: false,
                tension: 0.4
            }
        ];
    }
    charts.cpu = createChart('cpuChart', cpuDatasets);

    // Interface chart
    charts.interface = createChart('interfaceChart', []);

    // Session statistics chart - dual axis for Fortinet (includes Setup Rate)
    if (vendorType === 'fortinet') {
        charts.sessionStats = createDualAxisChart('sessionStatsChart', [
            {
                label: 'Active Sessions',
                data: [],
                borderColor: '#e67e22',
                backgroundColor: '#e67e2220',
                fill: false,
                tension: 0.4,
                yAxisID: 'y'
            },
            {
                label: 'Setup Rate (/s)',
                data: [],
                borderColor: '#27ae60',
                backgroundColor: '#27ae6020',
                fill: false,
                tension: 0.4,
                yAxisID: 'y1'
            }
        ], {
            y: { title: 'Active Sessions' },
            y1: { title: 'Setup Rate (/s)', position: 'right' }
        });
    } else {
        charts.sessionStats = createChart('sessionStatsChart', [
            {
                label: 'Active Sessions',
                data: [],
                borderColor: '#e67e22',
                backgroundColor: '#e67e2220',
                fill: false,
                tension: 0.4
            }
        ]);
    }

    // Packet buffer chart (Palo Alto only)
    const pbufCanvas = document.getElementById('pbufChart');
    if (pbufCanvas) {
        charts.pbuf = createChart('pbufChart', [
            {
                label: 'Packet Buffer (%)',
                data: [],
                borderColor: '#f39c12',
                backgroundColor: '#f39c1220',
                fill: false,
                tension: 0.4
            }
        ]);
    }

    // FortiGate metrics chart (only if vendor is Fortinet)
    if (vendorType === 'fortinet') {
        const fortinetCanvas = document.getElementById('fortinetMetricsChart');
        if (fortinetCanvas) {
            charts.fortinetMetrics = createDualAxisChart('fortinetMetricsChart', [
                {
                    label: 'Memory Usage (%)',
                    data: [],
                    borderColor: '#9b59b6',
                    backgroundColor: '#9b59b620',
                    fill: false,
                    tension: 0.4,
                    yAxisID: 'y'
                },
                {
                    label: 'NPU Sessions',
                    data: [],
                    borderColor: '#1abc9c',
                    backgroundColor: '#1abc9c20',
                    fill: false,
                    tension: 0.4,
                    yAxisID: 'y1'
                }
            ], {
                y: { title: 'Memory %', max: 100 },
                y1: { title: 'Sessions', position: 'right' }
            });
        }
    }
}

function createDualAxisChart(canvasId, datasets, axisConfig) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    const themeColors = getThemeColors();

    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            scales: {
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    beginAtZero: true,
                    max: axisConfig.y.max || undefined,
                    grid: { color: themeColors.gridColor },
                    ticks: { color: themeColors.tickColor },
                    title: {
                        display: true,
                        text: axisConfig.y.title || '',
                        color: themeColors.tickColor
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    beginAtZero: true,
                    grid: { drawOnChartArea: false },
                    ticks: { color: themeColors.tickColor },
                    title: {
                        display: true,
                        text: axisConfig.y1.title || '',
                        color: themeColors.tickColor
                    }
                },
                x: {
                    type: 'time',
                    time: {
                        displayFormats: {
                            minute: 'HH:mm',
                            hour: 'HH:mm',
                            day: 'MMM dd'
                        }
                    },
                    grid: { color: themeColors.gridColor },
                    ticks: {
                        color: themeColors.tickColor,
                        maxTicksLimit: 10
                    }
                }
            },
            plugins: {
                legend: {
                    display: true,
                    labels: { color: themeColors.tickColor }
                },
                tooltip: {
                    enabled: true,
                    mode: 'index',
                    intersect: false
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            onHover: (event, activeElements, chart) => {
                if (activeElements.length > 0) {
                    const dataIndex = activeElements[0].index;
                    const datasetIndex = activeElements[0].datasetIndex;
                    syncChartHover(chart, dataIndex, datasetIndex);
                }
            }
        }
    });

    // Add event listener for mouse leave
    ctx.canvas.addEventListener('mouseleave', () => {
        hideHoverSummary();
    });

    return chart;
}

function updateInterfaceChart() {
    if (!lastFetchedInterfaceData || Object.keys(lastFetchedInterfaceData).length === 0) return;

    const datasets = [];
    const colors = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#e67e22', '#1abc9c', '#34495e'];
    let colorIndex = 0;

    // Determine which data fields to use based on unit
    const isMbps = currentInterfaceUnit === 'mbps';
    const rxField = isMbps ? 'rx_mbps' : 'rx_pps';
    const txField = isMbps ? 'tx_mbps' : 'tx_pps';
    const unitLabel = isMbps ? 'Mbps' : 'PPS';

    selectedInterfaces.forEach(interfaceName => {
        const interfaceData = lastFetchedInterfaceData[interfaceName];
        if (!interfaceData || interfaceData.length === 0) return;

        const reversedData = [...interfaceData].reverse();
        const color = colors[colorIndex % colors.length];
        colorIndex++;

        // Use {x, y} format so each interface can have its own timestamps
        if (currentInterfaceView === 'rx' || currentInterfaceView === 'both') {
            datasets.push({
                label: `${interfaceName} RX`,
                data: reversedData.map(d => ({
                    x: convertFromUserTimezone(d.timestamp),
                    y: d[rxField] || 0
                })),
                borderColor: color,
                backgroundColor: color + '20',
                fill: false,
                tension: 0.4
            });
        }

        if (currentInterfaceView === 'tx' || currentInterfaceView === 'both') {
            datasets.push({
                label: `${interfaceName} TX`,
                data: reversedData.map(d => ({
                    x: convertFromUserTimezone(d.timestamp),
                    y: d[txField] || 0
                })),
                borderColor: color,
                backgroundColor: color + '20',
                fill: false,
                tension: 0.4,
                borderDash: currentInterfaceView === 'both' ? [5, 5] : []
            });
        }

        if (currentInterfaceView === 'total') {
            datasets.push({
                label: `${interfaceName} Total`,
                data: reversedData.map(d => ({
                    x: convertFromUserTimezone(d.timestamp),
                    y: isMbps ? (d.total_mbps || 0) : ((d.rx_pps || 0) + (d.tx_pps || 0))
                })),
                borderColor: color,
                backgroundColor: color + '20',
                fill: false,
                tension: 0.4
            });
        }
    });

    // Clear labels since we're using {x, y} data format with time scale
    charts.interface.data.labels = [];
    charts.interface.data.datasets = datasets;
    charts.interface.update('active');
}

function updateSessionStatsChart() {
    if (!lastFetchedSessionStats || lastFetchedSessionStats.length === 0) return;

    const reversedData = [...lastFetchedSessionStats].reverse();
    const localTimes = reversedData.map(d => convertFromUserTimezone(d.timestamp));

    charts.sessionStats.data.labels = localTimes;
    charts.sessionStats.data.datasets[0].data = reversedData.map(d => d.active_sessions || 0);

    // For Fortinet, also update setup rate from vendor metrics (second dataset)
    if (vendorType === 'fortinet' && charts.sessionStats.data.datasets.length > 1) {
        if (lastFetchedVendorMetrics && lastFetchedVendorMetrics.length > 0) {
            const reversedVendorData = [...lastFetchedVendorMetrics].reverse();
            // Map vendor metrics timestamps to setup rate values
            charts.sessionStats.data.datasets[1].data = reversedVendorData.map(d => d.session_setup_rate || 0);
            // Use vendor metrics timestamps for labels (they should align)
            const vendorTimes = reversedVendorData.map(d => convertFromUserTimezone(d.timestamp));
            charts.sessionStats.data.labels = vendorTimes;
        }
    }

    charts.sessionStats.update('active');
}

function updateFortinetMetricsChart() {
    if (vendorType !== 'fortinet') return;
    if (!charts.fortinetMetrics) return;
    if (!lastFetchedVendorMetrics || lastFetchedVendorMetrics.length === 0) return;

    const reversedData = [...lastFetchedVendorMetrics].reverse();
    const localTimes = reversedData.map(d => convertFromUserTimezone(d.timestamp));

    charts.fortinetMetrics.data.labels = localTimes;
    charts.fortinetMetrics.data.datasets[0].data = reversedData.map(d => d.memory_usage_percent || 0);
    charts.fortinetMetrics.data.datasets[1].data = reversedData.map(d => d.npu_sessions || 0);
    charts.fortinetMetrics.update('active');

    // Update summary values
    if (lastFetchedVendorMetrics.length > 0) {
        const latest = lastFetchedVendorMetrics[0];
        const memoryEl = document.getElementById('fortinetMemory');
        const npuSessionsEl = document.getElementById('fortinetNpuSessions');

        if (memoryEl) {
            memoryEl.textContent = `${(latest.memory_usage_percent || 0).toFixed(1)}%`;
        }
        if (npuSessionsEl) {
            npuSessionsEl.textContent = `${latest.npu_sessions || 0}`;
        }
    }
}

function updateCpuChart() {
    // CPU data now comes from vendor-specific tables (palo_alto_metrics, fortinet_metrics)
    if (!lastFetchedVendorMetrics || lastFetchedVendorMetrics.length === 0) return;
    if (!charts.cpu) return;

    const reversedData = [...lastFetchedVendorMetrics].reverse();
    const localTimes = reversedData.map(d => convertFromUserTimezone(d.timestamp));

    // Update chart labels
    charts.cpu.data.labels = localTimes;

    if (vendorType === 'fortinet') {
        // Fortinet: single CPU metric from fortinet_metrics table
        const cpuDataset = charts.cpu.data.datasets[0];
        cpuDataset.data = reversedData.map(d => d.cpu_usage || 0);
        cpuDataset.label = 'CPU (%)';
    } else {
        // Palo Alto: Mgmt CPU + Data Plane CPU from palo_alto_metrics table
        let dpCpuData, dpCpuLabel;
        switch(currentCpuAggregation) {
            case 'max':
                dpCpuData = reversedData.map(d => d.data_plane_cpu_max || 0);
                dpCpuLabel = 'Data Plane CPU - Max (%)';
                break;
            case 'p95':
                dpCpuData = reversedData.map(d => d.data_plane_cpu_p95 || 0);
                dpCpuLabel = 'Data Plane CPU - P95 (%)';
                break;
            default:
                dpCpuData = reversedData.map(d => d.data_plane_cpu_mean || 0);
                dpCpuLabel = 'Data Plane CPU - Mean (%)';
        }

        // Update datasets based on currentCpuView
        const mgmtDataset = charts.cpu.data.datasets[0];
        const dpDataset = charts.cpu.data.datasets[1];

        // Update management CPU dataset
        mgmtDataset.data = reversedData.map(d => d.mgmt_cpu || 0);
        mgmtDataset.hidden = !currentCpuView.mgmt;

        // Update data plane CPU dataset
        dpDataset.data = dpCpuData;
        dpDataset.label = dpCpuLabel;
        dpDataset.hidden = !currentCpuView.dp;
    }

    charts.cpu.update('active');
}

function updateCharts(data) {
    if (!data.metrics || data.metrics.length === 0) return;

    // Store data for CPU chart updates
    lastFetchedData = data.metrics;

    const reversedData = [...data.metrics].reverse();
    const localTimes = reversedData.map(d => convertFromUserTimezone(d.timestamp));

    // Update CPU Chart
    updateCpuChart();

    // Packet Buffer Chart (Palo Alto only - data now in palo_alto_metrics table)
    if (charts.pbuf && lastFetchedVendorMetrics && lastFetchedVendorMetrics.length > 0) {
        const reversedVendorData = [...lastFetchedVendorMetrics].reverse();
        const vendorTimes = reversedVendorData.map(d => convertFromUserTimezone(d.timestamp));
        charts.pbuf.data.labels = vendorTimes;
        charts.pbuf.data.datasets[0].data = reversedVendorData.map(d => d.pbuf_util_percent || 0);
        charts.pbuf.update('active');
    }

    // Update interface charts
    updateInterfaceChart();

    // Update session statistics chart
    updateSessionStatsChart();

    // Update FortiGate metrics chart (if applicable)
    updateFortinetMetricsChart();

    // Update legends
    updateInterfaceLegend();
}

function updateInterfaceLegend() {
    const legend = document.getElementById('interfaceLegend');
    if (selectedInterfaces.length === 0) {
        const dataType = currentInterfaceUnit === 'mbps' ? 'bandwidth' : 'packet';
        legend.innerHTML = `<div class="legend-item">Select interfaces to view ${dataType} data</div>`;
        return;
    }

    let html = '';
    const colors = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#e67e22', '#1abc9c', '#34495e'];
    const unit = currentInterfaceUnit === 'mbps' ? 'Mbps' : 'PPS';

    selectedInterfaces.forEach((interfaceName, index) => {
        const color = colors[index % colors.length];

        if (currentInterfaceView === 'rx') {
            html += `<div class="legend-item">
                <span class="legend-color" style="background-color: ${color};"></span>
                <span>${interfaceName} RX (${unit})</span>
            </div>`;
        } else if (currentInterfaceView === 'tx') {
            html += `<div class="legend-item">
                <span class="legend-color" style="background-color: ${color};"></span>
                <span>${interfaceName} TX (${unit})</span>
            </div>`;
        } else if (currentInterfaceView === 'total') {
            html += `<div class="legend-item">
                <span class="legend-color" style="background-color: ${color};"></span>
                <span>${interfaceName} Total (${unit})</span>
            </div>`;
        } else {
            html += `<div class="legend-item">
                <span class="legend-color" style="background-color: ${color};"></span>
                <span>${interfaceName} RX (solid) / TX (dashed) - ${unit}</span>
            </div>`;
        }
    });

    legend.innerHTML = html;
}

function downloadCSV() {
    // Use vendor metrics for CPU/memory data (now in vendor-specific tables)
    if (!lastFetchedVendorMetrics || lastFetchedVendorMetrics.length === 0) {
        alert('No data available to download. Please load some data first.');
        return;
    }

    // Build headers based on vendor type
    const headers = [
        'Timestamp (Local)',
        'Timestamp (UTC)',
        'Firewall Name'
    ];

    if (vendorType === 'fortinet') {
        // Fortinet-specific metrics
        headers.push('CPU (%)');
        headers.push('Memory (%)');
        headers.push('Session Setup Rate (/s)');
        headers.push('NPU Sessions');
    } else {
        // Palo Alto-specific metrics (default)
        headers.push('Management CPU (%)');
        headers.push('Data Plane CPU Mean (%)');
        headers.push('Data Plane CPU Max (%)');
        headers.push('Data Plane CPU P95 (%)');
        headers.push('Packet Buffer (%)');
    }

    // Add interface headers
    selectedInterfaces.forEach(interfaceName => {
        headers.push(`${interfaceName} RX (Mbps)`);
        headers.push(`${interfaceName} TX (Mbps)`);
        headers.push(`${interfaceName} Total (Mbps)`);
    });

    const csvRows = [headers.join(',')];

    // Sort vendor metrics by timestamp
    const sortedData = [...lastFetchedVendorMetrics].sort((a, b) =>
        new Date(a.timestamp) - new Date(b.timestamp)
    );

    sortedData.forEach(row => {
        const localTime = convertFromUserTimezone(row.timestamp);
        const csvRow = [
            `"${localTime.toLocaleString()}"`,
            `"${row.timestamp}"`,
            `"${row.firewall_name || firewallName}"`
        ];

        if (vendorType === 'fortinet') {
            // Fortinet-specific data
            csvRow.push(formatValue(row.cpu_usage) || '');
            csvRow.push(formatValue(row.memory_usage_percent) || '');
            csvRow.push(formatValue(row.session_setup_rate) || '');
            csvRow.push(row.npu_sessions !== null ? row.npu_sessions : '');
        } else {
            // Palo Alto-specific data
            csvRow.push(formatValue(row.mgmt_cpu) || '');
            csvRow.push(formatValue(row.data_plane_cpu_mean) || '');
            csvRow.push(formatValue(row.data_plane_cpu_max) || '');
            csvRow.push(formatValue(row.data_plane_cpu_p95) || '');
            csvRow.push(formatValue(row.pbuf_util_percent) || '');
        }

        // Add interface data
        selectedInterfaces.forEach(interfaceName => {
            const interfaceData = lastFetchedInterfaceData[interfaceName];
            if (interfaceData && interfaceData.length > 0) {
                // Find matching timestamp
                const matchingInterface = interfaceData.find(iData =>
                    Math.abs(new Date(iData.timestamp) - new Date(row.timestamp)) < 60000 // within 1 minute
                );

                if (matchingInterface) {
                    csvRow.push(formatValue(matchingInterface.rx_mbps) || '');
                    csvRow.push(formatValue(matchingInterface.tx_mbps) || '');
                    csvRow.push(formatValue(matchingInterface.total_mbps) || '');
                } else {
                    csvRow.push('', '', '');
                }
            } else {
                csvRow.push('', '', '');
            }
        });

        csvRows.push(csvRow.join(','));
    });

    const csvContent = csvRows.join('\n');
    const now = new Date();
    const startDate = document.getElementById('startDate').value;
    const endDate = document.getElementById('endDate').value;

    let filename = `${firewallName}_firewall_metrics_${now.getFullYear()}${(now.getMonth()+1).toString().padStart(2,'0')}${now.getDate().toString().padStart(2,'0')}`;

    if (startDate && endDate) {
        filename += `_${startDate}_to_${endDate}`;
    }

    filename += '.csv';

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');

    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        const originalButton = document.querySelector('button[onclick="downloadCSV()"]');
        const originalText = originalButton.textContent;
        originalButton.textContent = 'Downloaded!';
        originalButton.style.background = '#27ae60';

        setTimeout(() => {
            originalButton.textContent = originalText;
            originalButton.style.background = '#27ae60';
        }, 2000);
    }
}

async function refreshData() {
    const data = await fetchMetrics();

    if (data && (data.metrics.length > 0 || Object.keys(data.interfaces).length > 0)) {
        updateCurrentValues(data);
        updateCharts(data);
    }
}

function setupAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
    }

    if (autoRefreshEnabled) {
        refreshInterval = setInterval(refreshData, 60000);
    }
}

// Synchronized chart hover and hover summary functions
function syncChartHover(sourceChart, dataIndex, datasetIndex = 0) {
    // Step 1: Get the actual timestamp from the hovered point
    const hoveredTimestamp = getTimestampFromChartPoint(sourceChart, dataIndex, datasetIndex);
    if (!hoveredTimestamp) {
        hideHoverSummary();
        return;
    }

    // Step 2: Sync other charts by finding matching timestamps
    Object.keys(charts).forEach(chartKey => {
        const chart = charts[chartKey];
        if (!chart || chart === sourceChart) return;

        let matchedIndex = -1;

        if (chartKey === 'interface') {
            // Interface chart uses {x, y} format - find closest point in first visible dataset
            const visibleDatasets = chart.data.datasets.filter(ds => !ds.hidden);
            if (visibleDatasets.length > 0 && visibleDatasets[0].data.length > 0) {
                const timestamps = visibleDatasets[0].data.map(p => new Date(p.x));
                matchedIndex = findClosestTimestampIndex(timestamps, hoveredTimestamp, 60000);
            }
        } else {
            // Other charts use labels array
            if (chart.data.labels && chart.data.labels.length > 0) {
                const timestamps = chart.data.labels.map(t => new Date(t));
                matchedIndex = findClosestTimestampIndex(timestamps, hoveredTimestamp, 60000);
            }
        }

        if (matchedIndex >= 0) {
            // Set active elements for matched index
            const activeElements = chart.data.datasets
                .map((dataset, dsIndex) => ({
                    datasetIndex: dsIndex,
                    index: matchedIndex
                }))
                .filter((_, dsIndex) => !chart.data.datasets[dsIndex].hidden);

            chart.setActiveElements(activeElements);
            chart.tooltip.setActiveElements(activeElements, {x: 0, y: 0});
            chart.update('none');
        } else {
            // No matching point found - clear this chart's tooltip
            chart.setActiveElements([]);
            chart.tooltip.setActiveElements([], {x: 0, y: 0});
            chart.update('none');
        }
    });

    // Step 3: Update hover summary using timestamp-based lookup
    updateHoverSummaryByTimestamp(hoveredTimestamp);
}

// Timestamp-based hover summary update
function updateHoverSummaryByTimestamp(targetTimestamp) {
    // CPU/pbuf data now comes from vendor-specific tables
    if (!lastFetchedVendorMetrics || lastFetchedVendorMetrics.length === 0) return;

    const targetMs = targetTimestamp.getTime();
    const toleranceMs = 60000; // 60 second tolerance

    // Find closest vendor metrics point (CPU, memory, pbuf are in vendor tables)
    const reversedVendorData = [...lastFetchedVendorMetrics].reverse();
    let closestVendorIndex = -1;
    let closestVendorDiff = Infinity;

    reversedVendorData.forEach((item, index) => {
        const itemMs = new Date(item.timestamp).getTime();
        const diff = Math.abs(itemMs - targetMs);
        if (diff < closestVendorDiff) {
            closestVendorDiff = diff;
            closestVendorIndex = index;
        }
    });

    // Update timestamp display
    document.getElementById('hoverSummaryTime').textContent = targetTimestamp.toLocaleString();

    if (vendorType === 'fortinet') {
        // Fortinet-specific hover data - all from vendor metrics
        const hoverCpuEl = document.getElementById('hoverCpu');
        const hoverMemoryEl = document.getElementById('hoverFortinetMemory');
        const hoverSetupRateEl = document.getElementById('hoverSessionSetupRate');  // Now in session section
        const hoverNpuEl = document.getElementById('hoverFortinetNpu');

        if (closestVendorIndex === -1 || closestVendorDiff > toleranceMs) {
            if (hoverCpuEl) hoverCpuEl.innerHTML = '<span style="color: #95a5a6;">-- (no data)</span>';
            if (hoverMemoryEl) hoverMemoryEl.innerHTML = '<span style="color: #95a5a6;">-- (no data)</span>';
            if (hoverSetupRateEl) hoverSetupRateEl.innerHTML = '<span style="color: #95a5a6;">-- (no data)</span>';
            if (hoverNpuEl) hoverNpuEl.innerHTML = '<span style="color: #95a5a6;">-- (no data)</span>';
        } else {
            // All Fortinet data now comes from vendor metrics table
            const vendorPoint = reversedVendorData[closestVendorIndex];

            // Update CPU from vendor metrics
            if (hoverCpuEl) {
                hoverCpuEl.innerHTML = `${formatValue(vendorPoint.cpu_usage)} <span style="color: #95a5a6;">%</span>`;
            }
            if (hoverMemoryEl) {
                hoverMemoryEl.innerHTML = `${formatValue(vendorPoint.memory_usage_percent)} <span style="color: #95a5a6;">%</span>`;
            }
            if (hoverSetupRateEl) {
                hoverSetupRateEl.innerHTML = `${formatValue(vendorPoint.session_setup_rate, 1)} <span style="color: #95a5a6;">/s</span>`;
            }
            if (hoverNpuEl) {
                hoverNpuEl.innerHTML = `${formatValue(vendorPoint.npu_sessions, 0)}`;
            }
        }
    } else {
        // Palo Alto-specific hover data - all from vendor metrics table
        if (closestVendorIndex === -1 || closestVendorDiff > toleranceMs) {
            // No matching metrics data point - show "no data" indicators
            document.getElementById('hoverMgmtCpu').innerHTML = '<span style="color: #95a5a6;">-- (no data)</span>';
            document.getElementById('hoverDpCpu').innerHTML = '<span style="color: #95a5a6;">-- (no data)</span>';
            document.getElementById('hoverPbuf').innerHTML = '<span style="color: #95a5a6;">-- (no data)</span>';
        } else {
            const vendorPoint = reversedVendorData[closestVendorIndex];

            // Update CPU values from vendor metrics
            document.getElementById('hoverMgmtCpu').innerHTML =
                `${formatValue(vendorPoint.mgmt_cpu)} <span style="color: #95a5a6;">%</span>`;

            let dpCpuValue, dpCpuLabel;
            switch(currentCpuAggregation) {
                case 'max':
                    dpCpuValue = vendorPoint.data_plane_cpu_max;
                    dpCpuLabel = 'Data Plane CPU (Max):';
                    break;
                case 'p95':
                    dpCpuValue = vendorPoint.data_plane_cpu_p95;
                    dpCpuLabel = 'Data Plane CPU (P95):';
                    break;
                default:
                    dpCpuValue = vendorPoint.data_plane_cpu_mean;
                    dpCpuLabel = 'Data Plane CPU (Mean):';
            }
            document.getElementById('hoverDpCpuLabel').textContent = dpCpuLabel;
            document.getElementById('hoverDpCpu').innerHTML =
                `${formatValue(dpCpuValue)} <span style="color: #95a5a6;">%</span>`;

            // Update packet buffer from vendor metrics
            document.getElementById('hoverPbuf').innerHTML =
                `${formatValue(vendorPoint.pbuf_util_percent)} <span style="color: #95a5a6;">%</span>`;
        }
    }

    // Update interface data using timestamp matching
    const interfaceSection = document.getElementById('hoverInterfaceSection');
    const interfaceDataDiv = document.getElementById('hoverInterfaceData');
    const interfaceSectionTitle = document.getElementById('hoverInterfaceSectionTitle');

    // Update section title based on current unit
    if (interfaceSectionTitle) {
        interfaceSectionTitle.textContent = currentInterfaceUnit === 'mbps'
            ? 'Interface Bandwidth'
            : 'Interface Packets';
    }

    if (selectedInterfaces.length > 0 && Object.keys(lastFetchedInterfaceData).length > 0) {
        interfaceSection.style.display = 'block';
        let interfaceHtml = '';

        // Determine which fields to display based on current unit
        const isMbps = currentInterfaceUnit === 'mbps';
        const rxField = isMbps ? 'rx_mbps' : 'rx_pps';
        const txField = isMbps ? 'tx_mbps' : 'tx_pps';
        const unit = isMbps ? 'Mbps' : 'PPS';

        selectedInterfaces.forEach(interfaceName => {
            const interfaceData = lastFetchedInterfaceData[interfaceName];
            if (interfaceData && interfaceData.length > 0) {
                // Find closest interface data point by timestamp
                const reversedInterfaceData = [...interfaceData].reverse();
                let closestIfaceIndex = -1;
                let closestIfaceDiff = Infinity;

                reversedInterfaceData.forEach((item, index) => {
                    const itemMs = new Date(item.timestamp).getTime();
                    const diff = Math.abs(itemMs - targetMs);
                    if (diff < closestIfaceDiff) {
                        closestIfaceDiff = diff;
                        closestIfaceIndex = index;
                    }
                });

                const displayName = getInterfaceDisplayName(interfaceName, window.currentInterfaceConfig);

                // Ensure valid match within tolerance
                const withinTolerance = closestIfaceIndex >= 0 &&
                                        Number.isFinite(closestIfaceDiff) &&
                                        closestIfaceDiff <= toleranceMs;

                if (withinTolerance) {
                    const interfacePoint = reversedInterfaceData[closestIfaceIndex];
                    const rxValue = interfacePoint[rxField] || 0;
                    const txValue = interfacePoint[txField] || 0;
                    // Format PPS with commas for readability, Mbps with decimals
                    const rxDisplay = isMbps ? formatValue(rxValue) : Math.round(rxValue).toLocaleString();
                    const txDisplay = isMbps ? formatValue(txValue) : Math.round(txValue).toLocaleString();
                    interfaceHtml += `
                        <div class="hover-summary-item">
                            <span class="hover-summary-label">${displayName}:</span>
                            <span class="hover-summary-value">
                                ${rxDisplay} / ${txDisplay} <span style="color: #95a5a6;">${unit}</span>
                            </span>
                        </div>
                    `;
                } else {
                    // No matching interface data at this timestamp
                    interfaceHtml += `
                        <div class="hover-summary-item">
                            <span class="hover-summary-label">${displayName}:</span>
                            <span class="hover-summary-value" style="color: #95a5a6;">-- (no data)</span>
                        </div>
                    `;
                }
            }
        });

        interfaceDataDiv.innerHTML = interfaceHtml ||
            '<div style="color: #95a5a6; font-style: italic; text-align: center;">No interface data available</div>';
    } else {
        interfaceSection.style.display = 'none';
    }

    // Update session statistics using timestamp matching
    const sessionSection = document.getElementById('hoverSessionSection');
    if (lastFetchedSessionStats && lastFetchedSessionStats.length > 0) {
        sessionSection.style.display = 'block';

        // Find closest session data point by timestamp
        const reversedSessionData = [...lastFetchedSessionStats].reverse();
        let closestSessionIndex = -1;
        let closestSessionDiff = Infinity;

        reversedSessionData.forEach((item, index) => {
            const itemMs = new Date(item.timestamp).getTime();
            const diff = Math.abs(itemMs - targetMs);
            if (diff < closestSessionDiff) {
                closestSessionDiff = diff;
                closestSessionIndex = index;
            }
        });

        if (closestSessionIndex >= 0 && closestSessionDiff <= toleranceMs) {
            const sessionPoint = reversedSessionData[closestSessionIndex];
            document.getElementById('hoverActiveSessions').innerHTML =
                `${formatValue(sessionPoint.active_sessions, 0)} <span style="color: #95a5a6;">sessions</span>`;
        } else {
            document.getElementById('hoverActiveSessions').innerHTML =
                '<span style="color: #95a5a6;">-- (no data)</span>';
        }
    } else {
        sessionSection.style.display = 'none';
    }

    // Show the summary card
    document.getElementById('hoverSummary').classList.add('visible');
}

function hideHoverSummary() {
    document.getElementById('hoverSummary').classList.remove('visible');

    // Clear all chart tooltips
    Object.keys(charts).forEach(chartKey => {
        const chart = charts[chartKey];
        if (chart) {
            chart.setActiveElements([]);
            chart.tooltip.setActiveElements([], {x: 0, y: 0});
            chart.update('none');
        }
    });
}

// Event listeners
document.getElementById('autoRefresh').addEventListener('change', function(e) {
    autoRefreshEnabled = e.target.checked;
    setupAutoRefresh();
});

// CPU aggregation selector (Palo Alto only)
const cpuAggregationEl = document.getElementById('cpuAggregation');
if (cpuAggregationEl) {
    cpuAggregationEl.addEventListener('change', function(e) {
        currentCpuAggregation = e.target.value;
        refreshData();
    });
}

document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        if (refreshInterval) {
            clearInterval(refreshInterval);
        }
    } else {
        setupAutoRefresh();
    }
});
