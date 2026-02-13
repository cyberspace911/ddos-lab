// Main JavaScript for DDoS Dashboard

// Global variables
let currentUser = null;
let authToken = localStorage.getItem('ddos_auth_token');
let socket = null;
let charts = {};

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Check authentication
    if (!authToken && !window.location.pathname.includes('login')) {
        window.location.href = '/login';
        return;
    }
    
    // Initialize components
    initSidebar();
    initNotifications();
    initWebSocket();
    
    // Load initial data based on current page
    loadPageData();
    
    // Start periodic updates
    startPeriodicUpdates();
});

// Sidebar functionality
function initSidebar() {
    // Highlight current page in sidebar
    const currentPath = window.location.pathname;
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        const href = item.getAttribute('href');
        if (href === currentPath) {
            item.classList.add('active');
        }
        
        item.addEventListener('click', function(e) {
            navItems.forEach(i => i.classList.remove('active'));
            this.classList.add('active');
        });
    });
    
    // Mobile menu toggle
    const mobileMenuToggle = document.querySelector('[onclick="toggleMobileMenu()"]');
    if (mobileMenuToggle) {
        mobileMenuToggle.addEventListener('click', toggleMobileMenu);
    }
}

// Toggle mobile menu
function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    if (mobileMenu) {
        mobileMenu.classList.toggle('hidden');
    }
}

// Notification system
function initNotifications() {
    // Create notification container if it doesn't exist
    if (!document.getElementById('notification-container')) {
        const container = document.createElement('div');
        container.id = 'notification-container';
        container.className = 'fixed top-4 right-4 z-50 space-y-2';
        document.body.appendChild(container);
    }
}

// Show notification
function showNotification(message, type = 'info', duration = 3000) {
    const container = document.getElementById('notification-container');
    if (!container) return;
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    
    notification.innerHTML = `
        <div class="flex items-center p-4 rounded-lg shadow-lg ${getNotificationColor(type)}">
            <i class="fas ${icons[type] || icons.info} mr-3"></i>
            <span>${message}</span>
            <button class="ml-4 text-sm opacity-75 hover:opacity-100" onclick="this.parentElement.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        </div>
    `;
    
    container.appendChild(notification);
    
    // Auto-remove after duration
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, duration);
    
    return notification;
}

function getNotificationColor(type) {
    const colors = {
        success: 'bg-green-500 text-white',
        error: 'bg-red-500 text-white',
        warning: 'bg-yellow-500 text-white',
        info: 'bg-blue-500 text-white'
    };
    return colors[type] || colors.info;
}

// WebSocket connection
function initWebSocket() {
    if (!authToken) return;
    
    try {
        socket = io();
        
        socket.on('connect', () => {
            console.log('WebSocket connected');
            showNotification('Connected to real-time updates', 'success', 2000);
        });
        
        socket.on('disconnect', () => {
            console.log('WebSocket disconnected');
            showNotification('Disconnected from real-time updates', 'warning', 2000);
        });
        
        socket.on('real_time_metrics', handleRealTimeMetrics);
        socket.on('attack_detected', handleAttackDetection);
        socket.on('incident_created', handleNewIncident);
        
    } catch (error) {
        console.error('WebSocket connection failed:', error);
    }
}

// Handle real-time metrics
function handleRealTimeMetrics(data) {
    // Update dashboard if we're on the dashboard page
    if (window.updateDashboardMetrics) {
        window.updateDashboardMetrics(data);
    }
    
    // Update sidebar stats
    updateSidebarStats(data);
}

// Update sidebar statistics
function updateSidebarStats(data) {
    const defenseLevel = document.getElementById('sidebar-defense-level');
    const uptime = document.getElementById('sidebar-uptime');
    const load = document.getElementById('sidebar-load');
    
    if (defenseLevel) {
        // This would come from the actual defense level
        defenseLevel.textContent = 'Enterprise';
    }
    
    if (uptime && data.timestamp) {
        const now = new Date();
        const timestamp = new Date(data.timestamp);
        const diff = Math.floor((now - timestamp) / 1000);
        
        if (diff < 60) {
            uptime.textContent = 'Just now';
        } else if (diff < 3600) {
            uptime.textContent = `${Math.floor(diff / 60)}m ago`;
        } else {
            uptime.textContent = `${Math.floor(diff / 3600)}h ago`;
        }
    }
    
    if (load && data.cpu) {
        load.textContent = data.cpu.load.toFixed(2);
    }
}

// Handle attack detection
function handleAttackDetection(data) {
    showNotification(`Attack detected: ${data.type}`, 'error');
    
    // Update incident count
    updateIncidentCount();
    
    // Show attack banner if on dashboard
    const attackBanner = document.getElementById('attack-alert');
    if (attackBanner) {
        attackBanner.classList.remove('hidden');
        const details = document.getElementById('attack-details');
        if (details) {
            details.textContent = `${data.type} detected with ${data.confidence}% confidence`;
        }
    }
}

// Handle new incident
function handleNewIncident(data) {
    showNotification(`New incident created: ${data.incident_id}`, 'warning');
    updateIncidentCount();
}

// Update incident count
async function updateIncidentCount() {
    try {
        const response = await apiRequest('/incidents');
        if (response) {
            const openIncidents = response.filter(i => i.status === 'open').length;
            
            // Update all incident count elements
            document.querySelectorAll('.incident-count').forEach(element => {
                element.textContent = openIncidents;
                if (openIncidents > 0) {
                    element.classList.remove('hidden');
                }
            });
        }
    } catch (error) {
        console.error('Failed to update incident count:', error);
    }
}

// API request helper
async function apiRequest(endpoint, method = 'GET', data = null) {
    const headers = {
        'Content-Type': 'application/json'
    };
    
    if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }
    
    const options = {
        method,
        headers
    };
    
    if (data) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`/api${endpoint}`, options);
        
        if (response.status === 401) {
            // Unauthorized - redirect to login
            localStorage.removeItem('ddos_auth_token');
            window.location.href = '/login';
            return null;
        }
        
        if (!response.ok) {
            throw new Error(`API request failed: ${response.status}`);
        }
        
        return await response.json();
        
    } catch (error) {
        console.error('API request failed:', error);
        showNotification(`API request failed: ${error.message}`, 'error');
        return null;
    }
}

// Load page-specific data
function loadPageData() {
    const path = window.location.pathname;
    
    switch (path) {
        case '/dashboard':
            loadDashboardData();
            break;
        case '/firewall':
            loadFirewallData();
            break;
        case '/incidents':
            loadIncidentsData();
            break;
        case '/reports':
            loadReportsData();
            break;
        case '/settings':
            loadSettingsData();
            break;
    }
}

// Load dashboard data
async function loadDashboardData() {
    try {
        const metrics = await apiRequest('/metrics');
        if (metrics && window.updateDashboardMetrics) {
            window.updateDashboardMetrics(metrics);
        }
        
        // Load recent incidents
        const incidents = await apiRequest('/incidents?limit=5');
        if (incidents && window.updateRecentIncidents) {
            window.updateRecentIncidents(incidents);
        }
        
    } catch (error) {
        console.error('Failed to load dashboard data:', error);
    }
}

// Load firewall data
async function loadFirewallData() {
    try {
        const rules = await apiRequest('/firewall/rules');
        if (rules && window.updateFirewallRules) {
            window.updateFirewallRules(rules);
        }
    } catch (error) {
        console.error('Failed to load firewall data:', error);
    }
}

// Load incidents data
async function loadIncidentsData() {
    try {
        const incidents = await apiRequest('/incidents');
        if (incidents && window.updateIncidentsList) {
            window.updateIncidentsList(incidents);
        }
    } catch (error) {
        console.error('Failed to load incidents data:', error);
    }
}

// Load reports data
async function loadReportsData() {
    try {
        const metricsHistory = await apiRequest('/metrics/history?limit=100');
        if (metricsHistory && window.updateReportsData) {
            window.updateReportsData(metricsHistory);
        }
    } catch (error) {
        console.error('Failed to load reports data:', error);
    }
}

// Load settings data
async function loadSettingsData() {
    try {
        const settings = await apiRequest('/settings');
        if (settings && window.updateSettingsForm) {
            window.updateSettingsForm(settings);
        }
    } catch (error) {
        console.error('Failed to load settings data:', error);
    }
}

// Start periodic updates
function startPeriodicUpdates() {
    // Update data every 30 seconds
    setInterval(() => {
        loadPageData();
    }, 30000);
    
    // Update time every second
    setInterval(updateCurrentTime, 1000);
    updateCurrentTime();
}

// Update current time display
function updateCurrentTime() {
    const timeElements = document.querySelectorAll('.current-time');
    const now = new Date();
    const timeString = now.toLocaleTimeString();
    const dateString = now.toLocaleDateString();
    
    timeElements.forEach(element => {
        element.textContent = `${dateString} ${timeString}`;
    });
}

// Format bytes to human readable
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Format time
function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Format date
function formatDate(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleDateString();
}

// Format relative time
function formatRelativeTime(timestamp) {
    const now = new Date();
    const date = new Date(timestamp);
    const diff = Math.floor((now - date) / 1000);
    
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
    if (diff < 604800) return `${Math.floor(diff / 86400)} days ago`;
    
    return formatDate(timestamp);
}

// Create chart
function createChart(canvasId, config) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    // Destroy existing chart if it exists
    if (charts[canvasId]) {
        charts[canvasId].destroy();
    }
    
    // Create new chart
    charts[canvasId] = new Chart(ctx.getContext('2d'), config);
    return charts[canvasId];
}

// Logout function
function logout() {
    if (confirm('Are you sure you want to logout?')) {
        localStorage.removeItem('ddos_auth_token');
        window.location.href = '/login';
    }
}

// Export data
function exportData(data, filename, type = 'json') {
    let content, mimeType;
    
    if (type === 'json') {
        content = JSON.stringify(data, null, 2);
        mimeType = 'application/json';
    } else if (type === 'csv') {
        content = convertToCSV(data);
        mimeType = 'text/csv';
    } else {
        throw new Error('Unsupported export type');
    }
    
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    
    URL.revokeObjectURL(url);
    showNotification(`Data exported as ${filename}`, 'success');
}

// Convert data to CSV
function convertToCSV(data) {
    if (!Array.isArray(data) || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const rows = data.map(row => 
        headers.map(header => 
            JSON.stringify(row[header] || '')
        ).join(',')
    );
    
    return [headers.join(','), ...rows].join('\n');
}

// Debounce function for performance
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Throttle function for performance
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// Error boundary for async operations
async function withErrorBoundary(operation, errorMessage) {
    try {
        return await operation();
    } catch (error) {
        console.error(`${errorMessage}:`, error);
        showNotification(`${errorMessage}: ${error.message}`, 'error');
        return null;
    }
}

// Initialize modals
function initModal(modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    
    // Close modal on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
            modal.classList.add('hidden');
        }
    });
    
    // Close modal on background click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
        }
    });
}

// Show modal
function showModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }
}

// Hide modal
function hideModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = 'auto';
    }
}

// Initialize tooltips
function initTooltips() {
    const tooltips = document.querySelectorAll('[data-tooltip]');
    
    tooltips.forEach(element => {
        element.addEventListener('mouseenter', function() {
            const tooltipText = this.getAttribute('data-tooltip');
            if (!tooltipText) return;
            
            const tooltip = document.createElement('div');
            tooltip.className = 'tooltip';
            tooltip.textContent = tooltipText;
            tooltip.style.position = 'absolute';
            tooltip.style.zIndex = '1000';
            tooltip.style.background = 'rgba(0,0,0,0.9)';
            tooltip.style.color = 'white';
            tooltip.style.padding = '5px 10px';
            tooltip.style.borderRadius = '4px';
            tooltip.style.fontSize = '12px';
            
            document.body.appendChild(tooltip);
            
            const rect = this.getBoundingClientRect();
            tooltip.style.left = `${rect.left + rect.width / 2 - tooltip.offsetWidth / 2}px`;
            tooltip.style.top = `${rect.top - tooltip.offsetHeight - 5}px`;
            
            this._tooltip = tooltip;
        });
        
        element.addEventListener('mouseleave', function() {
            if (this._tooltip) {
                this._tooltip.remove();
                this._tooltip = null;
            }
        });
    });
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard', 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showNotification('Failed to copy to clipboard', 'error');
    });
}

// Validate IP address
function isValidIP(ip) {
    const pattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (!pattern.test(ip)) return false;
    
    const parts = ip.split('/')[0].split('.');
    return parts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
    });
}

// Validate port
function isValidPort(port) {
    const num = parseInt(port, 10);
    return !isNaN(num) && num >= 1 && num <= 65535;
}

// Create UUID
function createUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Get query parameters
function getQueryParams() {
    const params = {};
    const queryString = window.location.search.substring(1);
    const pairs = queryString.split('&');
    
    pairs.forEach(pair => {
        const [key, value] = pair.split('=');
        if (key) {
            params[decodeURIComponent(key)] = decodeURIComponent(value || '');
        }
    });
    
    return params;
}

// Set query parameters
function setQueryParams(params) {
    const queryString = Object.entries(params)
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        .join('&');
    
    const newUrl = window.location.pathname + (queryString ? `?${queryString}` : '');
    window.history.pushState({}, '', newUrl);
}

// Initialize all modals on page load
document.addEventListener('DOMContentLoaded', () => {
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        initModal(modal.id);
    });
    
    initTooltips();
});

// Export utility functions
window.DDOSDashboard = {
    showNotification,
    apiRequest,
    formatBytes,
    formatTime,
    formatDate,
    formatRelativeTime,
    createChart,
    exportData,
    copyToClipboard,
    isValidIP,
    isValidPort,
    createUUID,
    getQueryParams,
    setQueryParams,
    logout
};
