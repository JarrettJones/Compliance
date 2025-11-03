// Main JavaScript for Firmware Version Checker

// Global variables
let currentCheckId = null;
let checkInterval = null;

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize any other components
    initializeFormValidation();
    initializeDataTables();
}

// Form validation utilities
function initializeFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
}

// Data tables initialization (if needed)
function initializeDataTables() {
    // This can be extended to add DataTables or other table enhancements
    const tables = document.querySelectorAll('.data-table');
    tables.forEach(table => {
        // Add sorting, filtering, etc. if needed
    });
}

// Utility functions
function showAlert(message, type = 'info', duration = 5000) {
    const alertContainer = document.getElementById('alert-container') || createAlertContainer();
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    alertContainer.appendChild(alertDiv);
    
    // Auto-hide after duration
    if (duration > 0) {
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, duration);
    }
}

function createAlertContainer() {
    const container = document.createElement('div');
    container.id = 'alert-container';
    container.className = 'fixed-top';
    container.style.top = '80px';
    container.style.right = '20px';
    container.style.left = '20px';
    container.style.zIndex = '1060';
    document.body.appendChild(container);
    return container;
}

// Loading state management
function setLoading(element, loading = true) {
    if (loading) {
        element.classList.add('loading');
        if (element.tagName === 'BUTTON') {
            element.disabled = true;
            element.dataset.originalHtml = element.innerHTML;
            element.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Loading...';
        }
    } else {
        element.classList.remove('loading');
        if (element.tagName === 'BUTTON') {
            element.disabled = false;
            if (element.dataset.originalHtml) {
                element.innerHTML = element.dataset.originalHtml;
                delete element.dataset.originalHtml;
            }
        }
    }
}

// API helper functions
async function apiCall(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    };
    
    const finalOptions = { ...defaultOptions, ...options };
    
    try {
        const response = await fetch(url, finalOptions);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('API call failed:', error);
        throw error;
    }
}

// Firmware checking utilities
function formatFirmwareVersion(version) {
    if (!version || version === 'PLACEHOLDER_VERSION') {
        return '<span class="text-muted">Not available</span>';
    }
    return `<code>${version}</code>`;
}

function getFirmwareStatusBadge(status) {
    const badges = {
        'success': '<span class="badge bg-success">Success</span>',
        'error': '<span class="badge bg-danger">Error</span>',
        'not_implemented': '<span class="badge bg-warning">Not Implemented</span>',
        'placeholder': '<span class="badge bg-secondary">Placeholder</span>'
    };
    
    return badges[status] || '<span class="badge bg-secondary">Unknown</span>';
}

// System management utilities
function validateIPAddress(ip) {
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    return ipRegex.test(ip);
}

function validatePortNumber(port) {
    const portNum = parseInt(port);
    return portNum >= 1 && portNum <= 65535;
}

// Data export utilities
function exportToJson(data, filename) {
    const dataStr = JSON.stringify(data, null, 2);
    downloadFile(dataStr, filename, 'application/json');
}

function exportToCsv(data, filename, headers) {
    let csvContent = headers.join(',') + '\n';
    
    data.forEach(row => {
        const csvRow = headers.map(header => {
            const value = row[header] || '';
            return `"${value.toString().replace(/"/g, '""')}"`;
        }).join(',');
        csvContent += csvRow + '\n';
    });
    
    downloadFile(csvContent, filename, 'text/csv');
}

function downloadFile(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    link.style.display = 'none';
    
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    URL.revokeObjectURL(url);
}

// Date/time utilities
function formatDateTime(dateString) {
    if (!dateString) return 'Never';
    
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatTimeAgo(dateString) {
    if (!dateString) return 'Never';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
    return `${Math.floor(diffInSeconds / 86400)} days ago`;
}

// Search and filter utilities
function setupSearch(inputId, tableId) {
    const searchInput = document.getElementById(inputId);
    const table = document.getElementById(tableId);
    
    if (!searchInput || !table) return;
    
    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const rows = table.querySelector('tbody').querySelectorAll('tr');
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(searchTerm) ? '' : 'none';
        });
    });
}

// Theme management (if needed for future dark mode)
function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
}

function getTheme() {
    return localStorage.getItem('theme') || 'light';
}

// Error handling
function handleError(error, context = '') {
    console.error(`Error ${context}:`, error);
    
    let message = 'An unexpected error occurred.';
    if (error.message) {
        message = error.message;
    } else if (typeof error === 'string') {
        message = error;
    }
    
    showAlert(message, 'danger');
}

// Confirmation dialogs
function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

// Copy to clipboard utility
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showAlert('Copied to clipboard!', 'success', 2000);
        return true;
    } catch (err) {
        console.error('Failed to copy to clipboard:', err);
        showAlert('Failed to copy to clipboard', 'danger', 3000);
        return false;
    }
}

// Progress tracking
function updateProgress(progressBar, percentage, text = '') {
    if (progressBar) {
        progressBar.style.width = percentage + '%';
        progressBar.setAttribute('aria-valuenow', percentage);
        
        if (text) {
            progressBar.textContent = text;
        }
    }
}

// WebSocket utilities (if needed for real-time updates)
function connectWebSocket(url, handlers = {}) {
    const ws = new WebSocket(url);
    
    ws.onopen = handlers.onOpen || function() {
        console.log('WebSocket connected');
    };
    
    ws.onmessage = handlers.onMessage || function(event) {
        console.log('WebSocket message:', event.data);
    };
    
    ws.onclose = handlers.onClose || function() {
        console.log('WebSocket disconnected');
    };
    
    ws.onerror = handlers.onError || function(error) {
        console.error('WebSocket error:', error);
    };
    
    return ws;
}

// Debounce utility for search inputs
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