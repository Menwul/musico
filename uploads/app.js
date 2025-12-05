// app.js - Shared JavaScript for all pages
const API_BASE = window.location.origin;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    setupEventListeners();
});

// Setup global event listeners
function setupEventListeners() {
    // Global logout handler
    document.addEventListener('click', function(e) {
        if (e.target.matches('[data-logout]') || e.target.closest('[data-logout]')) {
            logout();
        }
    });
}

// Check authentication - SIMPLIFIED VERSION
async function checkAuth() {
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    
    if (token && userData) {
        try {
            // Don't automatically update nav, just store user
            currentUser = JSON.parse(userData);
        } catch (error) {
            console.error('Auth check failed:', error);
        }
    } else if (window.location.pathname.includes('dashboard')) {
        // Redirect from protected pages if no token
        window.location.href = '/login';
    }
}

// Show notification
function showNotification(message, type = 'info', duration = 3000) {
    // Create notification element
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    // Auto remove after duration
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, duration);
}

// Logout
async function logout() {
    const token = localStorage.getItem('token');
    
    // Clear local storage
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    
    showNotification('Logged out successfully', 'success');
    
    // Redirect to home page
    setTimeout(() => {
        window.location.href = '/';
    }, 1500);
}

// API Helper
async function apiRequest(endpoint, options = {}) {
    const token = localStorage.getItem('token');
    
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };
    
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api${endpoint}`, {
            ...options,
            headers
        });
        
        // Handle unauthorized
        if (response.status === 401) {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            showNotification('Session expired. Please log in again.', 'warning');
            
            if (window.location.pathname.includes('dashboard')) {
                setTimeout(() => {
                    window.location.href = '/login';
                }, 1000);
            }
            return null;
        }
        
        // Handle other errors
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            showNotification(error.message || `Error: ${response.status}`, 'error');
            return null;
        }
        
        return await response.json();
    } catch (error) {
        console.error('API request failed:', error);
        showNotification('Network error. Please check your connection.', 'error');
        return null;
    }
}

// Redirect if not logged in
function requireAuth() {
    const token = localStorage.getItem('token');
    if (!token) {
        showNotification('Please log in to perform this action', 'warning');
        
        // If on a protected page, redirect to login
        if (window.location.pathname.includes('dashboard') || 
            window.location.pathname.includes('upload')) {
            setTimeout(() => {
                window.location.href = '/login';
            }, 1500);
        }
        return false;
    }
    return true;
}

// Make functions globally available
window.API_BASE = API_BASE;
window.requireAuth = requireAuth;
window.showNotification = showNotification;
window.logout = logout;
window.apiRequest = apiRequest;