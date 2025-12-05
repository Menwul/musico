// app.js - Shared JavaScript for SoundConnect
const API_BASE = window.location.origin + '/api';  // Dynamic base URL
let currentUser = null;
let socket = null;
let audioPlayer = new Audio();

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    checkAuth();
    updateAuthButtons();
    setupAudioPlayer();
});

// Check authentication and get user data
async function checkAuth() {
    const token = localStorage.getItem('token');
    const userStr = localStorage.getItem('user');
    
    if (token && userStr) {
        try {
            currentUser = JSON.parse(userStr);
            console.log('✅ User authenticated:', currentUser.username);
            
            // Connect WebSocket with token
            connectSocket(token);
            
            return currentUser;
        } catch (error) {
            console.error('❌ Failed to parse user data:', error);
            clearAuth();
            return null;
        }
    }
    
    return null;
}

// Update authentication buttons in navbar
function updateAuthButtons() {
    const authButtons = document.querySelector('.auth-buttons');
    if (!authButtons) return;
    
    const user = checkAuth();
    
    if (user) {
        authButtons.innerHTML = `
            <div style="display: flex; align-items: center; gap: 1rem;">
                <a href="/profile" class="btn btn-outline" style="display: flex; align-items: center; gap: 0.5rem;">
                    <i class="fas fa-user"></i>
                    <span>${user.display_name || user.username}</span>
                </a>
                <button onclick="logout()" class="btn btn-outline" style="display: flex; align-items: center; gap: 0.5rem;">
                    <i class="fas fa-sign-out-alt"></i>
                    <span>Logout</span>
                </button>
            </div>
        `;
    } else {
        authButtons.innerHTML = `
            <div style="display: flex; align-items: center; gap: 1rem;">
                <a href="/login" class="btn btn-outline">Login</a>
                <a href="/register" class="btn btn-primary">Sign Up</a>
            </div>
        `;
    }
}

// Show notification
function showNotification(message, type = 'info', duration = 3000) {
    // Remove existing notifications
    const existing = document.querySelectorAll('.notification');
    existing.forEach(n => n.remove());
    
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    
    // Get icon based on type
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    
    notification.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; width: 100%;">
            <div style="display: flex; align-items: center; gap: 0.5rem;">
                <i class="fas fa-${icons[type] || 'info-circle'}"></i>
                <span>${message}</span>
            </div>
            <button onclick="this.parentElement.parentElement.remove()" 
                    style="background: none; border: none; color: white; font-size: 1.2rem; cursor: pointer;">
                &times;
            </button>
        </div>
    `;
    
    // Add styles if not already present
    if (!document.querySelector('#notification-styles')) {
        const styles = document.createElement('style');
        styles.id = 'notification-styles';
        styles.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                background: var(--dark-light);
                color: white;
                padding: 1rem 1.5rem;
                border-radius: 8px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                z-index: 9999;
                min-width: 300px;
                max-width: 400px;
                border-left: 4px solid var(--primary);
                animation: slideIn 0.3s ease-out;
            }
            
            .notification-success {
                border-left-color: var(--success);
            }
            
            .notification-error {
                border-left-color: var(--danger);
            }
            
            .notification-warning {
                border-left-color: var(--warning);
            }
            
            .notification-info {
                border-left-color: var(--info);
            }
            
            @keyframes slideIn {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(styles);
    }
    
    // Add to page
    document.body.appendChild(notification);
    
    // Remove after duration
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, duration);
}

// Logout function
async function logout() {
    try {
        const token = localStorage.getItem('token');
        
        // Call logout API
        const response = await fetch(`${API_BASE}/logout`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        // Disconnect socket
        if (socket) {
            socket.disconnect();
            socket = null;
        }
        
        // Clear local storage
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        currentUser = null;
        
        // Update navbar
        updateAuthButtons();
        
        showNotification('Logged out successfully', 'success');
        
        // Redirect to home page
        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
        
    } catch (error) {
        console.error('Logout error:', error);
        
        // Still clear local storage even if API fails
        clearAuth();
        
        showNotification('Logged out', 'info');
        
        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
    }
}

// Clear authentication
function clearAuth() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    currentUser = null;
    if (socket) {
        socket.disconnect();
        socket = null;
    }
    updateAuthButtons();
}

// Setup audio player
function setupAudioPlayer() {
    audioPlayer.addEventListener('timeupdate', updateProgress);
    audioPlayer.addEventListener('ended', playNextTrack);
    audioPlayer.addEventListener('error', (e) => {
        console.error('Audio player error:', e);
        showNotification('Failed to play audio', 'error');
    });
}

function updateProgress() {
    const progress = document.querySelector('.progress');
    if (progress) {
        const percent = (audioPlayer.currentTime / audioPlayer.duration) * 100 || 0;
        progress.style.width = `${percent}%`;
    }
}

function playNextTrack() {
    console.log('Track ended');
    // Auto-play next track logic can be added here
}

// WebSocket connection
function connectSocket(token) {
    if (!token) {
        console.log('⚠️ No token available for WebSocket');
        return;
    }
    
    if (socket && socket.connected) {
        console.log('✅ WebSocket already connected');
        return;
    }
    
    try {
        console.log('🔌 Attempting WebSocket connection...');
        
        // Simple connection without complex options
        socket = io(window.location.origin, {
            query: { token: token },
            transports: ['polling']  // Start with polling only
        });
        
        socket.on('connect', () => {
            console.log('✅ WebSocket connected successfully');
            
            // Now try to upgrade to WebSocket if available
            if (socket.io.engine.transport.name === 'polling') {
                socket.io.engine.on('upgrade', () => {
                    console.log('🔄 Upgraded to WebSocket transport');
                });
            }
        });
        
        socket.on('connect_error', (error) => {
            console.error('❌ WebSocket connection error:', error.message);
            
            // Try without token if auth fails
            if (error.message.includes('auth') || error.message.includes('token')) {
                console.log('⚠️ Trying connection without token...');
                socket = io(window.location.origin);
            }
        });
        
        socket.on('disconnect', (reason) => {
            console.log('🔴 WebSocket disconnected:', reason);
            
            // Auto-reconnect after delay
            if (reason !== 'io server disconnect') {
                setTimeout(() => {
                    if (token) {
                        console.log('🔄 Attempting to reconnect...');
                        connectSocket(token);
                    }
                }, 3000);
            }
        });
        
        socket.on('connected', (data) => {
            console.log('📡 WebSocket authenticated:', data);
        });
        
        // Your other event handlers...
        
    } catch (error) {
        console.error('Failed to initialize WebSocket:', error);
    }
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
        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers
        });
        
        if (response.status === 401) {
            // Token expired or invalid
            clearAuth();
            showNotification('Session expired. Please login again.', 'error');
            setTimeout(() => {
                window.location.href = '/login';
            }, 1500);
            return null;
        }
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }
        
        return await response.json();
        
    } catch (error) {
        console.error('API request failed:', error);
        showNotification('Network error: ' + error.message, 'error');
        return null;
    }
}

// Require authentication - redirect if not logged in
function requireAuth() {
    const user = checkAuth();
    if (!user) {
        showNotification('Please login to continue', 'error');
        setTimeout(() => {
            window.location.href = '/login';
        }, 1500);
        return false;
    }
    return true;
}

// Play track
function playTrack(track) {
    if (!track || !track.file_url) {
        showNotification('No audio file available', 'error');
        return;
    }
    
    try {
        audioPlayer.src = track.file_url;
        audioPlayer.play().then(() => {
            showNotification(`Playing: ${track.title}`, 'success');
            
            // Update player UI if exists
            const playerInfo = document.querySelector('.player-info');
            if (playerInfo) {
                playerInfo.innerHTML = `
                    <div class="track-title">${track.title}</div>
                    <div class="track-artist">${track.artist?.display_name || 'Unknown Artist'}</div>
                `;
            }
            
            // Update play button
            const playBtn = document.querySelector('.play-btn');
            if (playBtn) {
                playBtn.innerHTML = '<i class="fas fa-pause"></i>';
            }
        }).catch(error => {
            console.error('Play error:', error);
            showNotification('Could not play audio', 'error');
        });
    } catch (error) {
        console.error('Play track error:', error);
        showNotification('Failed to play track', 'error');
    }
}

// Toggle play/pause
function togglePlay() {
    if (audioPlayer.paused) {
        audioPlayer.play().then(() => {
            const playBtn = document.querySelector('.play-btn');
            if (playBtn) playBtn.innerHTML = '<i class="fas fa-pause"></i>';
        }).catch(error => {
            showNotification('Failed to play', 'error');
        });
    } else {
        audioPlayer.pause();
        const playBtn = document.querySelector('.play-btn');
        if (playBtn) playBtn.innerHTML = '<i class="fas fa-play"></i>';
    }
}

// Helper: Format numbers with commas
function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Helper: Get time ago from timestamp
function getTimeAgo(timestamp) {
    if (!timestamp) return 'Just now';
    
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 60) {
        return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    } else if (diffHours < 24) {
        return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    } else if (diffDays < 7) {
        return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    } else if (diffDays < 30) {
        return Math.floor(diffDays / 7) + ' weeks ago';
    } else if (diffDays < 365) {
        return Math.floor(diffDays / 30) + ' months ago';
    } else {
        return Math.floor(diffDays / 365) + ' years ago';
    }
}

// Seek track
function seekTrack(e) {
    if (!audioPlayer.duration) return;
    
    const progressBar = e.currentTarget;
    const clickX = e.offsetX;
    const width = progressBar.clientWidth;
    const percent = clickX / width;
    
    audioPlayer.currentTime = percent * audioPlayer.duration;
}

// Export functions to window object
window.API_BASE = API_BASE;
window.checkAuth = checkAuth;
window.showNotification = showNotification;
window.requireAuth = requireAuth;
window.logout = logout;
window.playTrack = playTrack;
window.togglePlay = togglePlay;
window.formatNumber = formatNumber;
window.getTimeAgo = getTimeAgo;
window.apiRequest = apiRequest;