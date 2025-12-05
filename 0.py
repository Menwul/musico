import os
import re

def create_follow_fix_script():
    """Create a proper script to fix the follow page"""
    
    script_content = '''import os
import re

def fix_follow_page(file_path):
    """Fix the follow.html page completely"""
    print(f"🔧 Fixing {file_path}...")
    
    # Read the current file
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return False
    
    # Create backup
    backup_path = file_path + '.backup_fixed'
    try:
        with open(backup_path, 'w', encoding='utf-8') as backup_file:
            backup_file.write(content)
        print(f"📁 Backup created: {backup_path}")
    except Exception as e:
        print(f"❌ Error creating backup: {e}")
        return False
    
    # Find the script section
    script_start = content.find('<script>')
    script_end = content.find('</script>')
    
    if script_start == -1 or script_end == -1:
        print("❌ Could not find script tags in the file")
        return False
    
    # The new fixed JavaScript code
    new_js = '''<script>
        // Global variables
        let currentUser = null;
        let currentTab = 'all';
        let isLoading = false;
        
        // DOM Elements
        const usersGrid = document.getElementById('usersGrid');
        const emptyState = document.getElementById('emptyState');
        const emptyMessage = document.getElementById('emptyMessage');
        const searchUsersInput = document.getElementById('searchUsersInput');
        const userStats = document.getElementById('userStats');
        
        // Check authentication
        document.addEventListener('DOMContentLoaded', async function() {
            console.log('Follow page loading...');
            
            const token = localStorage.getItem('token');
            if (!token) {
                window.location.href = '/login';
                return;
            }
            
            try {
                // Get current user
                const response = await fetch('/api/users/me', {
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error('Failed to get user');
                }
                
                currentUser = await response.json();
                console.log('Current user:', currentUser.username);
                
                // Update user stats
                if (userStats && currentUser) {
                    document.getElementById('currentFollowers').textContent = currentUser.followers_count || 0;
                    document.getElementById('currentFollowing').textContent = currentUser.following_count || 0;
                    document.getElementById('currentTracks').textContent = currentUser.tracks_count || 0;
                    userStats.style.display = 'block';
                }
                
                // Load users
                await loadUsers();
                
                // Update nav buttons
                updateNavAuthButtons();
                
            } catch (error) {
                console.error('Initialization error:', error);
                alert('Failed to load page: ' + error.message);
            }
        });
        
        // Load users
        async function loadUsers() {
            if (isLoading) return;
            
            isLoading = true;
            usersGrid.innerHTML = '<div class="loading"><div class="loading-spinner"></div><p>Loading artists...</p></div>';
            emptyState.style.display = 'none';
            
            try {
                let url = '/api/chat/users';
                if (currentTab === 'following' && currentUser) {
                    url = '/api/users/' + currentUser.id + '/following';
                } else if (currentTab === 'followers' && currentUser) {
                    url = '/api/users/' + currentUser.id + '/followers';
                }
                
                const token = localStorage.getItem('token');
                const response = await fetch(url, {
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error('Failed to load users');
                }
                
                const result = await response.json();
                const users = result.users || result.following || result.followers || [];
                
                if (users.length === 0) {
                    showEmptyState();
                    return;
                }
                
                renderUsers(users);
                
            } catch (error) {
                console.error('Error loading users:', error);
                usersGrid.innerHTML = '<div style="text-align: center; padding: 3rem; color: red;">Failed to load artists. Please try again.</div>';
            } finally {
                isLoading = false;
            }
        }
        
        // Render users
        function renderUsers(users) {
            usersGrid.innerHTML = '';
            emptyState.style.display = 'none';
            
            users.forEach(user => {
                const userCard = document.createElement('div');
                userCard.className = 'user-card';
                
                userCard.innerHTML = `
                    <img src="${user.profile_pic || 'https://via.placeholder.com/100/8a2be2/ffffff?text=' + (user.username ? user.username.charAt(0).toUpperCase() : 'U')}" 
                         class="user-avatar"
                         onclick="viewProfile(${user.id})"
                         style="cursor: pointer;">
                    
                    <div class="user-info">
                        <div class="user-name" onclick="viewProfile(${user.id})" style="cursor: pointer;">
                            ${user.display_name || user.username}
                        </div>
                        <div class="user-username">@${user.username}</div>
                        
                        <div class="user-bio">${user.bio || 'No bio yet'}</div>
                        
                        <div class="user-stats">
                            <div class="user-stat">
                                <i class="fas fa-music"></i>
                                <span>${user.tracks_count || 0} tracks</span>
                            </div>
                        </div>
                    </div>
                    
                    <div>
                        <button class="btn btn-primary follow-btn" 
                                onclick="toggleFollow(${user.id}, this)">
                            <i class="fas fa-user-plus"></i> Follow
                        </button>
                    </div>
                `;
                
                usersGrid.appendChild(userCard);
            });
        }
        
        // Show empty state
        function showEmptyState() {
            usersGrid.innerHTML = '';
            emptyState.style.display = 'block';
            
            if (currentTab === 'following') {
                emptyMessage.textContent = 'You are not following any artists yet';
            } else if (currentTab === 'followers') {
                emptyMessage.textContent = 'No one is following you yet';
            } else {
                emptyMessage.textContent = 'No artists found';
            }
        }
        
        // Toggle follow/unfollow
        async function toggleFollow(userId, button) {
            if (!currentUser) return;
            
            try {
                const token = localStorage.getItem('token');
                const response = await fetch('/api/users/' + userId + '/follow', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    }
                });
                
                if (!response.ok) {
                    throw new Error('Failed to follow');
                }
                
                const result = await response.json();
                
                if (result.action === 'followed') {
                    button.innerHTML = '<i class="fas fa-user-check"></i> Following';
                    button.classList.add('following');
                    alert('You are now following this artist!');
                    
                    // Update following count
                    if (currentUser) {
                        const followingElement = document.getElementById('currentFollowing');
                        if (followingElement) {
                            const currentCount = parseInt(followingElement.textContent) || 0;
                            followingElement.textContent = currentCount + 1;
                        }
                    }
                    
                } else {
                    button.innerHTML = '<i class="fas fa-user-plus"></i> Follow';
                    button.classList.remove('following');
                    alert('You unfollowed this artist');
                    
                    // Update following count
                    if (currentUser) {
                        const followingElement = document.getElementById('currentFollowing');
                        if (followingElement) {
                            const currentCount = parseInt(followingElement.textContent) || 0;
                            followingElement.textContent = Math.max(0, currentCount - 1);
                        }
                    }
                    
                    // If on following tab, reload
                    if (currentTab === 'following') {
                        setTimeout(loadUsers, 500);
                    }
                }
                
            } catch (error) {
                console.error('Error:', error);
                alert('Failed to follow artist');
            }
        }
        
        // Switch tabs
        function switchTab(tab) {
            if (currentTab === tab || isLoading) return;
            
            currentTab = tab;
            
            // Update active tab
            document.querySelectorAll('.follow-tab').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Load users for the tab
            loadUsers();
        }
        
        // Search users
        function searchUsers() {
            const query = searchUsersInput.value.trim();
            console.log('Searching for:', query);
            // For now, just reload all users
            // In a real app, you would filter or make an API call
        }
        
        // View profile
        function viewProfile(userId) {
            window.location.href = '/profile?user_id=' + userId;
        }
        
        // Update nav buttons
        function updateNavAuthButtons() {
            const authButtons = document.querySelector('.auth-buttons');
            if (currentUser) {
                authButtons.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 1rem;">
                        <a href="/profile" class="btn btn-outline btn-small">
                            <i class="fas fa-user"></i> ${currentUser.display_name || currentUser.username}
                        </a>
                        <a href="/logout" class="btn btn-primary btn-small">
                            <i class="fas fa-sign-out-alt"></i> Logout
                        </a>
                    </div>
                `;
            }
        }
    </script>'''
    
    # Replace the script content
    new_content = content[:script_start] + new_js + content[script_end + 9:]
    
    # Write the fixed content
    try:
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(new_content)
        
        print("✅ Successfully fixed follow.html!")
        print("\\n🔧 The page should now:")
        print("   1. Load without infinite loading")
        print("   2. Show follow buttons")
        print("   3. Update button text instantly")
        print("   4. Show user stats")
        
        return True
        
    except Exception as e:
        print(f"❌ Error writing file: {e}")
        return False

def find_follow_page():
    """Find the follow.html file"""
    # Check common locations
    locations = [
        'follow.html',
        'templates/follow.html',
        'templates/../follow.html',
        '../follow.html'
    ]
    
    for location in locations:
        if os.path.exists(location):
            return os.path.abspath(location)
    
    # Search in current directory and subdirectories
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file == 'follow.html':
                return os.path.join(root, file)
    
    return None

def main():
    """Main function"""
    print("=" * 60)
    print("🛠️  FOLLOW PAGE FIXER")
    print("=" * 60)
    
    # Find the file
    follow_path = find_follow_page()
    
    if not follow_path:
        print("❌ Could not find follow.html")
        print("💡 Place this script in the same folder as your project")
        return
    
    print(f"📄 Found: {follow_path}")
    
    # Confirm
    print("\\n⚠️  This will fix the follow page JavaScript")
    choice = input("Continue? (y/N): ").strip().lower()
    
    if choice not in ['y', 'yes']:
        print("❌ Cancelled")
        return
    
    print("\\n🔄 Fixing...")
    print("=" * 60)
    
    if fix_follow_page(follow_path):
        print("\\n" + "=" * 60)
        print("✅ FIX COMPLETE!")
        print("=" * 60)
        print("\\n🎉 Refresh your browser and visit /follow")
        print("\\n🔄 If still having issues:")
        print("   1. Check browser console (F12)")
        print("   2. Make sure you're logged in")
        print("   3. Restart your Flask server")
    else:
        print("\\n❌ Fix failed")

if __name__ == "__main__":
    main()'''
    
    # Save the script
    filename = "fix_follow_simple.py"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(script_content)
    
    print(f"✅ Created: {filename}")
    print(f"\\n🚀 Run it with: python {filename}")

# Run the creation
create_follow_fix_script()