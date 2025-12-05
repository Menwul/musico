import eventlet
eventlet.monkey_patch()
from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from datetime import datetime, timezone, timedelta
from flask_socketio import join_room, leave_room
import os
import secrets
import hashlib
import base64
from sqlalchemy import func, desc

# ========== INIT APP ==========
app = Flask(__name__, 
            instance_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'),
            static_folder='static',
            template_folder='templates')

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(app.instance_path, 'soundconnect.db')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# Allowed extensions
ALLOWED_AUDIO_EXTENSIONS = {'mp3', 'wav', 'ogg', 'm4a'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_audio_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_AUDIO_EXTENSIONS

def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

# Initialize extensions
CORS(app)
db = SQLAlchemy(app)
socketio = SocketIO(app, 
                   cors_allowed_origins="*",
                   async_mode='threading',
                   logger=False,  # Turn off for production
                   engineio_logger=False,
                   ping_timeout=60,
                   ping_interval=25)

# ========== DATABASE MODELS ==========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    display_name = db.Column(db.String(100))
    bio = db.Column(db.Text, default='')
    profile_pic = db.Column(db.String(500), default='default.png')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime)
    
    # Relationships
    tracks = db.relationship('Track', backref='artist', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')
    followers_rel = db.relationship('Follow', foreign_keys='Follow.followed_id', backref='followed', lazy=True)
    following_rel = db.relationship('Follow', foreign_keys='Follow.follower_id', backref='follower', lazy=True)
    
    def set_password(self, password):
        salt = secrets.token_hex(16)
        hash_obj = hashlib.sha256((password + salt).encode())
        self.password_hash = f"{salt}${hash_obj.hexdigest()}"
    
    def check_password(self, password):
        if '$' not in self.password_hash:
            return False
        salt, stored_hash = self.password_hash.split('$', 1)
        hash_obj = hashlib.sha256((password + salt).encode())
        return hash_obj.hexdigest() == stored_hash
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name or self.username,
            'profile_pic': self.profile_pic,
            'bio': self.bio,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    is_read = db.Column(db.Boolean, default=False)
    message_type = db.Column(db.String(20), default='text')  # text, audio, image, file
    file_url = db.Column(db.String(500))
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')
    
    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'is_read': self.is_read,
            'message_type': self.message_type,
            'file_url': self.file_url,
            'sender': self.sender.to_dict() if self.sender else None,
            'receiver': self.receiver.to_dict() if self.receiver else None
        }

class ChatRoom(db.Model):
    __tablename__ = 'chat_rooms'
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_message_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    __table_args__ = (db.UniqueConstraint('user1_id', 'user2_id', name='unique_chat_room'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user1_id': self.user1_id,
            'user2_id': self.user2_id,
            'created_at': self.created_at.isoformat(),
            'last_message_at': self.last_message_at.isoformat()
        }

class Track(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    file_url = db.Column(db.String(500))
    cover_art = db.Column(db.String(500))
    genre = db.Column(db.String(50), default='Other')
    plays = db.Column(db.Integer, default=0)
    upload_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    
    # Relationships
    likes = db.relationship('Like', backref='track', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='track', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'file_url': self.file_url,
            'cover_art': self.cover_art,
            'genre': self.genre,
            'plays': self.plays,
            'upload_date': self.upload_date.isoformat(),
            'user_id': self.user_id
        }

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    track_id = db.Column(db.Integer, db.ForeignKey('track.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('user_id', 'track_id', name='unique_like'),)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    track_id = db.Column(db.Integer, db.ForeignKey('track.id'), nullable=False, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'track_id': self.track_id
        }

class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    __table_args__ = (db.UniqueConstraint('follower_id', 'followed_id', name='unique_follow'),)

# ========== HELPER FUNCTIONS ==========
def get_user_from_token(token):
    """Get user from JWT token"""
    if not token or not token.startswith('Bearer '):
        return None
    
    try:
        # Extract the token
        token_str = token.split('Bearer ')[1]
        
        # Decode token to get user_id
        try:
            decoded = base64.b64decode(token_str).decode('utf-8')
            if ':' in decoded:
                user_id = int(decoded.split(':')[0])
                user = User.query.get(user_id)
                if user:
                    return user
        except:
            pass
        
        return None
        
    except Exception as e:
        print(f"Token error: {e}")
        return None

def get_time_ago(timestamp):
    """Convert timestamp to "time ago" string"""
    now = datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    
    diff = now - timestamp
    
    if diff.days > 365:
        return f"{diff.days // 365} years ago"
    elif diff.days > 30:
        return f"{diff.days // 30} months ago"
    elif diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600} hours ago"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60} minutes ago"
    else:
        return "Just now"

# ========== API ENDPOINTS ==========

# ========== AUTH ENDPOINTS ==========
@app.route('/api/register', methods=['POST'])
def api_register():
    """User registration"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Missing fields'}), 400
    
    # Validate username
    if len(data['username']) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    # Validate password
    if len(data['password']) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    # Check if username exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    # Check if email exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    user = User(
        username=data['username'],
        email=data['email'],
        display_name=data.get('display_name', data['username']),
        bio=data.get('bio', '')
    )
    user.set_password(data['password'])
    user.last_login = datetime.now(timezone.utc)
    
    try:
        db.session.add(user)
        db.session.commit()
        
        # Create token
        token_data = f"{user.id}:{secrets.token_hex(16)}"
        token = base64.b64encode(token_data.encode('utf-8')).decode('utf-8')
        
        return jsonify({
            'message': 'Registration successful!',
            'user': user.to_dict(),
            'token': token,
            'success': True
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """User login"""
    data = request.get_json()
    
    if not data or 'identifier' not in data or 'password' not in data:
        return jsonify({'error': 'Missing credentials'}), 400
    
    # Find user by username or email
    user = User.query.filter(
        (User.username == data['identifier']) | 
        (User.email == data['identifier'])
    ).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid username/email or password'}), 401
    
    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    
    # Create token
    token_data = f"{user.id}:{secrets.token_hex(16)}"
    token = base64.b64encode(token_data.encode('utf-8')).decode('utf-8')
    
    return jsonify({
        'message': 'Login successful!',
        'user': user.to_dict(),
        'token': token,
        'success': True
    }), 200

@app.route('/api/logout', methods=['POST'])
def api_logout():
    """Logout user"""
    # Client-side token invalidation - in production use token blacklist
    return jsonify({
        'message': 'Logged out successfully',
        'success': True
    }), 200

# ========== USER ENDPOINTS ==========
@app.route('/api/users/me', methods=['GET'])
def api_get_current_user():
    """Get current authenticated user profile"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        # Get user stats
        tracks_count = Track.query.filter_by(user_id=user.id).count()
        followers_count = Follow.query.filter_by(followed_id=user.id).count()
        following_count = Follow.query.filter_by(follower_id=user.id).count()
        
        user_data = user.to_dict()
        user_data.update({
            'tracks_count': tracks_count,
            'followers_count': followers_count,
            'following_count': following_count
        })
        
        return jsonify(user_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to load profile: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>', methods=['GET'])
def api_get_user(user_id):
    """Get user profile with stats"""
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Get user stats
        tracks_count = Track.query.filter_by(user_id=user_id).count()
        followers_count = Follow.query.filter_by(followed_id=user_id).count()
        following_count = Follow.query.filter_by(follower_id=user_id).count()
        
        user_data = user.to_dict()
        user_data.update({
            'tracks_count': tracks_count,
            'followers_count': followers_count,
            'following_count': following_count
        })
        
        return jsonify(user_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to load user: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>/follow', methods=['POST'])
def api_toggle_follow(user_id):
    """Follow/unfollow a user"""
    token = request.headers.get('Authorization')
    current_user = get_user_from_token(token)
    
    if not current_user:
        return jsonify({'error': 'Authentication required'}), 401
    
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot follow yourself'}), 400
    
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if already following
        existing_follow = Follow.query.filter_by(
            follower_id=current_user.id,
            followed_id=user_id
        ).first()
        
        if existing_follow:
            # Unfollow
            db.session.delete(existing_follow)
            action = 'unfollowed'
        else:
            # Follow
            follow = Follow(follower_id=current_user.id, followed_id=user_id)
            db.session.add(follow)
            action = 'followed'
        
        db.session.commit()
        
        # Get updated followers count
        followers_count = Follow.query.filter_by(followed_id=user_id).count()
        
        # Notify user via WebSocket
        if action == 'followed':
            socketio.emit('user_followed', {
                'follower': current_user.to_dict(),
                'followed_user_id': user_id
            })
        
        return jsonify({
            'action': action,
            'followers_count': followers_count,
            'success': True
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to follow user: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>/tracks', methods=['GET'])
def api_get_user_tracks(user_id):
    """Get tracks uploaded by a specific user"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 12, type=int)
        
        # Get user's tracks
        query = Track.query.filter_by(user_id=user_id)
        
        # Get total count
        total = query.count()
        
        # Get paginated results
        tracks = query.order_by(Track.upload_date.desc())\
                     .offset((page-1) * limit)\
                     .limit(limit)\
                     .all()
        
        # Get user info
        user = User.query.get(user_id)
        
        # Prepare tracks data
        tracks_data = []
        for track in tracks:
            track_data = track.to_dict()
            
            if user:
                track_data['artist'] = user.to_dict()
            
            # Get counts
            track_data['likes_count'] = Like.query.filter_by(track_id=track.id).count()
            track_data['comments_count'] = Comment.query.filter_by(track_id=track.id).count()
            
            tracks_data.append(track_data)
        
        return jsonify({
            'tracks': tracks_data,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit,
            'success': True
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to load user tracks: {str(e)}'}), 500

@app.route('/api/users/update', methods=['PUT'])
def api_update_profile():
    """Update user profile"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        data = request.get_json()
        
        # Update fields if provided
        if 'display_name' in data:
            user.display_name = data['display_name'].strip()
        
        if 'bio' in data:
            user.bio = data['bio'].strip()
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict(),
            'success': True
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update profile: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>/is-following', methods=['GET'])
def api_check_following(user_id):
    """Check if current user is following another user"""
    token = request.headers.get('Authorization')
    current_user = get_user_from_token(token)
    
    if not current_user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        is_following = Follow.query.filter_by(
            follower_id=current_user.id,
            followed_id=user_id
        ).first() is not None
        
        return jsonify({
            'is_following': is_following,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to check follow status: {str(e)}'}), 500

# ========== TRACK ENDPOINTS ==========
@app.route('/api/tracks', methods=['GET'])
def api_tracks():
    """Get ALL tracks from database"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        genre = request.args.get('genre')
        user_id = request.args.get('user_id', type=int)
        
        query = Track.query
        
        if genre and genre != 'all':
            query = query.filter_by(genre=genre)
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        # Get total count for pagination
        total = query.count()
        
        # Get paginated results
        tracks = query.order_by(Track.upload_date.desc())\
                     .offset((page-1) * limit)\
                     .limit(limit)\
                     .all()
        
        # Get like and comment counts
        tracks_data = []
        for track in tracks:
            track_data = track.to_dict()
            
            # Get artist info
            artist = User.query.get(track.user_id)
            if artist:
                track_data['artist'] = artist.to_dict()
            else:
                track_data['artist'] = {'username': 'Unknown', 'display_name': 'Unknown Artist'}
            
            # Get counts
            track_data['likes_count'] = Like.query.filter_by(track_id=track.id).count()
            track_data['comments_count'] = Comment.query.filter_by(track_id=track.id).count()
            
            tracks_data.append(track_data)
        
        return jsonify({
            'tracks': tracks_data,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit,
            'success': True
        }), 200
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/tracks/<int:track_id>', methods=['DELETE'])
def api_delete_track(track_id):
    """Delete a track from database"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        track = Track.query.get(track_id)
        
        if not track:
            return jsonify({'error': 'Track not found'}), 404
        
        # Check if user owns the track
        if track.user_id != user.id:
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Delete associated likes and comments
        Like.query.filter_by(track_id=track_id).delete()
        Comment.query.filter_by(track_id=track_id).delete()
        
        # Delete track
        db.session.delete(track)
        db.session.commit()
        
        return jsonify({
            'message': 'Track deleted successfully',
            'success': True
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete track: {str(e)}'}), 500

@app.route('/api/tracks/<int:track_id>/play', methods=['POST'])
def api_increment_plays(track_id):
    """Increment play count in database"""
    try:
        track = Track.query.get(track_id)
        
        if not track:
            return jsonify({'error': 'Track not found'}), 404
        
        track.plays += 1
        db.session.commit()
        
        return jsonify({
            'plays': track.plays,
            'success': True
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to increment plays: {str(e)}'}), 500

@app.route('/api/tracks/<int:track_id>/like', methods=['POST'])
def api_like_track(track_id):
    """Like/unlike a track in database"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        track = Track.query.get(track_id)
        
        if not track:
            return jsonify({'error': 'Track not found'}), 404
        
        # Check if already liked
        existing_like = Like.query.filter_by(
            user_id=user.id,
            track_id=track_id
        ).first()
        
        if existing_like:
            # Unlike
            db.session.delete(existing_like)
            action = 'unliked'
        else:
            # Like
            like = Like(user_id=user.id, track_id=track_id)
            db.session.add(like)
            action = 'liked'
        
        db.session.commit()
        
        # Get updated like count
        like_count = Like.query.filter_by(track_id=track_id).count()
        
        # Notify track owner via WebSocket
        if action == 'liked' and track.user_id != user.id:
            socketio.emit('track_liked', {
                'track_id': track_id,
                'track_title': track.title,
                'user': user.to_dict()
            })
        
        return jsonify({
            'action': action,
            'likes_count': like_count,
            'success': True
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to like track: {str(e)}'}), 500

@app.route('/api/tracks/upload', methods=['POST'])
def api_upload_track():
    """Upload a track with audio file and optional cover art"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        # Check if audio file exists
        if 'audio' not in request.files:
            return jsonify({'error': 'No audio file provided'}), 400
        
        audio_file = request.files['audio']
        
        if audio_file.filename == '':
            return jsonify({'error': 'No audio file selected'}), 400
        
        if not allowed_audio_file(audio_file.filename):
            return jsonify({'error': 'File type not allowed. Use MP3, WAV, or OGG'}), 400
        
        # Get form data
        title = request.form.get('title')
        description = request.form.get('description', '')
        genre = request.form.get('genre', 'Other')
        
        if not title:
            return jsonify({'error': 'Track title is required'}), 400
        
        # Create uploads directory if it doesn't exist
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate unique filename
        original_filename = secure_filename(audio_file.filename)
        unique_filename = f"{user.id}_{int(datetime.now(timezone.utc).timestamp())}_{original_filename}"
        audio_path = os.path.join(upload_folder, unique_filename)
        
        # Save audio file
        audio_file.save(audio_path)
        
        # Handle cover art if provided
        cover_art_url = None
        if 'cover_art' in request.files:
            cover_file = request.files['cover_art']
            if cover_file and cover_file.filename != '' and allowed_image_file(cover_file.filename):
                cover_filename = f"cover_{user.id}_{int(datetime.now(timezone.utc).timestamp())}_{secure_filename(cover_file.filename)}"
                cover_path = os.path.join(upload_folder, cover_filename)
                cover_file.save(cover_path)
                cover_art_url = f"/uploads/{cover_filename}"
        
        # Create track in database
        track = Track(
            title=title,
            description=description,
            file_url=f"/uploads/{unique_filename}",
            cover_art=cover_art_url,
            genre=genre,
            user_id=user.id
        )
        
        db.session.add(track)
        db.session.commit()
        
        # Return track data
        track_data = track.to_dict()
        track_data['artist'] = user.to_dict()
        
        return jsonify({
            'message': 'Track uploaded successfully',
            'track': track_data,
            'success': True
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

# ========== SEARCH ENDPOINT ==========
@app.route('/api/search', methods=['GET'])
def api_search():
    """Search tracks, artists, and genres"""
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'error': 'Search query required'}), 400
    
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 12, type=int)
    
    try:
        # Search in tracks (title, description, genre)
        track_query = Track.query.filter(
            db.or_(
                Track.title.ilike(f'%{query}%'),
                Track.description.ilike(f'%{query}%'),
                Track.genre.ilike(f'%{query}%')
            )
        )
        
        # Search in users (username, display_name)
        user_query = User.query.filter(
            db.or_(
                User.username.ilike(f'%{query}%'),
                User.display_name.ilike(f'%{query}%')
            )
        )
        
        # Get tracks from search results
        tracks_from_search = track_query.all()
        
        # Also get tracks from user search results
        users = user_query.all()
        user_ids = [user.id for user in users]
        
        if user_ids:
            tracks_from_users = Track.query.filter(Track.user_id.in_(user_ids)).all()
            tracks_from_search += tracks_from_users
        
        # Remove duplicates
        track_ids = set()
        unique_tracks = []
        for track in tracks_from_search:
            if track.id not in track_ids:
                track_ids.add(track.id)
                unique_tracks.append(track)
        
        # Sort by upload date (newest first)
        unique_tracks.sort(key=lambda x: x.upload_date, reverse=True)
        
        # Pagination
        total = len(unique_tracks)
        start = (page - 1) * limit
        end = start + limit
        paginated_tracks = unique_tracks[start:end]
        
        # Prepare response
        tracks_data = []
        for track in paginated_tracks:
            track_data = track.to_dict()
            
            # Get artist info
            artist = User.query.get(track.user_id)
            if artist:
                track_data['artist'] = artist.to_dict()
            
            # Get counts
            track_data['likes_count'] = Like.query.filter_by(track_id=track.id).count()
            track_data['comments_count'] = Comment.query.filter_by(track_id=track.id).count()
            
            tracks_data.append(track_data)
        
        return jsonify({
            'tracks': tracks_data,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit,
            'query': query,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Search failed: {str(e)}'}), 500

# ========== DASHBOARD ENDPOINTS ==========
@app.route('/api/dashboard/stats', methods=['GET'])
def api_dashboard_stats():
    """Get dashboard statistics from database"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        # Total plays (sum of all track plays for this user)
        total_plays = db.session.query(func.sum(Track.plays))\
            .filter(Track.user_id == user.id)\
            .scalar() or 0
        
        # Total likes (count of likes on user's tracks)
        total_likes = db.session.query(func.count(Like.id))\
            .join(Track, Like.track_id == Track.id)\
            .filter(Track.user_id == user.id)\
            .scalar() or 0
        
        # Followers count
        followers_count = db.session.query(func.count(Follow.id))\
            .filter(Follow.followed_id == user.id)\
            .scalar() or 0
        
        # User's tracks count
        tracks_count = db.session.query(func.count(Track.id))\
            .filter(Track.user_id == user.id)\
            .scalar() or 0
        
        # Total comments on user's tracks
        total_comments = db.session.query(func.count(Comment.id))\
            .join(Track, Comment.track_id == Track.id)\
            .filter(Track.user_id == user.id)\
            .scalar() or 0
        
        # Monthly listeners (simplified)
        monthly_listeners = total_plays
        
        return jsonify({
            'total_plays': total_plays,
            'total_likes': total_likes,
            'followers_count': followers_count,
            'tracks_count': tracks_count,
            'total_comments': total_comments,
            'monthly_listeners': monthly_listeners,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/dashboard/activity', methods=['GET'])
def api_dashboard_activity():
    """Get recent activity from database"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        activities = []
        
        # Recent likes on user's tracks
        recent_likes = db.session.query(Like, Track, User)\
            .join(Track, Like.track_id == Track.id)\
            .join(User, Like.user_id == User.id)\
            .filter(Track.user_id == user.id)\
            .order_by(Like.timestamp.desc())\
            .limit(5)\
            .all()
        
        for like, track, liker in recent_likes:
            activities.append({
                'id': like.id,
                'type': 'like',
                'user': {
                    'username': liker.username,
                    'display_name': liker.display_name or liker.username
                },
                'track': {'id': track.id, 'title': track.title},
                'message': f'liked your track "{track.title}"',
                'timestamp': like.timestamp.isoformat(),
                'time_ago': get_time_ago(like.timestamp),
                'icon': 'heart',
                'color': 'primary'
            })
        
        # Recent comments on user's tracks
        recent_comments = db.session.query(Comment, Track, User)\
            .join(Track, Comment.track_id == Track.id)\
            .join(User, Comment.user_id == User.id)\
            .filter(Track.user_id == user.id)\
            .order_by(Comment.timestamp.desc())\
            .limit(5)\
            .all()
        
        for comment, track, commenter in recent_comments:
            activities.append({
                'id': comment.id,
                'type': 'comment',
                'user': {
                    'username': commenter.username,
                    'display_name': commenter.display_name or commenter.username
                },
                'track': {'id': track.id, 'title': track.title},
                'message': f'commented on "{track.title}": {comment.content[:50]}...',
                'timestamp': comment.timestamp.isoformat(),
                'time_ago': get_time_ago(comment.timestamp),
                'icon': 'comment',
                'color': 'warning'
            })
        
        # Recent followers
        recent_followers = db.session.query(Follow, User)\
            .join(User, Follow.follower_id == User.id)\
            .filter(Follow.followed_id == user.id)\
            .order_by(Follow.timestamp.desc())\
            .limit(5)\
            .all()
        
        for follow, follower in recent_followers:
            activities.append({
                'id': follow.id,
                'type': 'follow',
                'user': {
                    'username': follower.username,
                    'display_name': follower.display_name or follower.username
                },
                'message': 'started following you',
                'timestamp': follow.timestamp.isoformat(),
                'time_ago': get_time_ago(follow.timestamp),
                'icon': 'user-plus',
                'color': 'secondary'
            })
        
        # Sort all activities by timestamp (newest first)
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Limit to 10 most recent activities
        activities = activities[:10]
        
        return jsonify(activities), 200
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/user/tracks', methods=['GET'])
def api_user_tracks():
    """Get tracks for current user from database"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        # Get user's tracks with like and comment counts
        tracks = db.session.query(
            Track,
            func.count(Like.id).label('likes_count'),
            func.count(Comment.id).label('comments_count')
        )\
        .outerjoin(Like, Track.id == Like.track_id)\
        .outerjoin(Comment, Track.id == Comment.track_id)\
        .filter(Track.user_id == user.id)\
        .group_by(Track.id)\
        .order_by(Track.upload_date.desc())\
        .all()
        
        tracks_data = []
        for track, likes_count, comments_count in tracks:
            track_data = track.to_dict()
            track_data['likes_count'] = likes_count or 0
            track_data['comments_count'] = comments_count or 0
            track_data['artist'] = user.to_dict()
            tracks_data.append(track_data)
        
        return jsonify(tracks_data), 200
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# ========== CHAT ENDPOINTS ==========
@app.route('/api/chat/conversations', methods=['GET'])
def api_chat_conversations():
    """Get all conversations for current user"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        # Get all chat rooms where user is involved
        conversations = []
        
        # Rooms where user is user1
        rooms_as_user1 = ChatRoom.query.filter_by(user1_id=user.id).all()
        for room in rooms_as_user1:
            other_user = User.query.get(room.user2_id)
            if other_user:
                # Get last message
                last_message = ChatMessage.query.filter(
                    ((ChatMessage.sender_id == user.id) & (ChatMessage.receiver_id == other_user.id)) |
                    ((ChatMessage.sender_id == other_user.id) & (ChatMessage.receiver_id == user.id))
                ).order_by(ChatMessage.timestamp.desc()).first()
                
                # Count unread messages
                unread_count = ChatMessage.query.filter_by(
                    sender_id=other_user.id,
                    receiver_id=user.id,
                    is_read=False
                ).count()
                
                conversations.append({
                    'room_id': room.id,
                    'user': other_user.to_dict(),
                    'last_message': last_message.to_dict() if last_message else None,
                    'unread_count': unread_count,
                    'last_message_at': room.last_message_at.isoformat()
                })
        
        # Rooms where user is user2
        rooms_as_user2 = ChatRoom.query.filter_by(user2_id=user.id).all()
        for room in rooms_as_user2:
            other_user = User.query.get(room.user1_id)
            if other_user:
                # Get last message
                last_message = ChatMessage.query.filter(
                    ((ChatMessage.sender_id == user.id) & (ChatMessage.receiver_id == other_user.id)) |
                    ((ChatMessage.sender_id == other_user.id) & (ChatMessage.receiver_id == user.id))
                ).order_by(ChatMessage.timestamp.desc()).first()
                
                # Count unread messages
                unread_count = ChatMessage.query.filter_by(
                    sender_id=other_user.id,
                    receiver_id=user.id,
                    is_read=False
                ).count()
                
                conversations.append({
                    'room_id': room.id,
                    'user': other_user.to_dict(),
                    'last_message': last_message.to_dict() if last_message else None,
                    'unread_count': unread_count,
                    'last_message_at': room.last_message_at.isoformat()
                })
        
        # Sort by last message timestamp
        conversations.sort(key=lambda x: x['last_message_at'], reverse=True)
        
        return jsonify({
            'conversations': conversations,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/chat/messages/<int:receiver_id>', methods=['GET'])
def api_chat_messages(receiver_id):
    """Get messages between current user and receiver"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        # Get or create chat room
        room = ChatRoom.query.filter(
            ((ChatRoom.user1_id == user.id) & (ChatRoom.user2_id == receiver_id)) |
            ((ChatRoom.user1_id == receiver_id) & (ChatRoom.user2_id == user.id))
        ).first()
        
        if not room:
            # Create new chat room
            room = ChatRoom(
                user1_id=min(user.id, receiver_id),
                user2_id=max(user.id, receiver_id)
            )
            db.session.add(room)
            db.session.commit()
        
        # Get messages
        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == user.id) & (ChatMessage.receiver_id == receiver_id)) |
            ((ChatMessage.sender_id == receiver_id) & (ChatMessage.receiver_id == user.id))
        ).order_by(ChatMessage.timestamp.asc()).all()
        
        # Mark messages as read
        ChatMessage.query.filter_by(
            sender_id=receiver_id,
            receiver_id=user.id,
            is_read=False
        ).update({'is_read': True})
        db.session.commit()
        
        return jsonify({
            'messages': [msg.to_dict() for msg in messages],
            'room_id': room.id,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/chat/send', methods=['POST'])
def api_chat_send():
    """Send a chat message"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        message_type = data.get('message_type', 'text')
        file_url = data.get('file_url')
        
        if not receiver_id or not content:
            return jsonify({'error': 'Missing receiver_id or content'}), 400
        
        # Get or create chat room
        room = ChatRoom.query.filter(
            ((ChatRoom.user1_id == user.id) & (ChatRoom.user2_id == receiver_id)) |
            ((ChatRoom.user1_id == receiver_id) & (ChatRoom.user2_id == user.id))
        ).first()
        
        if not room:
            # Create new chat room
            room = ChatRoom(
                user1_id=min(user.id, receiver_id),
                user2_id=max(user.id, receiver_id)
            )
            db.session.add(room)
        
        # Create message
        message = ChatMessage(
            sender_id=user.id,
            receiver_id=receiver_id,
            content=content,
            message_type=message_type,
            file_url=file_url
        )
        
        # Update room's last message timestamp
        room.last_message_at = datetime.now(timezone.utc)
        
        db.session.add(message)
        db.session.commit()
        
        # Prepare data for WebSocket
        message_data = message.to_dict()
        
        # Emit via WebSocket
        socketio.emit('new_message', {
            'message': message_data,
            'room_id': room.id
        }, room=f'user_{receiver_id}')
        
        return jsonify({
            'message': message_data,
            'success': True
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to send message: {str(e)}'}), 500

@app.route('/api/chat/online-users', methods=['GET'])
def api_online_users():
    """Get only online users"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        online_users = []
        for user_id, socket_id in user_socket_map.items():
            # Skip current user
            if user_id == user.id:
                continue
                
            # Get user from database
            u = User.query.get(user_id)
            if u:
                user_dict = u.to_dict()
                user_dict['is_online'] = True
                user_dict['status'] = 'online'
                online_users.append(user_dict)
        
        return jsonify({
            'users': online_users,
            'count': len(online_users),
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get online users: {str(e)}'}), 500

@app.route('/api/chat/users', methods=['GET'])
def api_chat_users():
    """Get all users for chat (excluding current user)"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        # Get all users except current user
        users = User.query.filter(User.id != user.id).all()
        
        users_data = []
        for u in users:
            user_dict = u.to_dict()
            # Check if user is online by looking at the socket map
            user_dict['is_online'] = u.id in user_socket_map
            user_dict['status'] = 'online' if u.id in user_socket_map else 'offline'
            users_data.append(user_dict)
        
        return jsonify({
            'users': users_data,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/api/chat/unread-count', methods=['GET'])
def api_chat_unread_count():
    """Get total unread messages count"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        unread_count = ChatMessage.query.filter_by(
            receiver_id=user.id,
            is_read=False
        ).count()
        
        return jsonify({
            'unread_count': unread_count,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500

# ========== PROFILE PICTURE UPLOAD ==========
@app.route('/api/users/upload-profile-pic', methods=['POST'])
def api_upload_profile_pic():
    """Upload profile picture"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        if 'profile_pic' not in request.files:
            return jsonify({'error': 'No profile picture provided'}), 400
        
        profile_pic = request.files['profile_pic']
        
        if profile_pic.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_image_file(profile_pic.filename):
            return jsonify({'error': 'File type not allowed. Use PNG, JPG, or JPEG'}), 400
        
        # Create uploads directory if it doesn't exist
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate unique filename
        original_filename = secure_filename(profile_pic.filename)
        unique_filename = f"profile_{user.id}_{int(datetime.now(timezone.utc).timestamp())}_{original_filename}"
        profile_pic_path = os.path.join(upload_folder, unique_filename)
        
        # Save profile picture
        profile_pic.save(profile_pic_path)
        
        # Update user profile picture in database
        user.profile_pic = f"/uploads/{unique_filename}"
        db.session.commit()
        
        return jsonify({
            'message': 'Profile picture updated successfully',
            'profile_pic': user.profile_pic,
            'success': True
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to upload profile picture: {str(e)}'}), 500

# ========== USER LIKED TRACKS ==========
@app.route('/api/users/<int:user_id>/likes', methods=['GET'])
def api_get_user_likes(user_id):
    """Get tracks liked by a user"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 12, type=int)
        
        # Get liked tracks
        liked_tracks = db.session.query(Track)\
            .join(Like, Track.id == Like.track_id)\
            .filter(Like.user_id == user_id)\
            .order_by(Like.timestamp.desc())\
            .offset((page-1) * limit)\
            .limit(limit)\
            .all()
        
        # Get total count
        total = db.session.query(func.count(Like.id))\
            .filter(Like.user_id == user_id)\
            .scalar()
        
        # Prepare tracks data
        tracks_data = []
        for track in liked_tracks:
            track_data = track.to_dict()
            
            # Get artist info
            artist = User.query.get(track.user_id)
            if artist:
                track_data['artist'] = artist.to_dict()
            
            # Get counts
            track_data['likes_count'] = Like.query.filter_by(track_id=track.id).count()
            track_data['comments_count'] = Comment.query.filter_by(track_id=track.id).count()
            
            # Check if current user liked this track
            track_data['liked'] = True  # Since we're getting from likes
            
            tracks_data.append(track_data)
        
        return jsonify({
            'tracks': tracks_data,
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit,
            'success': True
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to load liked tracks: {str(e)}'}), 500

# ========== CHECK IF USER LIKED TRACK ==========
@app.route('/api/tracks/<int:track_id>/check-like', methods=['GET'])
def api_check_track_like(track_id):
    """Check if current user liked a track"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        liked = Like.query.filter_by(
            user_id=user.id,
            track_id=track_id
        ).first() is not None
        
        return jsonify({
            'liked': liked,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to check like status: {str(e)}'}), 500

# ========== GET TRACK DETAILS ==========
@app.route('/api/tracks/<int:track_id>', methods=['GET'])
def api_get_track(track_id):
    """Get track details with counts"""
    try:
        track = Track.query.get(track_id)
        
        if not track:
            return jsonify({'error': 'Track not found'}), 404
        
        track_data = track.to_dict()
        
        # Get artist info
        artist = User.query.get(track.user_id)
        if artist:
            track_data['artist'] = artist.to_dict()
        
        # Get counts
        track_data['likes_count'] = Like.query.filter_by(track_id=track_id).count()
        track_data['comments_count'] = Comment.query.filter_by(track_id=track_id).count()
        
        # Get comments
        comments = Comment.query.filter_by(track_id=track_id)\
            .order_by(Comment.timestamp.desc())\
            .limit(50)\
            .all()
        
        comments_data = []
        for comment in comments:
            comment_data = comment.to_dict()
            comment_author = User.query.get(comment.user_id)
            if comment_author:
                comment_data['author'] = comment_author.to_dict()
            comments_data.append(comment_data)
        
        track_data['comments'] = comments_data
        
        return jsonify({
            'track': track_data,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to load track: {str(e)}'}), 500

# ========== ADD COMMENT TO TRACK ==========
@app.route('/api/tracks/<int:track_id>/comment', methods=['POST'])
def api_add_comment(track_id):
    """Add comment to track"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        data = request.get_json()
        content = data.get('content')
        
        if not content or not content.strip():
            return jsonify({'error': 'Comment content is required'}), 400
        
        # Check if track exists
        track = Track.query.get(track_id)
        if not track:
            return jsonify({'error': 'Track not found'}), 404
        
        # Create comment
        comment = Comment(
            content=content.strip(),
            user_id=user.id,
            track_id=track_id
        )
        
        db.session.add(comment)
        db.session.commit()
        
        # Prepare response
        comment_data = comment.to_dict()
        comment_data['author'] = user.to_dict()
        
        return jsonify({
            'message': 'Comment added successfully',
            'comment': comment_data,
            'success': True
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to add comment: {str(e)}'}), 500

# ========== GET FOLLOWING/FOLLOWERS ==========
@app.route('/api/users/<int:user_id>/followers', methods=['GET'])
def api_get_followers(user_id):
    """Get user's followers"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        
        # Get followers
        followers = db.session.query(User)\
            .join(Follow, User.id == Follow.follower_id)\
            .filter(Follow.followed_id == user_id)\
            .order_by(Follow.timestamp.desc())\
            .offset((page-1) * limit)\
            .limit(limit)\
            .all()
        
        # Get total count
        total = db.session.query(func.count(Follow.id))\
            .filter(Follow.followed_id == user_id)\
            .scalar()
        
        return jsonify({
            'followers': [user.to_dict() for user in followers],
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit,
            'success': True
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to load followers: {str(e)}'}), 500

@app.route('/api/users/<int:user_id>/following', methods=['GET'])
def api_get_following(user_id):
    """Get users that a user is following"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        
        # Get following
        following = db.session.query(User)\
            .join(Follow, User.id == Follow.followed_id)\
            .filter(Follow.follower_id == user_id)\
            .order_by(Follow.timestamp.desc())\
            .offset((page-1) * limit)\
            .limit(limit)\
            .all()
        
        # Get total count
        total = db.session.query(func.count(Follow.id))\
            .filter(Follow.follower_id == user_id)\
            .scalar()
        
        return jsonify({
            'following': [user.to_dict() for user in following],
            'total': total,
            'page': page,
            'pages': (total + limit - 1) // limit,
            'success': True
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to load following: {str(e)}'}), 500

# ========== STATIC FILE SERVING ==========
@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    """Serve uploaded files"""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except Exception as e:
        return jsonify({'error': 'File not found'}), 404

@app.route('/api/chat/send-media', methods=['POST'])
def api_chat_send_media():
    """Send media message (image, audio, video, file)"""
    token = request.headers.get('Authorization')
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({'error': 'Authentication required'}), 401
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        receiver_id = request.form.get('receiver_id')
        message_type = request.form.get('message_type', 'file')
        content = request.form.get('content', 'Media file')
        
        if not receiver_id:
            return jsonify({'error': 'Missing receiver_id'}), 400
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Create uploads directory if it doesn't exist
        upload_folder = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate unique filename
        original_filename = secure_filename(file.filename)
        unique_filename = f"chat_{user.id}_{receiver_id}_{int(datetime.now(timezone.utc).timestamp())}_{original_filename}"
        file_path = os.path.join(upload_folder, unique_filename)
        
        # Save file
        file.save(file_path)
        
        # Get or create chat room
        room = ChatRoom.query.filter(
            ((ChatRoom.user1_id == user.id) & (ChatRoom.user2_id == receiver_id)) |
            ((ChatRoom.user1_id == receiver_id) & (ChatRoom.user2_id == user.id))
        ).first()
        
        if not room:
            # Create new chat room
            room = ChatRoom(
                user1_id=min(user.id, int(receiver_id)),
                user2_id=max(user.id, int(receiver_id))
            )
            db.session.add(room)
        
        # Create message
        message = ChatMessage(
            sender_id=user.id,
            receiver_id=receiver_id,
            content=content,
            message_type=message_type,
            file_url=f"/uploads/{unique_filename}"
        )
        
        # Update room's last message timestamp
        room.last_message_at = datetime.now(timezone.utc)
        
        db.session.add(message)
        db.session.commit()
        
        # Prepare response
        message_data = message.to_dict()
        
        # Emit via WebSocket
        socketio.emit('new_message', {
            'message': message_data,
            'room_id': room.id
        }, room=f'user_{receiver_id}')
        
        return jsonify({
            'message': message_data,
            'success': True
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to send media: {str(e)}'}), 500

# ========== TEMPLATE ROUTES ==========
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/explore')
def explore():
    return render_template('explore.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')

@app.route('/profile')
def profile():
    """Profile page - can be for current user or viewing other users"""
    user_id = request.args.get('user_id')
    return render_template('profile_view.html', user_id=user_id)

@app.route('/artist/<int:artist_id>')
def artist_profile_page(artist_id):
    """Artist profile page route - alternative URL for sharing"""
    return render_template('profile_view.html', user_id=artist_id)

@app.route('/chat')
def chat():
    return render_template('chat.html')

@app.route('/inbox')
def inbox():
    return render_template('inbox.html')

# KEEP THIS ONE - remove the duplicate at the end of the file
@app.route('/follow')
def follow():
    return render_template('follow.html')

@app.route('/logout')
def logout_page():
    """Logout page"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Logging out - SoundConnect</title>
        <style>
            body {
                background: linear-gradient(135deg, #1a0b2e 0%, #0d0630 100%);
                color: white;
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .container {
                text-align: center;
                padding: 2rem;
                background: rgba(255,255,255,0.1);
                border-radius: 15px;
                backdrop-filter: blur(10px);
            }
            .spinner {
                border: 4px solid rgba(255,255,255,0.3);
                border-radius: 50%;
                border-top: 4px solid #8a2be2;
                width: 50px;
                height: 50px;
                animation: spin 1s linear infinite;
                margin: 0 auto 1rem;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="spinner"></div>
            <h2>Logging out...</h2>
            <p>Please wait while we log you out.</p>
        </div>
        <script>
            // Clear local storage
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            
            // Redirect to home page
            setTimeout(() => {
                window.location.href = '/';
            }, 2000);
        </script>
    </body>
    </html>
    '''

# ========== WEBRTC VIDEO CALL HANDLERS ==========
active_calls = {}  # Store active calls: {call_id: {caller_id: X, callee_id: Y, status: 'ringing'/'active'}}
user_socket_map = {}  # Map user_id to socket_id for direct messaging

@socketio.on('connect')
def handle_connect():
    try:
        print('🟢 Client connected')
        
        # Get token from query parameters
        token = request.args.get('token')
        
        if token:
            print(f'🔑 Token received: {token[:30]}...')
            user = get_user_from_token(f'Bearer {token}')
            
            if user:
                # Store user-socket mapping
                user_socket_map[user.id] = request.sid
                
                # Join user room
                join_room(f'user_{user.id}')
                
                # Broadcast to all clients that this user is online
                socketio.emit('user_status_change', {
                    'user_id': user.id,
                    'status': 'online',
                    'username': user.username,
                    'display_name': user.display_name or user.username,
                    'profile_pic': user.profile_pic
                })
                
                emit('connected', {
                    'message': 'Connected to chat!',
                    'user_id': user.id,
                    'username': user.username
                })
                print(f'✅ User {user.username} connected to chat (socket: {request.sid})')
                return True
            else:
                print('❌ Invalid token')
        else:
            print('⚠️ No token provided')
        
        # Default connection for guests
        emit('connected', {'message': 'Connected as guest'})
        print('👤 Guest connected')
        return True
        
    except Exception as e:
        print(f'❌ WebSocket connection error: {str(e)}')
        import traceback
        traceback.print_exc()
        return False

@socketio.on('disconnect')
def handle_disconnect():
    try:
        # Remove user from socket map
        for user_id, socket_id in list(user_socket_map.items()):
            if socket_id == request.sid:
                # Find user before removing
                user = User.query.get(user_id)
                if user:
                    # Broadcast that user went offline
                    socketio.emit('user_status_change', {
                        'user_id': user_id,
                        'status': 'offline',
                        'username': user.username,
                        'display_name': user.display_name or user.username,
                        'profile_pic': user.profile_pic
                    })
                
                del user_socket_map[user_id]
                print(f'👋 User {user_id} disconnected')
                
                # End any active calls for this user
                for call_id, call_data in list(active_calls.items()):
                    if user_id in [call_data['caller_id'], call_data['callee_id']]:
                        # Notify other user
                        other_user = call_data['callee_id'] if user_id == call_data['caller_id'] else call_data['caller_id']
                        
                        if other_user in user_socket_map:
                            emit('call_ended', {
                                'call_id': call_id,
                                'reason': 'User disconnected',
                                'ended_by': user_id
                            }, room=user_socket_map[other_user])
                        
                        # Clean up call
                        del active_calls[call_id]
                        print(f'📴 Ended call {call_id} due to disconnect')
                break
                
    except Exception as e:
        print(f'❌ Disconnect error: {e}')

@socketio.on('start_video_call')
def handle_start_video_call(data):
    """Start a video call"""
    try:
        caller_id = data.get('caller_id')
        callee_id = data.get('callee_id')
        call_id = data.get('call_id')
        
        print(f'📞 Video call request: {caller_id} -> {callee_id} (Call ID: {call_id})')
        
        # Check if callee is online
        if callee_id not in user_socket_map:
            emit('call_failed', {
                'call_id': call_id,
                'reason': 'User is offline'
            }, room=request.sid)
            return
        
        # Store call info
        active_calls[call_id] = {
            'caller_id': caller_id,
            'callee_id': callee_id,
            'status': 'ringing',
            'start_time': datetime.now(timezone.utc).isoformat()
        }
        
        # Get caller info
        caller = User.query.get(caller_id)
        caller_name = caller.display_name if caller.display_name else caller.username
        
        # Notify callee
        emit('incoming_video_call', {
            'call_id': call_id,
            'caller_id': caller_id,
            'caller_name': caller_name,
            'caller_avatar': caller.profile_pic if caller.profile_pic else None
        }, room=user_socket_map[callee_id])
        
        # Confirm to caller
        emit('call_initiated', {
            'call_id': call_id,
            'callee_id': callee_id,
            'message': 'Calling...'
        }, room=request.sid)
        
        print(f'📱 Call {call_id} initiated successfully')
        
    except Exception as e:
        print(f'❌ Error handling start_video_call: {e}')
        emit('call_failed', {
            'call_id': data.get('call_id'),
            'reason': f'Server error: {str(e)}'
        }, room=request.sid)

@socketio.on('accept_video_call')
def handle_accept_video_call(data):
    """Accept a video call"""
    try:
        call_id = data.get('call_id')
        user_id = data.get('user_id')
        
        call = active_calls.get(call_id)
        if not call:
            emit('call_error', {
                'call_id': call_id,
                'message': 'Call not found'
            }, room=request.sid)
            return
        
        if user_id != call['callee_id']:
            emit('call_error', {
                'call_id': call_id,
                'message': 'Unauthorized'
            }, room=request.sid)
            return
        
        print(f'✅ Call accepted: {call_id}')
        call['status'] = 'active'
        call['answer_time'] = datetime.now(timezone.utc).isoformat()
        
        # Notify caller that call was accepted
        emit('call_accepted', {
            'call_id': call_id,
            'callee_id': user_id
        }, room=user_socket_map[call['caller_id']])
        
        print(f'🤝 Call {call_id} is now active')
        
    except Exception as e:
        print(f'❌ Error handling accept_video_call: {e}')

@socketio.on('reject_video_call')
def handle_reject_video_call(data):
    """Reject a video call"""
    try:
        call_id = data.get('call_id')
        user_id = data.get('user_id')
        
        call = active_calls.get(call_id)
        if call:
            print(f'❌ Call rejected: {call_id} by user {user_id}')
            
            # Notify caller
            if call['caller_id'] in user_socket_map:
                emit('call_rejected', {
                    'call_id': call_id,
                    'callee_id': user_id,
                    'reason': data.get('reason', 'Call rejected')
                }, room=user_socket_map[call['caller_id']])
            
            # Clean up
            if call_id in active_calls:
                del active_calls[call_id]
                
    except Exception as e:
        print(f'❌ Error handling reject_video_call: {e}')

@socketio.on('end_video_call')
def handle_end_video_call(data):
    """End a video call"""
    try:
        call_id = data.get('call_id')
        user_id = data.get('user_id')
        
        call = active_calls.get(call_id)
        if call:
            # Determine other user
            caller_id = call['caller_id']
            callee_id = call['callee_id']
            other_user = callee_id if user_id == caller_id else caller_id
            
            print(f'📴 Call ended: {call_id} by user {user_id}')
            
            # Notify other user if online
            if other_user in user_socket_map:
                emit('call_ended', {
                    'call_id': call_id,
                    'ended_by': user_id,
                    'reason': data.get('reason', 'Call ended')
                }, room=user_socket_map[other_user])
            
            # Clean up
            if call_id in active_calls:
                del active_calls[call_id]
                
    except Exception as e:
        print(f'❌ Error handling end_video_call: {e}')

@socketio.on('webrtc_offer')
def handle_webrtc_offer(data):
    """Forward WebRTC offer to callee"""
    try:
        call_id = data.get('call_id')
        offer = data.get('offer')
        from_user = data.get('from_user')
        
        call = active_calls.get(call_id)
        if call and call['status'] == 'active':
            # Determine recipient
            to_user = call['callee_id'] if from_user == call['caller_id'] else call['caller_id']
            
            if to_user in user_socket_map:
                print(f'📤 Forwarding WebRTC offer for call {call_id}')
                
                emit('webrtc_offer', {
                    'call_id': call_id,
                    'offer': offer,
                    'from_user': from_user
                }, room=user_socket_map[to_user])
                
    except Exception as e:
        print(f'❌ Error handling webrtc_offer: {e}')

@socketio.on('webrtc_answer')
def handle_webrtc_answer(data):
    """Forward WebRTC answer to caller"""
    try:
        call_id = data.get('call_id')
        answer = data.get('answer')
        from_user = data.get('from_user')
        
        call = active_calls.get(call_id)
        if call and call['status'] == 'active':
            # Determine recipient
            to_user = call['caller_id'] if from_user == call['callee_id'] else call['callee_id']
            
            if to_user in user_socket_map:
                print(f'📥 Forwarding WebRTC answer for call {call_id}')
                
                emit('webrtc_answer', {
                    'call_id': call_id,
                    'answer': answer,
                    'from_user': from_user
                }, room=user_socket_map[to_user])
                
    except Exception as e:
        print(f'❌ Error handling webrtc_answer: {e}')

@socketio.on('webrtc_ice_candidate')
def handle_webrtc_ice_candidate(data):
    """Forward ICE candidate"""
    try:
        call_id = data.get('call_id')
        candidate = data.get('candidate')
        from_user = data.get('from_user')
        
        call = active_calls.get(call_id)
        if call and call['status'] == 'active':
            # Determine recipient
            to_user = call['callee_id'] if from_user == call['caller_id'] else call['caller_id']
            
            if to_user in user_socket_map:
                emit('webrtc_ice_candidate', {
                    'call_id': call_id,
                    'candidate': candidate,
                    'from_user': from_user
                }, room=user_socket_map[to_user])
                
    except Exception as e:
        print(f'❌ Error handling webrtc_ice_candidate: {e}')

@socketio.on('call_health_check')
def handle_call_health_check(data):
    """Check if call is still active"""
    try:
        call_id = data.get('call_id')
        user_id = data.get('user_id')
        
        call = active_calls.get(call_id)
        if call:
            emit('call_health_response', {
                'call_id': call_id,
                'status': call['status'],
                'timestamp': datetime.now(timezone.utc).isoformat()
            }, room=request.sid)
        else:
            emit('call_not_found', {
                'call_id': call_id
            }, room=request.sid)
            
    except Exception as e:
        print(f'❌ Error handling call_health_check: {e}')

@app.route('/api/users/<int:user_id>/followers-and-following', methods=['GET'])
def api_get_follow_stats(user_id):
    """Get user's followers and following counts"""
    try:
        followers_count = Follow.query.filter_by(followed_id=user_id).count()
        following_count = Follow.query.filter_by(follower_id=user_id).count()
        
        return jsonify({
            'followers_count': followers_count,
            'following_count': following_count,
            'success': True
        }), 200
    except Exception as e:
        return jsonify({'error': f'Failed to load follow stats: {str(e)}'}), 500

# ========== ARTIST STATS ENDPOINTS ==========
@app.route('/api/artists/<int:artist_id>/stats', methods=['GET'])
def api_get_artist_stats(artist_id):
    """Get artist statistics: total tracks, followers, and following"""
    try:
        # Get total tracks
        tracks_count = Track.query.filter_by(user_id=artist_id).count()
        
        # Get followers count
        followers_count = Follow.query.filter_by(followed_id=artist_id).count()
        
        # Get following count
        following_count = Follow.query.filter_by(follower_id=artist_id).count()
        
        # Get total plays across all tracks
        total_plays = db.session.query(func.sum(Track.plays))\
            .filter(Track.user_id == artist_id)\
            .scalar() or 0
        
        # Get total likes on artist's tracks
        total_likes = db.session.query(func.count(Like.id))\
            .join(Track, Like.track_id == Track.id)\
            .filter(Track.user_id == artist_id)\
            .scalar() or 0
        
        return jsonify({
            'tracks_count': tracks_count,
            'followers_count': followers_count,
            'following_count': following_count,
            'total_plays': total_plays,
            'total_likes': total_likes,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to load artist stats: {str(e)}'}), 500

@app.route('/api/artists/<int:artist_id>/profile', methods=['GET'])
def api_get_artist_profile(artist_id):
    """Get complete artist profile with stats"""
    token = request.headers.get('Authorization')
    current_user = get_user_from_token(token) if token else None
    
    try:
        artist = User.query.get(artist_id)
        
        if not artist:
            return jsonify({'error': 'Artist not found'}), 404
        
        # Get basic stats
        tracks_count = Track.query.filter_by(user_id=artist_id).count()
        followers_count = Follow.query.filter_by(followed_id=artist_id).count()
        following_count = Follow.query.filter_by(follower_id=artist_id).count()
        
        # Get total plays
        total_plays = db.session.query(func.sum(Track.plays))\
            .filter(Track.user_id == artist_id)\
            .scalar() or 0
        
        # Get recent tracks (limit 5)
        recent_tracks = Track.query.filter_by(user_id=artist_id)\
            .order_by(Track.upload_date.desc())\
            .limit(5)\
            .all()
        
        # Check if current user is following this artist
        is_following = False
        if current_user:
            is_following = Follow.query.filter_by(
                follower_id=current_user.id,
                followed_id=artist_id
            ).first() is not None
        
        # Get artist's top tracks (by plays)
        top_tracks = Track.query.filter_by(user_id=artist_id)\
            .order_by(Track.plays.desc())\
            .limit(5)\
            .all()
        
        # Format tracks data
        recent_tracks_data = []
        for track in recent_tracks:
            track_data = track.to_dict()
            track_data['likes_count'] = Like.query.filter_by(track_id=track.id).count()
            recent_tracks_data.append(track_data)
        
        top_tracks_data = []
        for track in top_tracks:
            track_data = track.to_dict()
            track_data['likes_count'] = Like.query.filter_by(track_id=track.id).count()
            top_tracks_data.append(track_data)
        
        artist_data = artist.to_dict()
        artist_data.update({
            'tracks_count': tracks_count,
            'followers_count': followers_count,
            'following_count': following_count,
            'total_plays': total_plays,
            'is_following': is_following,
            'recent_tracks': recent_tracks_data,
            'top_tracks': top_tracks_data,
            'joined_date': artist.created_at.strftime('%B %Y') if artist.created_at else 'Unknown'
        })
        
        return jsonify({
            'artist': artist_data,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to load artist profile: {str(e)}'}), 500

@app.route('/api/artists/top', methods=['GET'])
def api_get_top_artists():
    """Get top artists based on followers and plays"""
    try:
        limit = request.args.get('limit', 10, type=int)
        
        # Get all artists with stats
        artists = User.query.all()
        
        artists_with_stats = []
        for artist in artists:
            # Calculate artist stats
            tracks_count = Track.query.filter_by(user_id=artist.id).count()
            followers_count = Follow.query.filter_by(followed_id=artist.id).count()
            
            # Only include artists with tracks
            if tracks_count > 0:
                total_plays = db.session.query(func.sum(Track.plays))\
                    .filter(Track.user_id == artist.id)\
                    .scalar() or 0
                
                artist_data = artist.to_dict()
                artist_data.update({
                    'tracks_count': tracks_count,
                    'followers_count': followers_count,
                    'total_plays': total_plays,
                    'popularity_score': followers_count + (total_plays // 100)  # Simple scoring
                })
                
                artists_with_stats.append(artist_data)
        
        # Sort by popularity score (followers + plays)
        artists_with_stats.sort(key=lambda x: x['popularity_score'], reverse=True)
        
        # Limit results
        top_artists = artists_with_stats[:limit]
        
        return jsonify({
            'artists': top_artists,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to load top artists: {str(e)}'}), 500

# Add this new template route
@app.route('/artist/<int:artist_id>')
def artist_profile(artist_id):
    """Artist profile page route"""
    return render_template('artist_profile.html', artist_id=artist_id)

# Also update your existing profile route to handle artist profiles
@app.route('/profile')
def profile():
    """Profile page - can be for current user or viewing other users"""
    user_id = request.args.get('user_id')
    return render_template('profile_view.html', user_id=user_id)

@app.route('/api/artists/stats/bulk', methods=['POST'])
def api_get_bulk_artist_stats():
    """Get stats for multiple artists at once"""
    try:
        data = request.get_json()
        artist_ids = data.get('artist_ids', [])
        
        if not artist_ids:
            return jsonify({'error': 'No artist IDs provided'}), 400
        
        results = {}
        for artist_id in artist_ids:
            try:
                # Get stats
                tracks_count = Track.query.filter_by(user_id=artist_id).count()
                followers_count = Follow.query.filter_by(followed_id=artist_id).count()
                following_count = Follow.query.filter_by(follower_id=artist_id).count()
                
                results[artist_id] = {
                    'tracks_count': tracks_count,
                    'followers_count': followers_count,
                    'following_count': following_count,
                    'success': True
                }
            except Exception as e:
                results[artist_id] = {
                    'error': str(e),
                    'success': False
                }
        
        return jsonify({
            'results': results,
            'success': True
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to load bulk stats: {str(e)}'}), 500

# ========== RUN APP ==========
if __name__ == '__main__':
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Create uploads folder
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        # NO DEMO DATA - clean start for deployment
    
    print("=" * 50)
    print("🎵 SOUNDCONNECT - READY FOR DEPLOYMENT!")
    print("=" * 50)
    print("📊 PRODUCTION DATABASE")
    print("🔐 SECURE AUTHENTICATION")
    print("📈 ANALYTICS & STATISTICS")
    print("💬 REAL-TIME CHAT")
    print("=" * 50)
    print("🌐 Local: http://localhost:5000")
    print("=" * 50)
    
    # For production, set debug=False
    socketio.run(app, 
                 debug=True, 
                 host='0.0.0.0', 
                 port=5000, 
                 allow_unsafe_werkzeug=True)