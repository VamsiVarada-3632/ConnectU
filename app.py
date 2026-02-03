"""
ConnectU - Secure Social Media Application
Full Backend Implementation

Security Features Implemented:
1. Authentication: Single-Factor (Username/Password) + Multi-Factor (OTP)
2. Authorization: Access Control List (ACL) with role-based permissions
3. Encryption: AES-256 for messages, RSA for key exchange
4. Hashing: SHA-256 with Salt for password storage
5. Digital Signatures: RSA-based signature verification for posts
6. Encoding: Base64 encoding for images and data transfer

NIST SP 800-63-2 E-Authentication Architecture Compliance
"""

from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
from datetime import datetime, timedelta

# Import configuration
from config import get_config

# Import models
from models import db, User, Post, Message, Friendship, Notification, SecurityLog, Like, Comment

# Import security modules
from security.auth import AuthenticationService
from security.acl import ACL, require_authenticated, require_permission
from security.encryption import EncryptionService
from security.signatures import SignatureService
from security.encoding import EncodingService
from security.middleware import SecurityMiddleware, generate_csrf_token, SessionManager, require_csrf

# Import utilities
from utils.email import EmailService
from utils.validators import Validator, mask_email, get_time_ago


# Initialize Flask app
app = Flask(__name__)

# Load configuration
config_name = os.environ.get('FLASK_ENV', 'development')
app.config.from_object(get_config(config_name))

# Initialize extensions
db.init_app(app)


# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Initialize security middleware
security_middleware = SecurityMiddleware(app)

@login_manager.user_loader
def load_user(user_id):
    """Load user from database"""
    return User.query.get(int(user_id))

# Add CSRF token to all templates
@app.context_processor
def inject_global_data():
    unread_notifications = 0
    unread_messages = 0
    pending_friend_requests = 0
    if current_user.is_authenticated:
        unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
        unread_messages = Message.query.filter_by(receiver_id=current_user.id, is_read=False, is_deleted_receiver=False).count()
        pending_friend_requests = Friendship.query.filter_by(friend_id=current_user.id, status='pending').count()
        
    return dict(
        csrf_token=generate_csrf_token,
        get_time_ago=get_time_ago,
        unread_notifications_count=unread_notifications,
        unread_messages_count=unread_messages,
        pending_friend_requests_count=pending_friend_requests,
        datetime=datetime
    )




@app.route('/api/counts')
@login_required
def get_counts():
    """Get dynamic counts for badges and dashboard"""
    unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    unread_messages = Message.query.filter_by(receiver_id=current_user.id, is_read=False, is_deleted_receiver=False).count()
    
    # Friend counts
    pending_friend_requests = Friendship.query.filter_by(friend_id=current_user.id, status='pending').count()
    sent_friend_requests = Friendship.query.filter_by(user_id=current_user.id, status='pending').count()
    accepted_friends = Friendship.query.filter(
        db.and_(
            db.or_(Friendship.user_id == current_user.id, Friendship.friend_id == current_user.id),
            Friendship.status == 'accepted'
        )
    ).count()
    
    return jsonify({
        'success': True,
        'notifications': unread_notifications,
        'messages': unread_messages,
        'friend_requests': pending_friend_requests,
        'sent_requests': sent_friend_requests,
        'friends': accepted_friends
    })


@app.route('/')
def landing():
    """Landing page"""
    return render_template('landing.html')

@app.route('/register', methods=['GET', 'POST'])
@security_middleware.limiter.limit("20 per hour")
def register():
    """User registration with password hashing and OTP"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        
        # Validate inputs
        if not all([username, email, password]):
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        # Validate email
        if not Validator.validate_email(email):
            flash('Invalid email format', 'error')
            return render_template('register.html')
        
        # Validate username
        is_valid, message = Validator.validate_username(username)
        if not is_valid:
            flash(message, 'error')
            return render_template('register.html')
        
        # Register user
        user, result = AuthenticationService.register_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        
        if not user:
            flash(result, 'error')  # result contains error message
            return render_template('register.html')
        
        # Generate RSA key pair for encryption and signatures
        public_key, private_key = EncryptionService.generate_rsa_keypair()
        user.rsa_public_key = public_key
        # Encrypt private key with user's password before storage
        user.rsa_private_key_encrypted = EncryptionService.encrypt_private_key(private_key, password)
        db.session.commit()
        
        # Send OTP email
        otp_code = result  # result contains OTP code from registration
        EmailService.send_otp_email(email, otp_code, username)
        
        # Store user ID in session for OTP verification
        session['pending_user_id'] = user.id
        session['user_email'] = email
        session['user_password'] = password
        
        flash('Registration successful! Check your email for OTP verification.', 'success')
        return redirect(url_for('verify_otp'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@security_middleware.limiter.limit("50 per hour")
def login():
    """Single-factor authentication with optional 2FA"""
    if request.method == 'POST':
        # Form sends 'email' field, but user can enter username or email
        username_or_email = request.form.get('email') or request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        if not all([username_or_email, password]):
            flash('Please enter your email and password', 'error')
            return render_template('login.html')

        
        # Authenticate user
        user, requires_otp = AuthenticationService.login_user(username_or_email, password)
        
        if not user:
            flash(requires_otp, 'error')  # requires_otp contains error message
            return render_template('login.html')
        
        if requires_otp:
            # Send OTP email
            EmailService.send_otp_email(user.email, user.otp_temp_code, user.username)
            
            # Store user ID for OTP verification
            session['pending_user_id'] = user.id
            session['remember_me'] = remember
            session['user_password'] = password
            
            flash('OTP sent to your email. Please verify to continue.', 'info')
            return redirect(url_for('verify_otp'))
        
        # Single-factor login successful
        login_user(user, remember=remember)
        SessionManager.create_session(user, remember=remember)
        session['user_password'] = password
        
        flash(f'Welcome back, {user.username}!', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('feed'))
    
    return render_template('login.html')

@app.route('/guest-login')
def guest_login():
    """Bypass authentication to login as the guest user account"""
    guest_user = User.query.filter_by(username='guest1').first()
    if not guest_user:
        flash('Guest account not found. Please contact admin.', 'error')
        return redirect(url_for('login'))
    
    # Authenticate as guest without OTP
    login_user(guest_user)
    
    # Log security event
    SecurityLog.log_event(
        user_id=guest_user.id,
        event_type='guest_login',
        description='User logged in via Guest Login shortcut',
        severity='info'
    )
    
    flash('Logged in as Guest. You have read-only access.', 'success')
    return redirect(url_for('feed'))

@app.route('/verify-otp', methods=['GET', 'POST'])
@security_middleware.limiter.limit("20 per hour")
def verify_otp():
    """Multi-factor authentication - OTP verification"""
    if 'pending_user_id' not in session:
        flash('No pending verification', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Collect OTP from hidden input field (populated by JavaScript)
        otp_code = request.form.get('otp', '').strip()
        
        user_id = session['pending_user_id']
        
        # Verify OTP
        success, message = AuthenticationService.verify_otp(user_id, otp_code)
        
        if success:
            user = User.query.get(user_id)
            remember = session.get('remember_me', False)
            
            login_user(user, remember=remember)
            SessionManager.create_session(user, remember=remember)
            
            # Clear pending session data
            session.pop('pending_user_id', None)
            session.pop('remember_me', None)
            
            flash('Verification successful! Welcome to ConnectU.', 'success')
            return redirect(url_for('feed'))
        else:
            flash(message, 'error')
    
    # Mask email for display
    user_email = session.get('user_email', '')
    masked_email = mask_email(user_email)
    
    return render_template('verify_otp.html', masked_email=masked_email)

@app.route('/logout')
@login_required
def logout():
    """Logout user and destroy session"""
    if 'session_token' in session:
        SessionManager.destroy_session(session['session_token'])
    logout_user()
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('landing'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset request"""
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            import secrets
            reset_token = secrets.token_urlsafe(32)
            # Store token in session (in production, store in database)
            session[f'reset_token_{user.id}'] = reset_token
            session[f'reset_expiry_{user.id}'] = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            
            # Send reset email
            EmailService.send_password_reset_email(user.email, reset_token, user.username)
        
        # Always show success message for security (prevent email enumeration)
        flash('If that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# ============================================
# ROUTES - Main Application (Protected)
# ============================================

@app.route('/feed')
@login_required
def feed():
    """Main feed - show posts from user and friends ONLY"""
    # Get user's friends
    friendships = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == current_user.id, Friendship.status == 'accepted'),
            db.and_(Friendship.friend_id == current_user.id, Friendship.status == 'accepted')
        )
    ).all()
    
    # Extract friend IDs
    friend_ids = set()
    for friendship in friendships:
        if friendship.user_id == current_user.id:
            friend_ids.add(friendship.friend_id)
        else:
            friend_ids.add(friendship.user_id)
    
    # Include current user's ID to see own posts
    friend_ids.add(current_user.id)
    
    # Get posts from user and friends only
    posts = Post.query.filter(
        db.and_(
            Post.user_id.in_(friend_ids),
            db.or_(
                Post.visibility == 'public',
                db.and_(Post.visibility == 'friends', Post.user_id.in_(friend_ids))
            )
        )
    ).order_by(Post.created_at.desc()).limit(50).all()
    
    # Verify digital signatures
    for post in posts:
        if post.signature and post.author.rsa_public_key:
            is_valid, msg = SignatureService.verify_post(
                post.author.rsa_public_key,
                post.content,
                post.image_data or '',
                post.content_hash,
                post.signature
            )
            post.signature_valid = is_valid
    
    return render_template('feed.html', posts=posts)


@app.route('/create-post', methods=['GET', 'POST'])
@login_required
@require_permission('post', 'write')
def create_post():
    """Create new post with digital signature"""
    if request.method == 'POST':
        content = request.form.get('content')
        visibility = request.form.get('visibility', 'public')
        image_file = request.files.get('image')
        
        if not content:
            flash('Post content cannot be empty', 'error')
            return render_template('create_post.html')
        
        # Handle image upload
        image_data = None
        if image_file:
            is_valid, message = Validator.validate_image(image_file)
            if not is_valid:
                flash(message, 'error')
                return render_template('create_post.html')
            
            # Read, resize, and encode image
            image_bytes = image_file.read()
            # Optimize image size before storage
            optimized_bytes = EncodingService.resize_image_if_needed(image_bytes)
            
            mime_type = "image/jpeg"  # Resized images are converted to JPEG
            image_data = EncodingService.encode_image_to_base64(optimized_bytes, mime_type)
        
        # Create digital signature
        user_password = session.get('user_password')
        content_hash = None
        signature = None
        
        if current_user.rsa_private_key_encrypted and user_password:
            try:
                # 1. Decrypt private key
                private_key_pem = EncryptionService.decrypt_private_key(
                    current_user.rsa_private_key_encrypted,
                    user_password
                )
                
                # 2. Sign post
                content_hash, signature = SignatureService.sign_post(
                    private_key_pem,
                    content,
                    image_data
                )
            except Exception as e:
                print(f"Signing error: {e}")
                content_hash = SignatureService.hash_content_sha256(content + (image_data or ''))
                signature = None
        else:
            content_hash = SignatureService.hash_content_sha256(content + (image_data or ''))
            signature = None
        
        # Create post
        post = Post(
            user_id=current_user.id,
            content=content,
            image_data=image_data,
            visibility=visibility,
            content_hash=content_hash,
            signature=signature
        )
        
        db.session.add(post)
        db.session.commit()
        
        flash('Post created successfully!', 'success')
        return redirect(url_for('feed'))
    
    return render_template('create_post.html')

@app.route('/api/post/like/<int:post_id>', methods=['POST'])
@login_required
@require_permission('post', 'write')
def like_post(post_id):
    """Toggle like state for a post"""
    post = Post.query.get_or_404(post_id)
    existing_like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if existing_like:
        db.session.delete(existing_like)
        post.likes_count = max(0, post.likes_count - 1)
        action = 'unliked'
    else:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)
        post.likes_count += 1
        action = 'liked'
        
        # Create notification if not own post
        if post.user_id != current_user.id:
            notif = Notification(
                user_id=post.user_id,
                notification_type='like',
                title='New Like',
                message=f'{current_user.first_name} liked your post.',
                related_user_id=current_user.id,
                related_post_id=post.id
            )
            db.session.add(notif)
            
    db.session.commit()
    return jsonify({
        'success': True,
        'action': action,
        'likes_count': post.likes_count
    })

@app.route('/api/post/comment/<int:post_id>', methods=['POST'])
@login_required
@require_permission('post', 'write')
def add_comment(post_id):
    """Add a new comment to a post"""
    post = Post.query.get_or_404(post_id)
    content = request.json.get('content')
    
    if not content or not content.strip():
        return jsonify({'success': False, 'error': 'Comment content is required'}), 400
        
    comment = Comment(user_id=current_user.id, post_id=post_id, content=content.strip())
    db.session.add(comment)
    post.comments_count += 1
    
    # Create notification if not own post
    if post.user_id != current_user.id:
        notif = Notification(
            user_id=post.user_id,
            notification_type='comment',
            title='New Comment',
            message=f'{current_user.first_name} commented on your post.',
            related_user_id=current_user.id,
            related_post_id=post.id
        )
        db.session.add(notif)
        
    db.session.commit()
    return jsonify({
        'success': True,
        'comment': {
            'id': comment.id,
            'content': comment.content,
            'user_id': comment.user_id,
            'user_name': f"{current_user.first_name} {current_user.last_name}",
            'created_at': comment.created_at.isoformat()
        },
        'comments_count': post.comments_count
    })

@app.route('/api/post/delete/<int:post_id>', methods=['POST'])
@login_required
@require_permission('post', 'delete')
def delete_post(post_id):
    """Delete a post (owner or admin only)"""
    post = Post.query.get_or_404(post_id)
    
    # Check ownership or admin role
    if post.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
        
    db.session.delete(post)
    
    # Log security event
    SecurityLog.log_event(
        user_id=current_user.id,
        event_type='POST_DELETED',
        description=f'Deleted post ID: {post_id}',
        severity='info'
    )
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'Post deleted successfully'})

@app.route('/profile')
@app.route('/profile/<username>')
@login_required
def profile(username=None):
    """User profile page with ACL"""
    if username:
        user = User.query.filter_by(username=username).first_or_404()
    else:
        user = current_user
    
    # Check ACL
    if not ACL.check_profile_access(user, 'read'):
        flash('You do not have permission to view this profile', 'error')
        return redirect(url_for('feed'))
    
    # Get user's posts
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created_at.desc()).limit(20).all()
    
    # Verify digital signatures
    for post in posts:
        if post.signature and post.author.rsa_public_key:
            is_valid, _ = SignatureService.verify_post(
                post.author.rsa_public_key,
                post.content,
                post.image_data or '',
                post.content_hash,
                post.signature
            )
            post.signature_valid = is_valid
            
    # Add friendship status if viewing someone else
    friend_status = None
    friendship_id = None
    if user.id != current_user.id:
        friendship = Friendship.query.filter(
            db.or_(
                db.and_(Friendship.user_id == current_user.id, Friendship.friend_id == user.id),
                db.and_(Friendship.user_id == user.id, Friendship.friend_id == current_user.id)
            )
        ).first()
        
        if friendship:
            friendship_id = friendship.id
            if friendship.status == 'accepted':
                friend_status = 'friends'
            elif friendship.user_id == current_user.id:
                friend_status = 'request_sent'
            else:
                friend_status = 'request_received'
        else:
            friend_status = 'not_friends'
            
    # Calculate counts
    posts_count = Post.query.filter_by(user_id=user.id).count()
    friends_count = Friendship.query.filter(
        db.and_(
            db.or_(Friendship.user_id == user.id, Friendship.friend_id == user.id),
            Friendship.status == 'accepted'
        )
    ).count()
    
    return render_template('profile.html', 
                         user=user, 
                         posts=posts, 
                         posts_count=posts_count,
                         friends_count=friends_count,
                         friend_status=friend_status,
                         friendship_id=friendship_id)



@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile - owner only"""
    if not ACL.check_profile_access(current_user, 'write'):
        flash('Permission denied', 'error')
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.bio = request.form.get('bio')
        current_user.location = request.form.get('location')
        current_user.education = request.form.get('education')
        
        # Handle avatar upload
        avatar = request.files.get('avatar')
        if avatar:
            is_valid, msg = Validator.validate_image(avatar)
            if is_valid:
                avatar_bytes = avatar.read()
                # Optimize profile avatar
                optimized_avatar = EncodingService.resize_image_if_needed(avatar_bytes, max_size=(512, 512))
                current_user.avatar_data = EncodingService.encode_image_to_base64(optimized_avatar, 'image/jpeg')
        
        # Handle cover photo
        cover = request.files.get('cover')
        if cover:
            is_valid, msg = Validator.validate_image(cover)
            if is_valid:
                cover_bytes = cover.read()
                # Optimize cover photo
                optimized_cover = EncodingService.resize_image_if_needed(cover_bytes, max_size=(1200, 400))
                current_user.cover_data = EncodingService.encode_image_to_base64(optimized_cover, 'image/jpeg')
        
        # Privacy settings
        current_user.public_profile = request.form.get('public_profile') == 'on'
        current_user.show_email = request.form.get('show_email') == 'on'
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html')

@app.route('/chat')
@app.route('/chat/<username>')
@login_required
def chat(username=None):
    """Chat page with encrypted messaging"""
    # Get all users the current user has exchanged messages with
    sent_to_ids = db.session.query(Message.receiver_id).filter(Message.sender_id == current_user.id).distinct().all()
    received_from_ids = db.session.query(Message.sender_id).filter(Message.receiver_id == current_user.id).distinct().all()
    
    unique_ids = set([uid[0] for uid in sent_to_ids] + [uid[0] for uid in received_from_ids])
    conversations = User.query.filter(User.id.in_(unique_ids)).all() if unique_ids else []
    
    messages = []
    other_user = None
    
    if username:
        other_user = User.query.filter_by(username=username).first_or_404()
        
        # Get messages between users
        messages = Message.query.filter(
            db.or_(
                db.and_(
                    Message.sender_id == current_user.id, 
                    Message.receiver_id == other_user.id,
                    Message.is_deleted_sender == False
                ),
                db.and_(
                    Message.sender_id == other_user.id, 
                    Message.receiver_id == current_user.id,
                    Message.is_deleted_receiver == False
                )
            )
        ).order_by(Message.created_at.asc()).all()
        
        # Get user's password from session for private key decryption
        user_password = session.get('user_password')
        
        # Decrypt messages
        for msg in messages:
            try:
                if msg.encrypted_content:
                    # Choose the correct encrypted AES key based on whether current user is sender or receiver
                    encrypted_key = None
                    if msg.receiver_id == current_user.id:
                        encrypted_key = msg.aes_key_encrypted
                    elif msg.sender_id == current_user.id:
                        encrypted_key = msg.aes_key_sender_encrypted
                    
                    if encrypted_key and user_password and current_user.rsa_private_key_encrypted:
                        # 1. Decrypt user's private key
                        private_key_pem = EncryptionService.decrypt_private_key(
                            current_user.rsa_private_key_encrypted,
                            user_password
                        )
                        
                        # 2. Decrypt AES key using RSA private key
                        aes_key = EncryptionService.decrypt_key_with_rsa(
                            private_key_pem,
                            encrypted_key
                        )
                        
                        # 3. Decrypt message content using AES key
                        msg.decrypted_body = EncryptionService.decrypt_with_aes(
                            aes_key,
                            msg.encrypted_content,
                            msg.iv,
                            msg.auth_tag
                        )
                    else:
                        msg.decrypted_body = "[Encrypted Message]"

                else:
                    msg.decrypted_body = ""
            except Exception as e:
                msg.decrypted_body = "[Decryption Failed]"
    
    return render_template('chat.html', 
                         conversations=conversations, 
                         messages=messages, 
                         other_user=other_user)

@app.route('/api/chat/<username>')

@login_required
def get_chat_messages(username):
    """API endpoint to get decrypted chat messages as JSON"""
    other_user = User.query.filter_by(username=username).first_or_404()
    user_password = session.get('user_password')
    
    # Get messages between users
    messages = Message.query.filter(
        db.or_(
            db.and_(
                Message.sender_id == current_user.id, 
                Message.receiver_id == other_user.id,
                Message.is_deleted_sender == False
            ),
            db.and_(
                Message.sender_id == other_user.id, 
                Message.receiver_id == current_user.id,
                Message.is_deleted_receiver == False
            )
        )
    ).order_by(Message.created_at.asc()).all()
    
    messages_data = []
    
    for msg in messages:
        decrypted_body = ""
        if msg.encrypted_content:
            try:
                # Choose the correct encrypted AES key
                encrypted_key = None
                if msg.receiver_id == current_user.id:
                    encrypted_key = msg.aes_key_encrypted
                elif msg.sender_id == current_user.id:
                    encrypted_key = msg.aes_key_sender_encrypted
                
                if encrypted_key and user_password and current_user.rsa_private_key_encrypted:
                    # 1. Decrypt user's private key
                    private_key_pem = EncryptionService.decrypt_private_key(
                        current_user.rsa_private_key_encrypted,
                        user_password
                    )
                    
                    # 2. Decrypt AES key
                    aes_key = EncryptionService.decrypt_key_with_rsa(
                        private_key_pem,
                        encrypted_key
                    )
                    
                    # 3. Decrypt message content
                    decrypted_body = EncryptionService.decrypt_with_aes(
                        aes_key,
                        msg.encrypted_content,
                        msg.iv,
                        msg.auth_tag
                    )
                else:
                    decrypted_body = "[Encrypted Message]"
            except Exception:
                decrypted_body = "[Decryption Failed]"
        
        messages_data.append({
            'id': msg.id,
            'sender_id': msg.sender_id,
            'receiver_id': msg.receiver_id,
            'content': decrypted_body,
            'created_at': msg.created_at.strftime('%I:%M %p'),
            'is_read': msg.is_read
        })
    
    return jsonify({
        'success': True,
        'messages': messages_data,
        'other_user_id': other_user.id,
        'current_user_id': current_user.id
    })




@app.route('/send-message', methods=['POST'])
@login_required
@require_permission('message', 'write')
def send_message():
    """Send encrypted message"""
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')
    
    if not all([receiver_id, content]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    receiver = User.query.get(receiver_id)
    if not receiver or not receiver.rsa_public_key:
        return jsonify({'error': 'Invalid receiver or missing public key'}), 400
    
    try:
        # Encrypt message using hybrid encryption
        # We also encrypt the session key for the sender so they can view it later
        encrypted_data = EncryptionService.encrypt_message_hybrid(
            receiver.rsa_public_key,
            content,
            sender_public_key_pem=current_user.rsa_public_key
        )
        
        # Create message
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            encrypted_content=encrypted_data['encrypted_content'],
            aes_key_encrypted=encrypted_data['encrypted_key'],
            aes_key_sender_encrypted=encrypted_data.get('sender_encrypted_key'),
            iv=encrypted_data['iv'],
            auth_tag=encrypted_data.get('auth_tag')
        )


        db.session.add(message)
        db.session.commit()
        
        return jsonify({'success': True, 'message_id': message.id})
    except Exception as e:
        print(f"Message encryption error: {e}")
        return jsonify({'error': 'Message encryption failed'}), 500


@app.route('/api/messages/delete/<int:message_id>', methods=['POST'])
@login_required
@require_csrf()
def delete_message(message_id):
    """Delete a message (unsend)"""
    message = Message.query.get_or_404(message_id)
    
    # Check if the user is the sender
    if message.sender_id != current_user.id:
        return jsonify({'error': 'Unauthorized to delete this message'}), 403
    
    try:
        # Mark as deleted for both (unsend behavior)
        message.is_deleted_sender = True
        message.is_deleted_receiver = True
        
        # log security event
        from security.middleware import log_security_event
        log_security_event('MESSAGE_DELETED', f'Message ID: {message_id}', user_id=current_user.id)
        
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting message: {e}")
        return jsonify({'error': 'Failed to delete message'}), 500


@app.route('/friends')
@login_required
def friends():
    """Friends page - show actual friends and requests"""
    # Get accepted friends
    friendships = Friendship.query.filter(
        db.and_(
            db.or_(
                Friendship.user_id == current_user.id,
                Friendship.friend_id == current_user.id
            ),
            Friendship.status == 'accepted'
        )
    ).all()
    
    # Build friends list with user objects
    friends_list = []
    for friendship in friendships:
        friend_id = friendship.friend_id if friendship.user_id == current_user.id else friendship.user_id
        friend = User.query.get(friend_id)
        if friend:
            friends_list.append(friend)
    
    # Get pending friend requests (received)
    pending_requests = Friendship.query.filter_by(
        friend_id=current_user.id,
        status='pending'
    ).all()
    
    # Get sent friend requests
    sent_requests = Friendship.query.filter_by(
        user_id=current_user.id,
        status='pending'
    ).all()
    
    # Get friend suggestions (users not already friends)
    existing_friend_ids = [f.id for f in friends_list]
    pending_ids = [r.user_id for r in pending_requests] + [r.friend_id for r in sent_requests]
    all_excluded_ids = existing_friend_ids + pending_ids + [current_user.id]
    
    suggestions = User.query.filter(
        db.and_(
            User.id.notin_(all_excluded_ids),
            User.is_active == True
        )
    ).limit(10).all()
    
    return render_template('friends.html', 
                         friends=friends_list,
                         pending_requests=pending_requests,
                         sent_requests=sent_requests,
                         suggestions=suggestions)

@app.route('/search')
@login_required
def search():
    """Search for users dynamically"""
    query = request.args.get('q', '').strip()
    results = []
    
    if query:
        # Search by username, first name, or last name
        results = User.query.filter(
            db.and_(
                db.or_(
                    User.username.ilike(f'%{query}%'),
                    User.first_name.ilike(f'%{query}%'),
                    User.last_name.ilike(f'%{query}%'),
                    User.email.ilike(f'%{query}%')
                ),
                User.id != current_user.id,
                User.is_active == True
            )
        ).limit(20).all()
        
        # Add friendship status to each result
        for user in results:
            friendship = Friendship.query.filter(
                db.or_(
                    db.and_(Friendship.user_id == current_user.id, Friendship.friend_id == user.id),
                    db.and_(Friendship.user_id == user.id, Friendship.friend_id == current_user.id)
                )
            ).first()
            
            if friendship:
                if friendship.status == 'accepted':
                    user.friend_status = 'friends'
                elif friendship.user_id == current_user.id:
                    user.friend_status = 'request_sent'
                else:
                    user.friend_status = 'request_received'
            else:
                user.friend_status = 'not_friends'
    
    return render_template('search.html', query=query, results=results)

@app.route('/notifications')
@login_required
def notifications():
    """Notifications page"""
    user_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/settings')
@login_required
def settings():
    """Settings page"""
    return render_template('settings.html')

# ============================================
# API Routes - Friend Requests
# ============================================

@app.route('/api/friend-request/send/<int:user_id>', methods=['POST'])
@login_required
@require_csrf()
def send_friend_request(user_id):
    """Send a friend request"""
    target_user = User.query.get(user_id)
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    if user_id == current_user.id:
        return jsonify({'error': 'Cannot send friend request to yourself'}), 400
    
    # Check if friendship already exists
    existing = Friendship.query.filter(
        db.or_(
            db.and_(Friendship.user_id == current_user.id, Friendship.friend_id == user_id),
            db.and_(Friendship.user_id == user_id, Friendship.friend_id == current_user.id)
        )
    ).first()
    
    if existing:
        if existing.status == 'accepted':
            return jsonify({'error': 'Already friends'}), 400
        return jsonify({'error': 'Friend request already sent'}), 400
    
    # Create friend request
    friendship = Friendship(
        user_id=current_user.id, 
        friend_id=user_id, 
        status='pending',
        initiated_by=current_user.id
    )
    db.session.add(friendship)
    db.session.flush()

    notification = Notification(
        user_id=user_id,
        notification_type='friend_request',
        title='Friend Request',
        message=f'{current_user.username} sent you a friend request',
        related_user_id=current_user.id,
        related_friendship_id=friendship.id
    )

    db.session.add(notification)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Friend request sent'})

@app.route('/api/friend-request/accept/<int:friendship_id>', methods=['POST'])
@login_required
@require_csrf()
def accept_friend_request(friendship_id):
    """Accept a friend request"""
    friendship = Friendship.query.get(friendship_id)
    
    if not friendship or friendship.friend_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if friendship.status != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
    
    friendship.status = 'accepted'
    notification = Notification(
        user_id=friendship.user_id,
        notification_type='friend_accept',
        title='Friend Request Accepted',
        message=f'{current_user.username} accepted your friend request',
        related_user_id=current_user.id
    )

    db.session.add(notification)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Friend request accepted'})

@app.route('/api/friend-request/reject/<int:friendship_id>', methods=['POST'])
@login_required
@require_csrf()
def reject_friend_request(friendship_id):
    """Reject a friend request"""
    friendship = Friendship.query.get(friendship_id)
    
    if not friendship or friendship.friend_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(friendship)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Friend request rejected'})

@app.route('/api/friend-request/cancel/<int:friendship_id>', methods=['POST'])
@login_required
@require_csrf()
def cancel_friend_request(friendship_id):
    """Cancel a sent friend request"""
    friendship = Friendship.query.get(friendship_id)
    
    if not friendship or friendship.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized or request not found'}), 403
    
    if friendship.status != 'pending':
        return jsonify({'error': 'Request already processed'}), 400
    
    db.session.delete(friendship)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Friend request canceled'})

@app.route('/api/unfriend/<int:user_id>', methods=['POST'])
@login_required
@require_csrf()
def unfriend(user_id):
    """Remove a friend"""
    friendship = Friendship.query.filter(
        db.and_(
            db.or_(
                db.and_(Friendship.user_id == current_user.id, Friendship.friend_id == user_id),
                db.and_(Friendship.user_id == user_id, Friendship.friend_id == current_user.id)
            ),
            Friendship.status == 'accepted'
        )
    ).first()
    
    if not friendship:
        return jsonify({'error': 'Friendship not found'}), 404
    
    db.session.delete(friendship)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Friend removed'})

# ============================================
# Database Initialization
# ============================================


@app.cli.command()
def init_db():
    """Initialize the database"""
    db.create_all()
    print("Database initialized!")

@app.cli.command()
def create_test_users():
    """Create test users for all roles"""
    # 1. Admin
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@connectu.com', first_name='System', last_name='Admin', role='admin')
        admin.set_password('Admin@123')
        admin.otp_verified = True
        pk, sk = EncryptionService.generate_rsa_keypair()
        admin.rsa_public_key = pk
        admin.rsa_private_key_encrypted = EncryptionService.encrypt_private_key(sk, 'Admin@123')
        db.session.add(admin)
        print("Created admin: admin / Admin@123")

    # 2. Standard User
    if not User.query.filter_by(username='user1').first():
        user1 = User(username='user1', email='user1@connectu.com', first_name='John', last_name='Doe', role='user')
        user1.set_password('User1@123')
        user1.otp_verified = True
        pk, sk = EncryptionService.generate_rsa_keypair()
        user1.rsa_public_key = pk
        user1.rsa_private_key_encrypted = EncryptionService.encrypt_private_key(sk, 'User1@123')
        db.session.add(user1)
        print("Created user: user1 / User1@123")

    # 3. Guest User
    if not User.query.filter_by(username='guest1').first():
        guest1 = User(username='guest1', email='guest1@connectu.com', first_name='Guest', last_name='Visitor', role='guest')
        guest1.set_password('Guest1@123')
        guest1.otp_verified = True
        # Guest doesn't necessarily need encryption keys, but we can add them
        pk, sk = EncryptionService.generate_rsa_keypair()
        guest1.rsa_public_key = pk
        guest1.rsa_private_key_encrypted = EncryptionService.encrypt_private_key(sk, 'Guest1@123')
        db.session.add(guest1)
        print("Created guest: guest1 / Guest1@123")
    
    db.session.commit()
    print("Database seeding completed!")

# ============================================
# Admin Routes
# ============================================

@app.route('/admin')
@login_required
@require_permission('profile', 'delete') # Only admin based on ACL matrix
def admin_dashboard():
    """Admin dashboard - system overview"""
    if current_user.role != 'admin':
        abort(403)
        
    user_count = User.query.count()
    post_count = Post.query.count()
    msg_count = Message.query.count()
    
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    recent_logs = SecurityLog.query.order_by(SecurityLog.created_at.desc()).limit(10).all()
    
    return render_template('admin_dashboard.html', 
                          user_count=user_count,
                          post_count=post_count,
                          msg_count=msg_count,
                          recent_users=recent_users,
                          recent_logs=recent_logs)

@app.route('/admin/logs')
@login_required
def admin_logs():
    """Detailed security logs view"""
    if current_user.role != 'admin':
        abort(403)
        
    logs = SecurityLog.query.order_by(SecurityLog.created_at.desc()).limit(100).all()
    return render_template('admin_logs.html', logs=logs)

# ============================================
# Error Handlers
# ============================================

@app.errorhandler(403)
def forbidden(e):
    return render_template('landing.html'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('landing.html'), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    return render_template('landing.html'), 500

# ============================================
# Run Application
# ============================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables on first run
    app.run(debug=True, port=5001)
