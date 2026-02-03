"""
ConnectU - Database Models
SQLAlchemy models for secure social media application
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model with security features"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Profile information
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    bio = db.Column(db.String(150))
    location = db.Column(db.String(100))
    education = db.Column(db.String(100))
    interests = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    
    # Profile images (Base64 encoded)
    avatar_data = db.Column(db.Text)  # Base64 encoded avatar
    cover_data = db.Column(db.Text)   # Base64 encoded cover photo
    
    # RSA Keys for encryption and digital signatures
    rsa_public_key = db.Column(db.Text)  # Public key (PEM format)
    rsa_private_key_encrypted = db.Column(db.Text)  # Encrypted private key
    
    # OTP for multi-factor authentication
    otp_secret = db.Column(db.String(32))  # TOTP secret
    otp_verified = db.Column(db.Boolean, default=False)
    otp_temp_code = db.Column(db.String(6))  # Temporary OTP code
    otp_temp_expires = db.Column(db.DateTime)  # OTP expiry time
    
    # Privacy settings
    public_profile = db.Column(db.Boolean, default=True)
    show_email = db.Column(db.Boolean, default=False)
    show_online_status = db.Column(db.Boolean, default=True)
    allow_friend_requests = db.Column(db.Boolean, default=True)
    
    # Account status
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='user')  # user, admin, guest
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_seen = db.Column(db.DateTime)
    
    # Relationships
    posts = db.relationship('Post', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', 
                                   backref='sender', lazy='dynamic', cascade='all, delete-orphan')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id',
                                       backref='receiver', lazy='dynamic', cascade='all, delete-orphan')
    sessions = db.relationship('Session', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash password with salt using werkzeug (uses PBKDF2-SHA256)"""
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
    
    def check_password(self, password):
        """Verify password against hash"""
        return check_password_hash(self.password_hash, password)
    
    def generate_otp_secret(self):
        """Generate OTP secret for 2FA"""
        self.otp_secret = secrets.token_hex(16)
        return self.otp_secret
    
    def __repr__(self):
        return f'<User {self.username}>'


class Post(db.Model):
    """Post model with digital signature"""
    __tablename__ = 'posts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Content
    content = db.Column(db.Text, nullable=False)
    image_data = db.Column(db.Text)  # Base64 encoded image
    visibility = db.Column(db.String(20), default='public')  # public, friends, private
    
    # Digital signature for integrity
    content_hash = db.Column(db.String(64))  # SHA-256 hash of content
    signature = db.Column(db.Text)  # RSA signature of content hash
    
    # Metadata
    location = db.Column(db.String(100))
    tagged_users = db.Column(db.Text)  # JSON array of user IDs
    
    # Statistics
    likes_count = db.Column(db.Integer, default=0)
    comments_count = db.Column(db.Integer, default=0)
    
    # Relationships

    likes_list = db.relationship('Like', backref='post', cascade='all, delete-orphan', lazy='dynamic')
    comments_list = db.relationship('Comment', backref='post', cascade='all, delete-orphan', lazy='dynamic')
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<Post {self.id} by User {self.user_id}>'


class Message(db.Model):
    """Message model with end-to-end encryption"""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Encrypted content using AES-256
    encrypted_content = db.Column(db.Text, nullable=False)
    
    # Encryption metadata
    aes_key_encrypted = db.Column(db.Text)  # AES key encrypted with receiver's RSA public key
    aes_key_sender_encrypted = db.Column(db.Text)  # AES key encrypted with sender's RSA public key
    iv = db.Column(db.String(32))  # Initialization vector for AES-GCM
    auth_tag = db.Column(db.String(32))  # Authentication tag for AES-GCM
    
    # Status
    is_read = db.Column(db.Boolean, default=False)
    is_deleted_sender = db.Column(db.Boolean, default=False)
    is_deleted_receiver = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Message {self.id} from {self.sender_id} to {self.receiver_id}>'


class Friendship(db.Model):
    """Friendship model for user relationships"""
    __tablename__ = 'friendships'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Status: pending, accepted, declined, blocked
    status = db.Column(db.String(20), default='pending', index=True)
    
    # Who initiated the request
    initiated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint to prevent duplicate friendships
    __table_args__ = (
        db.UniqueConstraint('user_id', 'friend_id', name='unique_friendship'),
    )
    
    # Relationships for easier template access
    requester = db.relationship('User', foreign_keys=[user_id], backref='sent_requests_list')
    receiver = db.relationship('User', foreign_keys=[friend_id], backref='received_requests_list')
    initiator_user = db.relationship('User', foreign_keys=[initiated_by])

    
    def __repr__(self):
        return f'<Friendship {self.user_id} - {self.friend_id} ({self.status})>'


class Session(db.Model):
    """Active session model for session management"""
    __tablename__ = 'sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Session data
    session_token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    
    # Device information
    device_type = db.Column(db.String(50))  # Chrome on Windows, Mobile App on Android
    ip_address = db.Column(db.String(45))
    location = db.Column(db.String(100))  # City, Country
    user_agent = db.Column(db.String(255))
    
    # Status
    is_active = db.Column(db.Boolean, default=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<Session {self.session_token[:8]}... for User {self.user_id}>'


class SecurityLog(db.Model):
    """Security audit log"""
    __tablename__ = 'security_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    
    # Event details
    event_type = db.Column(db.String(50), nullable=False, index=True)  # login, logout, failed_login, etc.
    description = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    
    # Status
    severity = db.Column(db.String(20))  # info, warning, critical
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    @staticmethod
    def log_event(user_id, event_type, description, severity='info', commit=True):
        """Log a security event to the database"""
        from flask import request
        # Use a nested import to avoid circular dependency
        from models import db
        
        try:
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get('User-Agent') if request else None
        except RuntimeError:
            # Working outside of request context
            ip_address = None
            user_agent = None

        log = SecurityLog(
            user_id=user_id,
            event_type=event_type,
            description=description,
            severity=severity,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(log)
        if commit:
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                # If commit fails, we still want the error to propagate or handle it
                raise
        return log

    def __repr__(self):
        return f'<SecurityLog {self.event_type} at {self.created_at}>'


class Like(db.Model):
    """Post Like model"""
    __tablename__ = 'likes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Unique constraint to prevent multiple likes from same user
    __table_args__ = (
        db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),
    )
    
    def __repr__(self):
        return f'<Like User {self.user_id} -> Post {self.post_id}>'


class Comment(db.Model):
    """Post Comment model"""
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False, index=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self):
        return f'<Comment User {self.user_id} on Post {self.post_id}>'


class Notification(db.Model):
    """Notification model"""
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    
    # Notification details
    notification_type = db.Column(db.String(50), nullable=False)  # friend_request, like, comment, etc.
    title = db.Column(db.String(100))
    message = db.Column(db.Text)
    
    # Related entities
    related_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    related_post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))
    related_friendship_id = db.Column(db.Integer, db.ForeignKey('friendships.id'))
    
    related_user = db.relationship('User', foreign_keys=[related_user_id])
    related_post = db.relationship('Post', foreign_keys=[related_post_id])
    related_friendship = db.relationship('Friendship', foreign_keys=[related_friendship_id])
    
    # Status
    is_read = db.Column(db.Boolean, default=False)
    
    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)


    
    def __repr__(self):
        return f'<Notification {self.notification_type} for User {self.user_id}>'
