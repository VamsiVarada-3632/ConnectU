"""
ConnectU - Utility Functions
Input validation and helpers
"""

import re
from flask import flash
from werkzeug.utils import secure_filename


class Validator:
    """Input validation utilities"""
    
    @staticmethod
    def validate_email(email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_username(username):
        """Validate username (alphanumeric, underscore, 3-20 chars)"""
        if len(username) < 3 or len(username) > 20:
            return False, "Username must be 3-20 characters long"
        
        pattern = r'^[a-zA-Z0-9_]+$'
        if not re.match(pattern, username):
            return False, "Username can only contain letters, numbers, and underscores"
        
        return True, "Valid username"
    
    @staticmethod
    def validate_password(password):
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one number"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        return True, "Strong password"
    
    @staticmethod
    def sanitize_html(text):
        """Basic HTML sanitization"""
        # Remove script tags and other potentially dangerous elements
        text = re.sub(r'<script.*?</script>', '', text, flags=re.DOTALL)
        text = re.sub(r'<iframe.*?</iframe>', '', text, flags=re.DOTALL)
        text = re.sub(r'on\w+=".*?"', '', text)  # Remove event handlers
        return text
    
    @staticmethod
    def validate_image(file, max_size_mb=20):
        """Validate uploaded image"""
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
        
        if not file:
            return False, "No file provided"
        
        # Check filename
        filename = secure_filename(file.filename)
        if '.' not in filename:
            return False, "Invalid file"
        
        ext = filename.rsplit('.', 1)[1].lower()
        if ext not in allowed_extensions:
            return False, f"Invalid file type. Allowed: {', '.join(allowed_extensions)}"
        
        # Check file size
        file.seek(0, 2)  # Move to end
        size = file.tell()
        file.seek(0)  # Reset
        
        max_size = max_size_mb * 1024 * 1024
        if size > max_size:
            return False, f"File too large. Maximum size is {max_size_mb}MB"
        
        return True, "Valid image"


def flash_errors(form):
    """Flash all WTForm errors"""
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{field}: {error}", 'error')


def mask_email(email):
    """Mask email for privacy (show only first char and domain)"""
    if '@' not in email:
        return email
    
    username, domain = email.split('@', 1)
    if len(username) <= 2:
        masked_username = username[0] + '*'
    else:
        masked_username = username[0] + '*' * (len(username) - 2) + username[-1]
    
    return f"{masked_username}@{domain}"


def get_time_ago(timestamp):
    """Convert timestamp to human-readable relative time"""
    from datetime import datetime
    
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)
    
    now = datetime.utcnow()
    diff = now - timestamp
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return "just now"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes}m ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours}h ago"
    elif seconds < 604800:
        days = int(seconds / 86400)
        return f"{days}d ago"
    else:
        return timestamp.strftime("%b %d, %Y")


def jsonify_user(user):
    """Convert user object to JSON-safe dict"""
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email if user.show_email else None,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'avatar_data': user.avatar_data,
        'bio': user.bio,
        'public_profile': user.public_profile,
        'created_at': user.created_at.isoformat() if user.created_at else None
    }


def jsonify_post(post):
    """Convert post object to JSON-safe dict"""
    return {
        'id': post.id,
        'user_id': post.user_id,
        'content': post.content,
        'image_data': post.image_data,
        'visibility': post.visibility,
        'signature': post.signature,
        'created_at': post.created_at.isoformat() if post.created_at else None,
        'likes_count': post.likes_count,
        'comments_count': post.comments_count
    }
