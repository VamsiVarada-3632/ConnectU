"""
ConnectU Security Module
Security Middleware - CSRF, Rate Limiting, Session Management
"""

from functools import wraps
from flask import request, abort, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import SecurityLog
from datetime import datetime, timedelta
import secrets


class SecurityMiddleware:
    """Security middleware for the application"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize security middleware"""
        # Initialize rate limiter
        self.limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"],
            storage_uri=app.config.get('RATELIMIT_STORAGE_URL', 'memory://')
        )
        
        # Add security headers
        @app.after_request
        def add_security_headers(response):
            # Prevent clickjacking
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            
            # Prevent MIME type sniffing
            response.headers['X-Content-Type-Options'] = 'nosniff'
            
            # Enable XSS protection
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Content Security Policy
            response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
            
            # Strict Transport Security (HTTPS only)
            if app.config.get('SESSION_COOKIE_SECURE', False):
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            return response
        
        # Session timeout check
        @app.before_request
        def check_session_timeout():
            if 'last_activity' in session:
                timeout_minutes = app.config.get('SESSION_TIMEOUT_MINUTES', 30)
                last_activity = session['last_activity']
                
                if isinstance(last_activity, str):
                    last_activity = datetime.fromisoformat(last_activity)
                
                if datetime.utcnow() - last_activity > timedelta(minutes=timeout_minutes):
                    session.clear()
                    abort(401, description='Session expired due to inactivity')
            
            session['last_activity'] = datetime.utcnow().isoformat()
    
    def rate_limit(self, limit_string):
        """
        Decorator for rate limiting
        
        Usage:
            @security_middleware.rate_limit("5 per hour")
            def login():
                ...
        """
        def decorator(f):
            return self.limiter.limit(limit_string)(f)
        return decorator


def generate_csrf_token():
    """Generate CSRF token for forms"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def verify_csrf_token(token):
    """Verify CSRF token"""
    if 'csrf_token' not in session:
        return False
    return session['csrf_token'] == token


def require_csrf():
    """Decorator to require CSRF token"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
                if not token or not verify_csrf_token(token):
                    abort(403, description='CSRF token missing or invalid')
            return f(*args, **kwargs)
        return decorated_function
    return decorator


class SessionManager:
    """Manage user sessions securely"""
    
    @staticmethod
    def create_session(user, device_type=None, remember=False):
        """Create a new session for user"""
        from models import db, Session
        
        # Generate session token
        session_token = secrets.token_urlsafe(32)
        
        # Calculate expiry
        if remember:
            expires_at = datetime.utcnow() + timedelta(days=30)
        else:
            expires_at = datetime.utcnow() + timedelta(hours=24)
        
        # Create session record
        user_session = Session(
            user_id=user.id,
            session_token=session_token,
            device_type=device_type or request.headers.get('User-Agent', 'Unknown'),
            ip_address=request.remote_addr,
            expires_at=expires_at
        )
        
        db.session.add(user_session)
        db.session.commit()
        
        # Store in Flask session
        session['session_token'] = session_token
        session['user_id'] = user.id
        session['last_activity'] = datetime.utcnow().isoformat()
        
        if remember:
           session.permanent = True
        
        return session_token
    
    @staticmethod
    def validate_session(session_token):
        """Validate session token"""
        from models import Session as SessionModel
        
        user_session = SessionModel.query.filter_by(
            session_token=session_token,
            is_active=True
        ).first()
        
        if not user_session:
            return None
        
        # Check if expired
        if user_session.expires_at < datetime.utcnow():
            user_session.is_active = False
            from models import db
            db.session.commit()
            return None
        
        # Update last activity
        user_session.last_activity = datetime.utcnow()
        from models import db
        db.session.commit()
        
        return user_session
    
    @staticmethod
    def destroy_session(session_token):
        """Destroy a session"""
        from models import db, Session as SessionModel
        
        user_session = SessionModel.query.filter_by(session_token=session_token).first()
        if user_session:
            user_session.is_active = False
            db.session.commit()
        
        session.clear()
    
    @staticmethod
    def destroy_all_sessions(user_id):
        """Destroy all sessions for a user (logout from all devices)"""
        from models import db, Session as SessionModel
        
        SessionModel.query.filter_by(user_id=user_id).update({'is_active': False})
        db.session.commit()


def log_security_event(event_type, description, severity='info', user_id=None):
    """Helper to log security events using the model's log_event method"""
    return SecurityLog.log_event(
        user_id=user_id,
        event_type=event_type,
        description=description,
        severity=severity
    )
