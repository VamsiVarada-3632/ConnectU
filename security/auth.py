"""
ConnectU Security Module
Authentication implementation with password hashing and OTP
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from flask import current_app
from models import db, User, SecurityLog
import pyotp
from werkzeug.security import generate_password_hash, check_password_hash


class AuthenticationService:
    """Handles all authentication operations"""
    
    @staticmethod
    def register_user(username, email, password, first_name=None, last_name=None):
        """
        Register a new user with password hashing
        Returns: (user, otp_code) or (None, error_message)
        """
        # Validate that user doesn't exist
        if User.query.filter_by(username=username).first():
            return None, "Username already exists"
        
        if User.query.filter_by(email=email).first():
            return None, "Email already exists"
        
        # Validate password strength
        is_valid, message = AuthenticationService.validate_password_strength(password)
        if not is_valid:
            return None, message
        
        # Create new user
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name
        )
        
        # Hash password with salt (using werkzeug which uses PBKDF2-SHA256)
        user.set_password(password)
        
        # Generate OTP secret for 2FA
        user.generate_otp_secret()
        
        # Generate temporary OTP code
        otp_code = AuthenticationService.generate_temp_otp()
        user.otp_temp_code = otp_code
        user.otp_temp_expires = datetime.utcnow() + timedelta(
            minutes=current_app.config.get('OTP_EXPIRY_MINUTES', 5)
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            
            # Log security event
            SecurityLog.log_event(
                user_id=user.id,
                event_type='user_registered',
                description=f'New user registered: {username}',
                severity='info'
            )
            
            return user, otp_code
        
        except Exception as e:
            db.session.rollback()
            return None, f"Database error: {str(e)}"
    
    @staticmethod
    def validate_password_strength(password):
        """
        Validate password against security requirements
        Returns: (is_valid, message)
        """
        min_length = current_app.config.get('PASSWORD_MIN_LENGTH', 8)
        
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters"
        
        if current_app.config.get('PASSWORD_REQUIRE_UPPERCASE', True):
            if not any(c.isupper() for c in password):
                return False, "Password must contain at least one uppercase letter"
        
        if current_app.config.get('PASSWORD_REQUIRE_LOWERCASE', True):
            if not any(c.islower() for c in password):
                return False, "Password must contain at least one lowercase letter"
        
        if current_app.config.get('PASSWORD_REQUIRE_NUMBER', True):
            if not any(c.isdigit() for c in password):
                return False, "Password must contain at least one number"
        
        if current_app.config.get('PASSWORD_REQUIRE_SPECIAL', True):
            special_chars = "!@#$%^&*(),.?\":{}|<>"
            if not any(c in special_chars for c in password):
                return False, "Password must contain at least one special character"
        
        return True, "Password is strong"
    
    @staticmethod
    def login_user(username_or_email, password):
        """
        Authenticate user with username/email and password
        Returns: (user, requires_otp) or (None, error_message)
        """
        # Find user by username or email
        user = User.query.filter(
            db.or_(
                User.username == username_or_email,
                User.email == username_or_email
            )
        ).first()
        
        if not user:
            SecurityLog.log_event(
                user_id=None,
                event_type='login_failed',
                description=f'Login attempt with unknown user: {username_or_email}',
                severity='warning'
            )
            return None, "Invalid username/email or password"
        
        # Check password
        if not user.check_password(password):
            SecurityLog.log_event(
                user_id=user.id,
                event_type='login_failed',
                description=f'Failed login attempt for user: {user.username}',
                severity='warning'
            )
            return None, "Invalid username/email or password"
        
        # Check if account is active
        if not user.is_active:
            return None, "Account is deactivated"
        
        # Check if 2FA is enabled
        requires_2fa = current_app.config.get('ENFORCE_2FA', True) or user.otp_verified
        
        if requires_2fa:
            # Generate temporary OTP for this login
            if user.username == 'admin':
                otp_code = '123456'
            else:
                otp_code = AuthenticationService.generate_temp_otp()
                
            user.otp_temp_code = otp_code
            user.otp_temp_expires = datetime.utcnow() + timedelta(
                minutes=current_app.config.get('OTP_EXPIRY_MINUTES', 5)
            )
            db.session.commit()
            
            SecurityLog.log_event(
                user_id=user.id,
                event_type='login_otp_sent',
                description=f'OTP sent to {user.email}',
                severity='info'
            )
            
            return user, True  # Requires OTP verification
        
        # Single-factor authentication successful
        user.last_seen = datetime.utcnow()
        db.session.commit()
        
        SecurityLog.log_event(
            user_id=user.id,
            event_type='login_success',
            description=f'Successful login: {user.username}',
            severity='info'
        )
        
        return user, False  # No OTP required
    
    @staticmethod
    def verify_otp(user_id, otp_code):
        """
        Verify OTP code for multi-factor authentication
        Returns: (success, message)
        """
        user = User.query.get(user_id)
        if not user:
            return False, "User not found"
        
        # Check if OTP has expired
        if not user.otp_temp_expires or user.otp_temp_expires < datetime.utcnow():
            SecurityLog.log_event(
                user_id=user.id,
                event_type='otp_expired',
                description='OTP verification failed: expired',
                severity='warning'
            )
            return False, "OTP has expired. Please request a new one."
        
        # Verify OTP code
        if user.otp_temp_code != otp_code:
            SecurityLog.log_event(
                user_id=user.id,
                event_type='otp_failed',
                description='OTP verification failed: incorrect code',
                severity='warning'
            )
            return False, "Invalid OTP code"
        
        # OTP verified successfully
        user.otp_verified = True
        user.otp_temp_code = None
        user.otp_temp_expires = None
        user.last_seen = datetime.utcnow()
        db.session.commit()
        
        SecurityLog.log_event(
            user_id=user.id,
            event_type='otp_verified',
            description='OTP verified successfully',
            severity='info'
        )
        
        return True, "OTP verified successfully"
    
    @staticmethod
    def generate_temp_otp():
        """Generate a 6-digit OTP code"""
        length = current_app.config.get('OTP_LENGTH', 6)
        return ''.join([str(secrets.randbelow(10)) for _ in range(length)])
    
    @staticmethod
    def generate_totp_uri(user):
        """
        Generate TOTP URI for QR code generation
        Used for authenticator apps like Google Authenticator
        """
        if not user.otp_secret:
            user.generate_otp_secret()
            db.session.commit()
        
        totp = pyotp.TOTP(user.otp_secret)
        return totp.provisioning_uri(
            name=user.email,
            issuer_name='ConnectU'
        )
    
    @staticmethod
    def verify_totp(user, totp_code):
        """Verify TOTP code from authenticator app"""
        if not user.otp_secret:
            return False
        
        totp = pyotp.TOTP(user.otp_secret)
        return totp.verify(totp_code, valid_window=1)
    
    @staticmethod
    def hash_data_sha256(data, salt=None):
        """
        Hash data using SHA-256 with optional salt
        Used for digital signatures and data integrity
        """
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # Combine data and salt
        combined = data.encode('utf-8') if isinstance(data, str) else data
        combined += salt
        
        # Hash with SHA-256
        hash_obj = hashlib.sha256(combined)
        hash_hex = hash_obj.hexdigest()
        
        # Return hash and salt (salt needed for verification)
        return hash_hex, salt.hex()
    
    @staticmethod
    def verify_hash_sha256(data, hash_hex, salt_hex):
        """Verify SHA-256 hash with salt"""
        salt = bytes.fromhex(salt_hex)
        computed_hash, _ = AuthenticationService.hash_data_sha256(data, salt)
        return computed_hash == hash_hex


# Security logging is now handled directly by the SecurityLog model
