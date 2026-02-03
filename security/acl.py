"""
ConnectU Security Module
Access Control List (ACL) Implementation
"""

from functools import wraps
from flask import abort, session
from flask_login import current_user
from models import db, User, Post, Message


class ACL:
    """
    Access Control List implementation
    
    ACL Matrix (3 subjects × 3 objects):
    
    Subjects:
    1. Admin - Full system access
    2. Authenticated User - Standard user privileges
    3. Guest - Limited public access
    
    Objects:
    1. User Profiles - Personal data and settings
    2. Posts - User-generated content
    3. Messages - Private communications
    
    Access Rights Matrix:
    +-------------------+----------+-------+----------+
    |                   | Profiles | Posts | Messages |
    +-------------------+----------+-------+----------+
    | Admin             | RWD      | RWD   | R        |
    | Authenticated     | RW(own)  | RWD   | RW(own)  |
    | Guest             | R(pub)   | R     | -        |
    +-------------------+----------+-------+----------+
    
    R = Read, W = Write, D = Delete
    (own) = Only own resources
    (pub) = Only public profiles
    """
    
    # Define ACL rules
    ACL_RULES = {
        'admin': {
            'profile': ['read', 'write', 'delete'],
            'post': ['read', 'write', 'delete'],
            'message': ['read']  # Can read for moderation, but not write/delete
        },
        'user': {
            'profile': ['read_own', 'write_own', 'read_public'],
            'post': ['read', 'write', 'delete_own'],
            'message': ['read_own', 'write', 'delete_own']
        },
        'guest': {
            'profile': ['read_public'],
            'post': ['read'],
            'message': []  # No access
        }
    }
    
    @staticmethod
    def get_user_role():
        """Determine current user's role"""
        if not current_user.is_authenticated:
            return 'guest'
        
        if current_user.role == 'admin':
            return 'admin'
        
        return 'user'
    
    @staticmethod
    def can_access(resource_type, action, resource=None, owner_id=None):
        """
        Check if current user can perform action on resource
        
        Args:
            resource_type: 'profile', 'post', or 'message'
            action: 'read', 'write', or 'delete'
            resource: Actual resource object (optional)
            owner_id: ID of resource owner (optional)
        
        Returns:
            Boolean indicating if access is allowed
        """
        role = ACL.get_user_role()
        permissions = ACL.ACL_RULES.get(role, {}).get(resource_type, [])
        
        # Admin has special privileges
        if role == 'admin':
            return action in permissions
        
        # Check for ownership-based permissions
        if f'{action}_own' in permissions:
            if resource:
                # Get owner_id from resource
                if hasattr(resource, 'user_id'):
                    owner_id = resource.user_id
                elif hasattr(resource, 'id'):
                    owner_id = resource.id
            
            if owner_id and current_user.is_authenticated:
                if owner_id == current_user.id:
                    return True
        
        # Check for public read access
        if action == 'read' and 'read_public' in permissions:
            if resource_type == 'profile':
                if resource and hasattr(resource, 'public_profile'):
                    return resource.public_profile
                return True  # Default to public
            elif resource_type == 'post':
                if resource and hasattr(resource, 'visibility'):
                    return resource.visibility == 'public'
                return True  # Default to public
        
        # Check for general permissions
        return action in permissions
    
    @staticmethod
    def check_profile_access(profile_user, action='read'):
        """Check if current user can access another user's profile"""
        if not profile_user:
            return False
        
        # Own profile
        if current_user.is_authenticated and current_user.id == profile_user.id:
            return action in ['read', 'write', 'delete']
        
        # Admin
        if current_user.is_authenticated and current_user.role == 'admin':
            return True
        
        # Public profiles
        if action == 'read' and profile_user.public_profile:
            return True
        
        # Friends can view non-public profiles
        if action == 'read' and current_user.is_authenticated:
            # Check if users are friends
            from models import Friendship
            friendship = Friendship.query.filter(
                db.or_(
                    db.and_(Friendship.user_id == current_user.id, 
                           Friendship.friend_id == profile_user.id),
                    db.and_(Friendship.user_id == profile_user.id,
                           Friendship.friend_id == current_user.id)
                ),
                Friendship.status == 'accepted'
            ).first()
            if friendship:
                return True
        
        return False
    
    @staticmethod
    def check_post_access(post, action='read'):
        """Check if current user can access a post"""
        if not post:
            return False
        
        # Own post
        if current_user.is_authenticated and current_user.id == post.user_id:
            return True
        
        # Admin
        if current_user.is_authenticated and current_user.role == 'admin':
            return action in ['read', 'write', 'delete']
        
        # Read access based on visibility
        if action == 'read':
            if post.visibility == 'public':
                return True
            
            if post.visibility == 'friends' and current_user.is_authenticated:
                # Check if users are friends
                from models import Friendship
                friendship = Friendship.query.filter(
                    db.or_(
                        db.and_(Friendship.user_id == current_user.id,
                               Friendship.friend_id == post.user_id),
                        db.and_(Friendship.user_id == post.user_id,
                               Friendship.friend_id == current_user.id)
                    ),
                    Friendship.status == 'accepted'
                ).first()
                if friendship:
                    return True
            
            if post.visibility == 'private':
                return False
        
        return False
    
    @staticmethod
    def check_message_access(message, action='read'):
        """Check if current user can access a message"""
        if not message:
            return False
        
        if not current_user.is_authenticated:
            return False
        
        # Admin can only read messages (for moderation)
        if current_user.role == 'admin':
            return action == 'read'
        
        # Sender or receiver
        if current_user.id in [message.sender_id, message.receiver_id]:
            return action in ['read', 'delete']
        
        # Can write to a conversation
        if action == 'write':
            return True  # Will be filtered by actual send logic
        
        return False


def require_permission(resource_type, action):
    """
    Decorator to enforce ACL permissions on routes
    
    Usage:
        @require_permission('profile', 'write')
        def edit_profile():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Extract resource from kwargs if provided
            resource = kwargs.get('resource')
            owner_id = kwargs.get('owner_id')
            
            if not ACL.can_access(resource_type, action, resource, owner_id):
                abort(403)  # Forbidden
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_authenticated():
    """Decorator to require authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)  # Unauthorized
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_admin():
    """Decorator to require admin role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != 'admin':
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_ownership(get_resource_func):
    """
    Decorator to require resource ownership
    
    Usage:
        @require_ownership(lambda: Post.query.get_or_404(request.args.get('post_id')))
        def delete_post():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            
            resource = get_resource_func()
            
            # Check ownership
            if hasattr(resource, 'user_id'):
                if resource.user_id != current_user.id and current_user.role != 'admin':
                    abort(403)
            elif hasattr(resource, 'id'):
                if resource.id != current_user.id and current_user.role != 'admin':
                    abort(403)
            else:
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
