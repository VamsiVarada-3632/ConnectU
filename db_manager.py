#!/usr/bin/env python3
"""
ConnectU - Database Management Utilities
View and manage database users
"""

from app import app, db
from models import User, Post, Message, Session, SecurityLog

def view_all_users():
    """Display all users in the database"""
    with app.app_context():
        users = User.query.all()
        
        if not users:
            print("No users found in the database.")
            return
        
        print(f"\n{'='*80}")
        print(f"Total Users: {len(users)}")
        print(f"{'='*80}\n")
        
        for i, user in enumerate(users, 1):
            print(f"{i}. Username: {user.username}")
            print(f"   Email: {user.email}")
            print(f"   Name: {user.first_name or 'N/A'} {user.last_name or 'N/A'}")
            print(f"   Role: {user.role}")
            print(f"   OTP Verified: {'✓' if user.otp_verified else '✗'}")
            print(f"   Active: {'✓' if user.is_active else '✗'}")
            print(f"   Created: {user.created_at}")
            print(f"   Last Seen: {user.last_seen or 'Never'}")
            print(f"   {'-'*75}")
        print()

def delete_all_users():
    """Delete all users from the database"""
    with app.app_context():
        user_count = User.query.count()
        
        if user_count == 0:
            print("No users to delete.")
            return
        
        response = input(f"⚠️  Are you sure you want to delete {user_count} user(s)? (yes/no): ")
        
        if response.lower() != 'yes':
            print("Operation cancelled.")
            return
        
        # Delete related data first
        Session.query.delete()
        SecurityLog.query.delete()
        Message.query.delete()
        Post.query.delete()
        User.query.delete()
        
        db.session.commit()
        
        print(f"✓ Successfully deleted {user_count} user(s) and all related data.")
        print("✓ Database reset complete!")

def view_database_stats():
    """Display database statistics"""
    with app.app_context():
        user_count = User.query.count()
        post_count = Post.query.count()
        message_count = Message.query.count()
        session_count = Session.query.filter_by(is_active=True).count()
        
        print(f"\n{'='*50}")
        print("Database Statistics")
        print(f"{'='*50}")
        print(f"Users:           {user_count}")
        print(f"Posts:           {post_count}")
        print(f"Messages:        {message_count}")
        print(f"Active Sessions: {session_count}")
        print(f"{'='*50}\n")

if __name__ == '__main__':
    import sys
    
    print("\nConnectU Database Management")
    print("="*50)
    print("1. View all users")
    print("2. Delete all users")
    print("3. View database stats")
    print("4. Exit")
    print("="*50)
    
    choice = input("\nEnter your choice (1-4): ").strip()
    
    if choice == '1':
        view_all_users()
    elif choice == '2':
        delete_all_users()
    elif choice == '3':
        view_database_stats()
    elif choice == '4':
        print("Exiting...")
        sys.exit(0)
    else:
        print("Invalid choice!")
