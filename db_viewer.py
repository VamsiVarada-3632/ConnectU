#!/usr/bin/env python3
"""
ConnectU Database Viewer
A standalone utility to view and monitor the database
"""

import sqlite3
import os
from datetime import datetime
from tabulate import tabulate

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'connectu.db')


def get_db_connection():
    """Get database connection"""
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at: {DB_PATH}")
        return None
    return sqlite3.connect(DB_PATH)


def view_users():
    """Display all users in the database"""
    conn = get_db_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            id, 
            username, 
            first_name || ' ' || last_name as full_name,
            email, 
            role, 
            is_active,
            otp_verified,
            created_at
        FROM users 
        ORDER BY id
    """)
    
    users = cursor.fetchall()
    conn.close()
    
    if users:
        headers = ['ID', 'Username', 'Full Name', 'Email', 'Role', 'Active', 'OTP', 'Created']
        print("\n" + "="*100)
        print("👥 USERS DATABASE")
        print("="*100)
        print(tabulate(users, headers=headers, tablefmt='grid'))
        print(f"\n📊 Total Users: {len(users)}")
    else:
        print("\n❌ No users found in database")


def view_active_sessions():
    """Display active sessions"""
    conn = get_db_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            s.id,
            s.user_id,
            u.username,
            u.first_name || ' ' || u.last_name as full_name,
            s.ip_address,
            s.created_at as login_time,
            s.expires_at
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.expires_at > datetime('now')
        ORDER BY s.created_at DESC
    """)
    
    sessions = cursor.fetchall()
    conn.close()
    
    print("\n" + "="*100)
    print("🔐 ACTIVE SESSIONS")
    print("="*100)
    
    if sessions:
        headers = ['Session ID', 'User ID', 'Username', 'Full Name', 'IP Address', 'Login Time', 'Expires']
        print(tabulate(sessions, headers=headers, tablefmt='grid'))
        print(f"\n📊 Active Sessions: {len(sessions)}")
    else:
        print("\n❌ No active sessions")


def view_statistics():
    """Display database statistics"""
    conn = get_db_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    # Get counts
    stats = {}
    
    cursor.execute("SELECT COUNT(*) FROM users")
    stats['Total Users'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
    stats['Admins'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'user'")
    stats['Regular Users'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'guest'")
    stats['Guests'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM posts")
    stats['Total Posts'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM messages")
    stats['Total Messages'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM friendships WHERE status = 'accepted'")
    stats['Friendships'] = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')")
    stats['Active Sessions'] = cursor.fetchone()[0]
    
    conn.close()
    
    print("\n" + "="*100)
    print("📊 DATABASE STATISTICS")
    print("="*100)
    
    for key, value in stats.items():
        print(f"  {key:.<50} {value:>10}")
    print("="*100)


def view_recent_activity():
    """Display recent user activity"""
    conn = get_db_connection()
    if not conn:
        return
    
    cursor = conn.cursor()
    
    # Recent registrations
    cursor.execute("""
        SELECT 
            username,
            first_name || ' ' || last_name as full_name,
            email,
            role,
            created_at
        FROM users 
        ORDER BY created_at DESC 
        LIMIT 5
    """)
    
    recent_users = cursor.fetchall()
    
    print("\n" + "="*100)
    print("🆕 RECENT REGISTRATIONS (Last 5)")
    print("="*100)
    
    if recent_users:
        headers = ['Username', 'Full Name', 'Email', 'Role', 'Registered']
        print(tabulate(recent_users, headers=headers, tablefmt='grid'))
    else:
        print("\n❌ No users found")
    
    conn.close()


def main_menu():
    """Display main menu and handle user input"""
    while True:
        print("\n" + "="*100)
        print("🗄️  ConnectU Database Viewer".center(100))
        print("="*100)
        print("\n1. View All Users")
        print("2. View Active Sessions")
        print("3. View Database Statistics")
        print("4. View Recent Activity")
        print("5. View Everything")
        print("0. Exit")
        print("\n" + "="*100)
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            view_users()
        elif choice == '2':
            view_active_sessions()
        elif choice == '3':
            view_statistics()
        elif choice == '4':
            view_recent_activity()
        elif choice == '5':
            view_statistics()
            view_users()
            view_active_sessions()
            view_recent_activity()
        elif choice == '0':
            print("\n👋 Goodbye!\n")
            break
        else:
            print("\n❌ Invalid choice. Please try again.")
        
        input("\nPress Enter to continue...")


if __name__ == '__main__':
    try:
        # Check if tabulate is installed
        import tabulate
    except ImportError:
        print("❌ Required package 'tabulate' not found.")
        print("📦 Installing tabulate...")
        os.system("pip install tabulate")
        print("✅ Installation complete. Please run the script again.")
        exit(1)
    
    main_menu()
