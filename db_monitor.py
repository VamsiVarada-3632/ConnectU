#!/usr/bin/env python3
"""
ConnectU Database Monitor
Auto-refreshing monitor that updates dynamically as new users register
"""

import sqlite3
import os
import time
from datetime import datetime
from tabulate import tabulate
import sys


# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'connectu.db')


def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')


def get_db_connection():
    """Get database connection"""
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH)


def get_user_count():
    """Get total user count"""
    conn = get_db_connection()
    if not conn:
        return 0
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def get_active_session_count():
    """Get active session count"""
    conn = get_db_connection()
    if not conn:
        return 0
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')")
    count = cursor.fetchone()[0]
    conn.close()
    return count


def display_dashboard(refresh_interval=5):
    """Display live dashboard with auto-refresh"""
    
    print("\n" + "="*120)
    print("🔴 LIVE DATABASE MONITOR - Press Ctrl+C to exit".center(120))
    print("="*120)
    
    last_user_count = 0
    last_session_count = 0
    
    try:
        while True:
            clear_screen()
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            print("\n" + "="*120)
            print(f"🔴 LIVE DATABASE MONITOR - {current_time}".center(120))
            print(f"Auto-refresh every {refresh_interval} seconds | Press Ctrl+C to exit".center(120))
            print("="*120)
            
            conn = get_db_connection()
            if not conn:
                print("\n❌ Database not found!")
                time.sleep(refresh_interval)
                continue
            
            cursor = conn.cursor()
            
            # Get statistics
            cursor.execute("SELECT COUNT(*) FROM users")
            total_users = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now')")
            active_sessions = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM posts")
            total_posts = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM messages")
            total_messages = cursor.fetchone()[0]
            
            # Check for new users
            new_user_indicator = ""
            if total_users > last_user_count:
                new_user_indicator = f" 🆕 +{total_users - last_user_count} NEW!"
                last_user_count = total_users
            elif last_user_count == 0:
                last_user_count = total_users
            
            # Check for new sessions
            new_session_indicator = ""
            if active_sessions > last_session_count:
                new_session_indicator = f" 🆕 +{active_sessions - last_session_count} NEW!"
                last_session_count = active_sessions
            elif last_session_count == 0:
                last_session_count = active_sessions
            
            # Display stats
            print("\n📊 QUICK STATS")
            print("-" * 120)
            print(f"  👥 Total Users: {total_users}{new_user_indicator}")
            print(f"  🔐 Active Sessions: {active_sessions}{new_session_indicator}")
            print(f"  📝 Total Posts: {total_posts}")
            print(f"  💬 Total Messages: {total_messages}")
            
            # Display all users
            cursor.execute("""
                SELECT 
                    id, 
                    username, 
                    first_name || ' ' || last_name as full_name,
                    email, 
                    role, 
                    CASE WHEN is_active = 1 THEN '✅' ELSE '❌' END as active,
                    CASE WHEN otp_verified = 1 THEN '✅' ELSE '❌' END as verified,
                    created_at
                FROM users 
                ORDER BY id DESC
            """)
            
            users = cursor.fetchall()
            
            print("\n👥 ALL USERS")
            print("-" * 120)
            if users:
                headers = ['ID', 'Username', 'Full Name', 'Email', 'Role', 'Active', 'Verified', 'Created']
                print(tabulate(users, headers=headers, tablefmt='simple'))
            else:
                print("  No users found")
            
            # Display active sessions
            cursor.execute("""
                SELECT 
                    s.id,
                    u.username,
                    u.first_name || ' ' || u.last_name as full_name,
                    s.ip_address,
                    s.created_at as login_time
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.expires_at > datetime('now')
                ORDER BY s.created_at DESC
            """)
            
            sessions = cursor.fetchall()
            
            print("\n🔐 ACTIVE SESSIONS")
            print("-" * 120)
            if sessions:
                headers = ['Session ID', 'Username', 'Full Name', 'IP Address', 'Login Time']
                print(tabulate(sessions, headers=headers, tablefmt='simple'))
            else:
                print("  No active sessions")
            
            # Display recent activity
            cursor.execute("""
                SELECT 
                    username,
                    first_name || ' ' || last_name as full_name,
                    role,
                    created_at
                FROM users 
                ORDER BY created_at DESC 
                LIMIT 3
            """)
            
            recent = cursor.fetchall()
            
            print("\n🆕 RECENT REGISTRATIONS (Last 3)")
            print("-" * 120)
            if recent:
                headers = ['Username', 'Full Name', 'Role', 'Registered']
                print(tabulate(recent, headers=headers, tablefmt='simple'))
            else:
                print("  No recent activity")
            
            conn.close()
            
            print("\n" + "="*120)
            print(f"Next refresh in {refresh_interval} seconds...".center(120))
            print("="*120)
            
            time.sleep(refresh_interval)
            
    except KeyboardInterrupt:
        print("\n\n👋 Monitor stopped. Goodbye!\n")
        sys.exit(0)


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
    
    # Get refresh interval from command line argument
    refresh_interval = 5
    if len(sys.argv) > 1:
        try:
            refresh_interval = int(sys.argv[1])
        except ValueError:
            print("⚠️  Invalid refresh interval. Using default: 5 seconds")
    
    display_dashboard(refresh_interval)
