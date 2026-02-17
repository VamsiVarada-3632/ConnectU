# ConnectU Database Monitoring Tools

This directory contains two database monitoring utilities to view and track users dynamically.

## 📁 Files

### 1. `db_viewer.py` - Interactive Database Viewer
An interactive menu-driven tool to view database information.

**Features:**
- View all users
- View active sessions
- View database statistics
- View recent activity
- View everything at once

**Usage:**
```bash
python db_viewer.py
```

### 2. `db_monitor.py` - Live Database Monitor
A live, auto-refreshing monitor that updates dynamically as new users register.

**Features:**
- Real-time updates (auto-refresh every 5 seconds by default)
- Shows new user notifications
- Displays all users, active sessions, and recent activity
- Live statistics

**Usage:**
```bash
# Default: refresh every 5 seconds
python db_monitor.py

# Custom refresh interval (e.g., every 3 seconds)
python db_monitor.py 3
```

**Controls:**
- Press `Ctrl+C` to exit the monitor

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   pip install tabulate
   ```

2. **Run the interactive viewer:**
   ```bash
   python db_viewer.py
   ```

3. **Run the live monitor:**
   ```bash
   python db_monitor.py
   ```

## 📊 What You'll See

Both tools display:
- **User Information**: ID, username, full name, email, role, status
- **Active Sessions**: Currently logged-in users with IP addresses
- **Statistics**: Total users, posts, messages, friendships
- **Recent Activity**: Latest user registrations

## 💡 Use Cases

- **Development**: Monitor user registrations during testing
- **Debugging**: Check database state in real-time
- **Administration**: View all users and active sessions
- **Analytics**: Track user growth and activity

## 🔧 Requirements

- Python 3.6+
- SQLite3 (included with Python)
- tabulate package (`pip install tabulate`)

## 📝 Notes

- The database is located at: `instance/connectu.db`
- The monitor updates automatically - perfect for watching new user registrations
- Both scripts are read-only and won't modify the database
