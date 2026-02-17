# Database Monitoring Tools - Quick Demo

## ✅ Created Files

1. **`db_viewer.py`** - Interactive menu-driven database viewer
2. **`db_monitor.py`** - Live auto-refreshing monitor
3. **`DB_TOOLS_README.md`** - Complete documentation

## 🚀 How to Use

### Option 1: Interactive Viewer (Menu-based)
```bash
python db_viewer.py
```
Then select from the menu:
- 1 = View All Users
- 2 = View Active Sessions  
- 3 = View Database Statistics
- 4 = View Recent Activity
- 5 = View Everything
- 0 = Exit

### Option 2: Live Monitor (Auto-refresh)
```bash
# Refresh every 5 seconds (default)
python db_monitor.py

# Or set custom refresh interval (e.g., 3 seconds)
python db_monitor.py 3
```
Press `Ctrl+C` to stop the monitor.

## 📊 Current Database Status

**Total Users:** 5
- vamsi_3632 (user)
- surya119 (user)
- admin (admin)
- user1 (user)
- guest1 (guest)

**Active Sessions:** 1
- vamsi_3632 logged in from 127.0.0.1

**Content:**
- 5 Posts
- 21 Messages
- 1 Friendship

## 💡 Best Use Cases

**Use `db_viewer.py` when:**
- You want to check specific information
- You prefer a menu-driven interface
- You want to view data on-demand

**Use `db_monitor.py` when:**
- You're testing user registration
- You want to see new users in real-time
- You need continuous monitoring
- You're running the Flask app and want to track activity

## 🎯 Try It Now!

1. Open a terminal and run:
   ```bash
   cd /Users/vamsivvs/Downloads/social-media-front-end
   python db_monitor.py
   ```

2. In another terminal, start your Flask app:
   ```bash
   python app.py
   ```

3. Register a new user in the browser - watch it appear in the monitor instantly! 🎉

---

**Note:** Both tools are read-only and won't modify your database.
