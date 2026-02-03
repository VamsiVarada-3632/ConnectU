# ConnectU - Quick Database Commands

## View All Users
```bash
python3 -c "from app import app; from models import User; app.app_context().push(); users = User.query.all(); print(f'\nTotal Users: {len(users)}\n'); [print(f'{i}. {u.username} ({u.email}) - Last seen: {u.last_seen}') for i, u in enumerate(users, 1)] if users else print('No users found')"
```

## Delete All Users
```bash
python3 -c "from app import app, db; from models import User, Post, Message, Session, SecurityLog; app.app_context().push(); User.query.delete(); Post.query.delete(); Message.query.delete(); Session.query.delete(); SecurityLog.query.delete(); db.session.commit(); print('✓ All users deleted!')"
```

## View Active Sessions
```bash
python3 -c "from app import app; from models import Session; app.app_context().push(); sessions = Session.query.filter_by(is_active=True).all(); print(f'\nActive Sessions: {len(sessions)}\n'); [print(f'{i}. User ID {s.user_id} - {s.device_type} ({s.ip_address})') for i, s in enumerate(sessions, 1)] if sessions else print('No active sessions')"
```

## Count Everything
```bash
python3 -c "from app import app; from models import User, Post, Message; app.app_context().push(); print(f'\nUsers: {User.query.count()}\nPosts: {Post.query.count()}\nMessages: {Message.query.count()}\n')"
```

## Use the Database Manager Tool
```bash
python3 db_manager.py
```
Then choose:
- `1` - View all users
- `2` - Delete all users  
- `3` - View database stats
- `4` - Exit
