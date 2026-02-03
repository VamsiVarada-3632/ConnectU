# ConnectU - Secure Social Media Platform
Name: VVS VAMSI
Roll Number: CB.SC.U4CSE23454
Subject: Foundations of Cyber Security

--
## Project Overview

**ConnectU** is a secure, full-stack social media application built to demonstrate advanced security concepts and dynamic web features. It goes beyond a simple CRUD app by implementing real-world security standards like **AES-256 Encryption**, **RSA Digital Signatures**, **Multi-Factor Authentication (OTP)**, and a robust **Access Control List (ACL)**.

The platform allows users to:
- Securely register and login with 2FA (OTP)
- Connect with friends (Send/Accept/Reject requests)
- Share posts with granular privacy settings (Public/Friends/Private)
- Chat securely with friends
- Validates data integrity using digital signatures

---

## Quick Start Guide (3 Steps)

### Step 1: Install Dependencies
Open your terminal in the project folder and run:
```bash
pip3 install -r requirements.txt
```

### Step 2: Set Environment Variables
Create a `.env` file (or use the example provided).
```bash
# Copy example env file
cp .env.example .env
```
*Note: OTPs will be printed to the terminal console by default. To send real emails, configured SMTP in .env.*

### Step 3: Run the Application
```bash
python3 app.py
```
Visit **http://localhost:5000** in your browser.

---

## Security Features Implemented (Lab Requirements)

This project implements all required security modules for the lab evaluation.

| Module | Feature | Implementation Details | Status |
|:---:|---|---|:---:|
| **1** | **Authentication** | Secure Login + **2FA (OTP)** via Email/Console | Done |
| **2** | **Access Control** | **ACL Matrix** (Role-Based: Admin, User, Guest) | Done |
| **3** | **Encryption** | **AES-256** for private keys, **SHA-256** for passwords | Done |
| **4** | **Integrity** | **RSA Digital Signatures** for every post | Done |
| **5** | **Availability** | Rate limiting and input validation | Done |
| **6** | **Confidentiality** | HTTPS-ready headers, sensitive data masking | Done |

### How to Demonstrate Security in Viva:
1. **Show OTP**: Register a user, show the OTP code printed in the terminal.
2. **Show Encryption**: Open `social_media.db` (or `db_manager.py`) to show that passwords and private keys are NOT stored as plain text.
3. **Show ACL**: Try to access `/admin` with a normal user -> "403 Forbidden".
4. **Show Digital Signatures**: Create a post, then explain how `signatures.py` signs the content with the user's private key.

---

## Application Features

### 1. Dynamic Social Graph
- **Friend Requests**: Send, accept, reject, or unfriend users.
- **Real-time Notifications**: Get alerted when someone sends a request.
- **Smart Search**: Find users by name or email with status indicators (e.g., "Request Sent").

### 2. Intelligent Feed
- **Privacy First**: The feed respects your privacy settings.
  - **Public** posts: Visible to everyone.
  - **Friends** posts: Visible only to accepted friends.
  - **Private** posts: Visible only to you.
- **Conflict Resolution**: If you unfriend someone, their "Friends-Only" posts instantly disappear from your feed.

### 3. Secure Messaging
- Private 1-on-1 chat functionality.
- Messages are protected by the ACL (only sender/receiver can view).

---

## Project Structure

```
/social-media-front-end
├── app.py                 # Main Application Entry Point
├── models.py              # Database Models (User, Post, Friendship)
├── config.py              # App Configuration
├── requirements.txt       # Project Dependencies
│
├── security/              # SYSTEM CORE (Security Modules)
│   ├── auth.py            # Login/Register Logic
│   ├── acl.py             # Access Control List Implementation
│   ├── encryption.py      # AES/RSA Encryption Utils
│   ├── signatures.py      # Digital Signatures
│   └── validators.py      # Input Sanitization
│
├── static/                # CSS, JavaScript, Images
└── templates/             # HTML Files (Jinja2)
    ├── index.html         # Feed
    ├── login.html         # Auth Pages
    └── ...
```

---

## Useful Commands

**Initialize/Reset Database:**
```bash
python3 -c "from app import app, db; app.app_context().push(); db.create_all()"
```

**Create Admin User:**
```bash
python3 -c "from app import app, db; from models import User; app.app_context().push(); u=User(username='admin', email='admin@test.com', role='admin'); u.set_password('Admin@123'); db.session.add(u); db.session.commit()"
```

---

## Troubleshooting

- **"Module not found" error**: Run `pip3 install -r requirements.txt` again.
- **Port 5000 in use**: Open `app.py` and change the last line to `port=5001`.
- **Database Locked**: If the app crashes, delete `social_media.db` and re-run the user creation commands.

---

**Ready for Evaluation!**
