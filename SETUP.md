# ConnectU - Setup and Installation Guide

## Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

## Installation Steps

### 1. Clone or Navigate to Project Directory
```bash
cd /Users/vamsivvs/Downloads/social-media-front-end
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
```

### 3. Activate Virtual Environment
```bash
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

### 5. Configure Environment Variables
```bash
# Copy the example .env file
cp .env.example .env

# Edit .env and add your configuration
# At minimum, configure email settings for OTP
```

### 6. Initialize Database
```bash
# Create all database tables
flask init-db

# Create admin user (optional)
flask create-admin
```

### 7. Run the Application
```bash
# Development mode
python app.py

# Or using Flask CLI
export FLASK_APP=app.py
export FLASK_ENV=development
flask run
```

The application will be available at: http://localhost:5000

## Email Configuration

For OTP functionality to work, you need to configure email settings in `.env`:

### Option 1: Gmail
1. Go to your Google Account settings
2. Enable 2-Step Verification
3. Generate an App Password: https://myaccount.google.com/apppasswords
4. Add to `.env`:
```
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### Option 2: Development (Console Output)
For testing without email, you can temporarily modify `utils/email.py` to print OTP to console instead of sending email.

## Testing the Security Features

### 1. Authentication Testing

**Single-Factor Authentication:**
1. Go to http://localhost:5000/register
2. Create a new account
3. Password must meet requirements:
   - At least 8 characters
   - Uppercase and lowercase letters
   - At least one number
   - At least one special character

**Multi-Factor Authentication (OTP):**
1. After registration, check your email for OTP
2. Enter 6-digit OTP code
3. Account will be verified

### 2. Authorization (ACL) Testing

**Test as Guest (not logged in):**
- Can view landing page ✓
- Cannot access /feed ✗
- Cannot access /profile ✗
- Cannot access /chat ✗

**Test as Auth User:**
- Can view own profile ✓
- Can edit own profile ✓
- Can create posts ✓
- Can view public posts ✓
- Cannot edit others' profiles ✗

**Test as Admin:**
- Create admin: `flask create-admin`
- Login as admin (admin / Admin@123)
- Can access all resources ✓

### 3. Encryption Testing

**Message Encryption:**
1. Login as User A
2. Send message to User B
3. Check database - message content should be encrypted
4. Login as User B
5. Receive message - should be decrypted automatically

**Key Generation:**
- RSA keys are generated automatically during registration
- Check User model: `rsa_public_key` and `rsa_private_key_encrypted` fields

### 4. Digital Signatures Testing

**Post Integrity:**
1. Create a post
2. Post is signed with your RSA private key
3. Signature stored in `signature` field
4. Content hash stored in `content_hash` field
5. View feed - signature validation happens automatically

**Verification:**
```python
# In Python shell
from models import db, User, Post
from security.signatures import SignatureService

post = Post.query.first()
author = post.author

is_valid, msg = SignatureService.verify_post(
    author.rsa_public_key,
    post.content,
    post.image_data or '',
    post.content_hash,
    post.signature
)
print(f"Signature Valid: {is_valid}")
```

### 5. Encoding Testing

**Base64 Image Upload:**
1. Go to /create-post
2. Upload an image
3. Image is Base64 encoded
4. Check database - `image_data` field contains data URI
5. View in feed - automatically decoded for display

## Security Features Summary

### ✅ Implemented Features

| Component | Implementation | Marks |
|-----------|---------------|-------|
| **Authentication** | Password hashing (PBKDF2-SHA256) + OTP | 3m |
| **Authorization** | ACL (Admin/User/Guest × Profile/Post/Message) | 3m |
| **Encryption** | RSA-2048 + AES-256-GCM hybrid | 3m |
| **Hashing** | SHA-256 with salt + Digital signatures | 3m |
| **Encoding** | Base64 + QR codes + Security docs | 3m |

**Total: 15m + Viva (5m) = 20m**

## Common Issues and Solutions

### Issue: Email not sending
**Solution:** Check SMTP credentials in `.env`, ensure firewall allows SMTP traffic

### Issue: Database errors
**Solution:** Delete `connectu.db` and run `flask init-db` again

### Issue: "Module not found" errors
**Solution:** Make sure virtual environment is activated and dependencies installed

### Issue: CSRF token errors
**Solution:** Clear browser cookies and restart Flask app

## Security Best Practices

1. **Never commit `.env` file** - It's in `.gitignore`
2. **Change SECRET_KEY** in production
3. **Use HTTPS** in production (SESSION_COOKIE_SECURE)
4. **Regular security audits**
5. **Keep dependencies updated**

## Database Schema

The database (`connectu.db`) contains:
- Users with encrypted RSA keys
- Posts with digital signatures
- Encrypted messages
- Friend relationships
- Security logs
- Active sessions

## Next Steps

1. Test all security features
2. Create demo users and content
3. Prepare viva presentation
4. Document security architecture decisions
5. Create attack scenario demonstrations
