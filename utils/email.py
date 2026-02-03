"""
ConnectU - Email Utilities
Sending emails for OTP and notifications
"""

from flask import current_app
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class EmailService:
    """Handle all email operations using SMTP directly"""
    
    @staticmethod
    def send_email(to_email, subject, html_body, text_body):
        """Send email using SMTP"""
        try:
            # Get SMTP configuration
            smtp_server = current_app.config.get('MAIL_SERVER', 'smtp.gmail.com')
            smtp_port = current_app.config.get('MAIL_PORT', 587)
            smtp_username = current_app.config.get('MAIL_USERNAME')
            smtp_password = current_app.config.get('MAIL_PASSWORD')
            sender_email = current_app.config.get('MAIL_DEFAULT_SENDER', smtp_username)
            
            if not smtp_username or not smtp_password:
                # For development - just log to console
                print("\n" + "="*50)
                print("DEVELOPMENT MODE: Email Console Output")
                print(f"To: {to_email}")
                print(f"Subject: {subject}")
                print(f"Body:\n{text_body}")
                print("="*50 + "\n")
                return True
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = sender_email
            msg['To'] = to_email
            
            # Attach parts
            part1 = MIMEText(text_body, 'plain')
            part2 = MIMEText(html_body, 'html')
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.sendmail(sender_email, to_email, msg.as_string())
            
            logging.info(f"Email sent to {to_email}")
            return True
        
        except Exception as e:
            logging.error(f"Failed to send email: {str(e)}")
            # For development - print to console on error
            logging.warning(f"To: {to_email}")
            logging.warning(f"Subject: {subject}")
            logging.warning(f"Body:\n{text_body}")
            return False
    
    @staticmethod
    def send_otp_email(user_email, otp_code, username):
        """Send OTP email for authentication"""
        subject = "ConnectU - Your Verification Code"
        
        # HTML email template
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #1a56db 0%, #0d3a8c 100%); color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9fafb; padding: 30px; border-radius: 0 0 8px 8px; }}
                .otp-code {{ background: white; font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; padding: 20px; margin: 20px 0; border: 2px dashed #1a56db; border-radius: 8px; color: #1a56db; }}
                .info {{ background: #e0f2fe; padding: 15px; border-left: 4px solid #1a56db; margin: 20px 0; border-radius: 4px; }}
                .footer {{ text-align: center; margin-top: 20px; font-size: 12px; color: #6b7280; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 style="margin: 0;">🔒 ConnectU</h1>
                    <p style="margin: 10px 0 0 0;">Secure Social Platform</p>
                </div>
                <div class="content">
                    <h2>Hello, {username}!</h2>
                    <p>Your verification code is:</p>
                    
                    <div class="otp-code">{otp_code}</div>
                    
                    <div class="info">
                        <strong>⏱ This code will expire in 5 minutes</strong>
                    </div>
                    
                    <p>If you didn't request this code, please ignore this email or contact support if you're concerned about your account security.</p>
                    
                    <div class="footer">
                        <p>This is an automated message from ConnectU</p>
                        <p>© 2026 ConnectU - Secure Social Platform</p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Hello, {username}!
        
        Your ConnectU verification code is: {otp_code}
        
        This code will expire in 5 minutes.
        
        If you didn't request this code, please ignore this email.
        
        - ConnectU Team
        """
        
        return EmailService.send_email(user_email, subject, html_body, text_body)
    
    @staticmethod
    def send_password_reset_email(user_email, reset_token, username):
        """Send password reset email"""
        subject = "ConnectU - Password Reset Request"
        reset_link = f"http://localhost:5000/reset-password?token={reset_token}"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #1a56db;">Password Reset Request</h2>
                <p>Hello, {username}!</p>
                <p>You requested to reset your ConnectU password. Click the button below to proceed:</p>
                <p style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" style="background: #1a56db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a>
                </p>
                <p>Or copy this link: <a href="{reset_link}">{reset_link}</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </div>
        </body>
        </html>
        """
        
        text_body = f"""
        Hello, {username}!
        
        You requested to reset your ConnectU password.
        
        Click this link to reset: {reset_link}
        
        This link will expire in 1 hour.
        
        If you didn't request this, please ignore this email.
        
        - ConnectU Team
        """
        
        return EmailService.send_email(user_email, subject, html_body, text_body)
