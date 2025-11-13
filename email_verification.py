
import secrets
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Email configuration from environment variables
SMTP_CONFIG = {
    'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
    'smtp_port': int(os.getenv('SMTP_PORT', '587')),
    'from_email': os.getenv('EMAIL_FROM', ''),
    'from_password': os.getenv('EMAIL_PASSWORD', '')
}


def generate_verification_code(length: int = 6) -> str:

    return ''.join(secrets.choice(string.digits) for _ in range(length))


def generate_verification_token() -> str:
    
    return secrets.token_urlsafe(32)


def send_verification_email(to_email: str, verification_code: str) -> bool:

    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_CONFIG['from_email']
        msg['To'] = to_email
        msg['Subject'] = 'Email Verification - Call a Doctor'
        
        # Email body
        body = f"""
Hello,

Thank you for registering with Call a Doctor!

Please verify your email address by entering the following verification code:

    Verification Code: {verification_code}

This code will expire in 10 minutes.

If you did not register for this account, please ignore this email.

Best regards,
Call a Doctor Team
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Send email
        server = smtplib.SMTP(SMTP_CONFIG['smtp_server'], SMTP_CONFIG['smtp_port'])
        server.starttls()
        server.login(SMTP_CONFIG['from_email'], SMTP_CONFIG['from_password'])
        text = msg.as_string()
        server.sendmail(SMTP_CONFIG['from_email'], to_email, text)
        server.quit()
        
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication Error: {e}")
        print("Possible causes:")
        print("1. Gmail App Password is incorrect or expired")
        print("2. 2-Step Verification is not enabled on Gmail account")
        print("3. App Password was revoked - generate a new one")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP Error: {e}")
        return False
    except Exception as e:
        print(f"Failed to send verification email: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False


def send_verification_email_html(to_email: str, verification_code: str) -> bool:

    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = SMTP_CONFIG['from_email']
        msg['To'] = to_email
        msg['Subject'] = 'Email Verification - Call a Doctor'
        
        # Plain text version
        text = f"""
Hello,

Thank you for registering with Call a Doctor!

Please verify your email address by entering the following verification code:

Verification Code: {verification_code}

This code will expire in 10 minutes.

If you did not register for this account, please ignore this email.

Best regards,
Call a Doctor Team
        """
        
        # HTML version
        html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #0EBE7F;">Email Verification</h2>
              <p>Hello,</p>
              <p>Thank you for registering with <strong>Call a Doctor</strong>!</p>
              <p>Please verify your email address by entering the following verification code:</p>
              <div style="background-color: #D0F9EF; padding: 20px; text-align: center; margin: 20px 0; border-radius: 5px;">
                <h1 style="color: #0EBE7F; margin: 0; font-size: 36px; letter-spacing: 5px;">{verification_code}</h1>
              </div>
              <p style="color: #666; font-size: 12px;">This code will expire in 10 minutes.</p>
              <p>If you did not register for this account, please ignore this email.</p>
              <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
              <p style="color: #666; font-size: 12px;">Best regards,<br>Call a Doctor Team</p>
            </div>
          </body>
        </html>
        """
        
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email
        server = smtplib.SMTP(SMTP_CONFIG['smtp_server'], SMTP_CONFIG['smtp_port'])
        server.starttls()
        server.login(SMTP_CONFIG['from_email'], SMTP_CONFIG['from_password'])
        text = msg.as_string()
        server.sendmail(SMTP_CONFIG['from_email'], to_email, text)
        server.quit()
        
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication Error: {e}")
        print("Possible causes:")
        print("1. Gmail App Password is incorrect or expired")
        print("2. 2-Step Verification is not enabled on Gmail account")
        print("3. App Password was revoked - generate a new one")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP Error: {e}")
        return False
    except Exception as e:
        print(f"Failed to send verification email: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        traceback.print_exc()
        return False

