"""
Minimal Authentication API for Call a Doctor
Handles login authentication with rate limiting and lockout policies.
"""
from __future__ import annotations

from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from datetime import datetime, timedelta
from functools import wraps
import time
from collections import defaultdict
import jwt
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from security.password_utils import hash_password, verify_password, validate_password_strength
from security.captcha_utils import verify_captcha_hash
from security import RateLimiter
import time
import base64
import binascii
from config.database_config import get_database_connection, get_database_config
import re
import os
# -------------------- Validators & Sanitizers (inline) --------------------
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}$')
MOBILE_RE = re.compile(r'^01[0-9]{8,9}$')          # MY mobile 10–11 digits
LANDLINE_RE = re.compile(r'^0[2-9][0-9]{7,8}$')    # MY landline 9–10 digits
IC_RE = re.compile(r'^[0-9]{12}$')
MY_PASSPORT_RE = re.compile(r'^[AHKE]\d{8}$')
GENERIC_PASSPORT_RE = re.compile(r'^[A-Z0-9]{6,10}$')
NAME_RE = re.compile(r'^[a-zA-Z\s\'\-\.]{2,100}$')
WORKING_HOURS_RE = re.compile(r'(?i)(mon|tue|wed|thu|fri|sat|sun|daily).*(\d{1,2}(:\d{2})?\s?(am|pm)?|24\s?hours)')

COUNTRY_PPT = {
    "SG": re.compile(r'^[A-Z]{1,2}\d{7}[A-Z]$'),
    "PH": re.compile(r'^[A-Z]{1,2}\d{7}$'),
    "DE": re.compile(r'^[A-Z]{2}\d{7}$'),
    "CA": re.compile(r'^[A-Z]{2}\d{6,7}$'),
    "GB": re.compile(r'^\d{9}$'),
    "US": re.compile(r'^\d{9}$'),
    "JP": re.compile(r'^[A-Z]{2}\d{7}$'),
    "CN": re.compile(r'^[A-Z]\d{8,9}$'),
    "AU": re.compile(r'^[A-Z]\d{7}$'),
    "NZ": re.compile(r'^[A-Z]{2}\d{6}$'),
    "KR": re.compile(r'^[A-Z]{2}\d{7}$'),
    "FR": re.compile(r'^\d{2}[A-Z0-9]{2}\d{5}$'),
    "IN": re.compile(r'^[A-Z]\d{7}$'),
    "BR": re.compile(r'^[A-Z]{2}\d{6}$'),
}

def sanitize_input(text: str, max_length: int or None = None) -> str or None:
    if text is None: return None
    text = text.strip()
    if max_length and len(text) > max_length:
        text = text[:max_length]
    return text

def sanitize_phone_number(phone: str or None) -> str or None:
    if not phone: return None
    phone = re.sub(r'[\s\-\(\)]', '', phone.strip())
    if phone.startswith('+60'): phone = '0' + phone[3:]
    elif phone.startswith('60'): phone = '0' + phone[2:]
    return phone[:20]

def validate_email(email: str) -> bool:
    return bool(email and EMAIL_RE.match(email))

def validate_phone_number(phone: str | None) -> bool:
    if not phone: return False
    p = sanitize_phone_number(phone)
    return bool(MOBILE_RE.match(p) or LANDLINE_RE.match(p))

def validate_ic_passport(value: str) -> bool:
    if not value: return False
    v = value.strip().replace('-', '').replace(' ', '').upper()
    if IC_RE.match(v) or MY_PASSPORT_RE.match(v): return True
    for rx in COUNTRY_PPT.values():
        if rx.match(v): return True
    return bool(GENERIC_PASSPORT_RE.match(v))

def validate_name(name: str) -> bool:
    return bool(name and NAME_RE.match(name.strip()))

def validate_working_hours(wh: str) -> bool:
    if not wh or len(wh.strip()) < 5 or len(wh) > 200: return False
    return bool(WORKING_HOURS_RE.search(wh))

def validate_address(address: str) -> bool:
    if not address or len(address.strip()) < 5: return False
    return len(address) <= 500
# -------------------------------------------------------------------------

def normalize_clinic_status(value) -> str | None:
    """
    Normalize clinic status values coming from different tables/representations.
    Returns one of: 'approved', 'pending', 'rejected', or None if unknown.
    """
    if value is None:
        return None

    if value == 1 or value == '1':
        return 'approved'
    if value == 0 or value == '0':
        return 'pending'
    if value == 2 or value == '2':
        return 'rejected'

    status_str = str(value).strip().lower()
    if status_str in ('approve', 'approved', 'active'):
        return 'approved'
    if status_str in ('pending', 'awaiting', 'waiting', 'in review'):
        return 'pending'
    if status_str in ('rejected', 'reject', 'declined', 'denied'):
        return 'rejected'

    return None


app = Flask(__name__)
# CORS restricted to localhost for desktop app
CORS(app, origins=["http://localhost:*", "http://127.0.0.1:*"])

# JWT secret key from environment variable
JWT_SECRET = os.getenv('JWT_SECRET', 'cad_auth_secret_key_2024_change_in_production')
JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')

# Database configuration from environment variables
DB_CONFIG = get_database_config()

# IP-based rate limiting (in-memory for request tracking)
ip_attempts = defaultdict(list)
IP_RATE_LIMIT = 20  # Max requests per minute per IP
IP_WINDOW_SECONDS = 60
SOFT_BLOCK_MINUTES = 15  # Soft block duration
MAX_SOFT_BLOCKS_PER_DAY = 3  # Hard block after 3 soft blocks in a day

RESET_CODE_TTL_MINUTES = 10
PASSWORD_RESET_MAX_ATTEMPTS = 5


def send_verification_email_html_server(to_email: str, verification_code: str) -> bool:
    try:
        from_email = os.getenv('EMAIL_FROM', '')
        from_password = os.getenv('EMAIL_PASSWORD', '')
        msg = MIMEMultipart('alternative')
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = 'Email Verification - Call a Doctor'

        text = f"""Hello,

Thank you for registering with Call a Doctor!

Please verify your email address by entering the following verification code:

Verification Code: {verification_code}

This code will expire in 10 minutes.

If you did not register for this account, please ignore this email.

Best regards,
Call a Doctor Team
"""
        html = f"""<html><body>
        <h2 style="color:#0EBE7F;">Email Verification</h2>
        <p>Please use this code:</p>
        <div style="background:#D0F9EF;padding:16px;text-align:center;border-radius:6px;">
          <span style="font-size:28px;letter-spacing:4px;color:#0EBE7F;"><b>{verification_code}</b></span>
        </div>
        <p style="color:#666;font-size:12px;">Code expires in 10 minutes.</p>
        </body></html>"""

        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1); msg.attach(part2)

        # Get SMTP configuration from environment variables
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"[ERROR] send_verification_email_html_server failed: {e}")
        return False


def send_password_reset_email_html_server(to_email: str, reset_code: str) -> bool:
    """Send password reset OTP email."""
    try:
        from_email = os.getenv('EMAIL_FROM', '')
        from_password = os.getenv('EMAIL_PASSWORD', '')
        msg = MIMEMultipart('alternative')
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = 'Password Reset Verification Code - Call a Doctor'

        text = f"""Hello,

We received a request to reset your Call a Doctor account password.

Password Reset Code: {reset_code}

This code will expire in {RESET_CODE_TTL_MINUTES} minutes.

If you did not request a password reset, please ignore this email or contact support immediately.

Best regards,
Call a Doctor Team
"""
        html = f"""<html><body>
        <h2 style="color:#0EBE7F;">Password Reset Request</h2>
        <p>Please use this verification code to reset your password:</p>
        <div style="background:#D0F9EF;padding:16px;text-align:center;border-radius:6px;">
          <span style="font-size:28px;letter-spacing:4px;color:#0EBE7F;"><b>{reset_code}</b></span>
        </div>
        <p style="color:#666;font-size:12px;">This code expires in {RESET_CODE_TTL_MINUTES} minutes.</p>
        <p style="color:#999;font-size:12px;">If you did not request a password reset, no further action is required.</p>
        </body></html>"""

        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)

        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, from_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"[ERROR] send_password_reset_email_html_server failed: {e}")
        return False

def get_client_ip():
    """Extract client IP from request."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'


def ensure_ip_blocks_table():
    """Ensure ip_blocks table exists for tracking IP soft/hard blocks."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if table exists
        cursor.execute("""
            SELECT TABLE_NAME 
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_SCHEMA = 'cad' 
            AND TABLE_NAME = 'ip_blocks'
        """)
        if not cursor.fetchone():
            print("[INFO] Creating ip_blocks table...")
            cursor.execute("""
                CREATE TABLE ip_blocks (
                    ip_address VARCHAR(45) PRIMARY KEY,
                    soft_block_until DATETIME NULL,
                    hard_blocked TINYINT(1) DEFAULT 0,
                    first_soft_block_date DATE NULL,
                    soft_block_count INT DEFAULT 0,
                    last_updated DATETIME NOT NULL
                )
            """)
            conn.commit()
            print("[INFO] ip_blocks table created successfully")
        else:
            print("[INFO] ip_blocks table already exists")
    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to ensure ip_blocks table: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def check_ip_rate_limit():
    """
    Check IP rate limit with soft/hard blocking.
    Returns: (allowed: bool, reason: str, wait_seconds: int, block_created: bool)
    block_created: True if a new block was created, False if existing block prevented access
    """
    client_ip = get_client_ip()
    now = datetime.utcnow()
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get IP block status from database
        cursor.execute("""
            SELECT soft_block_until, hard_blocked, first_soft_block_date, soft_block_count
            FROM ip_blocks
            WHERE ip_address = %s
        """, (client_ip,))
        
        ip_block = cursor.fetchone()
        
        # Check hard block
        soft_block_count = 0
        first_soft_block_date = None
        if ip_block:
            soft_block_until, hard_blocked, first_soft_block_date, soft_block_count = ip_block
            soft_block_count = soft_block_count or 0  # Handle None
            
            if hard_blocked:
                return {
                    'allowed': False,
                    'reason': 'hard_block',
                    'message': 'Your IP has been permanently blocked. Please contact support/admin.',
                    'block_created': False  # Existing block prevented access
                }
            
            # Check soft block
            if soft_block_until and now < soft_block_until:
                remaining_seconds = int((soft_block_until - now).total_seconds())
                return {
                    'allowed': False,
                    'reason': 'soft_block',
                    'message': f'Too many requests. Please try again later.',
                    'wait_seconds': remaining_seconds,
                    'block_created': False  # Existing block prevented access
                }
            
            # Soft block expired - check if we need to reset daily counter
            if first_soft_block_date:
                days_since_first = (now.date() - first_soft_block_date).days
                if days_since_first >= 1:
                    # Reset daily counter (new day)
                    cursor.execute("""
                        UPDATE ip_blocks
                        SET soft_block_count = 0, first_soft_block_date = NULL
                        WHERE ip_address = %s
                    """, (client_ip,))
                    conn.commit()
                    soft_block_count = 0
        
        # Check rate limit (20 requests per minute)
        now_timestamp = time.time()
        ip_attempts[client_ip] = [t for t in ip_attempts[client_ip] if now_timestamp - t < IP_WINDOW_SECONDS]
        
        if len(ip_attempts[client_ip]) >= IP_RATE_LIMIT:
            # Rate limit exceeded - create soft block
            soft_block_until = now + timedelta(minutes=SOFT_BLOCK_MINUTES)
            
            # Increment soft block count
            soft_block_count += 1
            if not first_soft_block_date:
                first_soft_block_date = now.date()
            
            # Check if this is the 3rd soft block today
            if soft_block_count >= MAX_SOFT_BLOCKS_PER_DAY:
                # Hard block (system auto)
                if ip_block:
                    cursor.execute("""
                        UPDATE ip_blocks
                        SET soft_block_until = %s, hard_blocked = 1, 
                            soft_block_count = %s, first_soft_block_date = %s,
                            last_updated = %s
                        WHERE ip_address = %s
                    """, (now + timedelta(days=365 * 100), soft_block_count, first_soft_block_date, now, client_ip))
                else:
                    cursor.execute("""
                        INSERT INTO ip_blocks (ip_address, soft_block_until, hard_blocked, soft_block_count, first_soft_block_date, last_updated)
                        VALUES (%s, %s, 1, %s, %s, %s)
                    """, (client_ip, now + timedelta(days=365 * 100), 1, soft_block_count, first_soft_block_date, now))
                conn.commit()
                return {
                    'allowed': False,
                    'reason': 'hard_block',
                    'message': 'Your IP has been permanently blocked due to repeated violations. Please contact support/admin.',
                    'block_created': True  # New hard block created by system
                }
            else:
                # Soft block only (system auto)
                if ip_block:
                    cursor.execute("""
                        UPDATE ip_blocks
                        SET soft_block_until = %s, soft_block_count = %s,
                            first_soft_block_date = %s, last_updated = %s
                        WHERE ip_address = %s
                    """, (soft_block_until, soft_block_count, first_soft_block_date, now, client_ip))
                else:
                    cursor.execute("""
                        INSERT INTO ip_blocks (ip_address, soft_block_until, soft_block_count, first_soft_block_date, last_updated)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (client_ip, soft_block_until, soft_block_count, first_soft_block_date, now))
                conn.commit()
            
            remaining_seconds = SOFT_BLOCK_MINUTES * 60
            return {
                'allowed': False,
                'reason': 'soft_block',
                'message': f'Too many requests. Your IP is temporarily blocked for {SOFT_BLOCK_MINUTES} minutes.',
                'wait_seconds': remaining_seconds,
                'block_created': True  # New soft block created by system
            }
        
        # Record this request (within limit)
        ip_attempts[client_ip].append(now_timestamp)
        return {
            'allowed': True,
            'reason': '',
            'message': '',
            'block_created': False
        }
        
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in check_ip_rate_limit: {e}")
        # On error, allow the request (fail open)
        return {
            'allowed': True,
            'reason': '',
            'message': '',
            'block_created': False
        }
    finally:
        cursor.close()
        conn.close()


def get_db_connection():
    """Get database connection."""
    return get_database_connection()


def generate_jwt_token(user_id, user_type):
    """Generate JWT token for authenticated admin."""
    payload = {
        'user_id': user_id,
        'user_type': user_type,
        'exp': datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token):
    """Verify JWT token and return payload."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_admin_auth(f):
    """Decorator to require admin authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({
                'status': 'error',
                'message': 'Authorization token required'
            }), 401
        
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        payload = verify_jwt_token(token)
        if not payload:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired token'
            }), 401
        
        # Check if user is admin
        if payload.get('user_type') != 'admin':
            return jsonify({
                'status': 'error',
                'message': 'Admin access required'
            }), 403
        
        # Add user info to request context
        request.admin_user_id = payload.get('user_id')
        return f(*args, **kwargs)
    
    return decorated_function


def send_lock_notification_email(user_email):
    """Send email notification when account is permanently locked."""
    try:
        from_email = os.getenv('EMAIL_FROM', 'kuro2269@gmail.com')
        from_password = os.getenv('EMAIL_PASSWORD', '')
        admin_email = "admin@gmail.com"
        
        subject = "Account Permanently Locked - Call a Doctor"
        body = f"""Dear User,

Your account ({user_email}) has been permanently locked for security reasons.

If you believe this is an error or need assistance, please contact the administrator at:
{admin_email}

Please do not reply to this email as it is an automated notification.

Best regards,
Call a Doctor Security Team
"""
        
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = user_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Get SMTP configuration from environment variables
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', '587'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, from_password)
        text = msg.as_string()
        server.sendmail(from_email, user_email, text)
        server.quit()
        print(f"[INFO] Lock notification email sent to {user_email}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send lock notification email to {user_email}: {e}")
        return False


def create_refresh_token(user_id, client_ip, user_agent=None, remember_days=7):
    """Create a refresh token and store it in database. Returns the plain token."""
    expires_at = datetime.utcnow() + timedelta(days=remember_days)
    return create_refresh_token_with_expiry(user_id, client_ip, user_agent, expires_at)


def create_refresh_token_with_expiry(user_id, client_ip, user_agent=None, expires_at=None):
    """Create a refresh token with a specific expiry time. Returns the plain token."""
    if expires_at is None:
        expires_at = datetime.utcnow() + timedelta(days=7)
    
    try:
        # Generate secure random token
        refresh_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        
        # Store in database
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO user_sessions (user_id, token_hash, expires_at, user_agent, ip_address, revoked)
                VALUES (%s, %s, %s, %s, %s, 0)
            """, (user_id, token_hash, expires_at, user_agent, client_ip))
            conn.commit()
            print(f"[INFO] Refresh token created for user_id: {user_id}, expires_at: {expires_at}")
            return refresh_token
        except mysql.connector.Error as e:
            print(f"[ERROR] Failed to create refresh token: {e}")
            conn.rollback()
            return None
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"[ERROR] Error creating refresh token: {e}")
        return None


def validate_refresh_token(refresh_token, client_ip):
    """Validate refresh token and return user_id if valid. Returns (user_id, session_id) or (None, None)."""
    try:
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        now = datetime.utcnow()
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            # Find valid session
            cursor.execute("""
                SELECT session_id, user_id, expires_at, revoked, ip_address
                FROM user_sessions
                WHERE token_hash = %s
                AND expires_at > %s
                AND revoked = 0
            """, (token_hash, now))
            
            session = cursor.fetchone()
            if not session:
                return None, None
            
            # Check if account is locked
            cursor.execute("""
                SELECT permanently_locked, lock_until
                FROM user
                WHERE user_id = %s
            """, (session['user_id'],))
            user = cursor.fetchone()
            
            if not user:
                return None, None
            
            # Check if account is permanently locked
            if user['permanently_locked']:
                print(f"[INFO] Refresh token validation failed: account permanently locked (user_id: {session['user_id']})")
                return None, None
            
            # Check if account is temporarily locked
            if user['lock_until'] and user['lock_until'] > now:
                print(f"[INFO] Refresh token validation failed: account temporarily locked (user_id: {session['user_id']})")
                return None, None
            
            # Check IP block status
            ip_check = check_ip_rate_limit()
            if not ip_check['allowed']:
                print(f"[INFO] Refresh token validation failed: IP blocked (user_id: {session['user_id']}, ip: {client_ip})")
                return None, None
            
            # Update last_seen
            cursor.execute("""
                UPDATE user_sessions
                SET last_seen = %s
                WHERE session_id = %s
            """, (now, session['session_id']))
            conn.commit()
            
            return session['user_id'], session['session_id']
        except mysql.connector.Error as e:
            print(f"[ERROR] Failed to validate refresh token: {e}")
            return None, None
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"[ERROR] Error validating refresh token: {e}")
        return None, None


def revoke_refresh_token(session_id):
    """Revoke a refresh token by session_id."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                UPDATE user_sessions
                SET revoked = 1
                WHERE session_id = %s
            """, (session_id,))
            conn.commit()
            return cursor.rowcount > 0
        except mysql.connector.Error as e:
            print(f"[ERROR] Failed to revoke refresh token: {e}")
            return False
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"[ERROR] Error revoking refresh token: {e}")
        return False


def revoke_all_user_sessions(user_id):
    """Revoke all active and expired sessions for a user (used on login to ensure single active session)."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Revoke all sessions (active + expired) for this user
            cursor.execute("""
                UPDATE user_sessions
                SET revoked = 1
                WHERE user_id = %s
                AND revoked = 0
            """, (user_id,))
            revoked_count = cursor.rowcount
            conn.commit()
            if revoked_count > 0:
                print(f"[INFO] Revoked {revoked_count} previous session(s) for user_id: {user_id}")
            return revoked_count
        except mysql.connector.Error as e:
            print(f"[ERROR] Failed to revoke user sessions: {e}")
            conn.rollback()
            return 0
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        print(f"[ERROR] Error revoking user sessions: {e}")
        return 0


def log_audit_event(event_type, description, user_id=None, ip_address=None, metadata=None):
    """Log security events to audit_logs table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO audit_logs (event_type, description, user_id, ip_address, metadata, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            event_type,
            description,
            user_id,
            ip_address,
            str(metadata) if metadata else None,
            datetime.utcnow()
        ))
        conn.commit()
    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to log audit event: {e}")
    finally:
        cursor.close()
        conn.close()


def ensure_user_sessions_table():
    """Ensure user_sessions table exists for refresh tokens."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT TABLE_NAME 
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_SCHEMA = 'cad' 
            AND TABLE_NAME = 'user_sessions'
        """)
        if not cursor.fetchone():
            print("[INFO] Creating user_sessions table...")
            cursor.execute("""
                CREATE TABLE user_sessions (
                    session_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    token_hash VARCHAR(64) NOT NULL UNIQUE,
                    expires_at DATETIME NOT NULL,
                    user_agent VARCHAR(255) NULL,
                    ip_address VARCHAR(45) NULL,
                    revoked TINYINT(1) DEFAULT 0,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_user_id (user_id),
                    INDEX idx_token_hash (token_hash),
                    INDEX idx_expires_at (expires_at),
                    INDEX idx_revoked (revoked),
                    FOREIGN KEY (user_id) REFERENCES user(user_id) ON DELETE CASCADE
                )
            """)
            conn.commit()
            print("[INFO] user_sessions table created successfully")
        else:
            print("[INFO] user_sessions table already exists")
    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to ensure user_sessions table: {e}")
        # Don't raise - allow app to continue if table creation fails
    finally:
        cursor.close()
        conn.close()


def ensure_audit_logs_table():
    """Ensure audit_logs table exists."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT TABLE_NAME 
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_SCHEMA = 'cad' 
            AND TABLE_NAME = 'audit_logs'
        """)
        if not cursor.fetchone():
            print("[INFO] Creating audit_logs table...")
            cursor.execute("""
                CREATE TABLE audit_logs (
                    log_id INT AUTO_INCREMENT PRIMARY KEY,
                    event_type VARCHAR(50) NOT NULL,
                    description TEXT NOT NULL,
                    user_id INT NULL,
                    ip_address VARCHAR(45) NULL,
                    metadata TEXT NULL,
                    created_at DATETIME NOT NULL,
                    INDEX idx_event_type (event_type),
                    INDEX idx_user_id (user_id),
                    INDEX idx_ip_address (ip_address),
                    INDEX idx_created_at (created_at)
                )
            """)
            conn.commit()
            print("[INFO] audit_logs table created successfully")
        else:
            print("[INFO] audit_logs table already exists")
    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to ensure audit_logs table: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def ensure_auth_fields():
    """Ensure auth fields exist in user table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Baseline auth fields
        cursor.execute("""
            SELECT COLUMN_NAME 
            FROM INFORMATION_SCHEMA.COLUMNS 
            WHERE TABLE_SCHEMA = 'cad' 
              AND TABLE_NAME = 'user' 
              AND COLUMN_NAME = 'failed_attempts'
        """)
        if not cursor.fetchone():
            print("[INFO] Creating auth fields in user table...")
            cursor.execute("ALTER TABLE user ADD COLUMN failed_attempts INT DEFAULT 0")
            cursor.execute("ALTER TABLE user ADD COLUMN lock_until DATETIME NULL")
            cursor.execute("ALTER TABLE user ADD COLUMN permanently_locked TINYINT(1) DEFAULT 0")
            cursor.execute("ALTER TABLE user ADD COLUMN first_failure_time DATETIME NULL")
            cursor.execute("ALTER TABLE user ADD COLUMN has_been_locked_before TINYINT(1) DEFAULT 0")
            cursor.execute("ALTER TABLE user ADD COLUMN permanent_lock_time DATETIME NULL")
            conn.commit()
            print("[INFO] Auth fields created successfully")
        else:
            print("[INFO] Auth fields already exist")

        # Add any missing individual fields (backfill for older DBs)
        for field in ['first_failure_time', 'has_been_locked_before', 'permanent_lock_time']:
            cursor.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = 'cad' 
                  AND TABLE_NAME = 'user' 
                  AND COLUMN_NAME = %s
            """, (field,))
            if not cursor.fetchone():
                print(f"[INFO] Adding missing column: {field}")
                if field == 'first_failure_time':
                    cursor.execute("ALTER TABLE user ADD COLUMN first_failure_time DATETIME NULL")
                elif field == 'has_been_locked_before':
                    cursor.execute("ALTER TABLE user ADD COLUMN has_been_locked_before TINYINT(1) DEFAULT 0")
                elif field == 'permanent_lock_time':
                    cursor.execute("ALTER TABLE user ADD COLUMN permanent_lock_time DATETIME NULL")
                conn.commit()
                print(f"[INFO] Column {field} added successfully")

        # NEW: email verification fields
        for col, defn in [
            ("email_verified", "TINYINT(1) DEFAULT 0"),
            ("verification_code", "VARCHAR(10) NULL"),
            ("verification_code_expires", "DATETIME NULL"),
            ("password_reset_code", "VARCHAR(10) NULL"),
            ("password_reset_code_expires", "DATETIME NULL"),
            ("password_reset_attempts", "INT DEFAULT 0"),
        ]:
            cursor.execute("""
                SELECT COLUMN_NAME 
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_SCHEMA = 'cad' 
                  AND TABLE_NAME = 'user' 
                  AND COLUMN_NAME = %s
            """, (col,))
            if not cursor.fetchone():
                print(f"[INFO] Adding missing column: {col}")
                cursor.execute(f"ALTER TABLE user ADD COLUMN {col} {defn}")
                conn.commit()
                print(f"[INFO] Column {col} added successfully")

    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to ensure auth fields: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def ensure_password_history_table():
    """Ensure password_history table exists."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT COUNT(*) 
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_SCHEMA = 'cad' 
              AND TABLE_NAME = 'password_history'
        """)
        if cursor.fetchone()[0] == 0:
            print("[INFO] Creating password_history table...")
            cursor.execute("""
                CREATE TABLE password_history (
                    history_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_user_id (user_id),
                    INDEX idx_created_at (created_at),
                    FOREIGN KEY (user_id) REFERENCES user(user_id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
            conn.commit()
            print("[INFO] password_history table created successfully")
        else:
            print("[INFO] password_history table already exists")
    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to ensure password_history table: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def check_password_history(user_id: int, new_password: str, max_history: int = 5, current_password_hash: str = None) -> tuple[bool, str]:
    """
    Check if the new password has been used recently.
    
    Args:
        user_id: User ID to check
        new_password: Plaintext password to check
        max_history: Maximum number of previous passwords to check (default: 5)
        current_password_hash: Optional current password hash to also check against
        
    Returns:
        (is_allowed, message): (True, "") if password is allowed, (False, error_message) otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Ensure table exists
        ensure_password_history_table()
        
        # First check against current password if provided
        if current_password_hash and current_password_hash.strip():
            try:
                if verify_password(new_password, current_password_hash):
                    return False, f"Password cannot be one of your last {max_history} passwords. Please choose a different password."
            except Exception as e:
                print(f"[WARN] Error verifying password against current hash: {e}")
        
        # Get the last N password hashes from history
        cursor.execute("""
            SELECT password_hash 
            FROM password_history 
            WHERE user_id = %s 
            ORDER BY created_at DESC 
            LIMIT %s
        """, (user_id, max_history))
        
        history_rows = cursor.fetchall()
        print(f"[DEBUG] Checking password history for user_id {user_id}: found {len(history_rows)} history entries")
        
        # Check if new password matches any previous password
        for (old_hash,) in history_rows:
            try:
                if verify_password(new_password, old_hash):
                    print(f"[DEBUG] Password reuse detected for user_id {user_id}")
                    return False, f"Password cannot be one of your last {max_history} passwords. Please choose a different password."
            except Exception as e:
                print(f"[WARN] Error verifying password against history hash: {e}")
                # Continue checking other hashes
                continue
        
        print(f"[DEBUG] Password history check passed for user_id {user_id}")
        return True, ""
        
    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to check password history: {e}")
        import traceback
        traceback.print_exc()
        # On error, allow the password (fail open to avoid blocking legitimate users)
        return True, ""
    finally:
        cursor.close()
        conn.close()


def save_password_to_history(user_id: int, password_hash: str):
    """
    Save a password hash to the password history.
    
    Args:
        user_id: User ID
        password_hash: Hashed password to save
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Insert new password into history
        cursor.execute("""
            INSERT INTO password_history (user_id, password_hash, created_at)
            VALUES (%s, %s, %s)
        """, (user_id, password_hash, datetime.utcnow()))
        
        conn.commit()
        
        # Keep only the last N passwords (e.g., last 5)
        # Delete older entries beyond the limit
        cursor.execute("""
            DELETE ph1 FROM password_history ph1
            INNER JOIN (
                SELECT history_id 
                FROM password_history 
                WHERE user_id = %s 
                ORDER BY created_at DESC 
                LIMIT 999999 OFFSET 5
            ) ph2 ON ph1.history_id = ph2.history_id
        """, (user_id,))
        
        conn.commit()
        
    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to save password to history: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


def get_rate_limiter():
    """Get a RateLimiter instance for login attempts."""
    conn = get_db_connection()
    return RateLimiter(
        conn,
        window_seconds=15 * 60,  # 15 minutes
        max_attempts=5,
        lockout_seconds=15 * 60,
        captcha_threshold=3,  # Require CAPTCHA after 3 attempts
        max_backoff_seconds=16,
        max_lock_cycles=2
    )


def check_ip_rate_limit_for_endpoint():
    """Check IP rate limit and return error response if blocked. Returns (allowed: bool, error_response: tuple or None)."""
    client_ip = get_client_ip()
    ip_check = check_ip_rate_limit()
    if not ip_check['allowed']:
        # Determine event type based on whether block was created or access was denied
        block_created = ip_check.get('block_created', False)
        reason = ip_check['reason']
        
        if block_created:
            # System auto-created a new block
            if reason == 'hard_block':
                event_type = 'ip_hard_blocked'  # System auto hard block
            else:
                event_type = 'ip_soft_blocked'  # System auto soft block
        else:
            # Existing block prevented access
            event_type = 'ip_blocked'  # User action blocked by existing block
        
        # Log IP block event
        log_audit_event(
            event_type=event_type,
            description=f"IP {client_ip} blocked: {ip_check['reason']}",
            ip_address=client_ip,
            metadata={'reason': ip_check['reason'], 'message': ip_check['message'], 'block_created': block_created}
        )
        status_code = 403 if ip_check['reason'] == 'hard_block' else 429
        return False, (jsonify({
            'status': 'error',
            'message': ip_check['message']
        }), status_code)
    return True, None


@app.route('/login', methods=['POST'])
def login():
    """Handle login authentication with lockout policy."""
    client_ip = get_client_ip()
    
    # Check IP rate limit
    allowed, error_response = check_ip_rate_limit_for_endpoint()
    if not allowed:
        return error_response
    
    data = request.get_json()
    if not data:
        return jsonify({
            'status': 'error',
            'message': 'Invalid request'
        }), 400
    
    email = data.get('email', '').lower()
    password = data.get('password', '')
    remember_me = data.get('rememberMe', False)  # Get remember me flag
    
    # CAPTCHA validation
    captcha_text = data.get('captcha_text', '')
    captcha_hash = data.get('captcha_hash', '')
    captcha_timestamp = data.get('captcha_timestamp', 0)
    
    # Check if CAPTCHA is required based on rate limiting (IP-based)
    rate_limiter = get_rate_limiter()
    captcha_required = rate_limiter.should_require_captcha('login', client_ip)
    
    # If CAPTCHA is required but not provided, return response indicating CAPTCHA is needed
    if captcha_required and not (captcha_text and captcha_hash and captcha_timestamp):
        return jsonify({
            'status': 'captcha_required',
            'message': 'CAPTCHA verification required',
            'captcha_required': True
        }), 200
    
    # If CAPTCHA is provided, validate it
    if captcha_text and captcha_hash and captcha_timestamp:
        if not verify_captcha_hash(captcha_text, captcha_timestamp, captcha_hash):
            log_audit_event(
                event_type='login_failed',
                description=f"Login attempt failed: invalid or expired CAPTCHA",
                ip_address=client_ip,
                metadata={'email': email, 'reason': 'invalid_captcha'}
            )
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired CAPTCHA. Please refresh and try again.'
            }), 400
    
    if not email or not password:
        return jsonify({
            'status': 'error',
            'message': 'Email and password required'
        }), 400
    
    # Validate email format
    if not validate_email(email):
        return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if user exists and get auth fields
        cursor.execute("""
            SELECT user_id, user_type, user_password, failed_attempts, lock_until, permanently_locked,
                   first_failure_time, has_been_locked_before, permanent_lock_time, email_verified
            FROM user
            WHERE user_email = %s
        """, (email,))
        
        user = cursor.fetchone()
        
        if not user:
            # Record failed attempt in rate limiter (for CAPTCHA requirement tracking)
            try:
                rate_limiter.record_failure('login', client_ip)
            except Exception as e:
                print(f"[WARN] Failed to record rate limit failure: {e}")
            
            log_audit_event(
                event_type='login_failed',
                description=f"Login attempt failed: user not found",
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({
                'status': 'error',
                'message': 'Email does not exist',
                'email_not_found': True
            }), 404
        
        user_id, user_type, stored_password_hash, failed_attempts, lock_until, permanently_locked, first_failure_time, has_been_locked_before, permanent_lock_time, email_verified = user
        
        # Debug: Log current database values
        print(f"[DEBUG] User {user_id} ({email}): failed_attempts={failed_attempts}, lock_until={lock_until}, permanently_locked={permanently_locked}, first_failure_time={first_failure_time}, has_been_locked_before={has_been_locked_before}")
        
        # Get current time in UTC (all times stored and compared in UTC to avoid timezone issues)
        now = datetime.utcnow()
        
        # Check permanent lock (no auto-unlock)
        if permanently_locked:
            log_audit_event(
                event_type='login_blocked',
                description=f"Login blocked: account permanently locked (user_id: {user_id})",
                user_id=user_id,
                ip_address=client_ip,
                metadata={'email': email, 'lock_type': 'permanent'}
            )
            return jsonify({
                'status': 'permanent_lock',
                'message': 'Your account has been locked for security reasons. Please contact support/admin.'
            }), 403
        
        # Check temporary lock (using UTC time - lock will work correctly regardless of user's timezone)
        if lock_until and now < lock_until:
            remaining_seconds = int((lock_until - now).total_seconds())
            log_audit_event(
                event_type='login_blocked',
                description=f"Login blocked: account temporarily locked (user_id: {user_id})",
                user_id=user_id,
                ip_address=client_ip,
                metadata={'email': email, 'lock_type': 'temporary', 'remaining_seconds': remaining_seconds}
            )
            return jsonify({
                'status': 'temp_lock',
                'message': 'Too many attempts. Your account is temporarily locked for 15 minutes.',
                'lock_until': lock_until.isoformat(),
                'remaining_seconds': remaining_seconds
            }), 403
        
        # Time window for resetting failed attempts (60 minutes for soft lock)
        FAILURE_WINDOW_MINUTES = 60
        
        # Reset failed_attempts if time window has expired (60 minutes since first failure)
        # Note: has_been_locked_before now resets after 24 hours (daily reset)
        if first_failure_time:
            minutes_since_first_failure = (now - first_failure_time).total_seconds() / 60
            if minutes_since_first_failure >= FAILURE_WINDOW_MINUTES:
                # Time window expired - reset counter but keep lock history
                failed_attempts = 0
                first_failure_time = None
                cursor.execute("""
                    UPDATE user
                    SET failed_attempts = 0, first_failure_time = NULL
                    WHERE user_id = %s
                """, (user_id,))
                conn.commit()
            # Daily reset for lock history (similar to IP daily soft-block counter)
            hours_since_first_failure = (now - first_failure_time).total_seconds() / 3600 if first_failure_time else 0
            if has_been_locked_before and hours_since_first_failure >= 24:
                has_been_locked_before = 0
                cursor.execute("""
                    UPDATE user
                    SET has_been_locked_before = 0
                    WHERE user_id = %s
                """, (user_id,))
                conn.commit()
        
        # If lock_until has expired, clear it but keep has_been_locked_before flag
        if lock_until and now >= lock_until:
            lock_until = None
            cursor.execute("""
                UPDATE user
                SET lock_until = NULL
                WHERE user_id = %s
            """, (user_id,))
            conn.commit()
        
        # Verify password (plaintext for now - should be hashed in production)
        password_ok = False
        try:
            password_ok = verify_password(password, stored_password_hash or "")
        except Exception as e:
            print(f"[WARN] bcrypt verify error for user_id={user_id}: {e}")
            password_ok = False

        if not password_ok:
            # Set first_failure_time if this is the first failure
            if first_failure_time is None:
                first_failure_time = now
            
            # Increment failed attempts
            failed_attempts += 1
            new_lock_until = None
            new_permanently_locked = 0
            new_has_been_locked_before = has_been_locked_before
            new_permanent_lock_time = permanent_lock_time
            
            # First lock: 5 failed attempts (never been locked before)
            if failed_attempts >= 5 and not has_been_locked_before:
                # Temporary lock: 15 minutes
                new_lock_until = now + timedelta(minutes=15)
                new_has_been_locked_before = 1  # Mark that user has been locked
                lock_event_type = 'account_locked_temporary'
                lock_description = f"Account temporarily locked after 5 failed attempts (user_id: {user_id})"
            # Second lock: user was locked before, now failing again → permanent
            elif failed_attempts >= 5 and has_been_locked_before:
                new_permanently_locked = 1
                # Permanent lock: 100 years far-future timestamp
                new_lock_until = now + timedelta(days=365 * 100)
                new_permanent_lock_time = now
                lock_event_type = 'account_locked_permanent'
                lock_description = f"Account permanently locked after repeated violations (user_id: {user_id})"
            else:
                lock_event_type = None
                lock_description = None

            cursor.execute("""
                            UPDATE user
                               SET failed_attempts=%s,
                                   lock_until=%s,
                                   permanently_locked=%s,
                                   first_failure_time=%s,
                                   has_been_locked_before=%s,
                                   permanent_lock_time=%s
                             WHERE user_id=%s
                        """, (failed_attempts, new_lock_until, new_permanently_locked, first_failure_time,
                              new_has_been_locked_before, new_permanent_lock_time, user_id))
            conn.commit()

            # Record failed attempt in rate limiter (for CAPTCHA requirement tracking)
            try:
                rate_limiter.record_failure('login', client_ip)
            except Exception as e:
                print(f"[WARN] Failed to record rate limit failure: {e}")
            
            # Log failed login attempt
            log_audit_event(
                event_type='login_failed',
                description=f"Login failed: incorrect password (user_id: {user_id}, failed_attempts: {failed_attempts})",
                user_id=user_id,
                ip_address=client_ip,
                metadata={'email': email, 'failed_attempts': failed_attempts}
            )
            
            # Log account lock if it occurred
            if lock_event_type:
                log_audit_event(
                    event_type=lock_event_type,
                    description=lock_description,
                    user_id=user_id,
                    ip_address=client_ip,
                    metadata={'email': email, 'failed_attempts': failed_attempts}
                )
                
                # Send email notification if account is permanently locked
                if new_permanently_locked == 1:
                    send_lock_notification_email(email)
            
            return jsonify({
                'status': 'error',
                'message': 'Invalid email or password'
            }), 401
        
        # Success - reset all failure tracking (same as admin unlock for non-permanent cases)
        cursor.execute("""
            UPDATE user
            SET failed_attempts = 0, lock_until = NULL, first_failure_time = NULL,
                permanent_lock_time = NULL, has_been_locked_before = 0
            WHERE user_id = %s
        """, (user_id,))
        conn.commit()

        # Require email verification after confirming password is correct
        if not email_verified:
            log_audit_event(
                event_type='login_failed',
                description=f"Login attempt blocked: email not verified (user_id: {user_id})",
                user_id=user_id,
                ip_address=client_ip,
                metadata={'email': email, 'reason': 'email_not_verified'}
            )
            return jsonify({
                'status': 'error',
                'message': 'Email not verified. Please check your email and verify your account.',
                'email_not_verified': True
            }), 403

        # Clinic-specific approval check
        if user_type == 'clinic':
            cursor.execute("SELECT clinic_id, clinic_status FROM clinic WHERE user_id = %s", (user_id,))
            clinic_row = cursor.fetchone()
            if not clinic_row:
                log_audit_event(
                    event_type='login_failed',
                    description=f"Login attempt blocked: clinic profile not found (user_id: {user_id})",
                    user_id=user_id,
                    ip_address=client_ip,
                    metadata={'email': email, 'reason': 'clinic_profile_missing'}
                )
                return jsonify({
                    'status': 'error',
                    'message': 'Clinic profile not found. Please contact support.',
                    'clinic_profile_missing': True
                }), 403

            clinic_id, clinic_status = clinic_row
            cursor.execute("""
                SELECT cr_status
                FROM clinic_request
                WHERE clinic_id = %s
                ORDER BY cr_datetime DESC
                LIMIT 1
            """, (clinic_id,))
            request_row = cursor.fetchone()
            request_status = request_row[0] if request_row else None

            normalized_request_status = normalize_clinic_status(request_status)
            normalized_clinic_status = normalize_clinic_status(clinic_status)
            effective_status = normalized_request_status or normalized_clinic_status or 'pending'

            status_metadata = {
                'clinic_status': clinic_status,
                'clinic_request_status': request_status,
                'effective_status': effective_status
            }

            if effective_status == 'pending':
                log_audit_event(
                    event_type='login_failed',
                    description=f"Login attempt blocked: clinic pending approval (user_id: {user_id})",
                    user_id=user_id,
                    ip_address=client_ip,
                    metadata={'email': email, **status_metadata}
                )
                return jsonify({
                    'status': 'error',
                    'message': 'Your clinic registration is pending admin approval. Please wait for approval before logging in.',
                    'clinic_pending': True,
                    'clinic_status': effective_status
                }), 403
            elif effective_status == 'rejected':
                log_audit_event(
                    event_type='login_failed',
                    description=f"Login attempt blocked: clinic registration rejected (user_id: {user_id})",
                    user_id=user_id,
                    ip_address=client_ip,
                    metadata={'email': email, **status_metadata}
                )
                return jsonify({
                    'status': 'error',
                    'message': 'Your clinic registration has been rejected. Please contact admin for more information.',
                    'clinic_rejected': True,
                    'clinic_status': effective_status
                }), 403
            elif effective_status != 'approved':
                log_audit_event(
                    event_type='login_failed',
                    description=f"Login attempt blocked: clinic not approved (user_id: {user_id}, status: {clinic_status})",
                    user_id=user_id,
                    ip_address=client_ip,
                    metadata={'email': email, **status_metadata}
                )
                return jsonify({
                    'status': 'error',
                    'message': 'Your clinic account is not approved. Please contact admin.',
                    'clinic_not_approved': True,
                    'clinic_status': effective_status
                }), 403
        
        # Record successful login in rate limiter (resets CAPTCHA requirement)
        try:
            rate_limiter.record_success('login', client_ip)
        except Exception as e:
            print(f"[WARN] Failed to record rate limit success: {e}")
        
        # Log successful login
        log_audit_event(
            event_type='login_success',
            description=f"Login successful (user_id: {user_id}, user_type: {user_type})",
            user_id=user_id,
            ip_address=client_ip,
            metadata={'email': email, 'user_type': user_type}
        )
        
        # Generate JWT token for admin users
        response_data = {
            'status': 'success',
            'user_id': user_id,
            'user_type': user_type
        }
        
        if user_type == 'admin':
            token = generate_jwt_token(user_id, user_type)
            response_data['token'] = token
        
        # Revoke all previous sessions (active and expired) to ensure single active session
        # This handles: app closed without logout, expired sessions, multiple device logins
        revoked_count = revoke_all_user_sessions(user_id)
        if revoked_count > 0:
            log_audit_event(
                event_type='sessions_revoked_on_login',
                description=f"Revoked {revoked_count} previous session(s) on login (user_id: {user_id})",
                user_id=user_id,
                ip_address=client_ip,
                metadata={'email': email, 'revoked_count': revoked_count, 'remember_me': remember_me}
            )
        
        # Always create refresh token for session management (account lock detection, IP block detection)
        # Expiry: 7 days if "Remember Me" checked, 1 day if not checked
        user_agent = request.headers.get('User-Agent', '')
        remember_days = 7 if remember_me else 1  # 1 day for non-remember-me sessions
        refresh_token = create_refresh_token(user_id, client_ip, user_agent, remember_days=remember_days)
        if refresh_token:
            response_data['refresh_token'] = refresh_token
            log_audit_event(
                event_type='refresh_token_created',
                description=f"Refresh token created for user (user_id: {user_id}, remember_me: {remember_me})",
                user_id=user_id,
                ip_address=client_ip,
                metadata={'email': email, 'remember_me': remember_me, 'expiry_days': remember_days}
            )
        
        return jsonify(response_data), 200

    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in login: {e}")
        return jsonify({'status': 'error', 'message': f'Database error: {str(e)}'}), 500
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass

@app.route('/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token using refresh token."""
    client_ip = get_client_ip()
    data = request.get_json() or {}
    refresh_token_str = data.get('refresh_token', '')
    
    if not refresh_token_str:
        return jsonify({
            'status': 'error',
            'message': 'Refresh token required'
        }), 400
    
    # Validate refresh token and get session info
    token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()
    now = datetime.utcnow()
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # Find valid session and get expiry info
        cursor.execute("""
            SELECT session_id, user_id, expires_at, revoked, ip_address
            FROM user_sessions
            WHERE token_hash = %s
            AND expires_at > %s
            AND revoked = 0
        """, (token_hash, now))
        
        session = cursor.fetchone()
        if not session:
            return jsonify({
                'status': 'error',
                'message': 'Invalid or expired refresh token'
            }), 401
        
        user_id = session['user_id']
        session_id = session['session_id']
        original_expires_at = session['expires_at']
        
        # Check if account is locked
        cursor.execute("""
            SELECT permanently_locked, lock_until, user_type, user_email
            FROM user
            WHERE user_id = %s
        """, (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        # Check if account is permanently locked
        if user['permanently_locked']:
            return jsonify({
                'status': 'error',
                'message': 'Account permanently locked'
            }), 403
        
        # Check if account is temporarily locked
        if user['lock_until'] and user['lock_until'] > now:
            return jsonify({
                'status': 'error',
                'message': 'Account temporarily locked'
            }), 403
        
        # Check IP block status
        ip_check = check_ip_rate_limit()
        if not ip_check['allowed']:
            return jsonify({
                'status': 'error',
                'message': ip_check['message']
            }), 403
        
        # Update last_seen
        cursor.execute("""
            UPDATE user_sessions
            SET last_seen = %s
            WHERE session_id = %s
        """, (now, session_id))
        conn.commit()
        
        # Generate new JWT token for admin users
        response_data = {
            'status': 'success',
            'user_id': user_id,
            'user_type': user['user_type']
        }
        
        if user['user_type'] == 'admin':
            token = generate_jwt_token(user_id, user['user_type'])
            response_data['token'] = token
        
        # Rotate refresh token (preserve original expiry time)
        # Calculate remaining time from original token
        remaining_time = original_expires_at - now
        if remaining_time.total_seconds() > 0:
            # Preserve original expiry (don't extend session)
            user_agent = request.headers.get('User-Agent', '')
            # Calculate days from remaining time (for logging purposes)
            remaining_days = remaining_time.total_seconds() / 86400
            new_refresh_token = create_refresh_token_with_expiry(
                user_id, client_ip, user_agent, original_expires_at
            )
            if new_refresh_token:
                # Revoke old token
                revoke_refresh_token(session_id)
                response_data['refresh_token'] = new_refresh_token
                
                log_audit_event(
                    event_type='refresh_token_rotated',
                    description=f"Refresh token rotated for user (user_id: {user_id})",
                    user_id=user_id,
                    ip_address=client_ip,
                    metadata={'email': user['user_email'], 'remaining_days': round(remaining_days, 2)}
                )
        
        return jsonify(response_data), 200
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in refresh: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/auth/logout', methods=['POST'])
def logout():
    """Logout and revoke refresh token."""
    client_ip = get_client_ip()
    data = request.get_json() or {}
    refresh_token_str = data.get('refresh_token', '')
    
    if refresh_token_str:
        # Revoke refresh token
        token_hash = hashlib.sha256(refresh_token_str.encode()).hexdigest()
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Find session
            cursor.execute("""
                SELECT session_id, user_id
                FROM user_sessions
                WHERE token_hash = %s
            """, (token_hash,))
            session = cursor.fetchone()
            
            if session:
                session_id, user_id = session
                revoke_refresh_token(session_id)
                
                log_audit_event(
                    event_type='logout',
                    description=f"User logged out (user_id: {user_id})",
                    user_id=user_id,
                    ip_address=client_ip,
                    metadata={'session_id': session_id}
                )
        except mysql.connector.Error as e:
            print(f"[ERROR] Database error in logout: {e}")
        finally:
            cursor.close()
            conn.close()
    
    return jsonify({
        'status': 'success',
        'message': 'Logged out successfully'
    }), 200


@app.route('/auth/client-ip', methods=['GET'])
@require_admin_auth
def get_client_ip_endpoint():
    """Get client IP address (authenticated endpoint)."""
    client_ip = get_client_ip()
    return jsonify({
        'status': 'success',
        'ip_address': client_ip
    }), 200


@app.route('/auth/session-status', methods=['POST'])
def session_status():
    """Check session status (account status, IP status, token validity)."""
    client_ip = get_client_ip()
    data = request.get_json() or {}
    refresh_token_str = data.get('refresh_token', '')
    
    if not refresh_token_str:
        return jsonify({
            'status': 'error',
            'message': 'Refresh token required'
        }), 400
    
    # Validate refresh token
    user_id, session_id = validate_refresh_token(refresh_token_str, client_ip)
    
    if not user_id:
        return jsonify({
            'status': 'error',
            'message': 'Invalid or expired refresh token',
            'should_logout': True
        }), 401
    
    # Get user account status
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT permanently_locked, lock_until, user_type, user_email
            FROM user
            WHERE user_id = %s
        """, (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({
                'status': 'error',
                'message': 'User not found',
                'should_logout': True
            }), 404
        
        now = datetime.utcnow()
        status_info = {
            'status': 'valid',
            'user_id': user_id,
            'user_type': user['user_type'],
            'account_locked': False,
            'ip_blocked': False
        }
        
        # Check account lock status
        if user['permanently_locked']:
            status_info['status'] = 'error'
            status_info['message'] = 'Account permanently locked. Please contact admin.'
            status_info['account_locked'] = True
            status_info['should_logout'] = True
            return jsonify(status_info), 403
        
        if user['lock_until'] and user['lock_until'] > now:
            status_info['status'] = 'error'
            status_info['message'] = 'Account temporarily locked.'
            status_info['account_locked'] = True
            status_info['should_logout'] = True
            return jsonify(status_info), 403
        
        # Check IP block status
        ip_check = check_ip_rate_limit()
        if not ip_check['allowed']:
            status_info['status'] = 'error'
            status_info['message'] = ip_check['message']
            status_info['ip_blocked'] = True
            status_info['should_logout'] = True
            return jsonify(status_info), 403
        
        # All checks passed
        return jsonify(status_info), 200
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in session-status: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Database error',
            'should_logout': False
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/unlock', methods=['POST'])
@require_admin_auth
def admin_unlock():
    """Admin endpoint to unlock a user account."""
    admin_user_id = request.admin_user_id
    client_ip = get_client_ip()
    
    data = request.get_json()
    if not data:
        return jsonify({
            'status': 'error',
            'message': 'Invalid request'
        }), 400
    
    email = data.get('email', '').lower()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get user_id first
        cursor.execute("SELECT user_id FROM user WHERE user_email = %s", (email,))
        user_row = cursor.fetchone()
        
        if not user_row:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
        
        target_user_id = user_row[0]
        
        cursor.execute("""
            UPDATE user
            SET failed_attempts = 0, lock_until = NULL, permanently_locked = 0,
                first_failure_time = NULL, has_been_locked_before = 0, permanent_lock_time = NULL
            WHERE user_email = %s
        """, (email,))
        conn.commit()
        
        if cursor.rowcount > 0:
            # Log admin action
            log_audit_event(
                event_type='admin_unlock',
                description=f"Admin {admin_user_id} unlocked account: {email}",
                user_id=target_user_id,
                ip_address=client_ip,
                metadata={'admin_user_id': admin_user_id, 'email': email}
            )
            
            return jsonify({
                'status': 'success',
                'message': f'Account {email} unlocked successfully'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'User not found'
            }), 404
            
    except mysql.connector.Error as e:
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/unblock_ip', methods=['POST'])
@require_admin_auth
def admin_unblock_ip():
    """Admin endpoint to unblock an IP address."""
    admin_user_id = request.admin_user_id
    client_ip = get_client_ip()
    
    data = request.get_json()
    if not data:
        return jsonify({
            'status': 'error',
            'message': 'Invalid request'
        }), 400
    
    ip_address = data.get('ip_address', '')
    
    if not ip_address:
        return jsonify({
            'status': 'error',
            'message': 'IP address required'
        }), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            UPDATE ip_blocks
            SET soft_block_until = NULL, hard_blocked = 0,
                soft_block_count = 0, first_soft_block_date = NULL
            WHERE ip_address = %s
        """, (ip_address,))
        conn.commit()
        
        if cursor.rowcount > 0:
            # Log admin action
            log_audit_event(
                event_type='admin_unblock_ip',
                description=f"Admin {admin_user_id} unblocked IP: {ip_address}",
                ip_address=ip_address,
                metadata={'admin_user_id': admin_user_id, 'unblocked_ip': ip_address}
            )
            
            return jsonify({
                'status': 'success',
                'message': f'IP {ip_address} unblocked successfully'
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': 'IP address not found in block list'
            }), 404
            
    except mysql.connector.Error as e:
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/audit_logs', methods=['GET'])
@require_admin_auth
def admin_audit_logs():
    """Admin endpoint to view audit logs."""
    event_type = request.args.get('event_type')
    user_id = request.args.get('user_id', type=int)
    ip_address = request.args.get('ip_address')
    limit = request.args.get('limit', default=100, type=int)
    offset = request.args.get('offset', default=0, type=int)
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []
        
        if event_type:
            query += " AND event_type = %s"
            params.append(event_type)
        
        if user_id:
            query += " AND user_id = %s"
            params.append(user_id)
        
        if ip_address:
            query += " AND ip_address = %s"
            params.append(ip_address)
        
        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        logs = cursor.fetchall()
        
        # Convert datetime objects to ISO format strings for JSON serialization
        for log in logs:
            if 'created_at' in log and log['created_at']:
                if isinstance(log['created_at'], datetime):
                    log['created_at'] = log['created_at'].isoformat()
        
        # Get total count
        count_query = "SELECT COUNT(*) as total FROM audit_logs WHERE 1=1"
        count_params = []
        if event_type:
            count_query += " AND event_type = %s"
            count_params.append(event_type)
        if user_id:
            count_query += " AND user_id = %s"
            count_params.append(user_id)
        if ip_address:
            count_query += " AND ip_address = %s"
            count_params.append(ip_address)
        
        cursor.execute(count_query, count_params)
        total = cursor.fetchone()['total']
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'total': total,
            'limit': limit,
            'offset': offset
        }), 200
        
    except mysql.connector.Error as e:
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/blocked_accounts', methods=['GET'])
@require_admin_auth
def admin_blocked_accounts():
    """Admin endpoint to view blocked accounts."""
    print("[API] GET /admin/blocked_accounts called")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT user_id, user_email, user_type, failed_attempts, lock_until, 
                   permanently_locked, first_failure_time, has_been_locked_before, 
                   permanent_lock_time
            FROM user
            WHERE permanently_locked = 1 OR (lock_until IS NOT NULL AND lock_until > NOW())
            ORDER BY permanently_locked DESC, lock_until DESC
        """)
        
        accounts = cursor.fetchall()
        print(f"[API] /admin/blocked_accounts fetched rows: {len(accounts)}")
        
        # Format datetime fields
        for account in accounts:
            if account['lock_until']:
                account['lock_until'] = account['lock_until'].isoformat() if hasattr(account['lock_until'], 'isoformat') else str(account['lock_until'])
            if account['first_failure_time']:
                account['first_failure_time'] = account['first_failure_time'].isoformat() if hasattr(account['first_failure_time'], 'isoformat') else str(account['first_failure_time'])
            if account['permanent_lock_time']:
                account['permanent_lock_time'] = account['permanent_lock_time'].isoformat() if hasattr(account['permanent_lock_time'], 'isoformat') else str(account['permanent_lock_time'])
        
        resp = jsonify({
            'status': 'success',
            'accounts': accounts,
            'count': len(accounts)
        })
        print("[API] /admin/blocked_accounts returning 200")
        return resp, 200
        
    except mysql.connector.Error as e:
        print(f"[API][ERROR] /admin/blocked_accounts DB error: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/accounts', methods=['GET'])
@require_admin_auth
def admin_accounts_all():
    """Admin endpoint to view all accounts with lock status."""
    print("[API] GET /admin/accounts called")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT user_id, user_email, user_type, failed_attempts, lock_until,
                   permanently_locked, first_failure_time, has_been_locked_before,
                   permanent_lock_time
            FROM user
            ORDER BY user_email ASC
        """)
        accounts = cursor.fetchall()
        print(f"[API] /admin/accounts fetched rows: {len(accounts)}")
        # Normalize datetime to iso strings
        for account in accounts:
            for k in ['lock_until','first_failure_time','permanent_lock_time']:
                if account.get(k):
                    account[k] = account[k].isoformat() if hasattr(account[k],'isoformat') else str(account[k])
        print("[API] /admin/accounts returning 200")
        return jsonify({'status':'success','accounts':accounts,'count':len(accounts)}), 200
    except mysql.connector.Error as e:
        print(f"[API][ERROR] /admin/accounts DB error: {e}")
        return jsonify({'status':'error','message':'Database error'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/block_user', methods=['POST'])
@require_admin_auth
def admin_block_user():
    """Admin endpoint to permanently lock a user."""
    admin_user_id = request.admin_user_id
    client_ip = get_client_ip()
    data = request.get_json() or {}
    email = data.get('email','').lower()
    if not email:
        return jsonify({'status':'error','message':'Email required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id FROM user WHERE user_email=%s", (email,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'status':'error','message':'User not found'}), 404
        user_id = row[0]
        now = datetime.utcnow()
        cursor.execute("""
            UPDATE user
            SET permanently_locked=1, permanent_lock_time=%s,
                lock_until=%s, failed_attempts=0
            WHERE user_email=%s
        """, (now, now + timedelta(days=365 * 100), email))
        conn.commit()
        log_audit_event(
            event_type='admin_lock_permanent',
            description=f"Admin {admin_user_id} permanently locked account: {email}",
            user_id=user_id,
            ip_address=client_ip,
            metadata={'admin_user_id': admin_user_id, 'email': email}
        )
        
        # Send email notification to user about permanent lock
        send_lock_notification_email(email)
        
        return jsonify({'status':'success','message':f'Account {email} permanently locked'}), 200
    except mysql.connector.Error:
        return jsonify({'status':'error','message':'Database error'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/blocked_ips', methods=['GET'])
@require_admin_auth
def admin_blocked_ips():
    """Admin endpoint to view blocked IP addresses."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT ip_address, soft_block_until, hard_blocked, 
                   first_soft_block_date, soft_block_count, last_updated
            FROM ip_blocks
            WHERE hard_blocked = 1 OR (soft_block_until IS NOT NULL AND soft_block_until > UTC_TIMESTAMP())
            ORDER BY hard_blocked DESC, soft_block_until DESC
        """)
        
        ips = cursor.fetchall()
        
        # Format datetime fields
        for ip in ips:
            if ip['soft_block_until']:
                ip['soft_block_until'] = ip['soft_block_until'].isoformat() if hasattr(ip['soft_block_until'], 'isoformat') else str(ip['soft_block_until'])
            if ip['first_soft_block_date']:
                ip['first_soft_block_date'] = ip['first_soft_block_date'].isoformat() if hasattr(ip['first_soft_block_date'], 'isoformat') else str(ip['first_soft_block_date'])
            if ip['last_updated']:
                ip['last_updated'] = ip['last_updated'].isoformat() if hasattr(ip['last_updated'], 'isoformat') else str(ip['last_updated'])
        
        return jsonify({
            'status': 'success',
            'ips': ips,
            'count': len(ips)
        }), 200
        
    except mysql.connector.Error as e:
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/ip_list', methods=['GET'])
@require_admin_auth
def admin_ip_list():
    """Admin endpoint to list all known IP rows (blocked and unblocked)."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT ip_address, soft_block_until, hard_blocked, 
                   first_soft_block_date, soft_block_count, last_updated
            FROM ip_blocks
            ORDER BY hard_blocked DESC, soft_block_until DESC, last_updated DESC
        """)
        ips = cursor.fetchall()
        for ip in ips:
            if ip['soft_block_until']:
                ip['soft_block_until'] = ip['soft_block_until'].isoformat() if hasattr(ip['soft_block_until'], 'isoformat') else str(ip['soft_block_until'])
            if ip['first_soft_block_date']:
                ip['first_soft_block_date'] = ip['first_soft_block_date'].isoformat() if hasattr(ip['first_soft_block_date'], 'isoformat') else str(ip['first_soft_block_date'])
            if ip['last_updated']:
                ip['last_updated'] = ip['last_updated'].isoformat() if hasattr(ip['last_updated'], 'isoformat') else str(ip['last_updated'])
        return jsonify({'status':'success','ips': ips, 'count': len(ips)}), 200
    except mysql.connector.Error:
        return jsonify({'status':'error','message':'Database error'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/admin/block_ip', methods=['POST'])
@require_admin_auth
def admin_block_ip():
    """Admin endpoint to hard block an arbitrary IP (100-year block)."""
    admin_user_id = request.admin_user_id
    client_ip = get_client_ip()

    data = request.get_json() or {}
    ip_address = data.get('ip_address', '')
    if not ip_address:
        return jsonify({'status':'error','message':'IP address required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        now = datetime.utcnow()
        # Upsert hard block row
        cursor.execute("""
            INSERT INTO ip_blocks (ip_address, soft_block_until, hard_blocked, soft_block_count, first_soft_block_date, last_updated)
            VALUES (%s, %s, 1, 0, NULL, %s)
            ON DUPLICATE KEY UPDATE soft_block_until=%s, hard_blocked=1, last_updated=%s
        """, (ip_address, now + timedelta(days=365*100), now, now + timedelta(days=365*100), now))
        conn.commit()

        # Audit log
        log_audit_event(
            event_type='admin_block_ip',
            description=f"Admin {admin_user_id} hard blocked IP: {ip_address}",
            ip_address=ip_address,
            metadata={'admin_user_id': admin_user_id, 'blocked_ip': ip_address}
        )

        return jsonify({'status':'success','message':f'IP {ip_address} hard blocked'}), 200
    except mysql.connector.Error:
        return jsonify({'status':'error','message':'Database error'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/admin/account_stats', methods=['GET'])
@require_admin_auth
def admin_account_stats():
    """Admin endpoint to view account statistics."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get statistics
        stats = {}
        
        # Total accounts
        cursor.execute("SELECT COUNT(*) as total FROM user")
        stats['total_accounts'] = cursor.fetchone()['total']
        
        # Permanently locked accounts
        cursor.execute("SELECT COUNT(*) as total FROM user WHERE permanently_locked = 1")
        stats['permanently_locked'] = cursor.fetchone()['total']
        
        # Temporarily locked accounts (exclude permanently locked) - compare in UTC
        cursor.execute("SELECT COUNT(*) as total FROM user WHERE permanently_locked = 0 AND lock_until IS NOT NULL AND lock_until > UTC_TIMESTAMP()")
        stats['temporarily_locked'] = cursor.fetchone()['total']
        
        # Active accounts (not locked)
        cursor.execute("""
            SELECT COUNT(*) as total FROM user 
            WHERE permanently_locked = 0 AND (lock_until IS NULL OR lock_until <= UTC_TIMESTAMP())
        """)
        stats['active_accounts'] = cursor.fetchone()['total']
        
        # Blocked IPs
        cursor.execute("SELECT COUNT(*) as total FROM ip_blocks WHERE hard_blocked = 1")
        stats['hard_blocked_ips'] = cursor.fetchone()['total']
        
        cursor.execute("""
            SELECT COUNT(*) as total FROM ip_blocks 
            WHERE hard_blocked = 0 AND soft_block_until IS NOT NULL AND soft_block_until > UTC_TIMESTAMP()
        """)
        stats['soft_blocked_ips'] = cursor.fetchone()['total']
        
        # Recent login attempts (last 24 hours)
        cursor.execute("""
            SELECT COUNT(*) as total FROM audit_logs 
            WHERE event_type IN ('login_success', 'login_failed') 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        stats['login_attempts_24h'] = cursor.fetchone()['total']
        
        # Failed login attempts (last 24 hours)
        cursor.execute("""
            SELECT COUNT(*) as total FROM audit_logs 
            WHERE event_type = 'login_failed' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
        """)
        stats['failed_logins_24h'] = cursor.fetchone()['total']
        
        return jsonify({
            'status': 'success',
            'stats': stats
        }), 200
        
    except mysql.connector.Error as e:
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'service': 'auth_api'
    }), 200


@app.route('/register', methods=['POST'])
@app.route('/register', methods=['POST'])
def register():
    """Handle user/clinic registration with IP rate limiting and email verification."""
    client_ip = get_client_ip()

    # Check IP rate limit
    allowed, error_response = check_ip_rate_limit_for_endpoint()
    if not allowed:
        return error_response

    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid request'}), 400

    email = (sanitize_input((data.get('email') or '').lower(), 254) or '')
    password = data.get('password', '')
    user_type = (sanitize_input((data.get('user_type') or 'user'), 20) or 'user').lower()

    if user_type not in ('user', 'clinic'):
        return jsonify({'status': 'error', 'message': 'Unsupported user type'}), 400

    # Shared validations
    errors = []
    if not validate_email(email):
        errors.append("Invalid email format")

    ok, msg = validate_password_strength(password)
    if not ok:
        errors.append(msg)

    # Type-specific validations/normalization
    clinic_payload = {}
    if user_type == 'user':
        name = sanitize_input(data.get('name') or '', 100) or ''
        ic_passport_raw = sanitize_input(data.get('ic_passport') or '', 32) or ''
        gender = sanitize_input(data.get('gender') or '', 10) or ''
        address = sanitize_input(data.get('address') or '', 500) or ''
        contact = sanitize_phone_number(data.get('contact')) or ''

        if not validate_name(name):
            errors.append("Invalid name")
        if not validate_ic_passport(ic_passport_raw):
            errors.append("Invalid IC/Passport")
        if gender.lower() not in ['male', 'female', 'other']:
            errors.append("Invalid gender")
        if not validate_address(address):
            errors.append("Invalid address")
        if not validate_phone_number(contact):
            errors.append("Invalid phone number")

        user_payload = {
            'name': name,
            'ic_passport_hash': hashlib.sha256(ic_passport_raw.encode()).hexdigest(),
            'gender': gender,
            'address': address,
            'contact': contact,
        }
    else:
        clinic_name = sanitize_input(data.get('clinic_name') or '', 200) or ''
        clinic_operation = sanitize_input(data.get('clinic_operation') or '', 200) or ''
        clinic_address = (data.get('clinic_address') or '').strip()
        clinic_description = (data.get('clinic_description') or '').strip()
        clinic_contact_raw = data.get('clinic_contact')
        clinic_contact = sanitize_phone_number(clinic_contact_raw) if clinic_contact_raw else ''
        clinic_image_b64 = data.get('clinic_image') or ''
        medical_license_b64 = data.get('medical_license') or ''
        ssm_license_b64 = data.get('ssm_license') or ''

        if len(clinic_name) < 2:
            errors.append("Clinic name too short")
        if not validate_working_hours(clinic_operation):
            errors.append("Invalid working hours format")
        if not validate_address(clinic_address):
            errors.append("Invalid address (5-500 characters required)")
        if not validate_phone_number(clinic_contact):
            errors.append("Invalid clinic phone number")
        if not clinic_description or len(clinic_description) < 10:
            errors.append("Clinic description too short")

        def decode_b64(field_name: str, value: str) -> bytes | None:
            if not value:
                errors.append(f"{field_name} is required")
                return None
            try:
                decoded = base64.b64decode(value, validate=True)
                if not decoded:
                    errors.append(f"{field_name} is empty")
                    return None
                return decoded
            except (binascii.Error, TypeError):
                errors.append(f"Invalid {field_name} data")
                return None

        clinic_image_bytes = decode_b64("clinic image", clinic_image_b64)
        medical_license_bytes = decode_b64("medical license", medical_license_b64)
        ssm_license_bytes = decode_b64("SSM license", ssm_license_b64)

        clinic_payload = {
            'clinic_name': clinic_name,
            'clinic_operation': clinic_operation,
            'clinic_address': clinic_address[:500],
            'clinic_description': clinic_description[:2000],
            'clinic_contact': clinic_contact,
            'clinic_image': clinic_image_bytes,
            'medical_license': medical_license_bytes,
            'ssm_license': ssm_license_bytes,
        }

    if errors:
        log_audit_event(
            event_type='registration_failed',
            description="Registration failed: validation errors",
            ip_address=client_ip,
            metadata={'email': email, 'errors': errors, 'user_type': user_type}
        )
        return jsonify({'status': 'error', 'message': '; '.join(errors)}), 400

    # Prepare secure fields
    password_hash = hash_password(password)

    # Generate email verification code (6 digits) and expiry (10 minutes)
    verification_code = f"{secrets.randbelow(10 ** 6):06d}"
    code_expires = datetime.utcnow() + timedelta(minutes=10)

    conn = get_db_connection()
    conn.autocommit = False
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT user_id FROM user WHERE user_email=%s", (email,))
        if cursor.fetchone():
            conn.rollback()
            log_audit_event('registration_failed', "Registration failed: email already exists",
                            ip_address=client_ip, metadata={'email': email, 'user_type': user_type, 'reason': 'email_exists'})
            return jsonify({'status': 'error', 'message': 'Email already exists'}), 409

        if not send_verification_email_html_server(email, verification_code):
            conn.rollback()
            log_audit_event('registration_failed', "Registration failed: email send failed",
                            ip_address=client_ip, metadata={'email': email, 'user_type': user_type})
            return jsonify({'status': 'error',
                            'message': 'Failed to send verification email. Please check your email address and try again.'}), 500

        cursor.execute("""
            INSERT INTO user (user_email, user_password, user_type, email_verified, verification_code, verification_code_expires)
            VALUES (%s, %s, %s, 0, %s, %s)
        """, (email, password_hash, user_type, verification_code, code_expires))

        user_id = cursor.lastrowid
        if not user_id:
            conn.rollback()
            log_audit_event('registration_failed', "Registration failed: DB error creating user",
                            ip_address=client_ip, metadata={'email': email, 'user_type': user_type})
            return jsonify({'status': 'error', 'message': 'Failed to create user account'}), 500

        if user_type == 'user':
            cursor.execute("""
                INSERT INTO patient (patient_name, patient_ic_passport, patient_gender, patient_address, patient_contact, user_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                user_payload['name'],
                user_payload['ic_passport_hash'],
                user_payload['gender'],
                user_payload['address'],
                user_payload['contact'],
                user_id
            ))
        else:
            cursor.execute("""
                INSERT INTO clinic (
                    clinic_name,
                    clinic_operation,
                    clinic_address,
                    clinic_description,
                    clinic_contact,
                    clinic_image,
                    clinic_status,
                    medical_license,
                    ssm_license,
                    user_id
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                clinic_payload['clinic_name'],
                clinic_payload['clinic_operation'],
                clinic_payload['clinic_address'],
                clinic_payload['clinic_description'],
                clinic_payload['clinic_contact'],
                clinic_payload['clinic_image'],
                0,  # Pending approval
                clinic_payload['medical_license'],
                clinic_payload['ssm_license'],
                user_id
            ))
            clinic_id = cursor.lastrowid
            if not clinic_id:
                conn.rollback()
                log_audit_event('registration_failed', "Registration failed: DB error creating clinic",
                                ip_address=client_ip, metadata={'email': email, 'user_type': user_type})
                return jsonify({'status': 'error', 'message': 'Failed to create clinic profile'}), 500

            cursor.execute("""
                INSERT INTO clinic_request (cr_type, cr_reason, cr_datetime, cr_detail, cr_ifreject, cr_status, clinic_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                'join',
                'new registered',
                datetime.utcnow(),
                None,
                None,
                'pending',
                clinic_id
            ))

        conn.commit()

        event_type = 'user_registered' if user_type == 'user' else 'clinic_registered'
        log_audit_event(event_type, f"{user_type.capitalize()} registered (user_id: {user_id})",
                        user_id=user_id, ip_address=client_ip, metadata={'email': email})

        response_payload = {
            'status': 'success',
            'message': 'Registration successful. Verification required.',
            'user_id': user_id,
            'email': email,
            'verification_required': True,
            'user_type': user_type
        }
        if user_type == 'clinic':
            response_payload['clinic_request_status'] = 'pending'

        return jsonify(response_payload), 201

    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in register: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in register: {e}")
        try:
            conn.rollback()
        except Exception:
            pass
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500
    finally:
        try:
            cursor.close()
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


@app.route('/verify-email', methods=['POST'])
def verify_email():
    """Verify email with code (sent during registration)."""
    client_ip = get_client_ip()

    data = request.get_json() or {}
    email = (data.get('email') or '').lower()
    code = (data.get('otp_code') or data.get('code') or '').strip()

    if not email or not code:
        return jsonify({'status': 'error', 'message': 'Email and code are required'}), 400

    now = datetime.utcnow()
    conn = get_db_connection()
    # Ensure autocommit is False for transaction control
    conn.autocommit = False
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT user_id, email_verified, verification_code, verification_code_expires
            FROM user WHERE user_email=%s
        """, (email,))
        row = cursor.fetchone()
        if not row:
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        if row['email_verified']:
            conn.rollback()
            return jsonify({'status': 'success', 'message': 'Email already verified'}), 200

        if not row['verification_code'] or not row['verification_code_expires']:
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'No verification pending'}), 400

        if now > row['verification_code_expires']:
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'Verification code expired'}), 400

        if code != row['verification_code']:
            print(f"[VERIFY] Code mismatch - provided: {code}, expected: {row['verification_code']}")
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'Invalid verification code'}), 400

        # All validations passed - mark verified & clear code
        # Only execute this UPDATE if all checks above passed
        print(f"[VERIFY] Code verified successfully for user_id: {row['user_id']}, email: {email}")
        cursor.execute("""
            UPDATE user
               SET email_verified=1, verification_code=NULL, verification_code_expires=NULL
             WHERE user_id=%s AND email_verified=0
        """, (row['user_id'],))
        
        if cursor.rowcount == 0:
            # This shouldn't happen, but safety check
            print(f"[VERIFY] WARNING: UPDATE affected 0 rows for user_id: {row['user_id']}")
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'Failed to update verification status'}), 500
        
        print(f"[VERIFY] Successfully updated {cursor.rowcount} row(s) for user_id: {row['user_id']}")
        conn.commit()

        log_audit_event('email_verified', f"Email verified (user_id: {row['user_id']})",
                        user_id=row['user_id'], ip_address=client_ip, metadata={'email': email})

        return jsonify({'status': 'success', 'message': 'Email verified successfully'}), 200

    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in verify-email: {e}")
        try:
            conn.rollback()
        except:
            pass
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in verify-email: {e}")
        try:
            conn.rollback()
        except:
            pass
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500
    finally:
        try:
            cursor.close()
        except:
            pass
        try:
            conn.close()
        except:
            pass


@app.route('/resend-verification-code', methods=['POST'])
def resend_verification_code():
    """Resend verification code to user's email."""
    client_ip = get_client_ip()
    
    # Check IP rate limit
    allowed, error_response = check_ip_rate_limit_for_endpoint()
    if not allowed:
        return error_response
    
    data = request.get_json() or {}
    email = (data.get('email') or '').lower()
    
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400
    
    conn = get_db_connection()
    # Ensure autocommit is False for transaction control
    conn.autocommit = False
    cursor = conn.cursor(dictionary=True)
    try:
        # Check if user exists
        cursor.execute("""
            SELECT user_id, email_verified, verification_code_expires
            FROM user WHERE user_email=%s
        """, (email,))
        row = cursor.fetchone()
        
        if not row:
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        if row['email_verified']:
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'Email already verified'}), 400
        
        # Generate new verification code (6 digits) and expiry (10 minutes)
        new_verification_code = f"{secrets.randbelow(10 ** 6):06d}"
        new_code_expires = datetime.utcnow() + timedelta(minutes=10)
        
        # Send verification email
        if not send_verification_email_html_server(email, new_verification_code):
            conn.rollback()
            log_audit_event('resend_code_failed', "Resend verification code failed: email send failed",
                            ip_address=client_ip, metadata={'email': email})
            return jsonify({'status': 'error', 'message': 'Failed to send verification email. Please try again.'}), 500
        
        # Update database with new code (only update if email was sent successfully)
        cursor.execute("""
            UPDATE user
            SET verification_code=%s, verification_code_expires=%s
            WHERE user_id=%s
        """, (new_verification_code, new_code_expires, row['user_id']))
        conn.commit()
        
        log_audit_event('verification_code_resent', f"Verification code resent (user_id: {row['user_id']})",
                        user_id=row['user_id'], ip_address=client_ip, metadata={'email': email})
        
        return jsonify({
            'status': 'success',
            'message': 'Verification code resent successfully. Please check your email.'
        }), 200
        
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in resend-verification-code: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        print(f"[ERROR] Error in resend-verification-code: {e}")
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/forgot-password/request-otp', methods=['POST'])
def forgot_password_request():
    """Initiate password reset by sending a verification code to the user's email."""
    client_ip = get_client_ip()
    
    # Check IP rate limit
    allowed, error_response = check_ip_rate_limit_for_endpoint()
    if not allowed:
        return error_response
    
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    
    if not email:
        return jsonify({'status': 'error', 'message': 'Email is required'}), 400
    
    if not validate_email(email):
        return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
    
    conn = get_db_connection()
    conn.autocommit = False
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT user_id, email_verified
            FROM user
            WHERE user_email = %s
        """, (email,))
        row = cursor.fetchone()
        
        if not row:
            log_audit_event(
                event_type='forgot_password_failed',
                description="Password reset requested for non-existent email",
                ip_address=client_ip,
                metadata={'email': email}
            )
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'Email does not exist'}), 404
        
        if not row['email_verified']:
            log_audit_event(
                event_type='forgot_password_failed',
                description=f"Password reset requested for unverified email (user_id: {row['user_id']})",
                user_id=row['user_id'],
                ip_address=client_ip,
                metadata={'email': email}
            )
            conn.rollback()
            return jsonify({
                'status': 'error',
                'message': 'Email is not verified. Please verify your email before resetting your password.'
            }), 400
        
        reset_code = f"{secrets.randbelow(10 ** 6):06d}"
        reset_expires = datetime.utcnow() + timedelta(minutes=RESET_CODE_TTL_MINUTES)
        
        cursor.execute("""
            UPDATE user
               SET password_reset_code=%s,
                   password_reset_code_expires=%s,
                   password_reset_attempts=0
             WHERE user_id=%s
        """, (reset_code, reset_expires, row['user_id']))
        
        if cursor.rowcount == 0:
            conn.rollback()
            return jsonify({'status': 'error', 'message': 'Failed to initiate password reset'}), 500
        
        if not send_password_reset_email_html_server(email, reset_code):
            conn.rollback()
            log_audit_event(
                event_type='password_reset_email_failed',
                description=f"Password reset email failed to send (user_id: {row['user_id']})",
                user_id=row['user_id'],
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({
                'status': 'error',
                'message': 'Failed to send verification code. Please try again later.'
            }), 500
        
        conn.commit()
        
        log_audit_event(
            event_type='password_reset_code_sent',
            description=f"Password reset code sent (user_id: {row['user_id']})",
            user_id=row['user_id'],
            ip_address=client_ip,
            metadata={'email': email}
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Verification code sent. Please check your email.'
        }), 200
        
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in forgot_password: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in forgot_password: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/forgot-password/verify-otp', methods=['POST'])
def forgot_password_verify_otp():
    """Verify password reset code before allowing password update."""
    client_ip = get_client_ip()

    allowed, error_response = check_ip_rate_limit_for_endpoint()
    if not allowed:
        return error_response

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    code = (data.get('otp_code') or data.get('code') or '').strip()

    if not email or not code:
        return jsonify({'status': 'error', 'message': 'Email and verification code are required'}), 400

    if not validate_email(email):
        return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400

    if len(code) != 6 or not code.isdigit():
        return jsonify({'status': 'error', 'message': 'Invalid verification code'}), 400

    now = datetime.utcnow()
    conn = get_db_connection()
    conn.autocommit = False
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT user_id, password_reset_code, password_reset_code_expires, password_reset_attempts
              FROM user
             WHERE user_email = %s
        """, (email,))
        row = cursor.fetchone()

        if not row:
            conn.rollback()
            log_audit_event(
                event_type='password_reset_verify_failed',
                description="Password reset verification failed: user not found",
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({'status': 'error', 'message': 'User not found'}), 404

        if not row['password_reset_code'] or not row['password_reset_code_expires']:
            conn.rollback()
            return jsonify({
                'status': 'error',
                'message': 'No password reset request found or verification code expired. Please request a new code.'
            }), 400

        if now > row['password_reset_code_expires']:
            cursor.execute("""
                UPDATE user
                   SET password_reset_code=NULL,
                       password_reset_code_expires=NULL,
                       password_reset_attempts=0
                 WHERE user_id=%s
            """, (row['user_id'],))
            conn.commit()

            log_audit_event(
                event_type='password_reset_code_expired',
                description=f"Password reset code expired (user_id: {row['user_id']})",
                user_id=row['user_id'],
                ip_address=client_ip,
                metadata={'email': email}
            )

            return jsonify({
                'status': 'error',
                'message': 'Verification code has expired. Please request a new code.'
            }), 400

        if code != row['password_reset_code']:
            attempts = (row['password_reset_attempts'] or 0) + 1
            clear_code = attempts >= PASSWORD_RESET_MAX_ATTEMPTS

            if clear_code:
                cursor.execute("""
                    UPDATE user
                       SET password_reset_code=NULL,
                           password_reset_code_expires=NULL,
                           password_reset_attempts=0
                     WHERE user_id=%s
                """, (row['user_id'],))
            else:
                cursor.execute("""
                    UPDATE user
                       SET password_reset_attempts=%s
                     WHERE user_id=%s
                """, (attempts, row['user_id']))

            conn.commit()

            log_audit_event(
                event_type='password_reset_code_invalid',
                description=f"Invalid password reset code attempt (user_id: {row['user_id']})",
                user_id=row['user_id'],
                ip_address=client_ip,
                metadata={'email': email, 'attempts': attempts}
            )

            message = 'Invalid verification code'
            if clear_code:
                message = 'Too many invalid attempts. Please request a new verification code.'
            return jsonify({'status': 'error', 'message': message}), 400

        # Successful verification - reset attempts counter
        cursor.execute("""
            UPDATE user
               SET password_reset_attempts=0
             WHERE user_id=%s
        """, (row['user_id'],))
        conn.commit()

        log_audit_event(
            event_type='password_reset_code_verified',
            description=f"Password reset code verified (user_id: {row['user_id']})",
            user_id=row['user_id'],
            ip_address=client_ip,
            metadata={'email': email}
        )

        return jsonify({'status': 'success', 'message': 'Verification code valid. You may reset your password now.'}), 200

    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in forgot_password_verify_otp: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in forgot_password_verify_otp: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/forgot-password/verify', methods=['POST'])
def forgot_password_reset():
    """Verify password reset code and update the password."""
    client_ip = get_client_ip()
    
    # Check IP rate limit
    allowed, error_response = check_ip_rate_limit_for_endpoint()
    if not allowed:
        return error_response
    
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    code = (data.get('otp_code') or data.get('code') or '').strip()
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    if not all([email, code, new_password, confirm_password]):
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400
    
    if not validate_email(email):
        return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
    
    if len(code) != 6 or not code.isdigit():
        return jsonify({'status': 'error', 'message': 'Invalid verification code'}), 400
    
    if new_password != confirm_password:
        return jsonify({'status': 'error', 'message': 'Passwords do not match'}), 400
    
    ok, msg = validate_password_strength(new_password)
    if not ok:
        return jsonify({'status': 'error', 'message': msg}), 400

    # Check password history before proceeding
    ensure_password_history_table()
    conn_check = get_db_connection()
    cursor_check = conn_check.cursor(dictionary=True)
    try:
        cursor_check.execute("SELECT user_id, user_password FROM user WHERE user_email = %s", (email,))
        user_row = cursor_check.fetchone()
        if user_row:
            # Check password history including current password
            is_allowed, history_msg = check_password_history(user_row['user_id'], new_password, max_history=5, current_password_hash=user_row.get('user_password'))
            if not is_allowed:
                cursor_check.close()
                conn_check.close()
                return jsonify({'status': 'error', 'message': history_msg}), 400
    finally:
        cursor_check.close()
        conn_check.close()

    new_hash = hash_password(new_password)
    now = datetime.utcnow()
    conn = get_db_connection()
    conn.autocommit = False
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("""
            SELECT user_id, user_password, password_reset_code, password_reset_code_expires, password_reset_attempts
              FROM user
             WHERE user_email = %s
        """, (email,))
        row = cursor.fetchone()
        
        if not row:
            conn.rollback()
            log_audit_event(
                event_type='forgot_password_failed',
                description="Password reset verification failed: user not found",
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({'status': 'error', 'message': 'Email does not exist'}), 404
        
        if not row['password_reset_code'] or not row['password_reset_code_expires']:
            conn.rollback()
            return jsonify({
                'status': 'error',
                'message': 'No password reset request found or verification code expired. Please request a new code.'
            }), 400
        
        if now > row['password_reset_code_expires']:
            cursor.execute("""
                UPDATE user
                   SET password_reset_code=NULL,
                       password_reset_code_expires=NULL,
                       password_reset_attempts=0
                 WHERE user_id=%s
            """, (row['user_id'],))
            conn.commit()
            log_audit_event(
                event_type='password_reset_code_expired',
                description=f"Password reset code expired (user_id: {row['user_id']})",
                user_id=row['user_id'],
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({
                'status': 'error',
                'message': 'Verification code has expired. Please request a new code.'
            }), 400
        
        if code != row['password_reset_code']:
            attempts = (row['password_reset_attempts'] or 0) + 1
            clear_code = attempts >= PASSWORD_RESET_MAX_ATTEMPTS
            
            if clear_code:
                cursor.execute("""
                    UPDATE user
                       SET password_reset_code=NULL,
                           password_reset_code_expires=NULL,
                           password_reset_attempts=0
                     WHERE user_id=%s
                """, (row['user_id'],))
            else:
                cursor.execute("""
                    UPDATE user
                       SET password_reset_attempts=%s
                     WHERE user_id=%s
                """, (attempts, row['user_id']))
            
            conn.commit()
            
            log_audit_event(
                event_type='password_reset_code_invalid',
                description=f"Invalid password reset code attempt (user_id: {row['user_id']})",
                user_id=row['user_id'],
                ip_address=client_ip,
                metadata={'email': email, 'attempts': attempts}
            )
            
            message = 'Invalid verification code'
            if clear_code:
                message = 'Too many invalid attempts. Please request a new verification code.'
            return jsonify({'status': 'error', 'message': message}), 400
        
        # Get current password hash to save to history before updating
        current_password_hash = row['user_password']
        
        # Update password
        cursor.execute("""
            UPDATE user
               SET user_password=%s,
                   password_reset_code=NULL,
                   password_reset_code_expires=NULL,
                   password_reset_attempts=0
             WHERE user_id=%s
        """, (new_hash, row['user_id']))

        conn.commit()

        # Save old password to history (if it exists and is different from new password)
        # Only save if current password hash exists and is not empty
        if current_password_hash and current_password_hash.strip() and current_password_hash != new_hash:
            try:
                save_password_to_history(row['user_id'], current_password_hash)
                print(f"[INFO] Saved password to history for user_id: {row['user_id']}")
            except Exception as e:
                print(f"[WARN] Failed to save password to history: {e}")
                import traceback
                traceback.print_exc()
                # Don't fail the password reset if history save fails

        log_audit_event(
            event_type='password_reset',
            description=f"Password reset successful (user_id: {row['user_id']})",
            user_id=row['user_id'],
            ip_address=client_ip,
            metadata={'email': email}
        )
        
        return jsonify({'status': 'success', 'message': 'Password updated successfully'}), 200
    
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in verify_forgot_password: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in verify_forgot_password: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/change-password', methods=['POST'])
def change_password():
    """Change password for authenticated users (requires old password)."""
    client_ip = get_client_ip()
    
    # Check IP rate limit
    allowed, error_response = check_ip_rate_limit_for_endpoint()
    if not allowed:
        return error_response
    
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    if not all([email, old_password, new_password, confirm_password]):
        return jsonify({'status': 'error', 'message': 'All fields are required'}), 400
    
    if not validate_email(email):
        return jsonify({'status': 'error', 'message': 'Invalid email format'}), 400
    
    if new_password != confirm_password:
        return jsonify({'status': 'error', 'message': 'New passwords do not match'}), 400
    
    ok, msg = validate_password_strength(new_password)
    if not ok:
        return jsonify({'status': 'error', 'message': msg}), 400
    
    # Ensure password history table exists
    ensure_password_history_table()
    
    conn = get_db_connection()
    conn.autocommit = False
    cursor = conn.cursor(dictionary=True)
    try:
        # Get user and verify old password
        cursor.execute("""
            SELECT user_id, user_password
            FROM user
            WHERE user_email = %s
        """, (email,))
        
        row = cursor.fetchone()
        if not row:
            conn.rollback()
            log_audit_event(
                event_type='password_change_failed',
                description="Password change failed: user not found",
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({'status': 'error', 'message': 'User not found'}), 404
        
        # Verify old password
        if not verify_password(old_password, row['user_password']):
            conn.rollback()
            log_audit_event(
                event_type='password_change_failed',
                description=f"Password change failed: incorrect old password (user_id: {row['user_id']})",
                user_id=row['user_id'],
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({'status': 'error', 'message': 'Incorrect old password'}), 400
        
        # Check password history (includes checking against current password)
        is_allowed, history_msg = check_password_history(row['user_id'], new_password, max_history=5, current_password_hash=row['user_password'])
        if not is_allowed:
            conn.rollback()
            log_audit_event(
                event_type='password_change_failed',
                description=f"Password change failed: password reuse detected (user_id: {row['user_id']})",
                user_id=row['user_id'],
                ip_address=client_ip,
                metadata={'email': email, 'reason': 'password_reuse'}
            )
            return jsonify({'status': 'error', 'message': history_msg}), 400
        
        # Hash new password
        new_hash = hash_password(new_password)
        current_password_hash = row['user_password']
        
        # Update password
        cursor.execute("""
            UPDATE user
            SET user_password = %s
            WHERE user_id = %s
        """, (new_hash, row['user_id']))
        
        conn.commit()
        
        # Save old password to history
        # Only save if current password hash exists and is not empty
        if current_password_hash and current_password_hash.strip():
            try:
                save_password_to_history(row['user_id'], current_password_hash)
                print(f"[INFO] Saved password to history for user_id: {row['user_id']}")
            except Exception as e:
                print(f"[WARN] Failed to save password to history: {e}")
                import traceback
                traceback.print_exc()
                # Don't fail the password change if history save fails
        
        log_audit_event(
            event_type='password_change',
            description=f"Password changed successfully (user_id: {row['user_id']})",
            user_id=row['user_id'],
            ip_address=client_ip,
            metadata={'email': email}
        )
        
        return jsonify({'status': 'success', 'message': 'Password changed successfully'}), 200
        
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in change_password: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'Database error'}), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in change_password: {e}")
        conn.rollback()
        return jsonify({'status': 'error', 'message': 'An error occurred'}), 500
    finally:
        cursor.close()
        conn.close()


if __name__ == '__main__':
    # Ensure auth fields exist
    ensure_auth_fields()
    # Ensure IP blocks table exists
    ensure_ip_blocks_table()
    # Ensure audit logs table exists
    ensure_audit_logs_table()
    # Ensure password history table exists
    ensure_password_history_table()
    # Ensure user sessions table exists
    ensure_user_sessions_table()
    
    # Run the API (default: localhost:5000)
    print("Starting Auth API on http://localhost:5000")
    print("Endpoints:")
    print("  POST /login - User login (returns JWT token for admin, refresh token if rememberMe)")
    print("  POST /register - User registration (with IP rate limiting)")
    print("  POST /forgot-password - Reset password (with IP rate limiting)")
    print("  POST /auth/refresh - Refresh access token using refresh token")
    print("  POST /auth/logout - Logout and revoke refresh token")
    print("  GET /auth/client-ip - Get client IP address (requires JWT)")
    print("  POST /auth/session-status - Check session status (requires refresh token)")
    print("  POST /admin/unlock - Admin unlock user (requires JWT)")
    print("  POST /admin/unblock_ip - Admin unblock IP (requires JWT)")
    print("  GET /admin/audit_logs - View audit logs (requires JWT)")
    print("  GET /admin/blocked_accounts - View blocked accounts (requires JWT)")
    print("  GET /admin/blocked_ips - View blocked IPs (requires JWT)")
    print("  GET /admin/account_stats - View account statistics (requires JWT)")
    print("  GET /health - Health check")
    app.run(host='0.0.0.0', port=5000, debug=True)

