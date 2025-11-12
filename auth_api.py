"""
Minimal Authentication API for Call a Doctor
Handles login authentication with rate limiting and lockout policies.
"""
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

app = Flask(__name__)
# CORS restricted to localhost for desktop app
CORS(app, origins=["http://localhost:*", "http://127.0.0.1:*"])

# JWT secret key (in production, use environment variable)
JWT_SECRET = "cad_auth_secret_key_2024_change_in_production"
JWT_ALGORITHM = "HS256"

# Database configuration (should match your existing setup)
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'xueer.1014',  # TODO: Move to environment variable
    'database': 'cad'
}

# IP-based rate limiting (in-memory for request tracking)
ip_attempts = defaultdict(list)
IP_RATE_LIMIT = 20  # Max requests per minute per IP
IP_WINDOW_SECONDS = 60
SOFT_BLOCK_MINUTES = 15  # Soft block duration
MAX_SOFT_BLOCKS_PER_DAY = 3  # Hard block after 3 soft blocks in a day


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
    return mysql.connector.connect(**DB_CONFIG)


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
        from_email = "kuro2269@gmail.com"
        from_password = "dsormotxbswaovfn"
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
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
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
        # Check if columns exist, add if not
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
        
        # Also check and add new fields if they don't exist (for existing installations)
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
    except mysql.connector.Error as e:
        print(f"[ERROR] Failed to ensure auth fields: {e}")
        print(f"[ERROR] Error code: {e.errno}, SQL state: {e.sqlstate}")
        # Don't silently ignore - raise the error so we know something is wrong
        raise
    finally:
        cursor.close()
        conn.close()


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
    
    if not email or not password:
        return jsonify({
            'status': 'error',
            'message': 'Email and password required'
        }), 400
    
    # Validate email format
    if not email.endswith('@gmail.com'):
        return jsonify({
            'status': 'error',
            'message': 'Invalid email format'
        }), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if user exists and get auth fields
        cursor.execute("""
            SELECT user_id, user_type, user_password, failed_attempts, lock_until, permanently_locked,
                   first_failure_time, has_been_locked_before, permanent_lock_time
            FROM user
            WHERE user_email = %s
        """, (email,))
        
        user = cursor.fetchone()
        
        if not user:
            # Don't reveal if email exists - generic error
            log_audit_event(
                event_type='login_failed',
                description=f"Login attempt failed: user not found",
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({
                'status': 'error',
                'message': 'Invalid email or password'
            }), 401
        
        user_id, user_type, stored_password, failed_attempts, lock_until, permanently_locked, first_failure_time, has_been_locked_before, permanent_lock_time = user
        
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
        if password != stored_password:
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
            
            # Update user record
            try:
                rows_affected = cursor.execute("""
                    UPDATE user
                    SET failed_attempts = %s, lock_until = %s, permanently_locked = %s,
                        first_failure_time = %s, has_been_locked_before = %s, permanent_lock_time = %s
                    WHERE user_id = %s
                """, (failed_attempts, new_lock_until, new_permanently_locked, first_failure_time, new_has_been_locked_before, new_permanent_lock_time, user_id))
                conn.commit()
                print(f"[DEBUG] Updated user {user_id}: rows_affected={cursor.rowcount}, failed_attempts={failed_attempts}, lock_until={new_lock_until}, permanently_locked={new_permanently_locked}")
                
                # Verify the update worked
                cursor.execute("""
                    SELECT failed_attempts, lock_until, permanently_locked, first_failure_time, has_been_locked_before
                    FROM user WHERE user_id = %s
                """, (user_id,))
                verify_row = cursor.fetchone()
                if verify_row:
                    print(f"[DEBUG] Verified: user {user_id} now has failed_attempts={verify_row[0]}, lock_until={verify_row[1]}, permanently_locked={verify_row[2]}")
            except Exception as e:
                print(f"[ERROR] Failed to update user {user_id}: {e}")
                import traceback
                traceback.print_exc()
                conn.rollback()
                raise
            
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
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': f'Database error: {str(e)}'
        }), 500
    except Exception as e:
        print(f"[ERROR] Unexpected error in login: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


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
def register():
    """Handle user registration with IP rate limiting."""
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
    name = data.get('name', '')
    ic_passport = data.get('ic_passport', '')
    gender = data.get('gender', '')
    address = data.get('address', '')
    contact = data.get('contact', '')
    
    # Validate required fields
    if not all([email, password, name, ic_passport, gender, address, contact]):
        log_audit_event(
            event_type='registration_failed',
            description=f"Registration failed: missing required fields",
            ip_address=client_ip,
            metadata={'email': email if email else 'not_provided', 'reason': 'missing_fields'}
        )
        return jsonify({
            'status': 'error',
            'message': 'All fields are required'
        }), 400
    
    # Validate email format
    if not email.endswith('@gmail.com'):
        log_audit_event(
            event_type='registration_failed',
            description=f"Registration failed: invalid email format",
            ip_address=client_ip,
            metadata={'email': email, 'reason': 'invalid_email_format'}
        )
        return jsonify({
            'status': 'error',
            'message': 'Invalid email format'
        }), 400
    
    # Validate password length
    if len(password) < 8:
        log_audit_event(
            event_type='registration_failed',
            description=f"Registration failed: password too short",
            ip_address=client_ip,
            metadata={'email': email, 'reason': 'password_too_short'}
        )
        return jsonify({
            'status': 'error',
            'message': 'Password must be at least 8 characters'
        }), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if email already exists
        cursor.execute("""
            SELECT user_id FROM user WHERE user_email = %s
        """, (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            log_audit_event(
                event_type='registration_failed',
                description=f"Registration failed: email already exists",
                ip_address=client_ip,
                metadata={'email': email, 'reason': 'email_exists'}
            )
            return jsonify({
                'status': 'error',
                'message': 'Email already exists'
            }), 409
        
        # Create user account
        cursor.execute("""
            INSERT INTO user (user_email, user_password, user_type)
            VALUES (%s, %s, 'user')
        """, (email, password))
        conn.commit()
        
        # Get created user_id
        cursor.execute("""
            SELECT user_id FROM user WHERE user_email = %s
        """, (email,))
        user_result = cursor.fetchone()
        
        if not user_result:
            log_audit_event(
                event_type='registration_failed',
                description=f"Registration failed: database error creating user account",
                ip_address=client_ip,
                metadata={'email': email, 'reason': 'database_error'}
            )
            return jsonify({
                'status': 'error',
                'message': 'Failed to create user account'
            }), 500
        
        user_id = user_result[0]
        
        # Create patient record
        cursor.execute("""
            INSERT INTO patient (patient_name, patient_ic_passport, patient_gender, 
                               patient_address, patient_contact, user_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (name, ic_passport, gender, address, contact, user_id))
        conn.commit()
        
        # Log registration event
        log_audit_event(
            event_type='user_registered',
            description=f"User registered successfully (user_id: {user_id})",
            user_id=user_id,
            ip_address=client_ip,
            metadata={'email': email}
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Registration successful',
            'user_id': user_id
        }), 201
        
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in register: {e}")
        conn.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
    finally:
        cursor.close()
        conn.close()


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Handle forgot password with IP rate limiting."""
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
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    # Validate required fields
    if not all([email, new_password, confirm_password]):
        return jsonify({
            'status': 'error',
            'message': 'All fields are required'
        }), 400
    
    # Validate email format
    if not email.endswith('@gmail.com'):
        return jsonify({
            'status': 'error',
            'message': 'Invalid email format'
        }), 400
    
    # Validate password length
    if len(new_password) < 8:
        return jsonify({
            'status': 'error',
            'message': 'Password must be at least 8 characters'
        }), 400
    
    # Validate password match
    if new_password != confirm_password:
        return jsonify({
            'status': 'error',
            'message': 'Passwords do not match'
        }), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if user exists
        cursor.execute("""
            SELECT user_id FROM user WHERE user_email = %s
        """, (email,))
        user_result = cursor.fetchone()
        
        if not user_result:
            # Don't reveal if email exists - generic error
            log_audit_event(
                event_type='forgot_password_failed',
                description=f"Forgot password attempt failed: user not found",
                ip_address=client_ip,
                metadata={'email': email}
            )
            return jsonify({
                'status': 'error',
                'message': 'Email does not exist'
            }), 404
        
        user_id = user_result[0]
        
        # Update password
        cursor.execute("""
            UPDATE user SET user_password = %s WHERE user_id = %s
        """, (new_password, user_id))
        conn.commit()
        
        # Log password reset event
        log_audit_event(
            event_type='password_reset',
            description=f"Password reset successful (user_id: {user_id})",
            user_id=user_id,
            ip_address=client_ip,
            metadata={'email': email}
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Password updated successfully'
        }), 200
        
    except mysql.connector.Error as e:
        print(f"[ERROR] Database error in forgot_password: {e}")
        conn.rollback()
        return jsonify({
            'status': 'error',
            'message': 'Database error'
        }), 500
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

