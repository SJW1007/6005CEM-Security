import tkinter as tk
from tkinter import ttk
from tkinter import *
from PIL import ImageTk, Image
import mysql.connector
from io import BytesIO
from tkinter import filedialog
import os
import stat
from tkinter import messagebox
import datetime
from tkcalendar import Calendar
from datetime import datetime, timedelta, time
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import base64
from cryptography.fernet import Fernet
import hashlib

# Connect to the database
database = mysql.connector.connect(host="localhost", user="root", password="xueer.1014", database="cad")
cursor = database.cursor()

# Auth API endpoints
AUTH_API_BASE = 'http://localhost:5000'
AUTH_API_URL = f'{AUTH_API_BASE}/login'
REGISTER_URL = f'{AUTH_API_BASE}/register'
FORGOT_PASSWORD_URL = f'{AUTH_API_BASE}/forgot-password'
REFRESH_TOKEN_URL = f'{AUTH_API_BASE}/auth/refresh'
LOGOUT_URL = f'{AUTH_API_BASE}/auth/logout'
SESSION_STATUS_URL = f'{AUTH_API_BASE}/auth/session-status'
CLIENT_IP_URL = f'{AUTH_API_BASE}/auth/client-ip'

# Local storage file for refresh token
REFRESH_TOKEN_FILE = 'refresh_token.txt'
ENCRYPTION_KEY_FILE = '.token_key'  # Hidden file for encryption key

def get_or_create_encryption_key():
    """Get or create encryption key for token storage. Uses machine-specific key."""
    try:
        if os.path.exists(ENCRYPTION_KEY_FILE):
            # Load existing key
            with open(ENCRYPTION_KEY_FILE, 'rb') as f:
                return f.read()
        else:
            # Generate new key based on machine/user-specific data
            # This ensures key is consistent per machine but unique
            import platform
            machine_id = f"{platform.node()}{os.getlogin()}{os.path.expanduser('~')}"
            key_material = hashlib.sha256(machine_id.encode()).digest()
            # Convert to Fernet-compatible key (32 bytes, base64-encoded)
            key = base64.urlsafe_b64encode(key_material)
            
            # Save key (with restricted permissions)
            with open(ENCRYPTION_KEY_FILE, 'wb') as f:
                f.write(key)
            if os.name != 'nt':  # Linux/Mac
                os.chmod(ENCRYPTION_KEY_FILE, 0o600)  # Owner only
            
            return key
    except Exception as e:
        print(f"[ERROR] Failed to get/create encryption key: {e}")
        # Fallback: generate random key (will be different each time)
        return Fernet.generate_key()


# Fetch the image used for buttons, icons, backgrounds in the application
def load_image(description, width, height):
    cursor.execute('''SELECT app_image_data FROM app_image WHERE app_image_description=%s''', (description,))
    image_data = cursor.fetchone()
    if image_data:
        image_stream = BytesIO(image_data[0])
        img = Image.open(image_stream)
        resized_img = img.resize((width, height), Image.LANCZOS)
        tk_image = ImageTk.PhotoImage(resized_img)
        return tk_image


def detect_image_format(image_bytes):
    try:
        with io.BytesIO(image_bytes) as stream:
            img = Image.open(stream)
            fmt = img.format
            if fmt:
                return fmt.lower()
    except Exception:
        return None
    return None


class LoginRegister:
    def __init__(self):
        self.window = tk.Tk()
        self.refresh_token = None
        self.session_check_interval = 60000  # 1 minute in milliseconds
        self.session_check_job = None
        self.admin_token = None
        self.current_user_id = None
        self.current_user_type = None
        self.window.title('Call a Doctor')
        self.window.geometry('1050x600')
        icon = load_image('icon', 48, 48)
        self.window.iconphoto(False, icon)

        self.frame = tk.Frame(self.window, width=1050, height=600, bg='white')
        self.frame.pack()

        self.get_started_background = load_image('bg get started', 1050, 600)
        self.icon = load_image('icon', 100, 90)
        self.lfr_background = load_image('bg login_register as', 1050, 600)
        self.eye_closed_image = load_image('eye closed', 24, 24)
        self.eye_opened_image = load_image('eye opened', 24, 24)

        # Store the uploaded image for registering clinic
        self.image_var = None

        # Trace the existence of different main window
        self.user_window = None
        self.clinic_window = None
        self.doctor_window = None
        self.admin_window = None

        self._cooldown_handles = {}

        style = ttk.Style()
        style.theme_use('clam')

        style.configure('small_green.TButton', border=0, relief='flat', background='#0EBE7F', foreground='#FFFFFF',
                        font=('Rubik', 12, 'bold'))
        style.map('small_green.TButton', background=[('active', '#66C5A3')])
        style.configure('big_green.TButton', border=0, relief='flat', background='#0EBE7F', foreground='#FFFFFF',
                        font=('Rubik', 20, 'bold'))
        style.map('big_green.TButton', background=[('active', '#66C5A3')])
        style.configure('grey_word.TButton', border=0, relief='flat', background='white', foreground='#7E869F',
                        font=('Rubik', 9))
        style.map('grey_word.TButton', background=[('active', 'white')], foreground=[('active', '#4F5871')])
        style.configure('black_word.TButton', border=0, relief='flat', background='#08D5A7', foreground='#333333',
                        font=('Rubik', 8, 'bold'))
        style.map('black_word.TButton', background=[('active', '#08D5A7')], foreground=[('active', 'white')])
        style.configure('eye_closed_grey.TButton', border=0, relief='flat', background='#F5F5F5', image=self.eye_closed_image)
        style.map('eye_closed_grey.TButton', background=[('active', '#F5F5F5')])
        style.configure('eye_opened_grey.TButton', border=0, relief='flat', background='#F5F5F5', image=self.eye_opened_image)
        style.map('eye_opened_grey.TButton', background=[('active', '#F5F5F5')])
        style.configure('eye_closed_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_closed_image)
        style.map('eye_closed_green.TButton', background=[('active', '#D0F9EF')])
        style.configure('eye_opened_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_opened_image)
        style.map('eye_opened_green.TButton', background=[('active', '#D0F9EF')])
        style.configure('selection.TButton', border=0, relief='flat', background='#D0F9EF', foreground='#3DAEC7',
                        font=('Rubik', 12, 'bold'))
        style.map('selection.TButton', background=[('active', '#D0F9EF')], foreground=[('active', '#0B8FAC')])

    # Show the get started page in initial
    def run(self):
        # Try auto-login first
        if not self.attempt_auto_login():
            # No valid refresh token, show login screen
        self.show_get_started()
        self.window.mainloop()
    
    def handle_logout(self):
        """Handle logout - clear tokens and call logout API."""
        # Call logout API if refresh token exists
        if self.refresh_token:
            try:
                requests.post(
                    LOGOUT_URL,
                    json={'refresh_token': self.refresh_token},
                    timeout=5
                )
            except Exception as e:
                print(f"[ERROR] Logout API call failed: {e}")
        
        # Clear tokens and reset state
        self.clear_refresh_token()
        self.admin_token = None
        self.current_user_id = None
        self.current_user_type = None
        self.stop_periodic_session_check()
        
        # Close all user windows
        if self.user_window:
            try:
                self.user_window.window.withdraw()
            except:
                pass
        if self.clinic_window:
            try:
                self.clinic_window.window.withdraw()
            except:
                pass
        if self.doctor_window:
            try:
                self.doctor_window.window.withdraw()
            except:
                pass
        if self.admin_window:
            try:
                self.admin_window.window.withdraw()
            except:
                pass
        
        # Show login window
        self.window.deiconify()
        self.show_login()

    # Destroy all widgets and remove the clinic image data
    def reset(self):
        for widget in self.frame.winfo_children():
            widget.destroy()

        self.image_var = None

    @staticmethod
    def format_wait_time(seconds):
        seconds = max(int(seconds or 0), 0)
        minutes, secs = divmod(seconds, 60)
        if minutes and secs:
            return f'{minutes} minute(s) {secs} second(s)'
        if minutes:
            return f'{minutes} minute(s)'
        if secs:
            return f'{secs} second(s)'
        return 'a moment'

    def start_button_cooldown(self, widget, seconds, status_label=None, base_message='', keep_message_after=True):
        if seconds is None or seconds <= 0:
            return
        seconds = int(max(1, seconds))
        try:
            current_text = widget.cget('text')
        except tk.TclError:
            return

        base_text = getattr(widget, '_base_text', None)
        if base_text is None:
            base_text = current_text
            setattr(widget, '_base_text', base_text)

        existing_handle = self._cooldown_handles.pop(widget, None)
        if existing_handle:
            try:
                self.window.after_cancel(existing_handle)
            except tk.TclError:
                pass

        def update(remaining):
            try:
                widget.config(state='disabled')
            except tk.TclError:
                return

            if status_label and base_message:
                if remaining > 0:
                    status_label.config(text=f'{base_message} (retry in {remaining}s)')
                elif keep_message_after:
                    status_label.config(text=base_message)
                else:
                    status_label.config(text='')

            try:
                if remaining > 0:
                    widget.config(text=f'{base_text} ({remaining}s)')
                else:
                    widget.config(text=base_text)
            except tk.TclError:
                return

            if remaining <= 0:
                try:
                    widget.config(state='normal')
                except tk.TclError:
                    pass
                if status_label and base_message and not keep_message_after:
                    status_label.config(text='')
                self._cooldown_handles.pop(widget, None)
                return

            handle = self.window.after(1000, lambda: update(remaining - 1))
            self._cooldown_handles[widget] = handle

        update(seconds)

    # Set up the get started page with respective widgets
    def show_get_started(self):
        self.reset()
        gs_background_label = tk.Label(self.frame, image=self.get_started_background)
        gs_background_label.pack()

        gs_icon_label = tk.Label(self.frame, image=self.icon, bg='white')
        gs_icon_label.place(x=760, y=50)
        gs_text1 = tk.Label(self.frame, text='Call a Doctor', font=('Rubik', 40, 'bold'), bg='white', fg='#333333')
        gs_text1.place(x=645, y=150)
        gs_text2 = tk.Label(self.frame, text='Your Ultimate Doctor', font=('Rubik', 18), bg='white', fg='#888EA1')
        gs_text2.place(x=700, y=240)
        gs_text3 = tk.Label(self.frame, text='Appointment Booking App', font=('Rubik', 18), bg='white', fg='#888EA1')
        gs_text3.place(x=672, y=275)

        gs_get_started_button = ttk.Button(self.frame, text='Get Started', style='big_green.TButton', width=18, padding=6,
                                           cursor='hand2', command=lambda: self.show_register_as())
        gs_get_started_button.place(x=675, y=370)
        gs_login_grey_button = ttk.Button(self.frame, text='Login', style='grey_word.TButton', cursor='hand2', width=5,
                                          command=lambda: self.show_login())
        gs_login_grey_button.place(x=790, y=425)

    # Set up the register as page with respective widgets
    def show_register_as(self):
        self.reset()
        ra_background_label = tk.Label(self.frame, image=self.lfr_background)
        ra_background_label.pack()

        ra_text1 = tk.Label(self.frame, text='Register as', font=('Open Sans', 30, 'bold'), bg='white', fg='#333333')
        ra_text1.place(x=680, y=70)

        ra_user_button = ttk.Button(self.frame, text='Normal User', style='big_green.TButton', cursor='hand2', width=18, padding=12,
                                    command=lambda: self.show_registering_user())
        ra_user_button.place(x=640, y=200)
        ra_text2 = tk.Label(self.frame, text='OR', font=('Rubik', 14), bg='white', fg='#888EA1')
        ra_text2.place(x=770, y=290)
        ra_clinic_button = ttk.Button(self.frame, text='Clinic', style='big_green.TButton', cursor='hand2', width=18, padding=12,
                                      command=lambda: self.show_registering_clinic())
        ra_clinic_button.place(x=640, y=350)

        ra_text3 = tk.Label(self.frame, text='Have an account?', bg='#08D5A7', fg='#333333', font=('Rubik', 8, 'bold'))
        ra_text3.place(x=840, y=570)
        ra_login_black_button = ttk.Button(self.frame, text='Login', style='black_word.TButton', cursor='hand2', width=8,
                                           command=lambda: self.show_login())
        ra_login_black_button.place(x=940, y=565)

    # Helper functions for token management
    def save_refresh_token(self, token):
        """Save refresh token to local file with encryption and restricted permissions."""
        try:
            # Encrypt token before saving
            key = get_or_create_encryption_key()
            fernet = Fernet(key)
            encrypted_token = fernet.encrypt(token.encode())
            
            # Save encrypted token
            with open(REFRESH_TOKEN_FILE, 'wb') as f:
                f.write(encrypted_token)
            
            # Set file permissions: owner read/write only (more secure)
            try:
                if os.name != 'nt':  # Linux/Mac - set restrictive permissions
                    os.chmod(REFRESH_TOKEN_FILE, 0o600)  # rw------- (owner read/write only)
                # Note: Windows file permissions are managed by the OS and file system
                # By default, files are only accessible by the user who created them
            except Exception as perm_error:
                # If permission setting fails, continue anyway (some systems may not support it)
                print(f"[WARNING] Could not set file permissions: {perm_error}")
            
            # Store plaintext in memory (needed for API calls)
            self.refresh_token = token
        except Exception as e:
            print(f"[ERROR] Failed to save refresh token: {e}")
            # Fallback: save without encryption if encryption fails
            try:
                with open(REFRESH_TOKEN_FILE, 'w') as f:
                    f.write(token)
                self.refresh_token = token
            except Exception as fallback_error:
                print(f"[ERROR] Fallback save also failed: {fallback_error}")
    
    def load_refresh_token(self):
        """Load refresh token from local file and decrypt it."""
        try:
            if os.path.exists(REFRESH_TOKEN_FILE):
                # Try to read as encrypted (binary) first
                try:
                    with open(REFRESH_TOKEN_FILE, 'rb') as f:
                        encrypted_token = f.read()
                    
                    # Decrypt token
                    key = get_or_create_encryption_key()
                    fernet = Fernet(key)
                    token = fernet.decrypt(encrypted_token).decode()
                    
                    if token:
                        self.refresh_token = token
                        return token
                except Exception as decrypt_error:
                    # Fallback: try reading as plaintext (for backward compatibility)
                    print(f"[INFO] Token file not encrypted, reading as plaintext: {decrypt_error}")
                    with open(REFRESH_TOKEN_FILE, 'r') as f:
                        token = f.read().strip()
                        if token:
                            self.refresh_token = token
                            return token
        except Exception as e:
            print(f"[ERROR] Failed to load refresh token: {e}")
        return None
    
    def clear_refresh_token(self):
        """Clear refresh token from memory and file."""
        try:
            self.refresh_token = None
            if os.path.exists(REFRESH_TOKEN_FILE):
                os.remove(REFRESH_TOKEN_FILE)
        except Exception as e:
            print(f"[ERROR] Failed to clear refresh token: {e}")
    
    def check_session_status(self):
        """Periodic check of session status (account lock, IP block, token validity)."""
        if not self.refresh_token:
            return True  # No token to check, but don't logout
        
        try:
            response = requests.post(
                SESSION_STATUS_URL,
                json={'refresh_token': self.refresh_token},
                timeout=5
            )
            
            # Parse response (should always be JSON)
            try:
                data = response.json()
            except ValueError:
                # Response is not JSON - unexpected error
                print(f"[ERROR] Session status check returned non-JSON response: {response.status_code}")
                return True  # Don't logout on unexpected errors
            
            # Check if session is valid
            if response.status_code == 200:
                if data.get('status') == 'valid':
                    return True
                else:
                    # Status is not 'valid' but got 200 - should not happen, but handle it
                    if data.get('should_logout'):
                        self.handle_session_invalid(data.get('message', 'Session expired'))
                        return False
            else:
                # Non-200 status (401, 403, 404, etc.) - check if logout is required
                # This handles: permanent lock, temporary lock, IP block, token expiration
                if data.get('should_logout'):
                    message = data.get('message', 'Session expired')
                    lock_type = "permanent" if data.get('account_locked') and not data.get('ip_blocked') else "temporary/IP block"
                    print(f"[INFO] Session invalid - {lock_type} lock detected: {message}")
                    self.handle_session_invalid(message)
                    return False
                else:
                    # Error but don't logout (e.g., database error)
                    print(f"[WARNING] Session status check failed but should_logout is false: {data.get('message')}")
                    return True
                    
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Session status check network error: {e}")
            # Don't logout on network errors, just log
            return True
        except Exception as e:
            print(f"[ERROR] Session status check failed: {e}")
            import traceback
            traceback.print_exc()
            # Don't logout on unexpected errors
            return True
    
    def handle_session_invalid(self, message='Your session has expired. Please log in again.'):
        """Handle invalid session - clear tokens, revoke refresh token, and show login."""
        # Stop periodic checks first
        if self.session_check_job:
            self.window.after_cancel(self.session_check_job)
            self.session_check_job = None
        
        # Revoke refresh token in database (if token exists)
        if self.refresh_token:
            try:
                requests.post(
                    LOGOUT_URL,
                    json={'refresh_token': self.refresh_token},
                    timeout=5
                )
            except Exception as e:
                print(f"[ERROR] Failed to revoke refresh token on forced logout: {e}")
        
        # Clear tokens and reset state
        self.clear_refresh_token()
        self.admin_token = None
        self.current_user_id = None
        self.current_user_type = None
        
        # Close all user windows
        if self.user_window:
            try:
                self.user_window.window.withdraw()
            except:
                pass
        if self.clinic_window:
            try:
                self.clinic_window.window.withdraw()
            except:
                pass
        if self.doctor_window:
            try:
                self.doctor_window.window.withdraw()
            except:
                pass
        if self.admin_window:
            try:
                self.admin_window.window.withdraw()
            except:
                pass
        
        # Show login window
        self.window.deiconify()
        
        # Show login with message
        messagebox.showwarning("Session Expired", message)
        self.show_login()
    
    def start_periodic_session_check(self):
        """Start periodic session status checks."""
        def check():
            if not self.check_session_status():
                return  # Session invalid, will be handled by handle_session_invalid
            # Schedule next check
            self.session_check_job = self.window.after(self.session_check_interval, check)
        
        # Start first check after interval
        self.session_check_job = self.window.after(self.session_check_interval, check)
    
    def stop_periodic_session_check(self):
        """Stop periodic session status checks."""
        if self.session_check_job:
            self.window.after_cancel(self.session_check_job)
            self.session_check_job = None
    
    def attempt_auto_login(self):
        """Attempt auto-login using saved refresh token."""
        refresh_token = self.load_refresh_token()
        if not refresh_token:
            return False
        
        try:
            response = requests.post(
                REFRESH_TOKEN_URL,
                json={'refresh_token': refresh_token},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                user_id = data.get('user_id')
                user_type = data.get('user_type')
                new_refresh_token = data.get('refresh_token')
                admin_token = data.get('token')
                
                if user_id and user_type:
                    # Update tokens
                    if new_refresh_token:
                        self.save_refresh_token(new_refresh_token)
                    
                    self.admin_token = admin_token
                    self.current_user_id = user_id
                    self.current_user_type = user_type
                    
                    # Auto-login user
                    self.window.withdraw()
                    
                    if user_type == 'user':
                        if self.user_window:
                            self.user_window.run(user_id)
                        else:
                            self.user_window = User(self.window, self)
                            self.user_window.run(user_id)
                    elif user_type == 'clinic':
                        if self.clinic_window:
                            self.clinic_window.run(user_id)
                        else:
                            self.clinic_window = Clinic(self.window, self)
                            self.clinic_window.run(user_id)
                    elif user_type == 'doctor':
                        if self.doctor_window:
                            self.doctor_window.run(user_id)
                        else:
                            self.doctor_window = Doctor(self.window, self)
                            self.doctor_window.run(user_id)
                    elif user_type == 'admin':
                        if self.admin_window:
                            self.admin_window.run(user_id, admin_token)
                        else:
                            self.admin_window = Admin(self.window, self)
                            self.admin_window.run(user_id, admin_token)
                    
                    # Start periodic session checks
                    self.start_periodic_session_check()
                    return True
            else:
                # Invalid token - clear it
                data = response.json()
                self.clear_refresh_token()
                if data.get('message'):
                    print(f"[INFO] Auto-login failed: {data.get('message')}")
        except Exception as e:
            print(f"[ERROR] Auto-login failed: {e}")
            # Don't clear token on network errors
        
        return False

    # Set up the login page with respective widgets
    def show_login(self):
        # Stop periodic checks if running
        self.stop_periodic_session_check()
        
        # Validates the requirements for successful login
        def login():
            # Remove focus from all entries
            self.window.focus_set()

            if not (l_email_entry.cget('fg') == '#333333' and l_password_entry.cget('fg') == '#333333'):
                l_validate_login_label.config(text='Please fill in all the details')
                return

            user_email = l_email_entry.get().lower()
            user_password = l_password_entry.get()
            remember_me = remember_me_var.get()  # Get remember me checkbox value

            if not user_email.endswith('@gmail.com'):
                l_validate_login_label.config(text='Invalid Email Format')
                return

            # Call authentication API (hybrid architecture - all rate limiting handled server-side)
            try:
                response = requests.post(
                    AUTH_API_URL,
                    json={'email': user_email, 'password': user_password, 'rememberMe': remember_me},
                    timeout=5
                )
                
                if response.status_code == 200:
                    # Success
                    data = response.json()
                    user_id = data.get('user_id')
                    user_type = data.get('user_type')
                    refresh_token = data.get('refresh_token')
                    admin_token = data.get('token')
                    
                    if user_id and user_type:
                        # Store refresh token in memory (always needed for session management)
                        # Only save to file if "Remember Me" is checked
                        if refresh_token:
                            self.refresh_token = refresh_token
                            if remember_me:
                                # Save to file for auto-login on app restart
                                self.save_refresh_token(refresh_token)
                            else:
                                # Don't save to file, but keep in memory for session checks
                                # Delete file if it exists (but keep token in memory)
                                try:
                                    if os.path.exists(REFRESH_TOKEN_FILE):
                                        os.remove(REFRESH_TOKEN_FILE)
                                except Exception as e:
                                    print(f"[WARNING] Failed to remove refresh token file: {e}")
                        else:
                            self.refresh_token = None
                        
                        # Store tokens and user info
                        self.admin_token = admin_token
                        self.current_user_id = user_id
                        self.current_user_type = user_type
                        
                        l_validate_login_label.config(text='')
                        l_validate_login_label.update_idletasks()
                        
                        # Create/show user window before withdrawing login window
                        try:
                        if user_type == 'user':
                            if self.user_window:
                                self.user_window.run(user_id)
                            else:
                                    self.user_window = User(self.window, self)
                                self.user_window.run(user_id)
                        elif user_type == 'clinic':
                            if self.clinic_window:
                                self.clinic_window.run(user_id)
                            else:
                                    self.clinic_window = Clinic(self.window, self)
                                self.clinic_window.run(user_id)
                        elif user_type == 'doctor':
                            if self.doctor_window:
                                self.doctor_window.run(user_id)
                            else:
                                    self.doctor_window = Doctor(self.window, self)
                                self.doctor_window.run(user_id)
                        elif user_type == 'admin':
                            if self.admin_window:
                                    # Update admin token if window exists
                                    self.admin_window.admin_token = admin_token
                                self.admin_window.run(user_id, admin_token)
                            else:
                                    self.admin_window = Admin(self.window, self)
                                self.admin_window.run(user_id, admin_token)
                            
                            # Withdraw login window after user window is shown
                            self.window.withdraw()
                            
                            # Start periodic session checks
                            self.start_periodic_session_check()
                            return
                        except Exception as e:
                            print(f"[ERROR] Failed to show user window: {e}")
                            import traceback
                            traceback.print_exc()
                            l_validate_login_label.config(text='Error opening application. Please try again.')
                        return
                
                elif response.status_code == 403:
                    # Locked account or IP hard blocked
                    data = response.json()
                    status = data.get('status')
                    message = data.get('message', '')
                    
                    if status == 'permanent_lock':
                        l_validate_login_label.config(
                            text='Account locked. Please contact admin.'
                        )
                    elif status == 'temp_lock':
                        l_validate_login_label.config(
                            text='Too many attempts. Please try again later.'
                        )
                    elif message and 'IP' in message:
                        # IP hard blocked
                        l_validate_login_label.config(text=message)
                    else:
                        l_validate_login_label.config(text=message or 'Access denied')
                    return
                
                elif response.status_code == 401:
                    # Invalid credentials - generic error message
                    l_validate_login_label.config(text='Invalid email or password')
                    return
                
                elif response.status_code == 429:
                    # IP rate limited or soft blocked
                    data = response.json()
                    message = data.get('message', 'Too many requests. Please try again later.')
                    l_validate_login_label.config(text=message)
                    return
                
                else:
                    # Other error
                    l_validate_login_label.config(text='Login service unavailable. Please try again later.')
                    return
                    
            except requests.exceptions.RequestException:
                # API unavailable - fallback or show error
                l_validate_login_label.config(text='Error on authentication service.')
                return

        self.reset()
        l_background_label = tk.Label(self.frame, image=self.lfr_background)
        l_background_label.pack()

        l_text1 = tk.Label(self.frame, text='Login', font=('Open Sans', 30, 'bold'), bg='white', fg='#333333')
        l_text1.place(x=725, y=70)
        l_text2 = tk.Label(self.frame, text='Hi, Welcome Back!', font=('Rubik', 14), bg='white', fg='#888EA1')
        l_text2.place(x=700, y=130)

        l_email_label = tk.Label(self.frame, text='Email', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        l_email_label.place(x=620, y=200)
        l_email_entry_frame = tk.Frame(self.frame, bg='#F5F5F5', width=320, height=45, highlightbackground="#C8C7C7",
                                       highlightthickness=0.5)
        l_email_entry_frame.place(x=625, y=230)
        l_email_entry = tk.Entry(l_email_entry_frame, font=('Open Sans', 10), bg='#F5F5F5', fg='#858585', border=0, width=35)
        l_email_entry.place(x=10, y=12)
        l_email_entry.insert(0, 'Enter Your Email')
        l_email_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', l_email_entry))
        l_email_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', l_email_entry, 'Enter Your Email'))
        l_email_entry.bind('<Return>', lambda event: login())

        l_password_label = tk.Label(self.frame, text='Password', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        l_password_label.place(x=620, y=295)
        l_password_entry_frame = tk.Frame(self.frame, bg='#F5F5F5', width=320, height=45, highlightbackground="#C8C7C7",
                                          highlightthickness=0.5)
        l_password_entry_frame.place(x=625, y=325)
        l_password_entry = tk.Entry(l_password_entry_frame, font=('Open Sans', 10), bg='#F5F5F5', fg='#858585', border=0, width=35,
                                    show='')
        l_password_entry.place(x=10, y=12)
        l_password_entry.insert(0, 'Enter Your Password')
        l_password_eye_closed_button = ttk.Button(l_password_entry_frame, style='eye_closed_grey.TButton', cursor='hand2')
        l_password_eye_closed_button.place(x=270, y=2)
        l_password_eye_opened_button = ttk.Button(l_password_entry_frame, style='eye_opened_grey.TButton', cursor='hand2')
        l_password_visibility = tk.Label(l_password_entry_frame, text='Close')
        l_password_eye_closed_button.config(command=lambda: self.show_hide_password(l_password_entry, l_password_eye_opened_button,
                                                                                    l_password_eye_closed_button, l_password_visibility))
        l_password_eye_opened_button.config(command=lambda: self.show_hide_password(l_password_entry, l_password_eye_opened_button,
                                                                                    l_password_eye_closed_button, l_password_visibility))
        l_password_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', l_password_entry, l_password_visibility))
        l_password_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', l_password_entry, 'Enter Your Password'))
        l_password_entry.bind('<Return>', lambda event: login())

        # Remember Me checkbox
        remember_me_var = tk.BooleanVar()
        remember_me_checkbox = tk.Checkbutton(
            self.frame,
            text='Remember Me',
            variable=remember_me_var,
            font=('Open Sans', 10),
            bg='white',
            fg='#333333',
            activebackground='white',
            activeforeground='#333333',
            selectcolor='white'
        )
        remember_me_checkbox.place(x=625, y=373)

        l_login_button = ttk.Button(self.frame, text='Login', style='small_green.TButton', cursor='hand2', width=20, padding=5,
                                    command=lambda: login())
        l_login_button.place(x=690, y=426)
        l_validate_login_label = tk.Label(self.frame, text='', bg='white', fg='red', font=('Open Sans', 8), anchor='center',
                                          width=32)
        l_validate_login_label.place(x=689, y=406)

        l_forgot_password_grey_button = ttk.Button(self.frame, text='Forgot Password', style='grey_word.TButton', cursor='hand2',
                                                   width=15, command=lambda: self.show_forgot_password())
        l_forgot_password_grey_button.place(x=725, y=461)

        l_text3 = tk.Label(self.frame, text='Don\'t have an account?', bg='#08D5A7', fg='#333333', font=('Rubik', 8, 'bold'))
        l_text3.place(x=810, y=570)
        l_register_as_black_button = ttk.Button(self.frame, text='Register', style='black_word.TButton', cursor='hand2', width=8,
                                                command=lambda: self.show_register_as())
        l_register_as_black_button.place(x=940, y=565)

    # Set up forgot password page with respective widgets
    def show_forgot_password(self):
        # Validate the requirements for successful update password
        def update_password():
            # Remove focus from all entries
            self.window.focus_set()

            # Ensure email, new password and confirmation of new password have been entered
            if fp_email_entry.cget('fg') == '#333333'\
                    and fp_password_entry.cget('fg') == '#333333' and fp_confirmed_entry.cget('fg') == '#333333':
                user_email = fp_email_entry.get().lower()
                                new_password = fp_password_entry.get()
                confirm_password = fp_confirmed_entry.get()
                
                # Basic validation
                if not user_email.endswith('@gmail.com'):
                    fp_validate_update_label.config(text='Invalid Email Format')
                    return
                
                if len(new_password) < 8:
                    fp_validate_update_label.config(text='Minimum 8 characters of Password')
                    return
                
                if new_password != confirm_password:
                    fp_validate_update_label.config(text='Password does not match')
                    return
                
                # Call forgot password API
                try:
                    response = requests.post(
                        FORGOT_PASSWORD_URL,
                        json={
                            'email': user_email,
                            'new_password': new_password,
                            'confirm_password': confirm_password
                        },
                        timeout=5
                    )
                    
                    if response.status_code == 200:
                        # Password reset successful
                        fp_validate_update_label.config(text='')
                                messagebox.showinfo("Success", 'Password updated successfully')
                        # Direct user back to login page
                                self.show_login()
                            else:
                        # Handle error response
                        try:
                            data = response.json()
                            error_message = data.get('message', 'Password reset failed')
                            fp_validate_update_label.config(text=error_message)
                        except:
                            if response.status_code == 429:
                                fp_validate_update_label.config(text='Too many requests. Please try again later.')
                            elif response.status_code == 403:
                                fp_validate_update_label.config(text='IP blocked. Please contact admin.')
                            elif response.status_code == 404:
                        fp_validate_update_label.config(text='Email does not exist')
                else:
                                fp_validate_update_label.config(text='Password reset failed. Please try again.')
                except requests.exceptions.RequestException as e:
                    fp_validate_update_label.config(text='Network error. Please check your connection.')
                    print(f"[ERROR] Forgot password API call failed: {e}")
                except Exception as e:
                    fp_validate_update_label.config(text='Password reset failed. Please try again.')
                    print(f"[ERROR] Forgot password error: {e}")
            else:
                fp_validate_update_label.config(text='Please fill in all the details')

        self.reset()
        fp_background_label = tk.Label(self.frame, image=self.lfr_background)
        fp_background_label.pack()

        fp_text1 = tk.Label(self.frame, text='Forgot Password', font=('Open Sans', 30, 'bold'), bg='white', fg='#333333')
        fp_text1.place(x=620, y=35)

        fp_email_label = tk.Label(self.frame, text='Email', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        fp_email_label.place(x=620, y=135)
        fp_email_entry_frame = tk.Frame(self.frame, bg='#F5F5F5', width=320, height=45, highlightbackground="#C8C7C7",
                                        highlightthickness=0.5)
        fp_email_entry_frame.place(x=625, y=165)
        fp_email_entry = tk.Entry(fp_email_entry_frame, font=('Open Sans', 10), bg='#F5F5F5', fg='#858585', border=0, width=35)
        fp_email_entry.place(x=10, y=12)
        fp_email_entry.insert(0, 'Enter Your Email')
        fp_email_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', fp_email_entry))
        fp_email_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', fp_email_entry, 'Enter Your Email'))
        fp_email_entry.bind('<Return>', lambda event: update_password())

        fp_password_label = tk.Label(self.frame, text='New Password', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        fp_password_label.place(x=620, y=230)
        fp_password_entry_frame = tk.Frame(self.frame, bg='#F5F5F5', width=320, height=45, highlightbackground="#C8C7C7",
                                           highlightthickness=0.5)
        fp_password_entry_frame.place(x=625, y=260)
        fp_password_entry = tk.Entry(fp_password_entry_frame, font=('Open Sans', 10), bg='#F5F5F5', fg='#858585', border=0, width=35,
                                     show='')
        fp_password_entry.place(x=10, y=12)
        fp_password_entry.insert(0, 'Enter New Password')
        fp_password_eye_closed_button = ttk.Button(fp_password_entry_frame, style='eye_closed_grey.TButton', cursor='hand2')
        fp_password_eye_closed_button.place(x=270, y=2)
        fp_password_eye_opened_button = ttk.Button(fp_password_entry_frame, style='eye_opened_grey.TButton', cursor='hand2')
        fp_password_visibility = tk.Label(fp_password_entry_frame, text='Close')
        fp_password_eye_closed_button.config(command=lambda: self.show_hide_password(fp_password_entry, fp_password_eye_opened_button,
                                                                                     fp_password_eye_closed_button,
                                                                                     fp_password_visibility))
        fp_password_eye_opened_button.config(command=lambda: self.show_hide_password(fp_password_entry, fp_password_eye_opened_button,
                                                                                     fp_password_eye_closed_button,
                                                                                     fp_password_visibility))
        fp_password_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', fp_password_entry, fp_password_visibility))
        fp_password_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', fp_password_entry, 'Enter New Password'))
        fp_password_entry.bind('<Return>', lambda event: update_password())

        fp_confirmed_label = tk.Label(self.frame, text='Re-enter New Password', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        fp_confirmed_label.place(x=620, y=325)
        fp_confirmed_entry_frame = tk.Frame(self.frame, bg='#F5F5F5', width=320, height=45, highlightbackground="#C8C7C7",
                                            highlightthickness=0.5)
        fp_confirmed_entry_frame.place(x=625, y=355)
        fp_confirmed_entry = tk.Entry(fp_confirmed_entry_frame, font=('Open Sans', 10), bg='#F5F5F5', fg='#858585', border=0, width=35,
                                      show='')
        fp_confirmed_entry.place(x=10, y=12)
        fp_confirmed_entry.insert(0, 'Re-enter New Password')
        fp_confirmed_eye_closed_button = ttk.Button(fp_confirmed_entry_frame, style='eye_closed_grey.TButton', cursor='hand2')
        fp_confirmed_eye_closed_button.place(x=270, y=2)
        fp_confirmed_eye_opened_button = ttk.Button(fp_confirmed_entry_frame, style='eye_opened_grey.TButton', cursor='hand2')
        fp_confirmed_visibility = tk.Label(fp_confirmed_entry_frame, text='Close')
        fp_confirmed_eye_closed_button.config(command=lambda: self.show_hide_password(fp_confirmed_entry, fp_confirmed_eye_opened_button,
                                                                                      fp_confirmed_eye_closed_button,
                                                                                      fp_confirmed_visibility))
        fp_confirmed_eye_opened_button.config(command=lambda: self.show_hide_password(fp_confirmed_entry, fp_confirmed_eye_opened_button,
                                                                                      fp_confirmed_eye_closed_button,
                                                                                      fp_confirmed_visibility))
        fp_confirmed_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', fp_confirmed_entry, fp_confirmed_visibility))
        fp_confirmed_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', fp_confirmed_entry,
                                                                                   'Re-enter New Password'))
        fp_confirmed_entry.bind('<Return>', lambda event: update_password())

        fp_back_button = ttk.Button(self.frame, text='Back', style='small_green.TButton', cursor='hand2', width=20, padding=5,
                                    command=lambda: self.show_login())
        fp_back_button.place(x=690, y=440)
        fp_update_pass_button = ttk.Button(self.frame, text='Update Password', style='small_green.TButton', cursor='hand2', width=20,
                                           padding=5, command=lambda: update_password())
        fp_update_pass_button.place(x=690, y=490)
        fp_validate_update_label = tk.Label(self.frame, text='', font=('Open Sans', 8), bg='white', fg='red', anchor='center', width=32)
        fp_validate_update_label.place(x=689, y=419)

        fp_text3 = tk.Label(self.frame, text='Don\'t have an account?', bg='#08D5A7', fg='#333333', font=('Rubik', 8, 'bold'))
        fp_text3.place(x=810, y=570)
        fp_register_as_black_button = ttk.Button(self.frame, text='Register', style='black_word.TButton', cursor='hand2', width=8,
                                                 command=lambda: self.show_register_as())
        fp_register_as_black_button.place(x=940, y=565)

    # Set up the page for registering a normal user account (patient) with respective widgets
    def show_registering_user(self):
        # Validate the requirements for successful register a normal user account (patient)
        def register_user():
            # Remove focus from all entries
            self.window.focus_set()

            # Ensure all entries filled
            if ru_name_entry.cget('fg') == '#333333' and ru_ic_passport_entry.cget('fg') == '#333333' \
                    and ru_gender_entry.cget('fg') == '#333333' and ru_address_entry.cget('fg') == '#333333' \
                    and ru_contact_entry.cget('fg') == '#333333' and ru_email_entry.cget('fg') == '#333333' \
                    and ru_password_entry.cget('fg') == '#333333' and ru_confirmed_entry.cget('fg') == '#333333':
                user_email = ru_email_entry.get().lower()
                user_password = ru_password_entry.get()
                user_name = ru_name_entry.get()
                user_ic_passport = ru_ic_passport_entry.get()
                user_gender = ru_gender_entry.cget('text')
                user_address = ru_address_entry.get('1.0', 'end').strip()
                user_contact = ru_contact_entry.get()
                
                # Basic validation
                if not user_email.endswith('@gmail.com'):
                    ru_validate_register_label.config(text='Invalid email format')
                    return
                
                if len(user_password) < 8:
                    ru_validate_register_label.config(text='Minimum 8 character of Password')
                    return
                
                if user_password != ru_confirmed_entry.get():
                    ru_validate_register_label.config(text='Password does not match')
                    return
                
                # Validate gender (should not be "Select Your Gender")
                if user_gender == 'Select Your Gender' or user_gender == 'Clear':
                    ru_validate_register_label.config(text='Please select a gender')
                    return
                
                # Call registration API
                try:
                    response = requests.post(
                        REGISTER_URL,
                        json={
                            'email': user_email,
                            'password': user_password,
                            'name': user_name,
                            'ic_passport': user_ic_passport,
                            'gender': user_gender,
                            'address': user_address,
                            'contact': user_contact
                        },
                        timeout=5
                    )
                    
                    if response.status_code == 201:
                        # Registration successful
                                ru_validate_register_label.config(text='')
                                    messagebox.showinfo('Success', 'Register User Account Successfully')
                        # Direct user to login page
                                    self.show_login()
                            else:
                        # Handle error response
                        try:
                            data = response.json()
                            error_message = data.get('message', 'Registration failed')
                            ru_validate_register_label.config(text=error_message)
                        except:
                            if response.status_code == 429:
                                ru_validate_register_label.config(text='Too many requests. Please try again later.')
                            elif response.status_code == 403:
                                ru_validate_register_label.config(text='IP blocked. Please contact admin.')
                        else:
                                ru_validate_register_label.config(text='Registration failed. Please try again.')
                except requests.exceptions.RequestException as e:
                    ru_validate_register_label.config(text='Network error. Please check your connection.')
                    print(f"[ERROR] Registration API call failed: {e}")
                except Exception as e:
                    ru_validate_register_label.config(text='Registration failed. Please try again.')
                    print(f"[ERROR] Registration error: {e}")
            else:
                ru_validate_register_label.config(text='Please fill in all the details')

        self.reset()

        ru_text1 = tk.Label(self.frame, text='Register User Account', font=('Open Sans', 30, 'bold'), bg='white', fg='#333333')
        ru_text1.place(x=30, y=20)

        ru_name_label = tk.Label(self.frame, text='Name', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        ru_name_label.place(x=120, y=100)
        ru_name_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                       highlightthickness=0.5)
        ru_name_entry_frame.place(x=125, y=130)
        ru_name_entry = tk.Entry(ru_name_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35)
        ru_name_entry.place(x=10, y=12)
        ru_name_entry.insert(0, 'Enter Your Name')
        ru_name_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', ru_name_entry))
        ru_name_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', ru_name_entry, 'Enter Your Name'))
        ru_name_entry.bind('<Return>', lambda event: register_user())

        ru_ic_passport_label = tk.Label(self.frame, text='IC or Passport Number', font=('Open Sans', 12, 'bold'), bg='white',
                                        fg='#000000')
        ru_ic_passport_label.place(x=120, y=190)
        ru_ic_passport_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                              highlightthickness=0.5)
        ru_ic_passport_entry_frame.place(x=125, y=220)
        ru_ic_passport_entry = tk.Entry(ru_ic_passport_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                        width=35)
        ru_ic_passport_entry.place(x=10, y=12)
        ru_ic_passport_entry.insert(0, 'Enter Your IC or Passport Number')
        ru_ic_passport_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', ru_ic_passport_entry))
        ru_ic_passport_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', ru_ic_passport_entry,
                                                                                     'Enter Your IC or Passport Number'))
        ru_ic_passport_entry.bind('<Return>', lambda event: register_user())

        ru_gender_label = tk.Label(self.frame, text='Gender', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        ru_gender_label.place(x=120, y=280)
        ru_gender_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                         highlightthickness=0.5)
        ru_gender_entry_frame.place(x=125, y=310)
        ru_gender_entry = tk.Label(ru_gender_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
        ru_gender_entry.place(x=8, y=10)
        ru_gender_entry.config(text='Select Your Gender')
        ru_gender_button = ttk.Button(ru_gender_entry_frame, text='▼', style='selection.TButton', width=4, cursor='hand2',
                                      command=lambda: self.display_menu(ru_gender_entry_frame, 1, 40, ru_gender_menu))
        ru_gender_button.place(x=265, y=5)
        ru_gender_menu = tk.Menu(self.frame, tearoff=0, bg='#D0F9EF', fg='#333333', font=('Open Sans', 10))
        ru_gender_menu.add_command(label="Male", command=lambda: self.select_menu_option(ru_gender_entry, 'Male'))
        ru_gender_menu.add_command(label="Female", command=lambda: self.select_menu_option(ru_gender_entry, 'Female'))
        ru_gender_menu.add_separator()
        ru_gender_menu.add_command(label="Clear", command=lambda: self.select_menu_option(ru_gender_entry, 'Clear',
                                                                                          'Select Your Gender'))
        ru_gender_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ", command=ru_gender_menu.unpost)

        ru_address_label = tk.Label(self.frame, text='Address', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        ru_address_label.place(x=120, y=370)
        ru_address_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=85, highlightbackground="#C8C7C7",
                                          highlightthickness=0.5)
        ru_address_entry_frame.place(x=125, y=400)
        ru_address_entry = tk.Text(ru_address_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35,
                                   height=4, wrap='word')
        ru_address_entry.place(x=10, y=10)
        ru_address_entry.insert('1.0', 'Enter Your Address')
        ru_address_entry.bind('<FocusIn>', lambda event: self.focus_entry('text', ru_address_entry))
        ru_address_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('text', ru_address_entry, 'Enter Your Address'))
        ru_address_entry.bind('<Return>', lambda event: register_user())

        ru_contact_label = tk.Label(self.frame, text='Contact Number', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        ru_contact_label.place(x=590, y=100)
        ru_contact_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                          highlightthickness=0.5)
        ru_contact_entry_frame.place(x=595, y=130)
        ru_contact_entry = tk.Entry(ru_contact_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35)
        ru_contact_entry.place(x=10, y=12)
        ru_contact_entry.insert(0, 'Enter Your Contact Number')
        ru_contact_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', ru_contact_entry))
        ru_contact_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', ru_contact_entry, 'Enter Your Contact Number'))
        ru_contact_entry.bind('<Return>', lambda event: register_user())

        ru_email_label = tk.Label(self.frame, text='Email', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        ru_email_label.place(x=590, y=190)
        ru_email_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                        highlightthickness=0.5)
        ru_email_entry_frame.place(x=595, y=220)
        ru_email_entry = tk.Entry(ru_email_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35)
        ru_email_entry.place(x=10, y=12)
        ru_email_entry.insert(0, 'Enter Your Email')
        ru_email_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', ru_email_entry))
        ru_email_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', ru_email_entry, 'Enter Your Email'))
        ru_email_entry.bind('<Return>', lambda event: register_user())

        ru_password_label = tk.Label(self.frame, text='Password', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        ru_password_label.place(x=590, y=280)
        ru_password_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                           highlightthickness=0.5)
        ru_password_entry_frame.place(x=595, y=310)
        ru_password_entry = tk.Entry(ru_password_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35,
                                     show='')
        ru_password_entry.place(x=10, y=12)
        ru_password_entry.insert(0, 'Enter Your Password')
        ru_password_eye_closed_button = ttk.Button(ru_password_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
        ru_password_eye_closed_button.place(x=270, y=2)
        ru_password_eye_opened_button = ttk.Button(ru_password_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
        ru_password_visibility = tk.Label(ru_password_entry_frame, text='Close')
        ru_password_eye_closed_button.config(command=lambda: self.show_hide_password(ru_password_entry, ru_password_eye_opened_button,
                                                                                     ru_password_eye_closed_button,
                                                                                     ru_password_visibility))
        ru_password_eye_opened_button.config(command=lambda: self.show_hide_password(ru_password_entry, ru_password_eye_opened_button,
                                                                                     ru_password_eye_closed_button,
                                                                                     ru_password_visibility))
        ru_password_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', ru_password_entry, ru_password_visibility))
        ru_password_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', ru_password_entry, 'Enter Your Password'))
        ru_password_entry.bind('<Return>', lambda event: register_user())

        ru_confirmed_label = tk.Label(self.frame, text='Confirm Password', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        ru_confirmed_label.place(x=590, y=370)
        ru_confirmed_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                            highlightthickness=0.5)
        ru_confirmed_entry_frame.place(x=595, y=400)
        ru_confirmed_entry = tk.Entry(ru_confirmed_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35,
                                      show='')
        ru_confirmed_entry.place(x=10, y=12)
        ru_confirmed_entry.insert(0, 'Re-enter Your Password')
        ru_confirmed_eye_closed_button = ttk.Button(ru_confirmed_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
        ru_confirmed_eye_closed_button.place(x=270, y=2)
        ru_confirmed_eye_opened_button = ttk.Button(ru_confirmed_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
        ru_confirmed_visibility = tk.Label(ru_confirmed_entry_frame, text='Close')
        ru_confirmed_eye_closed_button.config(command=lambda: self.show_hide_password(ru_confirmed_entry, ru_confirmed_eye_opened_button,
                                                                                      ru_confirmed_eye_closed_button,
                                                                                      ru_confirmed_visibility))
        ru_confirmed_eye_opened_button.config(command=lambda: self.show_hide_password(ru_confirmed_entry, ru_confirmed_eye_opened_button,
                                                                                      ru_confirmed_eye_closed_button,
                                                                                      ru_confirmed_visibility))
        ru_confirmed_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', ru_confirmed_entry, ru_confirmed_visibility))
        ru_confirmed_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', ru_confirmed_entry,
                                                                                   'Re-enter Your Password'))
        ru_confirmed_entry.bind('<Return>', lambda event: register_user())

        ru_back_button = ttk.Button(self.frame, text='Back', style='small_green.TButton', cursor='hand2', width=15, padding=8,
                                    command=lambda: self.show_register_as())
        ru_back_button.place(x=40, y=530)

        ru_register_button = ttk.Button(self.frame, text='Register', style='small_green.TButton', cursor='hand2', width=15, padding=8,
                                        command=lambda: register_user())
        ru_register_button.place(x=850, y=530)
        ru_validate_register_label = tk.Label(self.frame, text='', font=('Open Sans', 8), anchor='center', width=30, bg='white', fg='red')
        ru_validate_register_label.place(x=835, y=509)

    # Set up the page for registering clinic account with respective widgets
    def show_registering_clinic(self):
        # Validate the requirements for successful register a clinic account
        def register_clinic():
            # Remove focus from all entries
            self.window.focus_set()

            # Ensure all information are filled
            if rc_name_entry.cget('fg') == '#333333' and rc_operation_entry.cget('fg') == '#333333' \
                    and rc_address_entry.cget('fg') == '#333333' and rc_describe_entry.cget('fg') == '#333333' \
                    and rc_contact_entry.cget('fg') == '#333333' and rc_image_entry.cget('fg') == '#333333' \
                    and rc_email_entry.cget('fg') == '#333333' and rc_password_entry.cget('fg') == '#333333' \
                    and rc_confirmed_entry.cget('fg') == '#333333':
                # Obtain the image data
                img = self.image_var
                # Ensure the image format
                if img.lower().endswith(('.jpg', '.jpeg', '.png')):
                    with open(img, 'rb') as file:
                        img_binary_data = file.read()
                    clinic_email = rc_email_entry.get().lower()
                    if clinic_email.endswith('@gmail.com'):
                        # Check for if any existing email
                        cursor.execute('''SELECT user_email FROM user WHERE user_email=%s''', (clinic_email, ))
                        existing_email = cursor.fetchone()
                        if not existing_email:
                            if len(rc_password_entry.get()) >= 8:
                                if rc_password_entry.get() == rc_confirmed_entry.get():
                                    rc_validate_register_label.config(text='')
                                    cursor.execute('''INSERT INTO user (user_email, user_password, user_type) VALUES (%s, %s, %s)''',
                                                   (clinic_email, rc_password_entry.get(), 'clinic'))
                                    database.commit()
                                    cursor.execute('''SELECT user_id FROM user WHERE user_email=%s''', (clinic_email,))
                                    user_id = cursor.fetchone()
                                    if user_id:
                                        # clinic_status is 0 because need to wait for project admin approval
                                        cursor.execute('''INSERT INTO clinic (clinic_name, clinic_operation, clinic_address, 
                                                       clinic_description, clinic_contact, clinic_image, clinic_status, user_id) 
                                                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)''',
                                                       (rc_name_entry.get(), rc_operation_entry.get(), rc_address_entry.get('1.0', 'end'),
                                                        rc_describe_entry.get('1.0', 'end'), rc_contact_entry.get(), img_binary_data,
                                                        0, user_id[0]))
                                        database.commit()
                                        cursor.execute('''SELECT clinic_id FROM clinic WHERE user_id=%s''', (user_id[0], ))
                                        clinic_id = cursor.fetchone()
                                        # The join request is submitted to the project admin
                                        cursor.execute('''INSERT INTO clinic_request (cr_type, cr_reason, cr_datetime, cr_detail, 
                                                       cr_ifreject, cr_status, clinic_id) 
                                                       VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                                                       ('join', 'new registered', datetime.now(), None, None, 'pending',
                                                        clinic_id[0]))
                                        database.commit()
                                        messagebox.showinfo('Success', 'Register Clinic Account Successfully')
                                        # Directed to the login page
                                        self.show_login()
                                else:
                                    rc_validate_register_label.config(text='Password does not match')
                            else:
                                rc_validate_register_label.config(text='Minimum 8 characters of Password')
                        else:
                            rc_validate_register_label.config(text='Email exists, please try another')
                    else:
                        rc_validate_register_label.config(text='Invalid email format')
                else:
                    rc_validate_register_label.config(text='Invalid image format')
            else:
                rc_validate_register_label.config(text='Please fill in all the details')

        self.reset()

        rc_text1 = tk.Label(self.frame, text='Register Clinic Account', font=('Open Sans', 30, 'bold'), bg='white', fg='#333333')
        rc_text1.place(x=30, y=20)

        rc_name_label = tk.Label(self.frame, text='Clinic Name', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_name_label.place(x=120, y=90)
        rc_name_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                       highlightthickness=0.5)
        rc_name_entry_frame.place(x=125, y=115)
        rc_name_entry = tk.Entry(rc_name_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35)
        rc_name_entry.place(x=10, y=12)
        rc_name_entry.insert(0, 'Enter Clinic Name')
        rc_name_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', rc_name_entry))
        rc_name_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', rc_name_entry, 'Enter Clinic Name'))
        rc_name_entry.bind('<Return>', lambda event: register_clinic())

        rc_operation_label = tk.Label(self.frame, text='Operation Hours', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_operation_label.place(x=120, y=170)
        rc_operation_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                            highlightthickness=0.5)
        rc_operation_entry_frame.place(x=125, y=195)
        rc_operation_entry = tk.Entry(rc_operation_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                      width=35)
        rc_operation_entry.place(x=10, y=12)
        rc_operation_entry.insert(0, 'Enter Operation Hours')
        rc_operation_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', rc_operation_entry))
        rc_operation_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', rc_operation_entry, 'Enter Operation Hours'))
        rc_operation_entry.bind('<Return>', lambda event: register_clinic())

        rc_address_label = tk.Label(self.frame, text='Address', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_address_label.place(x=120, y=250)
        rc_address_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=85, highlightbackground="#C8C7C7",
                                          highlightthickness=0.5)
        rc_address_entry_frame.place(x=125, y=275)
        rc_address_entry = tk.Text(rc_address_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=36,
                                   height=4, wrap='word')
        rc_address_entry.place(x=10, y=10)
        rc_address_entry.insert('1.0', 'Enter Clinic Address')
        rc_address_entry.bind('<FocusIn>', lambda event: self.focus_entry('text', rc_address_entry))
        rc_address_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('text', rc_address_entry, 'Enter Clinic Address'))
        rc_address_entry.bind('<Return>', lambda event: register_clinic())

        rc_describe_label = tk.Label(self.frame, text='Short Description', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_describe_label.place(x=120, y=370)
        rc_describe_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=85, highlightbackground="#C8C7C7",
                                           highlightthickness=0.5)
        rc_describe_entry_frame.place(x=125, y=395)
        rc_describe_entry = tk.Text(rc_describe_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35,
                                    height=4, wrap='word')
        rc_describe_entry.place(x=10, y=10)
        rc_describe_entry.insert('1.0', 'Enter Short Description')
        rc_describe_entry.bind('<FocusIn>', lambda event: self.focus_entry('text', rc_describe_entry))
        rc_describe_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('text', rc_describe_entry, 'Enter Short Description'))
        rc_describe_entry.bind('<Return>', lambda event: register_clinic())

        rc_contact_label = tk.Label(self.frame, text='Contact Number', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_contact_label.place(x=590, y=90)
        rc_contact_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                          highlightthickness=0.5)
        rc_contact_entry_frame.place(x=595, y=115)
        rc_contact_entry = tk.Entry(rc_contact_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35)
        rc_contact_entry.place(x=10, y=12)
        rc_contact_entry.insert(0, 'Enter Contact Number')
        rc_contact_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', rc_contact_entry))
        rc_contact_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', rc_contact_entry, 'Enter Contact Number'))
        rc_contact_entry.bind('<Return>', lambda event: register_clinic())

        rc_image_label = tk.Label(self.frame, text='Image', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_image_label.place(x=590, y=170)
        rc_image_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                        highlightthickness=0.5)
        rc_image_entry_frame.place(x=595, y=195)
        rc_image_entry = tk.Label(rc_image_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
        rc_image_entry.place(x=8, y=10)
        rc_image_entry.config(text='Upload Clinic Image')
        rc_image_button = ttk.Button(rc_image_entry_frame, text='⇫', style='selection.TButton', width=4, cursor='hand2',
                                     command=lambda: self.upload_image(rc_image_entry))
        rc_image_button.place(x=265, y=4)

        rc_email_label = tk.Label(self.frame, text='Email', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_email_label.place(x=590, y=250)
        rc_email_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                        highlightthickness=0.5)
        rc_email_entry_frame.place(x=595, y=275)
        rc_email_entry = tk.Entry(rc_email_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35)
        rc_email_entry.place(x=10, y=12)
        rc_email_entry.insert(0, 'Enter Your Email')
        rc_email_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', rc_email_entry))
        rc_email_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', rc_email_entry, 'Enter Your Email'))
        rc_email_entry.bind('<Return>', lambda event: register_clinic())

        rc_password_label = tk.Label(self.frame, text='Password', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_password_label.place(x=590, y=330)
        rc_password_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                           highlightthickness=0.5)
        rc_password_entry_frame.place(x=595, y=355)
        rc_password_entry = tk.Entry(rc_password_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35,
                                     show='')
        rc_password_entry.place(x=10, y=12)
        rc_password_entry.insert(0, 'Enter Your Password')
        rc_password_eye_closed_button = ttk.Button(rc_password_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
        rc_password_eye_closed_button.place(x=270, y=2)
        rc_password_eye_opened_button = ttk.Button(rc_password_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
        rc_password_visibility = tk.Label(rc_password_entry_frame, text='Close')
        rc_password_eye_closed_button.config(command=lambda: self.show_hide_password(rc_password_entry, rc_password_eye_opened_button,
                                                                                     rc_password_eye_closed_button,
                                                                                     rc_password_visibility))
        rc_password_eye_opened_button.config(command=lambda: self.show_hide_password(rc_password_entry, rc_password_eye_opened_button,
                                                                                     rc_password_eye_closed_button,
                                                                                     rc_password_visibility))
        rc_password_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', rc_password_entry, rc_password_visibility))
        rc_password_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', rc_password_entry, 'Enter Your Password'))
        rc_password_entry.bind('<Return>', lambda event: register_clinic())

        rc_confirmed_label = tk.Label(self.frame, text='Confirm Password', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        rc_confirmed_label.place(x=590, y=410)
        rc_confirmed_entry_frame = tk.Frame(self.frame, bg='#D0F9EF', width=320, height=45, highlightbackground="#C8C7C7",
                                            highlightthickness=0.5)
        rc_confirmed_entry_frame.place(x=595, y=435)
        rc_confirmed_entry = tk.Entry(rc_confirmed_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=35,
                                      show='')
        rc_confirmed_entry.place(x=10, y=12)
        rc_confirmed_entry.insert(0, 'Re-enter Your Password')
        rc_confirmed_eye_closed_button = ttk.Button(rc_confirmed_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
        rc_confirmed_eye_closed_button.place(x=270, y=2)
        rc_confirmed_eye_opened_button = ttk.Button(rc_confirmed_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
        rc_confirmed_visibility = tk.Label(rc_confirmed_entry_frame, text='Close')
        rc_confirmed_eye_closed_button.config(command=lambda: self.show_hide_password(rc_confirmed_entry, rc_confirmed_eye_opened_button,
                                                                                      rc_confirmed_eye_closed_button,
                                                                                      rc_confirmed_visibility))
        rc_confirmed_eye_opened_button.config(command=lambda: self.show_hide_password(rc_confirmed_entry, rc_confirmed_eye_opened_button,
                                                                                      rc_confirmed_eye_closed_button,
                                                                                      rc_confirmed_visibility))
        rc_confirmed_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', rc_confirmed_entry, rc_confirmed_visibility))
        rc_confirmed_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', rc_confirmed_entry,
                                                                                   'Re-enter Your Password'))
        rc_confirmed_entry.bind('<Return>', lambda event: register_clinic())

        rc_back_button = ttk.Button(self.frame, text='Back', style='small_green.TButton', cursor='hand2', width=15, padding=8,
                                    command=lambda: self.show_register_as())
        rc_back_button.place(x=40, y=530)
        rc_register_button = ttk.Button(self.frame, text='Register', style='small_green.TButton', cursor='hand2', width=15, padding=8,
                                        command=lambda: register_clinic())
        rc_register_button.place(x=850, y=530)
        rc_validate_register_label = tk.Label(self.frame, text='', font=('Open Sans', 8), anchor='center', width=30, bg='white', fg='red')
        rc_validate_register_label.place(x=835, y=509)

    # Show menu in predefined location
    def display_menu(self, frame, x, y, menu):
        root_x = frame.winfo_rootx()
        root_y = frame.winfo_rooty()
        adjusted_x = root_x + x
        adjusted_y = root_y + y

        menu.post(adjusted_x, adjusted_y)

    # Configure the text and font colour in both entry and text widgets when focusing on it based on current font colour
    # If it is a password entry, the visibility of password will be considered
    def focus_entry(self, entry_type, entry, visibility=None):
        if entry_type == 'entry':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
        elif entry_type == 'text':
            if entry.cget('fg') == '#858585':
                entry.delete('1.0', 'end')
                entry.config(fg='#333333')
        elif entry_type == 'password':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
                if visibility.cget('text') == 'Open':
                    entry.config(show='')
                elif visibility.cget('text') == 'Close':
                    entry.config(show='*')

    # Configure the text and font colour in both entry and text widgets when leaving focus from it based on input get
    # Re-enter the grey guidance text if no valid input
    # If it is a password entry, considered the show option
    def leave_focus_entry(self, entry_type, entry, text):
        if entry_type == 'entry':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585')
                entry.insert(0, text)
        elif entry_type == 'text':
            value = entry.get('1.0', 'end')
            if value.strip() == '':
                entry.delete('1.0', 'end')
                entry.config(fg='#858585')
                entry.insert('1.0', text)
        elif entry_type == 'password':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585', show='')
                entry.insert(0, text)

    # Function for showing and hiding password
    # Based on current visibility and font colour of entry
    def show_hide_password(self, entry, eye_open_button, eye_close_button, visibility):
        if visibility.cget('text') == 'Close' and entry.cget('fg') == '#858585':
            eye_open_button.place(x=270, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')
        elif visibility.cget('text') == 'Open' and entry.cget('fg') == '#858585':
            eye_open_button.place_forget()
            eye_close_button.place(x=270, y=2)
            entry.config(show='')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Open':
            eye_open_button.place_forget()
            eye_close_button.place(x=270, y=2)
            entry.config(show='*')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Close':
            eye_open_button.place(x=270, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')

    # Upon selecting an option in the menu, update the relevant label to show user's option
    def select_menu_option(self, label, option, text=None):
        if option == 'Clear':
            label.config(text=text, fg='#858585')
        else:
            label.config(text=option, fg='#333333')

    # Open a file window for the user to select clinic image
    def upload_image(self, label):
        img = filedialog.askopenfilename(initialdir="/gui/images", title="Select an Image",
                                         filetypes=(("JPEG files", "*.jpg;*.jpeg"), ("png files", "*.png"), ("all files", "*.*")))
        if img:
            img_name = os.path.basename(img)
            label.config(text=img_name, fg='#333333')
            self.image_var = img


class User:
    def __init__(self, main_window, login_register=None):
        self.root_window = main_window
        self.login_register = login_register  # Reference to LoginRegister instance
        self.user_id = None

        self.cursor = None

        self.window = tk.Toplevel(self.root_window)
        self.window.title('Call a Doctor')
        self.window.geometry('1050x600')
        icon = load_image('icon', 48, 48)
        self.window.iconphoto(False, icon)

        self.nf_icon = load_image('nf icon', 80, 70)
        self.search_button = load_image('search button', 18, 18)
        self.clear_search = load_image('clear search', 15, 15)
        self.eye_closed_image = load_image('eye closed', 24, 24)
        self.eye_opened_image = load_image('eye opened', 24, 24)

        # Dictionaries for storing id as keys and image data as values
        self.clinic_images = {}
        self.doctor_images = {}

        style = ttk.Style()
        style.theme_use('clam')

        style.configure('navigation.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        font=('Open Sans', 20, 'bold'))
        style.map('navigation.TButton', background=[('active', 'white')], foreground=[('active', '#77C7B5')])
        style.configure('back.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        font=('Open Sans', 18, 'bold'))
        style.map('back.TButton', background=[('active', 'white')], foreground=[('active', '#77C7B5')])
        style.configure('green_button.TButton', border=0, relief='flat', background='#7EE5CE', foreground='white',
                        font=('Open Sans', 14, 'bold'))
        style.map('green_button.TButton', background=[('active', '#77C7B5')])
        style.configure('selection.TButton', border=0, relief='flat', background='#D0F9EF', foreground='#3DAEC7',
                        font=('Rubik', 12, 'bold'))
        style.map('selection.TButton', background=[('active', '#D0F9EF')], foreground=[('active', '#0B8FAC')])
        style.configure('time.TButton', border=0, relief='flat', font=('Open Sans', 10), background='#B1FFEE',
                        foreground='#858585')
        style.map('time.TButton', background=[('disabled', '#FDD6D1'), ('active', '#B1FFEE')],
                  foreground=[('disabled', '#858585'), ('active', '#858585')])
        style.configure('selected_time.TButton', border=0, relief='flat', font=('Open Sans', 10), background='#7EE5CE',
                        foreground='#333333')
        style.map('selected_time.TButton', background=[('active', '#7EE5CE')], foreground=[('active', '#333333')])
        style.configure('eye_closed_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_closed_image)
        style.map('eye_closed_green.TButton', background=[('active', '#D0F9EF')])
        style.configure('eye_opened_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_opened_image)
        style.map('eye_opened_green.TButton', background=[('active', '#D0F9EF')])

        # Build up the navigation bar
        self.navigation_frame = tk.Frame(self.window, width=1050, height=90, bg='white')
        self.navigation_frame.pack()
        self.navigation_bar = tk.Frame(self.navigation_frame, height=5, bg='#166E82')

        nf_icon = tk.Label(self.navigation_frame, image=self.nf_icon, bg='white', cursor='hand2')
        nf_icon.place(x=10, y=10)
        nf_icon.bind('<Button-1>', lambda event: self.refresh())
        nf_name = tk.Label(self.navigation_frame, text='CaD', font=('Open Sans', 30, 'bold'), bg='white', fg='#166E82', cursor='hand2')
        nf_name.place(x=90, y=20)
        nf_name.bind('<Button-1>', lambda event: self.refresh())
        nf_clinic_button = ttk.Button(self.navigation_frame, text='Clinic', style='navigation.TButton', width=5,
                                      command=lambda: self.show_activity_frame(90, 567, self.clinic_frame))
        nf_clinic_button.place(x=565, y=30)
        nf_appointment_button = ttk.Button(self.navigation_frame, text='Appointment Request', style='navigation.TButton', width=20,
                                           command=lambda: self.show_activity_frame(315, 656, self.appointment_frame))
        nf_appointment_button.place(x=655, y=30)
        nf_me_button = ttk.Button(self.navigation_frame, text='Me', style='navigation.TButton', width=3,
                                  command=lambda: self.show_activity_frame(60, 976, self.me_frame))
        nf_me_button.place(x=975, y=30)

        # Create required main frames
        # The dictionaries are used to store the frame, canvas, scrollable frame within the main frames
        self.clinic_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_clinic_frames = {}

        self.appointment_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.current_status = 'Request'  # Default status
        self.all_appointment_frames = {}

        self.me_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_me_frame = {}

        # Determine the frame to be displayed upon a user login
        self.all_scrollable_frame = {}
        self.all_scrollable_frame[self.clinic_frame] = 1
        self.all_scrollable_frame[self.appointment_frame] = 0
        self.all_scrollable_frame[self.me_frame] = 0

    def logout(self):
        # Call handle_logout from LoginRegister if available (clears tokens and calls logout API)
        if self.login_register:
            self.login_register.handle_logout()
            return  # handle_logout will show login screen
        
        # Fallback: basic logout if login_register not available
        # Re-initialize all necessary variables, ready for next user
        self.user_id = None

        self.window.withdraw()
        self.root_window.deiconify()

        self.cursor.close()
        self.cursor = None
        self.current_status = 'Request'

        self.clinic_images = {}
        self.doctor_images = {}

        self.all_clinic_frames = {}
        self.all_appointment_frames = {}
        self.all_me_frame = {}

        self.all_scrollable_frame = {}
        self.all_scrollable_frame[self.clinic_frame] = 1
        self.all_scrollable_frame[self.appointment_frame] = 0
        self.all_scrollable_frame[self.me_frame] = 0

    def run(self, user_id):
        # Get the user_id of current user
        self.user_id = user_id

        self.cursor = database.cursor(dictionary=True)

        self.window.deiconify()
        self.refresh()

    # Refresh and update the contents in all the frames
    def refresh(self):
        cursor.execute('''UPDATE appointment_request ar
                       JOIN patient p ON ar.patient_id = p.patient_id
                       SET ar.ar_status = 'canceled'
                       WHERE CONCAT(ar.ar_date, ' ', ar.ar_time) < NOW()
                       AND ar.ar_status IN ('pending', 'ongoing')''')
        database.commit()

        self.set_up_appointment_frame()
        self.set_up_me_frame()
        self.set_up_clinic_frame()

        # Identify where the current user at
        if self.all_scrollable_frame[self.clinic_frame] == 1:
            self.show_activity_frame(90, 567, self.clinic_frame)
        elif self.all_scrollable_frame[self.appointment_frame] == 1:
            self.show_activity_frame(315, 656, self.appointment_frame)
        elif self.all_scrollable_frame[self.me_frame] == 1:
            self.show_activity_frame(60, 976, self.me_frame)

    # Pack the main frame as well as sub-frame correctly
    def show_activity_frame(self, bar_width, bar_x, frame):
        self.navigation_bar.config(width=bar_width)
        self.navigation_bar.place(x=bar_x, y=85)

        self.appointment_frame.pack_forget()
        self.me_frame.pack_forget()
        self.clinic_frame.pack_forget()

        frame.pack()
        frame.focus_set()

        # 1 means the user is currently in that frame
        key = list(self.all_scrollable_frame.keys())
        for k in key:
            if k == frame:
                self.all_scrollable_frame[k] = 1
            else:
                self.all_scrollable_frame[k] = 0

        # Determine the user is at which sub-frame
        if frame == self.clinic_frame:
            keys = list(self.all_clinic_frames.keys())
            for k in keys:
                active = self.all_clinic_frames[k][3]
                if active:
                    self.switch(k, self.all_clinic_frames)
        elif frame == self.appointment_frame:
            keys = list(self.all_appointment_frames.keys())
            for k in keys:
                active = self.all_appointment_frames[k][3]
                if active:
                    self.switch(k, self.all_appointment_frames)
        elif frame == self.me_frame:
            keys = list(self.all_me_frame.keys())
            for k in keys:
                active = self.all_me_frame[k][3]
                if active:
                    self.switch(k, self.all_me_frame)

    # Make sure the correct sub-frame is packed and the proper function of scrollbar within the correct canvas
    def switch(self, frame, frame_list):
        frames = list(frame_list.keys())
        for f in frames:
            if f == frame:
                frame_list[f][3] = 1
                frame_list[f][0].pack()
            else:
                frame_list[f][3] = 0
                frame_list[f][0].pack_forget()
        content = frame_list[frame][2]
        canvas = frame_list[frame][1]
        content.update_idletasks()
        # If no widget, the canvas cannot be scrolled
        if len(content.winfo_children()) == 0:
            canvas.configure(scrollregion=(0, 0, 0, 0))
        else:
            canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.bind_all("<MouseWheel>", lambda event: self.on_mouse_wheel(event, canvas))

    # Set up the clinic section
    def set_up_clinic_frame(self):
        # Remove the search keyword, move to the top of the list after reset the search
        def clear_search():
            search_entry.delete(0, tk.END)
            show_clinics()
            clinic_canvas.yview_moveto(0)

        # Move to the top of the list upon a new search
        def search():
            show_clinics()
            clinic_canvas.yview_moveto(0)

        # Based on the input in search entry, display corresponding results
        def show_clinics():
            self.leave_focus_entry('entry', search_entry, 'Search')
            clinics_frame.focus_set()
            for w in clinic_content_frame.winfo_children():
                w.destroy()

            # Determine whether there is a search keyword or not
            # Fetch active clinics only
            if search_entry.cget('fg') == '#858585':
                clear_search_button.place_forget()
                cursor.execute('''SELECT * FROM clinic WHERE clinic_status=%s ORDER BY clinic_name ASC''', (1, ))
                clinics = cursor.fetchall()
            elif search_entry.cget('fg') == '#333333':
                clear_search_button.place(x=170, y=8)
                search_query = search_entry.get().strip()
                # Find if any clinic's name and address partially match with the keyword
                cursor.execute('''SELECT * FROM clinic WHERE clinic_status=%s AND (clinic_name LIKE %s OR clinic_address LIKE %s)
                               ORDER BY clinic_name ASC''',
                               (1, '%'+search_query+'%', '%'+search_query+'%'))
                clinics = cursor.fetchall()

            x_value = 15
            count = 1
            if clinics:
                for clinic in clinics:
                    if count % 2 == 0:
                        y_value = 25
                    else:
                        y_value = 0

                    clinic_id = clinic[0]

                    image_stream = BytesIO(clinic[6])
                    img = Image.open(image_stream)
                    resized_img = img.resize((240, 200), Image.LANCZOS)
                    tk_image = ImageTk.PhotoImage(resized_img)
                    self.clinic_images[clinic_id] = tk_image

                    clinic_frame = tk.Frame(clinic_content_frame, height=200, width=1000, bg='white', highlightbackground='#166E82',
                                            highlightthickness=0.5, cursor='hand2')
                    clinic_frame.pack(padx=x_value, pady=y_value, fill='y', expand=True)

                    clinic_image = tk.Label(clinic_frame, image=self.clinic_images[clinic_id], bg='white')
                    clinic_image.grid(row=0, column=0, padx=20, pady=10, rowspan=4)
                    clinic_name = tk.Label(clinic_frame, text=clinic[1], font=('Open Sans', 20, 'bold'), bg='white', fg='#000000')
                    clinic_name.grid(row=0, column=1, sticky='w', columnspan=2, pady=(20, 10))
                    clinic_address_label = tk.Label(clinic_frame, text='Address: ', font=('Open Sans', 16), bg='white', fg='#000000')
                    clinic_address_label.grid(row=1, column=1, sticky='nw', pady=(0, 5))
                    clinic_address = tk.Label(clinic_frame, text=clinic[3].strip(), font=('Open Sans', 16), bg='white', fg='#000000',
                                              anchor='w', width=51, wraplength=620, justify='left')
                    clinic_address.grid(row=1, column=2, sticky='nw', pady=(0, 5))
                    clinic_operation_label = tk.Label(clinic_frame, text='Hours: ', font=('Open Sans', 16), bg='white',
                                                      fg='#000000')
                    clinic_operation_label.grid(row=2, column=1, sticky='w', pady=(0, 5))
                    clinic_operation = tk.Label(clinic_frame, text=clinic[2], font=('Open Sans', 16), bg='white', fg='#000000')
                    clinic_operation.grid(row=2, column=2, sticky='w', pady=(0, 5))
                    clinic_contact_label = tk.Label(clinic_frame, text='Contact: ', font=('Open Sans', 16),
                                                    bg='white', fg='#000000')
                    clinic_contact_label.grid(row=3, column=1, sticky='w', pady=(5, 20))
                    clinic_contact = tk.Label(clinic_frame, text=clinic[5], font=('Open Sans', 16), bg='white', fg='#000000')
                    clinic_contact.grid(row=3, column=2, sticky='w', pady=(5, 20))

                    clinic_frame.bind('<Button-1>', lambda event, c=clinic: show_new_detail(c))
                    for widgets in clinic_frame.winfo_children():
                        widgets.bind('<Button-1>', lambda event, c=clinic: show_new_detail(c))

                    count += 1

            self.switch('clinic', self.all_clinic_frames)

        # Ensure the user is at the top of the clinic information page when clicks on the clinic card frame
        def show_new_detail(c):
            show_detail(c)
            detail_canvas.yview_moveto(0)

        # Set up the clinic information page of selected clinic
        def show_detail(c):
            d_back_button.config(command=lambda: show_clinics())
            schedule_button.config(command=lambda: show_schedule(c))

            for w in detail_content_frame.winfo_children():
                w.destroy()

            clinic_id = c[0]
            clinic_frame = tk.Frame(detail_content_frame, height=200, width=1000, bg='white')
            clinic_frame.pack(padx=15, fill='y', expand=True)
            clinic_image = tk.Label(clinic_frame, image=self.clinic_images[clinic_id], bg='white')
            clinic_image.grid(row=0, column=0, padx=20, pady=10, rowspan=4)
            clinic_name = tk.Label(clinic_frame, text=c[1], font=('Open Sans', 20, 'bold'), bg='white', fg='#000000')
            clinic_name.grid(row=0, column=1, sticky='w', columnspan=2, pady=(20, 10))
            clinic_address_label = tk.Label(clinic_frame, text='Address: ', font=('Open Sans', 16), bg='white', fg='#000000')
            clinic_address_label.grid(row=1, column=1, sticky='nw', pady=(0, 5))
            clinic_address = tk.Label(clinic_frame, text=c[3].strip(), font=('Open Sans', 16), bg='white', fg='#000000',
                                      anchor='w', width=51, wraplength=620, justify='left')
            clinic_address.grid(row=1, column=2, sticky='nw', pady=(0, 5))
            clinic_operation_label = tk.Label(clinic_frame, text='Hours: ', font=('Open Sans', 16), bg='white',
                                              fg='#000000')
            clinic_operation_label.grid(row=2, column=1, sticky='w', pady=(0, 5))
            clinic_operation = tk.Label(clinic_frame, text=c[2], font=('Open Sans', 16), bg='white', fg='#000000')
            clinic_operation.grid(row=2, column=2, sticky='w', pady=(0, 5))
            clinic_contact_label = tk.Label(clinic_frame, text='Contact: ', font=('Open Sans', 16),
                                            bg='white', fg='#000000')
            clinic_contact_label.grid(row=3, column=1, sticky='w', pady=(5, 20))
            clinic_contact = tk.Label(clinic_frame, text=c[5], font=('Open Sans', 16), bg='white', fg='#000000')
            clinic_contact.grid(row=3, column=2, sticky='w', pady=(5, 20))
            clinic_describe = tk.Label(clinic_frame, text=c[4].strip(), font=('Open Sans', 12), bg='white', fg='#677294',
                                       anchor='w', wraplength=970, justify='left')
            clinic_describe.grid(row=4, column=0, columnspan=3, sticky='w', padx=20)

            doctors_frame = tk.Frame(detail_content_frame, width=1000, bg='white')
            doctors_frame.pack(pady=20, fill='y', expand=True)
            doctor_title = tk.Label(doctors_frame, text='Doctors', font=('Open Sans', 16, 'bold', 'underline'),
                                    bg='white', fg='#000000')
            doctor_title.pack(anchor='center', pady=10)
            # Fetch active doctors only
            cursor.execute('''SELECT * FROM doctor WHERE clinic_id=%s AND doctor_status=%s ORDER BY doctor_name''', (clinic_id, 1))
            doctors = cursor.fetchall()
            count = 1
            for doctor in doctors:
                if count % 2 == 0:
                    y_value = 10
                else:
                    y_value = 0

                doctor_frame = tk.Frame(doctors_frame, width=700, bg='white')
                doctor_frame.pack(pady=y_value, fill='y', expand=True)

                doctor_id = doctor[0]

                image_stream = BytesIO(doctor[9])
                img = Image.open(image_stream)
                resized_img = img.resize((120, 120), Image.LANCZOS)
                tk_image = ImageTk.PhotoImage(resized_img)
                self.doctor_images[doctor_id] = tk_image

                doctor_image = tk.Label(doctor_frame, image=self.doctor_images[doctor_id], bg='white')
                doctor_image.grid(row=0, column=0, rowspan=4, padx=5, pady=5)
                doctor_name = tk.Label(doctor_frame, text='Dr. '+doctor[1], font=('Open Sans', 14, 'bold'), bg='white', fg='#000000')
                doctor_name.grid(row=0, column=1, columnspan=2, sticky='w', pady=(5, 5))
                doctor_contact_label = tk.Label(doctor_frame, text='Contact: ', font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_contact_label.grid(row=1, column=1, sticky='w', pady=(0, 3))
                doctor_contact = tk.Label(doctor_frame, text=doctor[5], font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_contact.grid(row=1, column=2, sticky='w', pady=(0, 3))
                doctor_working_label = tk.Label(doctor_frame, text='Hours: ', font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_working_label.grid(row=2, column=1, sticky='w', pady=(0, 3))
                doctor_working = tk.Label(doctor_frame, text=doctor[6], font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_working.grid(row=2, column=2, sticky='w', pady=(0, 3))
                doctor_language_label = tk.Label(doctor_frame, text='Language: ', font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_language_label.grid(row=3, column=1, sticky='w', pady=(0, 5))
                languages = sorted(doctor[7].split(', '))
                doctor_language = tk.Label(doctor_frame, text=', '.join(languages), font=('Open Sans', 12), bg='white', fg='#000000',
                                           width=35, anchor='w')
                doctor_language.grid(row=3, column=2, sticky='w', pady=(0, 5))
                specializations = sorted(doctor[8].split(', '))
                doctor_specialize = tk.Label(doctor_frame, text='Specialize In\n'+'\n'.join([f"•{value}" for value in specializations]),
                                             font=('Open Sans', 12), bg='white', fg='#000000', anchor='e', width=20, justify='left')
                doctor_specialize.grid(row=1, column=3, rowspan=3, sticky='nw', padx=30, pady=(0, 5))

                count += 1

            self.switch('detail', self.all_clinic_frames)

        # Validate the requirements for successful schedule appointment
        def submit(c, d=None):
            schedule_frame.focus_set()
            if schedule_doctor.cget('fg') == '#333333' and schedule_date.cget('fg') == '#333333' \
                    and schedule_time.cget('fg') == '#333333':
                date = schedule_calendar.get_date()
                time = datetime.strptime(schedule_time.cget('text'), "%I%p").time()
                current = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute('''SELECT patient_id FROM patient WHERE user_id=%s''', (self.user_id, ))
                patient_id = cursor.fetchone()[0]
                # If a doctor is specified
                if d is not None:
                    if schedule_describe.cget('fg') == '#333333':
                        description = schedule_describe.get('1.0', 'end')
                    else:
                        description = None
                    # ar_doctor is 1 because the user has assigned a doctor
                    cursor.execute('''INSERT INTO appointment_request (ar_date, ar_time, ar_detail, ar_status, 
                                                       ar_doctor, ar_ifreject, ar_datetime, patient_id, clinic_id) 
                                                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                                   (date, time, description, 'pending', 1, None, current, patient_id, c[0]))
                    database.commit()
                    # Insert relevant data into appointment_request table so that the clinic admin no need to assign doctor again
                    cursor.execute('''SELECT ar_id FROM appointment_request WHERE ar_datetime=%s and patient_id=%s and clinic_id=%s''',
                                   (current, patient_id, c[0]))
                    ar_id = cursor.fetchone()[0]
                    cursor.execute('''INSERT INTO appointment (appointment_prescription, appointment_complete, ar_id, doctor_id) 
                                                       VALUES (%s, %s, %s, %s)''', (None, 0, ar_id, d[0]))
                    database.commit()
                else:
                    if schedule_describe.cget('fg') == '#333333':
                        description = schedule_describe.get('1.0', 'end')
                    else:
                        description = None
                    # ar_doctor is 0 because no doctor is assigned
                    # in this case, the clinic admin need to assign a doctor for this appointment afterward
                    cursor.execute('''INSERT INTO appointment_request (ar_date, ar_time, ar_detail, ar_status, 
                                                       ar_doctor, ar_ifreject, ar_datetime, patient_id, clinic_id) 
                                                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                                   (date, time, description, 'pending', 0, None, current, patient_id, c[0]))
                    database.commit()
                submit_error_label.config(text='')
                messagebox.showinfo('Success', 'Book Schedule Successfully')
                # Directed back to the clinic list page
                show_clinics()
            else:
                submit_error_label.config(text='Select all relevant details')

        # Verifies the validity of selected date for appointment
        # If valid, display the time section
        def select_day(except_day, c, d=None):
            schedule_frame.focus_set()
            schedule_time.config(text='Select a time', fg='#858585')
            schedule_time_label.grid_forget()
            schedule_time_frame.grid_forget()
            schedule_time_buttons.grid_forget()
            schedule_describe.delete('1.0', tk.END)
            self.leave_focus_entry('text', schedule_describe, 'Optional')
            schedule_describe_label.grid_forget()
            schedule_describe_frame.grid_forget()

            selected = schedule_calendar.get_date()
            current_date = datetime.now().date()
            selected_date = current_date.replace(year=int(selected.split('-')[0]),
                                                 month=int(selected.split('-')[1]),
                                                 day=int(selected.split('-')[2]))
            wd_dict = {0: 'Monday', 1: 'Tuesday', 2: 'Wednesday', 3: 'Thursday', 4: 'Friday', 5: 'Saturday', 6: 'Sunday'}
            if selected_date < current_date:
                schedule_date.config(fg='#8B0000', text='Selected date is passed')
            elif current_date <= selected_date <= current_date + timedelta(days=1):
                schedule_date.config(fg='#8B0000', text='Must be at least two days from now')
            else:
                if except_day['clinic'] != [] and selected_date.weekday() in except_day['clinic']:
                    schedule_date.config(fg='#8B0000', text='The clinic is closed on ' + wd_dict[selected_date.weekday()])
                elif except_day['doctor'] != [] and selected_date.weekday() in except_day['doctor']:
                    schedule_date.config(fg='#8B0000', text='The doctor is rest on ' + wd_dict[selected_date.weekday()])
                else:
                    schedule_date.config(fg='#333333', text=self.format_date(selected))
                    schedule_time_label.grid(row=3, column=1, sticky='w', pady=(0, 3), padx=110)
                    schedule_time_frame.grid(row=4, column=1, sticky='w', pady=(0, 3), padx=113)
                    schedule_time_buttons.grid(row=5, column=1, sticky='nw', pady=(3, 25), padx=113)
                    set_up_time_button(c, d)
                    submit_button.configure(command=lambda: submit(c, d))

            self.switch('schedule', self.all_clinic_frames)

        # Get the clinic and doctor rest day while displaying the date section
        def display_date_frame(text, c, d=None):
            self.select_menu_option(schedule_doctor, text)
            schedule_calendar.selection_clear()
            schedule_date.config(fg='#858585', text='Select a date')
            schedule_time.config(text='Select a time', fg='#858585')
            schedule_time_label.grid_forget()
            schedule_time_frame.grid_forget()
            schedule_time_buttons.grid_forget()
            schedule_describe.delete('1.0', tk.END)
            self.leave_focus_entry('text', schedule_describe, 'Optional')
            schedule_describe_label.grid_forget()
            schedule_describe_frame.grid_forget()

            schedule_date_label.grid(row=3, column=0, sticky='w', pady=(0, 3), padx=50)
            schedule_date_frame.grid(row=4, column=0, sticky='w', pady=(0, 3), padx=53)
            schedule_calendar.grid(row=5, column=0, sticky='w', pady=(3, 25), padx=53)

            except_days = {'Monday': 0, 'Tuesday': 1, 'Wednesday': 2, 'Thursday': 3, 'Friday': 4, 'Saturday': 5, 'Sunday': 6}
            close_rest_day = {'clinic': [],
                              'doctor': []}

            operation = c[2].split(', ')
            if len(operation) > 2:
                close_day = operation[2].split()[-1]
                close_day = except_days[close_day]
                close_rest_day['clinic'].append(close_day)
            if d is not None:
                working = d[6].split(', ')
                if len(working) > 2:
                    rest_day = working[2].split()[-1]
                    rest_day = except_days[rest_day]
                    close_rest_day['doctor'].append(rest_day)
            schedule_calendar.bind('<<CalendarSelected>>', lambda event: select_day(close_rest_day, c, d))

            self.switch('schedule', self.all_clinic_frames)

        # Configure the status and colour of the time buttons
        def set_up_time_button(c, d=None):
            for t in time_list:
                time_button_list[t][0].grid_forget()
                time_button_list[t][1] = -1
                time_button_list[t][0].state(['disabled'])
                time_button_list[t][0].config(style='time.TButton')
            time_format_12 = '%I%p'
            operation = c[2].split(', ')

            working = None
            if d is not None:
                working = d[6].split(', ')

            # working is not None means a doctor is specified
            if working and len(working) > 1:
                working_hour = working[1].split('-')
                start_work = working_hour[0].strip()
                start_work = datetime.strptime(start_work, time_format_12).time()
                end_work = working_hour[1].strip()
                # exclude the last hour
                end_work = datetime.strptime(end_work, time_format_12) - timedelta(hours=1)
                end_work = end_work.time()

                # Retrieve pending / ongoing appointments of the doctor on the selected date
                cursor.execute('''SELECT ar.ar_time FROM appointment_request ar
                                           JOIN appointment a ON ar.ar_id = a.ar_id
                                           WHERE a.doctor_id=%s AND ar.ar_date=%s AND ar.ar_status IN ('pending', 'ongoing')''',
                               (d[0], schedule_calendar.get_date()))
                booked_time = cursor.fetchall()
                booked_time_list = [self.timedelta_to_time(b_time[0]) for b_time in booked_time]

                row_value = 0
                column_value = 0
                for t in time_list:
                    datetime_t = datetime.strptime(t, time_format_12).time()
                    if start_work <= datetime_t <= end_work:
                        time_button_list[t][0].grid(row=row_value, column=column_value, padx=(0, 5), pady=(0, 5), sticky='nw')
                        column_value += 1
                        if column_value == 4:
                            column_value = 0
                            row_value += 1
                        if datetime_t not in booked_time_list:
                            time_button_list[t][1] = 0
                            time_button_list[t][0].state(['!disabled'])
            # Else the working hours is none, the time buttons will be organized based on clinic operation hours
            elif working and len(working) == 1:
                cursor.execute('''SELECT ar.ar_time FROM appointment_request ar
                               JOIN appointment a ON ar.ar_id = a.ar_id
                               WHERE a.doctor_id=%s AND ar.ar_date=%s AND ar.ar_status IN ('pending', 'ongoing')''',
                               (d[0], schedule_calendar.get_date()))
                booked_time = cursor.fetchall()
                booked_time_list = [self.timedelta_to_time(b_time[0]) for b_time in booked_time]

                if len(operation) > 1 and operation[1] != '24 hours':
                    operation_hour = operation[1].split('-')
                    start_operate = operation_hour[0].strip()
                    start_operate = datetime.strptime(start_operate, time_format_12).time()
                    end_operate = operation_hour[1].strip()
                    end_operate = datetime.strptime(end_operate, time_format_12) - timedelta(hours=1)
                    end_operate = end_operate.time()

                    row_value = 0
                    column_value = 0
                    for t in time_list:
                        datetime_t = datetime.strptime(t, time_format_12).time()
                        if start_operate <= datetime_t <= end_operate:
                            time_button_list[t][0].grid(row=row_value, column=column_value, padx=(0, 5), pady=(0, 5), sticky='nw')
                            column_value += 1
                            if column_value == 4:
                                column_value = 0
                                row_value += 1
                            if datetime_t not in booked_time_list:
                                time_button_list[t][1] = 0
                                time_button_list[t][0].state(['!disabled'])
                else:
                    row_value = 0
                    column_value = 0
                    for t in time_list:
                        datetime_t = datetime.strptime(t, time_format_12).time()
                        time_button_list[t][0].grid(row=row_value, column=column_value, padx=(0, 5), pady=(0, 5), sticky='nw')
                        column_value += 1
                        if column_value == 4:
                            column_value = 0
                            row_value += 1
                        if datetime_t not in booked_time_list:
                            time_button_list[t][1] = 0
                            time_button_list[t][0].state(['!disabled'])
            # If the user choose 'Random'
            elif len(operation) > 1 and operation[1] != '24 hours':
                operation_hour = operation[1].split('-')
                start_operate = operation_hour[0].strip()
                start_operate = datetime.strptime(start_operate, time_format_12).time()
                end_operate = operation_hour[1].strip()
                end_operate = datetime.strptime(end_operate, time_format_12) - timedelta(hours=1)
                end_operate = end_operate.time()

                row_value = 0
                column_value = 0
                for t in time_list:
                    datetime_t = datetime.strptime(t, time_format_12).time()
                    if start_operate <= datetime_t <= end_operate:
                        time_button_list[t][0].grid(row=row_value, column=column_value, padx=(0, 5), pady=(0, 5), sticky='nw')
                        column_value += 1
                        if column_value == 4:
                            column_value = 0
                            row_value += 1
                        time_button_list[t][1] = 0
                        time_button_list[t][0].state(['!disabled'])
            else:
                row_value = 0
                column_value = 0
                for t in time_list:
                    time_button_list[t][0].grid(row=row_value, column=column_value, padx=(0, 5), pady=(0, 5), sticky='nw')
                    column_value += 1
                    if column_value == 4:
                        column_value = 0
                        row_value += 1
                    time_button_list[t][1] = 0
                    time_button_list[t][0].state(['!disabled'])

        # Configure the time label and the appearance of time buttons (selected)
        # Display the description section
        def select_time(t_key):
            selected_time = t_key
            schedule_time.config(fg='#333333', text=selected_time)
            for t in time_list:
                if t != selected_time and time_button_list[t][1] == 1:
                    time_button_list[t][1] = 0
                    time_button_list[t][0].config(style='time.TButton')
            time_button_list[selected_time][1] = 1
            time_button_list[selected_time][0].config(style='selected_time.TButton')
            schedule_describe_label.grid(row=6, column=0, columnspan=2, sticky='w', pady=(0, 3), padx=50)
            schedule_describe_frame.grid(row=7, column=0, columnspan=2, sticky='w', pady=(0, 25), padx=53)
            self.switch('schedule', self.all_clinic_frames)

        # Set up the schedule appointment page
        def show_schedule(c):
            s_back_button.config(command=lambda: show_detail(c))
            submit_button.config(command=lambda: submit(c))

            schedule_clinic.config(text=c[1])

            schedule_doctor.config(text='Select a doctor', fg='#858585')
            doctor_menu.delete(0, tk.END)
            doctor_menu.add_command(label='Random', command=lambda: display_date_frame('Random', c, None))
            # Fetch active doctors only
            # Added into the menu as doctor selection
            cursor.execute('''SELECT * FROM doctor WHERE clinic_id=%s AND doctor_status=%s ORDER BY doctor_name''', (c[0], 1))
            doctors = cursor.fetchall()
            for doctor in doctors:
                doctor_name = "Dr. " + doctor[1]
                doctor_menu.add_command(label=doctor_name,
                                        command=lambda text=doctor_name, c=c, d=doctor: display_date_frame(text, c, d))
            doctor_menu.add_separator()
            doctor_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ", command=doctor_menu.unpost)

            schedule_date.config(text='Select a date', fg='#858585')
            schedule_date_label.grid_forget()
            schedule_date_frame.grid_forget()
            schedule_calendar.grid_forget()
            schedule_calendar.selection_clear()

            schedule_time.config(text='Select a time', fg='#858585')
            schedule_time_label.grid_forget()
            schedule_time_frame.grid_forget()
            schedule_time_buttons.grid_forget()

            schedule_describe.delete('1.0', tk.END)
            self.leave_focus_entry('text', schedule_describe, 'Optional')
            schedule_describe_label.grid_forget()
            schedule_describe_frame.grid_forget()

            submit_error_label.config(text='')

            self.switch('schedule', self.all_clinic_frames)
            schedule_canvas.yview_moveto(0)

        for widget in self.clinic_frame.winfo_children():
            widget.destroy()

        # Creation of sub-frame and some consistent widgets
        clinics_frame = tk.Frame(self.clinic_frame, width=1050, height=510, bg='white')
        search_frame = tk.Frame(clinics_frame, bg='#F5F5F5', width=230, height=35, highlightbackground="#C8C7C7",
                                highlightthickness=0.5)
        search_frame.place(x=785, y=15)
        search_entry = tk.Entry(search_frame, bg='#F5F5F5', font=('Roboto', 12), border=0, fg='#858585', width=16)
        search_entry.place(x=8, y=6)
        search_entry.insert(0, "Search")
        search_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', search_entry))
        search_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', search_entry, 'Search'))
        search_entry.bind('<Return>', lambda event: search())
        search_button = tk.Button(search_frame, bg='#F5F5F5', image=self.search_button, border=0, cursor='hand2',
                                  command=lambda: search())
        search_button.place(x=200, y=6)
        clear_search_button = tk.Button(search_frame, bg='#F5F5F5', image=self.clear_search, border=0, command=lambda: clear_search())
        clinic_canvas = tk.Canvas(clinics_frame, width=1030, height=430, bg='white', highlightthickness=0)
        clinic_canvas.place(x=0, y=75)
        clinic_scrollbar = tk.Scrollbar(clinics_frame, orient='vertical')
        clinic_scrollbar.place(x=1033, y=75, height=430)
        clinic_canvas.configure(yscrollcommand=clinic_scrollbar.set)
        clinic_scrollbar.configure(command=clinic_canvas.yview)
        clinic_content_frame = tk.Frame(clinic_canvas, bg='white')
        clinic_canvas.create_window((0, 0), window=clinic_content_frame, anchor="nw")
        self.all_clinic_frames['clinic'] = [clinics_frame, clinic_canvas, clinic_content_frame, 0]

        detail_frame = tk.Frame(self.clinic_frame, width=1050, height=510, bg='white')
        d_back_button = ttk.Button(detail_frame, text='< Back', style='back.TButton', cursor='hand2', width=6)
        d_back_button.place(x=20, y=15)
        schedule_button = ttk.Button(detail_frame, text='Schedule Appointment', cursor='hand2', style='green_button.TButton',
                                     width=26)
        schedule_button.place(x=720, y=18)
        detail_canvas = tk.Canvas(detail_frame, width=1030, height=430, bg='white', highlightthickness=0)
        detail_canvas.place(x=0, y=75)
        detail_scrollbar = tk.Scrollbar(detail_frame, orient='vertical')
        detail_scrollbar.place(x=1033, y=75, height=430)
        detail_canvas.configure(yscrollcommand=detail_scrollbar.set)
        detail_scrollbar.configure(command=detail_canvas.yview)
        detail_content_frame = tk.Frame(detail_canvas, bg='white')
        detail_canvas.create_window((0, 0), window=detail_content_frame, anchor="nw")
        self.all_clinic_frames['detail'] = [detail_frame, detail_canvas, detail_content_frame, 0]

        schedule_frame = tk.Frame(self.clinic_frame, width=1050, height=510, bg='white')
        s_back_button = ttk.Button(schedule_frame, text='< Back', style='back.TButton', cursor='hand2', width=6)
        s_back_button.place(x=20, y=15)
        submit_button = ttk.Button(schedule_frame, text='Submit', style='green_button.TButton', cursor='hand2', width=12)
        submit_button.place(x=874, y=18)
        submit_error_label = tk.Label(schedule_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        submit_error_label.place(x=680, y=27)
        schedule_canvas = tk.Canvas(schedule_frame, width=1030, height=430, bg='white', highlightthickness=0)
        schedule_canvas.place(x=0, y=75)
        schedule_scrollbar = tk.Scrollbar(schedule_frame, orient='vertical')
        schedule_scrollbar.place(x=1033, y=75, height=430)
        schedule_canvas.configure(yscrollcommand=schedule_scrollbar.set)
        schedule_scrollbar.configure(command=schedule_canvas.yview)
        schedule_content_frame = tk.Frame(schedule_canvas, bg='white')
        schedule_canvas.create_window((0, 0), window=schedule_content_frame, anchor="nw")
        self.all_clinic_frames['schedule'] = [schedule_frame, schedule_canvas, schedule_content_frame, 0]

        schedule_visit_label = tk.Label(schedule_content_frame, text='Schedule Visit', font=('Open Sans', 20, 'bold', 'underline'),
                                        bg='white', fg='#000000')
        schedule_visit_label.grid(row=0, column=0, columnspan=2, sticky='w', padx=50, pady=(10, 25))
        schedule_clinic_label = tk.Label(schedule_content_frame, text='Clinic', font=('Open Sans', 12, 'bold'),
                                         bg='white', fg='#000000')
        schedule_clinic_label.grid(row=1, column=0, sticky='w', pady=(0, 3), padx=50)
        schedule_clinic_frame = tk.Frame(schedule_content_frame, bg='#D0F9EF', width=380, height=45, highlightbackground='#C8C7C7',
                                         highlightthickness=0.5)
        schedule_clinic_frame.grid(row=2, column=0, sticky='w', pady=(0, 25), padx=53)
        schedule_clinic = tk.Label(schedule_clinic_frame, bg='#D0F9EF', fg='#333333', font=('Open Sans', 10))
        schedule_clinic.place(x=10, y=10)

        schedule_doctor_label = tk.Label(schedule_content_frame, text='Doctor', font=('Open Sans', 12, 'bold'),
                                         bg='white', fg='#000000')
        schedule_doctor_label.grid(row=1, column=1, sticky='w', pady=(0, 3), padx=110)
        schedule_doctor_frame = tk.Frame(schedule_content_frame, bg='#D0F9EF', width=380, height=45, highlightbackground='#C8C7C7',
                                         highlightthickness=0.5)
        schedule_doctor_frame.grid(row=2, column=1, sticky='w', pady=(0, 25), padx=113)
        schedule_doctor = tk.Label(schedule_doctor_frame, bg='#D0F9EF', font=('Open Sans', 10))
        schedule_doctor.place(x=10, y=10)
        schedule_doctor_button = ttk.Button(schedule_doctor_frame, text='▼', style='selection.TButton', width=4, cursor='hand2',
                                            command=lambda: self.display_menu(schedule_doctor_frame, 0, 40, doctor_menu))
        schedule_doctor_button.place(x=325, y=5)
        doctor_menu = tk.Menu(schedule_content_frame, tearoff=0, bg='#D0F9EF', fg='#333333', font=('Open Sans', 10))

        schedule_date_label = tk.Label(schedule_content_frame, text='Date', font=('Open Sans', 12, 'bold'),
                                       bg='white', fg='#000000')
        schedule_date_frame = tk.Frame(schedule_content_frame, bg='#D0F9EF', width=380, height=45, highlightbackground='#C8C7C7',
                                       highlightthickness=0.5)
        schedule_date = tk.Label(schedule_date_frame, bg='#D0F9EF', font=('Open Sans', 10))
        schedule_date.place(x=10, y=10)
        schedule_calendar = Calendar(schedule_content_frame, selectmode='day', date_pattern='yyyy-mm-dd', font=('Open Sans', 10))

        schedule_time_label = tk.Label(schedule_content_frame, text='Time', font=('Open Sans', 12, 'bold'),
                                       bg='white', fg='#000000')
        schedule_time_frame = tk.Frame(schedule_content_frame, bg='#D0F9EF', width=380, height=45, highlightbackground='#C8C7C7',
                                       highlightthickness=0.5)
        schedule_time = tk.Label(schedule_time_frame, bg='#D0F9EF', font=('Open Sans', 10))
        schedule_time.place(x=10, y=10)
        schedule_time_buttons = tk.Frame(schedule_content_frame, bg='white', width=380, height=200)
        time_button_list = {'8am': [], '9am': [], '10am': [],
                            '11am': [], '12pm': [], '1pm': [],
                            '2pm': [], '3pm': [], '4pm': [],
                            '5pm': [], '6pm': [], '7pm': [],
                            '8pm': []}
        time_list = time_button_list.keys()
        for time in time_list:
            time_button = ttk.Button(schedule_time_buttons, style='time.TButton', text=time, width=9, padding=10,
                                     command=lambda t_key=time: select_time(t_key))
            time_button.state(['disabled'])
            time_button_list[time].append(time_button)
            time_button_list[time].append(-1)

        schedule_describe_label = tk.Label(schedule_content_frame, text='Description', font=('Open Sans', 12, 'bold'),
                                           bg='white', fg='#000000')
        schedule_describe_frame = tk.Frame(schedule_content_frame, bg='#D0F9EF', width=928, height=150, highlightbackground='#C8C7C7',
                                           highlightthickness=0.5)
        schedule_describe = tk.Text(schedule_describe_frame, font=('Open Sans', 10), bg='#D0F9EF', border=0, width=128,
                                    height=8, wrap='word')
        schedule_describe.place(x=10, y=10)
        schedule_describe.bind('<FocusIn>', lambda event: self.focus_entry('text', schedule_describe))
        schedule_describe.bind('<FocusOut>', lambda event: self.leave_focus_entry('text', schedule_describe, 'Optional'))

        show_clinics()

    # Set up the appointment request section
    def set_up_appointment_frame(self):
        # Select a status to view corresponding appointments
        def filter_appointments(status):
            self.current_status = status
            display_appointments(status)
            update_tab_colors()
            a_canvas.yview_moveto(0)

        # Configure the colour of status tab button
        def update_tab_colors():
            for tab_button in tab_buttons:
                if tab_button.cget("text") == self.current_status:
                    tab_button.config(bg='#00C196', fg='white')
                else:
                    tab_button.config(bg='#E0FCF8', fg='#00C196')

        # Display appointments based on status
        def display_appointments(status):
            for widget in a_scrollable_frame.winfo_children():
                if isinstance(widget, tk.Frame):
                    widget.destroy()

            status_map = {
                'Request': 'pending',
                'Ongoing': 'ongoing',
                'Completed': 'completed',
                'Rejected': 'rejected',
                'Canceled': 'canceled'
            }

            query_asc = f"""
                        SELECT ar.ar_id, ar.ar_detail, ar.ar_date, ar.ar_time, ar.ar_doctor, 
                        ar.ar_ifreject, a.appointment_prescription,
                        c.clinic_name, d.doctor_name
                        FROM appointment_request ar
                        LEFT JOIN clinic c ON ar.clinic_id = c.clinic_id
                        LEFT JOIN appointment a ON ar.ar_id = a.ar_id
                        LEFT JOIN doctor d ON a.doctor_id = d.doctor_id
                        LEFT JOIN patient p ON ar.patient_id = p.patient_id
                        WHERE ar.ar_status = '{status_map[status]}' AND p.user_id = %s
                        ORDER BY ar.ar_date, ar.ar_time;
                        """

            query_dsc = f"""
                        SELECT ar.ar_id, ar.ar_detail, ar.ar_date, ar.ar_time, ar.ar_doctor, 
                        ar.ar_ifreject, a.appointment_prescription,
                        c.clinic_name, d.doctor_name
                        FROM appointment_request ar
                        LEFT JOIN clinic c ON ar.clinic_id = c.clinic_id
                        LEFT JOIN appointment a ON ar.ar_id = a.ar_id
                        LEFT JOIN doctor d ON a.doctor_id = d.doctor_id
                        LEFT JOIN patient p ON ar.patient_id = p.patient_id
                        WHERE ar.ar_status = '{status_map[status]}' AND p.user_id = %s
                        ORDER BY ar.ar_date DESC, ar.ar_time DESC;
                        """

            # For pending and ongoing, the appointments arranged in ascending datetime, indicating upcoming sequence
            if status == 'Request' or status == 'Ongoing':
                self.cursor.execute(query_asc, (self.user_id,))
                appointments = self.cursor.fetchall()
            # For rejected, canceled and completed, the appointments arranged in descending datetime
            else:
                self.cursor.execute(query_dsc, (self.user_id,))
                appointments = self.cursor.fetchall()

            for i, appointment in enumerate(appointments):
                ar_id = appointment['ar_id']
                ar_detail = appointment['ar_detail']
                ar_date = self.format_date(str(appointment['ar_date']))
                ar_time = self.timedelta_to_time(appointment['ar_time'])
                ar_time = ar_time.strftime("%I%p").lstrip('0').lower()
                clinic_name = appointment['clinic_name']
                doctor_name = ('Dr. ' + appointment['doctor_name']) if appointment['ar_doctor'] else '-'

                card_frame = tk.Frame(a_scrollable_frame, bg='white', highlightbackground='#00C196',
                                      highlightthickness=1)
                card_frame.grid(row=i + 1, column=0, columnspan=5, padx=20, pady=10, sticky='ew')
                card_frame.grid_columnconfigure(0, weight=1)
                card_frame.grid_columnconfigure(1, weight=1)
                card_frame.grid_columnconfigure(2, weight=1)
                card_frame.grid_columnconfigure(3, weight=1)

                id_label = tk.Label(card_frame, text=f"Appointment ID: {ar_id}", font=('Open Sans', 16, 'bold'),
                                    bg='white', fg='#333333')
                id_label.grid(row=0, column=0, sticky='w', padx=15, pady=(10, 5))

                clinic_label = tk.Label(card_frame, text=f"   Clinic: {clinic_name}", font=('Open Sans', 12, 'bold'), width=55,
                                        bg='white', fg='#333333', anchor='w')
                clinic_label.grid(row=1, column=0, sticky='w', padx=15, pady=5)

                doctor_label = tk.Label(card_frame, text=f"   Doctor: {doctor_name}", font=('Open Sans', 12),
                                        bg='white', fg='#333333')
                doctor_label.grid(row=2, column=0, sticky='w', padx=15, pady=5)

                date_label = tk.Label(card_frame, text=f"   Date: {ar_date}", font=('Open Sans', 12), bg='white',
                                      fg='#333333')
                date_label.grid(row=3, column=0, sticky='w', padx=15, pady=5)

                time_label = tk.Label(card_frame, text=f"   Time: {ar_time}", font=('Open Sans', 12), bg='white',
                                      fg='#333333')
                time_label.grid(row=4, column=0, sticky='w', padx=15, pady=(5, 15))

                description_label = tk.Label(card_frame, text="Description:", font=('Open Sans', 12), bg='white',
                                             fg='#333333')
                description_label.grid(row=1, column=4, columnspan=2, sticky='w', padx=10)

                description_frame = tk.Frame(card_frame)
                description_frame.grid(row=2, column=4, rowspan=3, sticky='nw', padx=15)

                description_text = tk.Text(description_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=40,
                                           height=4, borderwidth=1, relief='solid', wrap='word')
                if ar_detail is not None:
                    description_text.insert('1.0', ar_detail)
                description_text.config(state=tk.DISABLED)
                description_text.pack(side="left", fill="both", expand=True)

                text_scrollbar = tk.Scrollbar(description_frame, command=description_text.yview)
                text_scrollbar.pack(side="right", fill="y")

                description_text.config(yscrollcommand=text_scrollbar.set)

                if status != 'Canceled':
                    time_label.grid(row=4, column=0, sticky='w', padx=15, pady=5)
                    # Provide cancel button for the user to cancel pending or ongoing appointments
                    if status == 'Request' or status == 'Ongoing':
                        cancel_button = tk.Button(card_frame, text='Cancel', font=('Open Sans', 12, 'bold'), bg='#F5443E',
                                                  fg='white', width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                                  command=lambda ar_id=ar_id: cancel_appointment(ar_id))
                        cancel_button.grid(row=5, column=4, columnspan=2, sticky='e', padx=15, pady=(0, 15))
                    # Display the doctor's prescription for completed appointments
                    elif status == 'Completed':
                        appointment_prescription = appointment['appointment_prescription']
                        prescription_label = tk.Label(card_frame, text="   Prescription:", font=('Open Sans', 12),
                                                      bg='white', fg='#333333')
                        prescription_label.grid(row=5, column=0, padx=15, pady=5, sticky='w')
                        prescription_frame = tk.Frame(card_frame)
                        prescription_frame.grid(row=6, column=0, columnspan=5, sticky='nw', padx=(30, 15), pady=(0, 15))
                        prescription_text = tk.Text(prescription_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=103,
                                                    height=4, borderwidth=1, relief='solid')
                        prescription_text.insert('1.0', appointment_prescription)
                        prescription_text.config(state=tk.DISABLED)
                        prescription_text.pack(side="left", fill="both", expand=True)
                        prescription_scrollbar = tk.Scrollbar(prescription_frame, command=prescription_text.yview)
                        prescription_scrollbar.pack(side="right", fill="y")

                        prescription_text.config(yscrollcommand=prescription_scrollbar.set)
                    # Display the reject reason for appointments being rejected by clinic admin
                    elif status == 'Rejected':
                        ar_ifreject = appointment['ar_ifreject']
                        reject_label = tk.Label(card_frame, text="   Reject Reason:", font=('Open Sans', 12), bg='white', fg='#333333')
                        reject_label.grid(row=5, column=0, padx=15, pady=5, sticky='w')
                        reject_frame = tk.Frame(card_frame)
                        reject_frame.grid(row=6, column=0, columnspan=5, sticky='nw', padx=(30, 15), pady=(0, 15))
                        reject_text = tk.Text(reject_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=103,
                                              height=4, borderwidth=1, relief='solid')
                        reject_text.insert('1.0', ar_ifreject)
                        reject_text.config(state=tk.DISABLED)
                        reject_text.pack(side="left", fill="both", expand=True)
                        reject_scrollbar = tk.Scrollbar(reject_frame, command=reject_text.yview)
                        reject_scrollbar.pack(side="right", fill="y")

                        reject_text.config(yscrollcommand=reject_scrollbar.set)

            self.switch('appointment', self.all_appointment_frames)

        # Function for canceling an appointment
        def cancel_appointment(ar_id):
            update_query = "UPDATE appointment_request SET ar_status = 'canceled' WHERE ar_id = %s"
            self.cursor.execute(update_query, (ar_id,))
            database.commit()

            display_appointments(self.current_status)

        for widget in self.appointment_frame.winfo_children():
            widget.destroy()

        tab_button_frame = tk.Frame(self.appointment_frame, background='#ffffff')
        tab_button_frame.pack(fill='x', expand='True')

        # Create a canvas and a scrollbar
        a_canvas = tk.Canvas(self.appointment_frame, borderwidth=0, background="#ffffff", width=1030, height=500, highlightthickness=0)
        a_scrollbar = tk.Scrollbar(self.appointment_frame, orient="vertical", command=a_canvas.yview)
        a_scrollable_frame = tk.Frame(a_canvas, background="#ffffff")

        a_canvas.create_window((0, 0), window=a_scrollable_frame, anchor="nw")
        a_canvas.configure(yscrollcommand=a_scrollbar.set)

        # Pack the canvas and scrollbar
        a_canvas.pack(side="left", fill="both", expand=True)
        a_scrollbar.pack(side="right", fill="y")
        self.all_appointment_frames['appointment'] = [self.appointment_frame, a_canvas, a_scrollable_frame, 0]

        # Create the navigation buttons
        tab_buttons = []
        tabs = ['Request', 'Ongoing', 'Completed', 'Rejected', 'Canceled']
        for i, tab in enumerate(tabs):
            tab_button = tk.Button(tab_button_frame, text=tab, font=('Open Sans', 12, 'bold'),
                                   bg='#00C196' if tab == self.current_status else '#E0FCF8',
                                   fg='white' if tab == self.current_status else '#00C196', width=12, borderwidth=0,
                                   relief="ridge", bd=2, highlightbackground='#00C196', highlightthickness=0, padx=5,
                                   pady=5, command=lambda t=tab: filter_appointments(t))
            tab_button.grid(row=0, column=i, padx=14, pady=10)
            tab_button.config(relief="flat", highlightthickness=0, borderwidth=0, padx=30, pady=5)
            tab_buttons.append(tab_button)

        display_appointments(self.current_status)

    # Set up me section
    def set_up_me_frame(self):
        # Display personal information
        def show_personal():
            # Enable the entries and buttons for the user to edit
            def edit_personal():
                for entry in all_entries:
                    entry.config(state='normal', fg='#333333')
                gender_entry.config(fg='#333333')
                gender_button.config(state='normal')
                address_entry.config(state='normal', fg='#333333')

                edit_button.place_forget()
                p_save_button.place(x=945, y=15)

            # Ensure there are no empty entries
            # Update data to database accordingly
            def save_personal():
                personal_content_frame.focus_set()
                if all([entry.cget('fg') == '#333333' for entry in all_entries]) and gender_entry.cget('fg') == '#333333' \
                        and address_entry.cget('fg') == '#333333':
                    user_name = name_entry.get()
                    user_ic_passport = ic_passport_entry.get()
                    user_contact = contact_entry.get()
                    user_gender = gender_entry.cget('text')
                    user_address = address_entry.get('1.0', tk.END)
                    if all([user_name, user_ic_passport, user_contact, user_gender, user_address]):
                        cursor.execute('''UPDATE patient SET patient_name=%s, patient_ic_passport=%s, patient_gender=%s, 
                                       patient_address=%s, patient_contact=%s WHERE user_id=%s''',
                                       (user_name, user_ic_passport, user_gender, user_address, user_contact, self.user_id))
                        p_save_error_label.config(text='')
                        database.commit()
                        # Refresh the personal information, the entries and buttons are disabled again
                        show_personal()
                    else:
                        p_save_error_label.config(text='Please fill in all details')
                else:
                    p_save_error_label.config(text='Please fill in all details')

            # Make the password visible
            def personal_password_visible():
                password_entry.config(show='')
                password_eye_closed_button.place_forget()
                password_eye_opened_button.place(x=330, y=2)

            # Make the password invisible
            def personal_password_invisible():
                password_entry.config(show='*')
                password_eye_opened_button.place_forget()
                password_eye_closed_button.place(x=330, y=2)

            for widget in personal_content_frame.winfo_children():
                widget.destroy()

            edit_button.config(command=lambda: edit_personal())
            p_save_button.config(command=lambda: save_personal())
            p_save_button.place_forget()
            edit_button.place(x=945, y=15)
            p_save_error_label.config(text='')

            # Store all entries for easier management
            all_entries = []

            cursor.execute('''SELECT user_email, user_password FROM user WHERE user_id=%s''', (self.user_id, ))
            user_detail = cursor.fetchone()

            email_label = tk.Label(personal_content_frame, text='Email: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                   width=20, anchor='e')
            email_label.grid(row=0, column=0, padx=(150, 5), pady=5, sticky='e')
            email_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            email_frame.grid(row=0, column=1, padx=5, pady=5, sticky='w')
            email_entry = tk.Label(email_frame, bg='#D0F9EF', text=user_detail[0], fg='#858585', font=('Open Sans', 10))
            email_entry.place(x=5, y=12)

            password_label = tk.Label(personal_content_frame, text='Password: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                      width=20, anchor='e')
            password_label.grid(row=1, column=0, padx=(150, 5), pady=5, sticky='e')
            password_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            password_frame.grid(row=1, column=1, padx=5, pady=5, sticky='w')
            password_entry = tk.Entry(password_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), show='*', border=0)
            password_entry.place(x=7, y=12)
            password_entry.insert(0, user_detail[1])
            password_entry.config(state='disabled', disabledbackground='#D0F9EF')
            password_eye_closed_button = ttk.Button(password_frame, style='eye_closed_green.TButton', cursor='hand2')
            password_eye_closed_button.place(x=330, y=2)
            password_eye_opened_button = ttk.Button(password_frame, style='eye_opened_green.TButton', cursor='hand2')
            password_eye_closed_button.config(command=lambda: personal_password_visible())
            password_eye_opened_button.config(command=lambda: personal_password_invisible())

            cursor.execute('''SELECT * FROM patient WHERE user_id=%s''', (self.user_id, ))
            user_info = cursor.fetchone()

            name_label = tk.Label(personal_content_frame, text='Name: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                  width=20, anchor='e')
            name_label.grid(row=2, column=0, padx=(150, 5), pady=(40, 5), sticky='e')
            name_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            name_entry_frame.grid(row=2, column=1, padx=5, pady=(40, 5), sticky='w')
            name_entry = tk.Entry(name_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            name_entry.place(x=7, y=12)
            name_entry.insert(0, user_info[1])
            name_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(name_entry)

            ic_passport_label = tk.Label(personal_content_frame, text='IC / Passport: ', font=('Open Sans', 12, 'bold'), bg='white',
                                         fg='#000000', width=20, anchor='e')
            ic_passport_label.grid(row=3, column=0, padx=(150, 5), pady=5, sticky='e')
            ic_passport_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            ic_passport_entry_frame.grid(row=3, column=1, padx=5, pady=5, sticky='w')
            ic_passport_entry = tk.Entry(ic_passport_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            ic_passport_entry.place(x=7, y=12)
            ic_passport_entry.insert(0, user_info[2])
            ic_passport_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(ic_passport_entry)

            gender_label = tk.Label(personal_content_frame, text='Gender: ', font=('Open Sans', 12, 'bold'), bg='white',
                                    fg='#000000', width=20, anchor='e')
            gender_label.grid(row=4, column=0, padx=(150, 5), pady=5, sticky='e')
            gender_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            gender_entry_frame.grid(row=4, column=1, padx=5, pady=5, sticky='w')
            gender_entry = tk.Label(gender_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), text=user_info[3])
            gender_entry.place(x=5, y=12)
            gender_button = ttk.Button(gender_entry_frame, text='▼', style='selection.TButton', width=4,
                                       cursor='hand2', command=lambda: self.display_menu(gender_entry_frame, 0, 33, gender_menu))
            gender_button.place(x=330, y=5)
            gender_menu = tk.Menu(personal_content_frame, tearoff=0, bg='#D0F9EF', fg='#333333',
                                  font=('Open Sans', 10))
            gender_menu.add_command(label="Male", command=lambda: self.select_menu_option(gender_entry, 'Male'))
            gender_menu.add_command(label="Female", command=lambda: self.select_menu_option(gender_entry, 'Female'))
            gender_menu.add_separator()
            gender_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ",
                                    command=gender_menu.unpost)
            gender_button.config(state='disabled')

            contact_label = tk.Label(personal_content_frame, text='Contact Number: ', font=('Open Sans', 12, 'bold'), bg='white',
                                     fg='#000000', width=20, anchor='e')
            contact_label.grid(row=5, column=0, padx=(150, 5), pady=5, sticky='e')
            contact_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            contact_entry_frame.grid(row=5, column=1, padx=5, pady=5, sticky='w')
            contact_entry = tk.Entry(contact_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            contact_entry.place(x=7, y=12)
            contact_entry.insert(0, user_info[5])
            contact_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(contact_entry)

            address_label = tk.Label(personal_content_frame, text='Address: ', font=('Open Sans', 12, 'bold'), bg='white',
                                     fg='#000000', width=20, anchor='ne')
            address_label.grid(row=6, column=0, padx=(150, 5), pady=(5, 15), sticky='ne')
            address_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=90)
            address_entry_frame.grid(row=6, column=1, padx=5, pady=(5, 15), sticky='w')
            address_entry = tk.Text(address_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45,
                                    height=5, wrap='word')
            address_entry.place(x=7, y=5)
            address_entry.insert('1.0', user_info[4])
            address_entry.config(state='disabled')

            self.switch('personal', self.all_me_frame)

        # Display the reset password page
        def show_reset():
            # Validate the requirements for successful reset password
            def reset():
                reset_content_frame.focus_set()
                if old_entry.cget('fg') == '#333333' and new_entry.cget('fg') == '#333333' and confirm_entry.cget('fg') == '#333333':
                    cursor.execute('''SELECT user_password FROM user WHERE user_id=%s''', (self.user_id, ))
                    previous_password = cursor.fetchone()[0]
                    if old_entry.get() == previous_password:
                        if len(new_entry.get()) >= 8:
                            if new_entry.get() == confirm_entry.get():
                                cursor.execute('''UPDATE user SET user_password=%s WHERE user_id=%s''', (new_entry.get(), self.user_id))
                                database.commit()
                                save_error_label.config(text='')
                                messagebox.showinfo('Success', "Reset Password Successfully")
                                # Directed back to view the updated personal information
                                show_personal()
                            else:
                                save_error_label.config(text='Password does not match')
                        else:
                            save_error_label.config(text='Minimum 8 characters of password')
                    else:
                        save_error_label.config(text="Incorrect old password")
                else:
                    save_error_label.config(text="Please fill in all details")

            for widget in reset_content_frame.winfo_children():
                widget.destroy()

            save_error_label.config(text='')
            save_button.config(command=lambda: reset())

            reset_label = tk.Label(reset_content_frame, text='Reset Password',
                                   font=('Open Sans', 20, 'underline', 'bold'), bg='white', fg='#000000')
            reset_label.grid(row=0, column=0, columnspan=2, padx=35, pady=(10, 15), sticky='w')

            old_label = tk.Label(reset_content_frame, text='Old Password', font=('Open Sans', 12, 'bold'), bg='white',
                                         fg='#000000')
            old_label.grid(row=1, column=0, padx=50, pady=(5, 0), sticky='w')
            old_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            old_entry_frame.grid(row=2, column=0, padx=53, pady=(0, 5))
            old_entry = tk.Entry(old_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            old_entry.place(x=10, y=13)
            old_entry.insert(0, 'Enter Old Password')
            old_eye_closed_button = ttk.Button(old_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            old_eye_closed_button.place(x=330, y=2)
            old_eye_opened_button = ttk.Button(old_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            old_visibility = tk.Label(old_entry_frame, text='Close')
            old_eye_closed_button.config(command=lambda: self.show_hide_password(old_entry, old_eye_opened_button,
                                                                                 old_eye_closed_button, old_visibility))
            old_eye_opened_button.config(command=lambda: self.show_hide_password(old_entry, old_eye_opened_button,
                                                                                 old_eye_closed_button, old_visibility))
            old_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', old_entry, old_visibility))
            old_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', old_entry, 'Enter Old Password'))
            old_entry.bind('<Return>', lambda event: reset())

            new_label = tk.Label(reset_content_frame, text='New Password', font=('Open Sans', 12, 'bold'), bg='white',
                                 fg='#000000')
            new_label.grid(row=3, column=0, padx=50, pady=(15, 0), sticky='w')
            new_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            new_entry_frame.grid(row=4, column=0, padx=53, pady=(0, 5))
            new_entry = tk.Entry(new_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            new_entry.place(x=10, y=13)
            new_entry.insert(0, 'Enter New Password')
            new_eye_closed_button = ttk.Button(new_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            new_eye_closed_button.place(x=330, y=2)
            new_eye_opened_button = ttk.Button(new_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            new_visibility = tk.Label(new_entry_frame, text='Close')
            new_eye_closed_button.config(command=lambda: self.show_hide_password(new_entry, new_eye_opened_button,
                                                                                 new_eye_closed_button, new_visibility))
            new_eye_opened_button.config(command=lambda: self.show_hide_password(new_entry, new_eye_opened_button,
                                                                                 new_eye_closed_button, new_visibility))
            new_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', new_entry, new_visibility))
            new_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', new_entry, 'Enter New Password'))
            new_entry.bind('<Return>', lambda event: reset())

            confirm_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            confirm_entry_frame.grid(row=5, column=0, padx=53, pady=(0, 5))
            confirm_entry = tk.Entry(confirm_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            confirm_entry.place(x=10, y=13)
            confirm_entry.insert(0, 'Re-enter New Password')
            confirm_eye_closed_button = ttk.Button(confirm_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            confirm_eye_closed_button.place(x=330, y=2)
            confirm_eye_opened_button = ttk.Button(confirm_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            confirm_visibility = tk.Label(confirm_entry_frame, text='Close')
            confirm_eye_closed_button.config(command=lambda: self.show_hide_password(confirm_entry, confirm_eye_opened_button,
                                                                                     confirm_eye_closed_button, confirm_visibility))
            confirm_eye_opened_button.config(command=lambda: self.show_hide_password(confirm_entry, confirm_eye_opened_button,
                                                                                     confirm_eye_closed_button, confirm_visibility))
            confirm_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', confirm_entry, confirm_visibility))
            confirm_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', confirm_entry, 'Re-enter New Password'))
            confirm_entry.bind('<Return>', lambda event: reset())

            self.switch('reset', self.all_me_frame)

        for widget in self.me_frame.winfo_children():
            widget.destroy()

        # Creation of sub-frame and some consistent widgets
        personal_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        logout_button = tk.Button(personal_frame, text='Log Out', bg='red', fg='white', cursor='hand2', relief='flat', border=0,
                                  font=('Open Sans', 14, 'bold'), width=10, command=lambda: self.logout())
        logout_button.place(x=30, y=15)
        reset_password_button = ttk.Button(personal_frame, text='Reset Password', style='green_button.TButton', cursor='hand2',
                                           width=18, command=lambda: show_reset())
        reset_password_button.place(x=710, y=15)
        edit_button = ttk.Button(personal_frame, text='Edit', style='green_button.TButton', cursor='hand2', width=6)
        edit_button.place(x=945, y=15)
        p_save_button = ttk.Button(personal_frame, text='Save', style='green_button.TButton', cursor='hand2', width=6)
        p_save_error_label = tk.Label(personal_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        p_save_error_label.place(x=510, y=25)
        personal_canvas = tk.Canvas(personal_frame, width=1030, height=430, bg='white', highlightthickness=0)
        personal_canvas.place(x=0, y=75)
        personal_scrollbar = tk.Scrollbar(personal_frame, orient='vertical')
        personal_scrollbar.place(x=1033, y=75, height=430)
        personal_canvas.configure(yscrollcommand=personal_scrollbar.set)
        personal_scrollbar.configure(command=personal_canvas.yview)
        personal_content_frame = tk.Frame(personal_canvas, bg='white')
        personal_canvas.create_window((0, 0), window=personal_content_frame, anchor="nw")
        self.all_me_frame['personal'] = [personal_frame, personal_canvas, personal_content_frame, 0]

        reset_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        reset_back_button = ttk.Button(reset_frame, text='< Back', style='back.TButton', cursor='hand2', width=6,
                                       command=lambda: show_personal())
        reset_back_button.place(x=20, y=15)
        save_button = ttk.Button(reset_frame, text='Save', style='green_button.TButton', cursor='hand2', width=6)
        save_button.place(x=945, y=15)
        save_error_label = tk.Label(reset_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        save_error_label.place(x=750, y=25)
        reset_canvas = tk.Canvas(reset_frame, width=1030, height=430, bg='white', highlightthickness=0)
        reset_canvas.place(x=0, y=75)
        reset_scrollbar = tk.Scrollbar(reset_frame, orient='vertical')
        reset_scrollbar.place(x=1033, y=75, height=430)
        reset_canvas.configure(yscrollcommand=reset_scrollbar.set)
        reset_scrollbar.configure(command=reset_canvas.yview)
        reset_content_frame = tk.Frame(reset_canvas, bg='white')
        reset_canvas.create_window((0, 0), window=reset_content_frame, anchor="nw")
        self.all_me_frame['reset'] = [reset_frame, reset_canvas, reset_content_frame, 0]

        show_personal()

    def on_mouse_wheel(self, event, canvas):
        canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def focus_entry(self, entry_type, entry, visibility=None):
        if entry_type == 'entry':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
        elif entry_type == 'text':
            if entry.cget('fg') == '#858585':
                entry.delete('1.0', 'end')
                entry.config(fg='#333333')
        elif entry_type == 'password':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
                if visibility.cget('text') == 'Open':
                    entry.config(show='')
                elif visibility.cget('text') == 'Close':
                    entry.config(show='*')

    def leave_focus_entry(self, entry_type, entry, text):
        if entry_type == 'entry':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585')
                entry.insert(0, text)
        elif entry_type == 'text':
            value = entry.get('1.0', 'end')
            if value.strip() == '':
                entry.delete('1.0', 'end')
                entry.config(fg='#858585')
                entry.insert('1.0', text)
        elif entry_type == 'password':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585', show='')
                entry.insert(0, text)

    def display_menu(self, frame, x, y, menu):
        root_x = frame.winfo_rootx()
        root_y = frame.winfo_rooty()
        adjusted_x = root_x + x
        adjusted_y = root_y + y

        menu.post(adjusted_x, adjusted_y)

    def select_menu_option(self, label, option, text=None):
        if option == 'Clear':
            label.config(text=text, fg='#858585')
        else:
            label.config(text=option, fg='#333333')

    # Change the date from format YYYY:MM:DD to Day Month Year
    def format_date(self, date):
        full_date = date.split('-')
        year = full_date[0]
        month = full_date[1]
        day = full_date[2]
        months = {'01': 'January',
                  '02': 'February',
                  '03': 'March',
                  '04': 'April',
                  '05': 'May',
                  '06': 'June',
                  '07': 'July',
                  '08': 'August',
                  '09': 'September',
                  '10': 'October',
                  '11': 'November',
                  '12': 'December'}
        month = months[month]
        return f"{day} {month} {year}"

    def format_malaysia_time(self, iso_str):
        # Convert an ISO-like UTC string (YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS) to Malaysia time (UTC+8)
        # Output format: YYYY-MM-DD HH:MM
        try:
            from datetime import datetime, timedelta
            if not iso_str:
                return ''
            s = str(iso_str).replace('T', ' ')
            # Try parsing with seconds first, then without
            dt = None
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(s[:26], fmt)
                    break
                except Exception:
                    continue
            if dt is None:
                # Fallback: take first 16 chars (YYYY-MM-DD HH:MM)
                return s[:16]
            myt = dt + timedelta(hours=8)
            return myt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            return str(iso_str)[:16] if iso_str else ''
    # The time data type fetched from database is in timedelta format, converted if needed
    def timedelta_to_time(self, td_value):
        total_seconds = td_value.total_seconds()
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = int(total_seconds % 60)
        return time(hours, minutes, seconds)

    def show_hide_password(self, entry, eye_open_button, eye_close_button, visibility):
        if visibility.cget('text') == 'Close' and entry.cget('fg') == '#858585':
            eye_open_button.place(x=330, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')
        elif visibility.cget('text') == 'Open' and entry.cget('fg') == '#858585':
            eye_open_button.place_forget()
            eye_close_button.place(x=330, y=2)
            entry.config(show='')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Open':
            eye_open_button.place_forget()
            eye_close_button.place(x=330, y=2)
            entry.config(show='*')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Close':
            eye_open_button.place(x=330, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')


class Clinic:
    def __init__(self, main_window, login_register=None):
        self.root_window = main_window
        self.login_register = login_register  # Reference to LoginRegister instance
        self.user_id = None
        self.clinic_id = None

        self.cursor = None

        self.window = tk.Toplevel(self.root_window)
        self.window.title('Call a Doctor')
        self.window.geometry('1050x600')
        icon = load_image('icon', 48, 48)
        self.window.iconphoto(False, icon)

        self.nf_icon = load_image('nf icon', 80, 70)
        self.eye_closed_image = load_image('eye closed', 24, 24)
        self.eye_opened_image = load_image('eye opened', 24, 24)
        self.calendar = load_image('calendar', 20, 20)
        self.back_image = load_image('back', 80, 40)

        style = ttk.Style()
        style.theme_use('clam')

        style.configure('navigation.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        font=('Open Sans', 20, 'bold'))
        style.map('navigation.TButton', background=[('active', 'white')], foreground=[('active', '#77C7B5')])
        style.configure('white_word.TButton', border=0, relief='flat', background='#7EE5CE', foreground='white',
                        font=('Open Sans', 15, 'bold'))
        style.map('white_word.TButton', background=[('active', '#7EE5CE')], foreground=[('active', 'white')])
        style.configure('c_black_word.TButton', border=1, relief='flat', background='white', foreground='black',
                        font=('Open Sans', 12, 'bold'))
        style.map('c_black_word.TButton', background=[('active', 'white')], foreground=[('active', 'black')])
        style.configure('inactive.TButton', border=1, relief='flat', background='grey', foreground='black',
                        font=('Open Sans', 12, 'bold'))
        style.map('inactive.TButton', background=[('active', 'grey')], foreground=[('active', 'black')])
        style.configure('back_image.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        image=self.back_image)
        style.map('back_image.TButton', background=[('active', 'white')], foreground=[('active', '#7EE5CE')])
        style.configure('selection.TButton', border=0, relief='flat', background='#D0F9EF', foreground='#3DAEC7',
                        font=('Rubik', 12, 'bold'))
        style.map('selection.TButton', background=[('active', '#D0F9EF')], foreground=[('active', '#0B8FAC')])
        style.configure('eye_closed_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_closed_image)
        style.map('eye_closed_green.TButton', background=[('active', '#D0F9EF')])
        style.configure('eye_opened_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_opened_image)
        style.map('eye_opened_green.TButton', background=[('active', '#D0F9EF')])
        style.configure('calendar.TButton', border=0, relief='flat', background='#D0F9EF',
                        image=self.calendar)
        style.map('calendar.TButton', background=[('active', '#D0F9EF')])
        style.configure('green_button.TButton', border=0, relief='flat', background='#7EE5CE', foreground='white',
                        font=('Open Sans', 14, 'bold'))
        style.map('green_button.TButton', background=[('active', '#77C7B5')])
        style.configure('back.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        font=('Open Sans', 18, 'bold'))
        style.map('back.TButton', background=[('active', 'white')], foreground=[('active', '#77C7B5')])

        self.navigation_frame = tk.Frame(self.window, width=1050, height=90, bg='white')
        self.navigation_frame.pack()
        self.navigation_bar = tk.Frame(self.navigation_frame, height=5, bg='#166E82')

        nf_icon = tk.Label(self.navigation_frame, image=self.nf_icon, bg='white', cursor='hand2')
        nf_icon.place(x=10, y=10)
        nf_icon.bind('<Button-1>', lambda event: self.refresh())
        nf_name = tk.Label(self.navigation_frame, text='CaD', font=('Open Sans', 30, 'bold'), bg='white', fg='#166E82', cursor='hand2')
        nf_name.place(x=90, y=20)
        nf_name.bind('<Button-1>', lambda event: self.refresh())
        nf_appointment_button = ttk.Button(self.navigation_frame, text='Appointment Request', style='navigation.TButton', width=20,
                                           command=lambda: self.show_activity_frame(315, 327, self.appointment_frame))
        nf_appointment_button.place(x=326, y=30)
        nf_timetable_button = ttk.Button(self.navigation_frame, text='Timetable', style='navigation.TButton', width=9,
                                         command=lambda: self.show_activity_frame(150, 646, self.timetable_frame))
        nf_timetable_button.place(x=645, y=30)
        nf_doctor_list_button = ttk.Button(self.navigation_frame, text='Doctor List', style='navigation.TButton', width=10,
                                           command=lambda: self.show_activity_frame(165, 803, self.doctor_list_frame))
        nf_doctor_list_button.place(x=802, y=30)

        nf_me_button = ttk.Button(self.navigation_frame, text='Me', style='navigation.TButton', width=3,
                                  command=lambda: self.show_activity_frame(60, 976, self.me_frame))
        nf_me_button.place(x=975, y=30)

        self.appointment_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_appointment_frame = {}

        self.timetable_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.doctor_id = None  # Storing doctor_id that used to generate corresponding timetable

        self.doctor_list_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_doctor_list_frames = {}
        self.doctor_image_var = None  # Storing new doctor image data within the doctor list section

        self.me_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_me_frame = {}
        self.me_img_var = None  # Storing new clinic image data within me section

        self.all_scrollable_frame = {}
        self.all_scrollable_frame[self.appointment_frame] = 1
        self.all_scrollable_frame[self.timetable_frame] = 0
        self.all_scrollable_frame[self.doctor_list_frame] = 0
        self.all_scrollable_frame[self.me_frame] = 0

    def logout(self):
        # Call handle_logout from LoginRegister if available (clears tokens and calls logout API)
        if self.login_register:
            self.login_register.handle_logout()
            return  # handle_logout will show login screen
        
        # Fallback: basic logout if login_register not available
        self.user_id = None
        self.clinic_id = None

        self.cursor.close()
        self.cursor = None

        self.window.withdraw()
        self.root_window.deiconify()

        self.all_doctor_list_frames = {}
        self.doctor_image_var = None

        self.doctor_id = None

        self.all_me_frame = {}
        self.me_img_var = None

        self.all_appointment_frame = {}

        self.all_scrollable_frame = {}
        self.all_scrollable_frame[self.appointment_frame] = 1
        self.all_scrollable_frame[self.timetable_frame] = 0
        self.all_scrollable_frame[self.doctor_list_frame] = 0
        self.all_scrollable_frame[self.me_frame] = 0

    def run(self, user_id):
        self.user_id = user_id
        cursor.execute('''SELECT clinic_id FROM clinic WHERE user_id=%s''', (self.user_id,))
        self.clinic_id = cursor.fetchone()[0]

        self.cursor = database.cursor(dictionary=True)

        self.window.deiconify()
        self.refresh()

    def refresh(self):
        cursor.execute('''UPDATE appointment_request ar
                          JOIN patient p ON ar.patient_id = p.patient_id
                          SET ar.ar_status = 'canceled'
                          WHERE CONCAT(ar.ar_date, ' ', ar.ar_time) < NOW()
                          AND ar.ar_status IN ('pending', 'ongoing')''')
        database.commit()

        self.set_up_appointment_frame()
        self.set_up_timetable_frame()
        self.set_up_doctor_list_frame()
        self.set_up_me_frame()

        if self.all_scrollable_frame[self.appointment_frame] == 1:
            self.show_activity_frame(315, 327, self.appointment_frame)
        elif self.all_scrollable_frame[self.timetable_frame] == 1:
            self.show_activity_frame(150, 646, self.timetable_frame)
        elif self.all_scrollable_frame[self.doctor_list_frame] == 1:
            self.show_activity_frame(165, 803, self.doctor_list_frame)
        elif self.all_scrollable_frame[self.me_frame] == 1:
            self.show_activity_frame(60, 976, self.me_frame)

    def show_activity_frame(self, bar_width, bar_x, frame):
        self.navigation_bar.config(width=bar_width)
        self.navigation_bar.place(x=bar_x, y=85)

        self.appointment_frame.pack_forget()
        self.timetable_frame.pack_forget()
        self.doctor_list_frame.pack_forget()
        self.me_frame.pack_forget()

        frame.pack()
        frame.focus_set()

        key = list(self.all_scrollable_frame.keys())
        for k in key:
            if k == frame:
                self.all_scrollable_frame[k] = 1
            else:
                self.all_scrollable_frame[k] = 0

        if frame == self.doctor_list_frame:
            keys = list(self.all_doctor_list_frames.keys())
            for k in keys:
                active = self.all_doctor_list_frames[k][3]
                if active:
                    self.switch(k, self.all_doctor_list_frames)
        elif frame == self.timetable_frame:
            self.timetable_frame.bind_all("<MouseWheel>", lambda event: self.do_nothing(event))
        elif frame == self.appointment_frame:
            keys = list(self.all_appointment_frame.keys())
            for k in keys:
                active = self.all_appointment_frame[k][3]
                if active:
                    self.switch(k, self.all_appointment_frame)
        elif frame == self.me_frame:
            keys = list(self.all_me_frame.keys())
            for k in keys:
                active = self.all_me_frame[k][3]
                if active:
                    self.switch(k, self.all_me_frame)

    def switch(self, frame, frame_list):
        frames = list(frame_list.keys())
        for f in frames:
            if f == frame:
                frame_list[f][3] = 1
                frame_list[f][0].pack()
            else:
                frame_list[f][3] = 0
                frame_list[f][0].pack_forget()
        content = frame_list[frame][2]
        canvas = frame_list[frame][1]
        content.update_idletasks()
        if len(content.winfo_children()) == 0:
            canvas.configure(scrollregion=(0, 0, 0, 0))
        else:
            canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.bind_all("<MouseWheel>", lambda event: self.on_mouse_wheel(event, canvas))

    def set_up_appointment_frame(self):
        def get_working(working_hours):
            time_format_12 = '%I%p'
            # Parse the working hours
            parts = working_hours.split(', ')
            if len(parts) > 2:
                working_hour = parts[1].split('-')
                start_work = working_hour[0].strip()
                start_work = datetime.strptime(start_work, time_format_12).time()
                end_work = working_hour[1].strip()
                end_work = datetime.strptime(end_work, time_format_12) - timedelta(hours=1)
                end_work = end_work.time()
                rest_days = parts[2].split()[-1]
                whole = [start_work, end_work, rest_days]
            elif len(parts) > 1:
                working_hour = parts[1].split('-')
                start_work = working_hour[0].strip()
                start_work = datetime.strptime(start_work, time_format_12).time()
                end_work = working_hour[1].strip()
                end_work = datetime.strptime(end_work, time_format_12) - timedelta(hours=1)
                end_work = end_work.time()
                whole = [start_work, end_work]
            else:
                whole = []
            return whole

        def display_appointments():
            for widget in appointment_scrollable_frame.winfo_children():
                widget.destroy()

            # Select related pending appointments
            query = f"""SELECT ar.ar_id, ar.ar_detail, ar.ar_date, ar.ar_time, ar.ar_status, d.doctor_id, p.patient_address,
                        p.patient_name, p.patient_contact, p.patient_ic_passport, p.patient_gender, d.doctor_name
                        FROM appointment_request ar
                        LEFT JOIN patient p ON ar.patient_id = p.patient_id
                        LEFT JOIN clinic c ON ar.clinic_id = c.clinic_id
                        LEFT JOIN appointment a ON ar.ar_id = a.ar_id
                        LEFT JOIN doctor d ON a.doctor_id = d.doctor_id
                        WHERE ar.ar_status = %s AND ar.clinic_id = %s
                        ORDER BY ar.ar_date, ar.ar_time;"""
            self.cursor.execute(query, ('pending', self.clinic_id))
            appointments = self.cursor.fetchall()

            if not appointments:
                no_appointments_label = tk.Label(appointment_scrollable_frame, text="No appointments found.",
                                                 font=('Open Sans', 12, 'bold'), bg='white', fg='red')
                no_appointments_label.pack(padx=440, pady=30)
            else:
                for i, appointment in enumerate(appointments):
                    ar_id = appointment['ar_id']
                    ar_details = appointment['ar_detail']
                    ar_date = appointment['ar_date']
                    ar_date_str = self.format_date(str(ar_date))
                    ar_time = appointment['ar_time']
                    ar_time_str = self.timedelta_to_time(ar_time)
                    ar_time_str = ar_time_str.strftime("%I%p").lstrip('0').lower()
                    ar_status = appointment['ar_status']
                    patient_name = appointment['patient_name']
                    patient_contact = appointment['patient_contact']
                    patient_ic = appointment['patient_ic_passport']
                    patient_gender = appointment['patient_gender']
                    doctor_name = appointment['doctor_name'] if appointment['doctor_name'] else 'Select a doctor'
                    doctor_id = appointment['doctor_id']
                    patient_address = appointment['patient_address']

                    # Convert ar_date to a weekday name
                    appointment_day = ar_date.strftime('%A')

                    available_doctors_query = """SELECT doctor_id, doctor_name, doctor_working_hour
                                                 FROM doctor 
                                                 WHERE clinic_id = %s AND doctor_status=1 AND doctor_id NOT IN 
                                                 (SELECT a.doctor_id 
                                                 FROM appointment a
                                                 JOIN appointment_request ar ON a.ar_id = ar.ar_id
                                                 WHERE ar.ar_date = %s AND ar.ar_time = %s AND ar.ar_status IN ('pending', 'ongoing'))
                                                 ORDER BY doctor_name;"""
                    self.cursor.execute(available_doctors_query, (self.clinic_id, ar_date, ar_time))
                    available_doctors = self.cursor.fetchall()

                    # Filter out doctors who are available on the appointment datetime
                    ava_doctors = {}
                    for doc in available_doctors:
                        working = get_working(doc['doctor_working_hour'])
                        if working and len(working) > 2:
                            if appointment_day != working[2] and (working[0] <= self.timedelta_to_time(ar_time) <= working[1]):
                                ava_doctors[doc['doctor_id']] = doc['doctor_name']
                        elif working and len(working) == 2:
                            if working[0] <= self.timedelta_to_time(ar_time) <= working[1]:
                                ava_doctors[doc['doctor_id']] = doc['doctor_name']
                        else:
                            ava_doctors[doc['doctor_id']] = doc['doctor_name']
                    doctor_names = [f"{doc_id}.  {doc_name}" for doc_id, doc_name in ava_doctors.items()]

                    card_frame = tk.Frame(appointment_scrollable_frame, bg='white', highlightbackground='#00C196',
                                          highlightthickness=1)
                    card_frame.grid(row=i + 1, column=0, columnspan=5, padx=25, pady=10, sticky='ew')
                    card_frame.grid_columnconfigure(0, weight=1)
                    card_frame.grid_columnconfigure(1, weight=1)
                    card_frame.grid_columnconfigure(2, weight=1)
                    card_frame.grid_columnconfigure(3, weight=1)

                    id_label = tk.Label(card_frame, text=f"Appointment ID: {ar_id}", font=('Open Sans', 16, 'bold'),
                                        bg='white', fg='#333333')
                    id_label.grid(row=0, column=0, sticky='w', padx=15, pady=(10, 5))

                    patient_label = tk.Label(card_frame, text=f"   Patient Name: {patient_name}", font=('Open Sans', 12, 'bold'),
                                             bg='white', fg='#333333', width=53, anchor='w')
                    patient_label.grid(row=1, column=0, sticky='w', padx=15, pady=5)

                    ic_label = tk.Label(card_frame, text=f"   IC / Passport: {patient_ic}", font=('Open Sans', 12),
                                        bg='white', fg='#333333')
                    ic_label.grid(row=2, column=0, sticky='w', padx=15, pady=5)

                    gender_label = tk.Label(card_frame, text=f"   Gender: {patient_gender}", font=('Open Sans', 12),
                                            bg='white', fg='#333333')
                    gender_label.grid(row=3, column=0, sticky='w', padx=15, pady=5)

                    date_label = tk.Label(card_frame, text=f"   Date: {ar_date_str}", font=('Open Sans', 12), bg='white',
                                          fg='#333333')
                    date_label.grid(row=4, column=0, sticky='w', padx=15, pady=5)

                    time_label = tk.Label(card_frame, text=f"   Time: {ar_time_str}", font=('Open Sans', 12), bg='white',
                                          fg='#333333')
                    time_label.grid(row=5, column=0, sticky='w', padx=15, pady=5)

                    contact_label = tk.Label(card_frame, text=f"   Contact Number: {patient_contact}", font=('Open Sans', 12),
                                             bg='white', fg='#333333')
                    contact_label.grid(row=6, column=0, sticky='w', padx=15, pady=5)

                    doctor_label = tk.Label(card_frame, text="Doctor:", font=('Open Sans', 12), bg='white', fg='#333333')
                    doctor_label.grid(row=1, column=2, sticky='w', padx=15, pady=5)

                    doctor_combo = ttk.Combobox(card_frame, font=('Open Sans', 12), state="readonly")
                    if doctor_name != 'Select a doctor':
                        # A specific doctor is assigned by the user, so the clinic admin cannot modify on it
                        doctor_names.append(f'{doctor_id}.  {doctor_name}')
                        doctor_combo['values'] = doctor_names
                        doctor_combo.set(f'{doctor_id}.  {doctor_name}')
                        doctor_combo.config(state="disabled")
                    else:
                        # Set up the combobox with available doctors
                        doctor_combo['values'] = doctor_names
                        doctor_combo.set(doctor_name)
                    doctor_combo.grid(row=1, column=3, sticky='e', padx=20, pady=5)

                    description_label = tk.Label(card_frame, text="Description:", font=('Open Sans', 12), bg='white',
                                                 fg='#333333')
                    description_label.grid(row=2, column=2, sticky='w', padx=15, pady=5)

                    description_frame = tk.Frame(card_frame)
                    description_frame.grid(row=3, column=2, rowspan=4, columnspan=2, sticky='w', padx=20, pady=5)

                    description_text = tk.Text(description_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=40,
                                               height=6, borderwidth=1, relief='solid')
                    if ar_details is not None:
                        description_text.insert('1.0', ar_details)
                    description_text.config(state=tk.DISABLED)
                    description_text.pack(side="left", fill="both", expand=True)

                    text_scrollbar = tk.Scrollbar(description_frame, command=description_text.yview)
                    text_scrollbar.pack(side="right", fill="y")

                    description_text.config(yscrollcommand=text_scrollbar.set)

                    address_label = tk.Label(card_frame, text="   Address:", font=('Open Sans', 12), bg='white',
                                             fg='#333333')
                    address_label.grid(row=7, column=0, sticky='w', padx=15, pady=5)
                    address_frame = tk.Frame(card_frame)
                    address_frame.grid(row=8, column=0, columnspan=5, sticky='w', padx=(30, 20), pady=5)
                    address_text = tk.Text(address_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=102,
                                           height=3, borderwidth=1, relief='solid')
                    address_text.insert('1.0', patient_address)
                    address_text.config(state=tk.DISABLED)
                    address_text.pack(side="left", fill="both", expand=True)
                    address_scrollbar = tk.Scrollbar(address_frame, command=address_text.yview)
                    address_scrollbar.pack(side="right", fill="y")
                    address_text.config(yscrollcommand=address_scrollbar.set)

                    # Creation of reject and accept buttons
                    if ar_status == 'pending':
                        reject_button = tk.Button(card_frame, text='Reject', font=('Open Sans', 12, 'bold'), bg='#F5443E',
                                                  fg='white', width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                                  command=lambda ar_id=ar_id,
                                                                 card_frame=card_frame: show_reject_reason(ar_id, card_frame))
                        reject_button.grid(row=9, column=0, sticky='w', padx=15, pady=10)

                        accept_button = tk.Button(card_frame, text='Accept', font=('Open Sans', 12, 'bold'), bg='#00C196',
                                                  fg='white', width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                                  command=lambda ar_time=ar_time, ar_date=ar_date, ar_id=ar_id, combo=doctor_combo:
                                                          accept_appointment(ar_time, ar_date, ar_id, combo))
                        accept_button.grid(row=9, column=3, sticky='e', padx=15, pady=10)

            self.switch('appointment', self.all_appointment_frame)

        # Display the entry for entering reject reason, confirm button and cancel button
        def show_reject_reason(ar_id, card_frame):
            # Ensure the clinic admin has entered a reason
            # Update the database with the reason
            def reject_appointment():
                if reject_reason_entry.cget('fg') == '#333333' and reject_reason_entry.get().strip() != '':
                    reject_reason = reject_reason_entry.get()

                    update_query = "UPDATE appointment_request SET ar_status = 'rejected', ar_ifreject = %s WHERE ar_id = %s"
                    self.cursor.execute(update_query, (reject_reason, ar_id))
                    database.commit()

                    display_appointments()
                else:
                    messagebox.showerror('Error', 'Please fill in reject reason')

            # Destroy those extra widgets for rejecting
            def cancel_reject():
                reject_reason_entry.destroy()
                cancel_button.destroy()
                confirm_button.destroy()

                self.switch('appointment', self.all_appointment_frame)

            reject_reason_entry = tk.Entry(card_frame, font=('Open Sans', 12), bg='#E0FCF8', fg='#858585')
            reject_reason_entry.grid(row=10, column=0, sticky='ew', padx=10, pady=(5, 15), columnspan=5)
            reject_reason_entry.insert(0, 'Fill in reject reason')
            reject_reason_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', reject_reason_entry))
            reject_reason_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', reject_reason_entry,
                                                                                        'Fill in reject reason'))

            cancel_button = tk.Button(card_frame, text='Cancel', font=('Open Sans', 12, 'bold'), bg='#F5443E', fg='white',
                                      width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                      command=lambda: cancel_reject())
            cancel_button.grid(row=9, column=0, sticky='w', padx=15, pady=10)

            confirm_button = tk.Button(card_frame, text='Confirm', font=('Open Sans', 12, 'bold'), bg='#00C196', fg='white',
                                       width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                       command=lambda: reject_appointment())
            confirm_button.grid(row=9, column=3, sticky='e', padx=15, pady=10)

            self.switch('appointment', self.all_appointment_frame)

        # Validates the requirements for the clinic admin to accept an appointment successfully
        def accept_appointment(ar_time, ar_date, ar_id, combo):
            try:
                selected_doctor = combo.get()
                # Each appointment must assign with a doctor
                if selected_doctor == 'Select a doctor':
                    messagebox.showerror('Error', 'Please select a doctor')
                    return

                doctor_id = int(selected_doctor.split('.')[0])

                # Each doctor can only have one appointment at the identical datetime
                cursor.execute('''SELECT a.appointment_id 
                               FROM appointment a 
                               LEFT JOIN appointment_request ar ON ar.ar_id = a.ar_id
                               WHERE ar.ar_date=%s AND ar.ar_time=%s AND ar.ar_status='ongoing' AND a.doctor_id=%s''',
                               (ar_date, ar_time, doctor_id))
                exist = cursor.fetchone()

                if exist is None:
                    # Update the appointment_request table
                    assign_query = """UPDATE appointment_request
                                      SET ar_status = 'ongoing', ar_doctor = 1
                                      WHERE ar_id = %s"""
                    self.cursor.execute(assign_query, (ar_id,))
                    database.commit()

                    cursor.execute('''SELECT appointment_id FROM appointment WHERE ar_id=%s''', (ar_id, ))
                    appointment_id = cursor.fetchone()

                    # If the appointment initially is not with specified doctor
                    if appointment_id is None:
                        insert_query = """INSERT INTO appointment (appointment_prescription, appointment_complete, ar_id, doctor_id)
                                          VALUES (%s, %s, %s, %s)"""
                        self.cursor.execute(insert_query, (None, 0, ar_id, doctor_id))
                        database.commit()
                    else:
                        pass
                else:
                    messagebox.showerror('Error', 'The doctor is booked at that time')

                display_appointments()

            except Exception as e:
                print(f"Error accepting appointment: {e}")

        for widget in self.appointment_frame.winfo_children():
            widget.destroy()

        # Create a canvas and a scrollbar
        appointment_canvas = tk.Canvas(self.appointment_frame, borderwidth=0, background="#ffffff", width=1030, height=600,
                                       highlightthickness=0)
        appointment_canvas.pack(side="left", fill="both", expand=True)
        appointment_scrollbar = tk.Scrollbar(self.appointment_frame, orient="vertical", command=appointment_canvas.yview)
        appointment_scrollbar.pack(side="right", fill="y")
        appointment_canvas.configure(yscrollcommand=appointment_scrollbar.set)
        appointment_scrollable_frame = tk.Frame(appointment_canvas, background="#ffffff")
        appointment_canvas.create_window((0, 0), window=appointment_scrollable_frame, anchor="nw")
        self.all_appointment_frame['appointment'] = [self.appointment_frame, appointment_canvas, appointment_scrollable_frame, 0]

        display_appointments()

    def set_up_timetable_frame(self):
        def show_calendar():
            calendar_frame.place(x=150, y=85)
            calendar_frame.lift()

        def hide_calendar():
            calendar_frame.place_forget()

        # Get the selected date on calendar, format it and configure to the date label
        def select_date():
            selected_date = cal.get_date()
            selected_date = self.format_date(str(selected_date))
            date_entry.config(text=selected_date, fg='#333333')
            hide_calendar()

        # Fetch all doctors of the clinic, both active and inactive
        def fetch_doctors():
            cursor.execute('''SELECT doctor_id, doctor_name, doctor_status FROM doctor WHERE clinic_id=%s
                           ORDER BY doctor_status DESC, doctor_name ASC''', (self.clinic_id,))
            doctors = cursor.fetchall()
            return doctors

        def select_doctor(d):
            self.select_menu_option(doctor_entry, d[1])
            self.doctor_id = d[0]

        # View timetable of selected date and doctor
        def view_appointments():
            def fetch_doctor_workinghours():
                cursor.execute('''SELECT doctor_working_hour FROM doctor WHERE doctor_id=%s''', (self.doctor_id, ))
                workinghours = cursor.fetchone()
                return workinghours[0] if workinghours else None

            # Retrieve ongoing appointments
            def fetch_appointments(date):
                cursor.execute('''SELECT ar_time FROM appointment_request ar
                               JOIN appointment a ON ar.ar_id = a.ar_id
                               WHERE ar.ar_date = %s AND a.doctor_id = %s
                               AND ar.ar_status = 'ongoing' AND a.appointment_complete = 0''',
                               (date, self.doctor_id))
                appointments = cursor.fetchall()
                return [appointment[0] for appointment in appointments]

            def parse_doctor_workinghours(workinghours):
                time_format_12 = '%I%p'
                # Parse the working hours
                parts = workinghours.split(', ')
                if len(parts) > 2:
                    working_hour = parts[1].split('-')
                    start_work = working_hour[0].strip()
                    start_work = datetime.strptime(start_work, time_format_12).time()
                    end_work = working_hour[1].strip()
                    end_work = datetime.strptime(end_work, time_format_12) - timedelta(hours=1)
                    end_work = end_work.time()
                    rest_days = parts[2].split()[-1]
                    whole = [start_work, end_work, rest_days]
                elif len(parts) > 1:
                    working_hour = parts[1].split('-')
                    start_work = working_hour[0].strip()
                    start_work = datetime.strptime(start_work, time_format_12).time()
                    end_work = working_hour[1].strip()
                    end_work = datetime.strptime(end_work, time_format_12) - timedelta(hours=1)
                    end_work = end_work.time()
                    whole = [start_work, end_work]
                else:
                    whole = []
                return whole

            hide_calendar()
            selected_date = date_entry.cget('text')
            selected_doctor = doctor_entry.cget('text')

            # Ensure both date and doctor are selected
            if not selected_date or not selected_doctor or selected_date == 'Select Date' or selected_doctor == 'Select Doctor':
                doctor_name_label.configure(fg='red', text='Please choose a date and a doctor')
                tree.place_forget()
                return

            current_date = datetime.now().date()
            # Parse the date string into a datetime object
            date_obj = datetime.strptime(selected_date, '%d %B %Y')
            # Format the datetime object into the desired string format
            formatted_date = date_obj.strftime('%Y-%m-%d')
            selected_date_obj = datetime.strptime(formatted_date, '%Y-%m-%d').date()
            # Error if the chosen date is passed
            if selected_date_obj < current_date:
                doctor_name_label.configure(fg='red', text='The selected date is passed. Please choose a valid date')
                tree.place_forget()
                return

            cursor.execute('''SELECT clinic_operation FROM clinic WHERE clinic_id=%s''', (self.clinic_id,))
            c_operation = cursor.fetchone()[0]
            c_operation = c_operation.split(', ')
            # Error if chosen date is clinic rest day
            if len(c_operation) > 2:
                c_rest = c_operation[2].split()[-1]
                if selected_date_obj.strftime('%A') == c_rest:
                    doctor_name_label.configure(fg='red', text=f'Your clinic is rest on {c_rest}')
                    tree.place_forget()
                    return

            doctor_workinghours = fetch_doctor_workinghours()
            working_list = parse_doctor_workinghours(doctor_workinghours)
            # Error if chosen date is the doctor rest day
            if working_list and len(working_list) > 2:
                if selected_date_obj.strftime('%A') == working_list[2]:
                    doctor_name_label.configure(fg='red', text=f'{selected_doctor} is rest on {working_list[2]}')
                    tree.place_forget()
                    return

            doctor_name_label.configure(fg='#333333', text=selected_doctor + '   ' + selected_date)

            # Fetch ongoing appointments for the selected date and doctor
            appointments = fetch_appointments(selected_date_obj)
            # Convert database fetched times to datetime.time objects
            appointment_times = [datetime.strptime(str(app_time), '%H:%M:%S').time() for app_time in appointments]

            # Standard time slots from 08:00 to 20:00
            time_slots = [time(hour, 0, 0) for hour in range(8, 21)]  # 8 AM to 8 PM

            # Clear the treeview
            for item in tree.get_children():
                tree.delete(item)

            # Determine the doctor working hours, if no determine the clinic operation hours
            start = None  # Start working / operate time
            end = None  # End working / operate time
            if working_list and len(working_list) > 1:
                start = working_list[0]
                end = working_list[1]
            else:
                if len(c_operation) > 1 and c_operation[1] != '24 hours':
                    time_format_12 = '%I%p'
                    operation_hour = c_operation[1].split('-')
                    start_operate = operation_hour[0].strip()
                    start = datetime.strptime(start_operate, time_format_12).time()
                    end_operate = operation_hour[1].strip()
                    end_operate = datetime.strptime(end_operate, time_format_12) - timedelta(hours=1)
                    end = end_operate.time()

            for time_slot in time_slots:
                if start and end:
                    # Make all time slots within the working / operation hours available
                    if start <= time_slot <= end:
                        status = 'Available'
                        tag = 'Available'
                        # Update time slots to booked if there is an ongoing appointments
                        if time_slot in appointment_times:
                            status = 'Booked'
                            tag = 'Booked'
                    # Otherwise the time slots exceed the range are all label as not on shift
                    else:
                        status = 'Not on shift'
                        tag = 'Not on shift'
                        # There might be a case like sudden change of working hours or operation hours
                        # This not on shift (booked) is to notify the clinic that the doctor has an ongoing appointment on the time slot
                        # Even it is not in the working / operation range
                        if time_slot in appointment_times:
                            status = 'Not on shift (Booked)'
                            tag = 'Not on shift (Booked)'
                # If not working / operation hours provided, 8am-8pm all available
                # Except for ongoing appointments on certain time slots
                else:
                    if time_slot in appointment_times:
                        status = 'Booked'
                        tag = 'Booked'
                    else:
                        status = 'Available'
                        tag = 'Available'
                # Insert the treeview row by row
                formatted_time = time_slot.strftime('%I%p').lstrip('0').lower()
                tree.insert("", tk.END, values=(formatted_time, status), tags=(tag,))

            tree.place(x=120, y=150)

        for widget in self.timetable_frame.winfo_children():
            widget.destroy()

        date_doctor_frame = tk.Frame(self.timetable_frame, width=1050, height=510, bg='white')
        date_doctor_frame.place(x=0, y=0)

        date_label = tk.Label(date_doctor_frame, text="Date:", font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        date_label.place(x=100, y=50)
        doctor_label = tk.Label(date_doctor_frame, text="Doctor:", font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        doctor_label.place(x=500, y=50)
        view_button = ttk.Button(date_doctor_frame, text='View', style='white_word.TButton', width=8, cursor='hand2',
                                 command=lambda: view_appointments())
        view_button.place(x=920, y=42)
        doctor_name_label = tk.Label(date_doctor_frame, text='', fg='#333333', font=('Open Sans', 12, 'bold'), bg='white',
                                     justify='center', width=90)
        doctor_name_label.place(x=70, y=120)
        columns = ("time", "status")
        tree = ttk.Treeview(date_doctor_frame, columns=columns, show='headings', height=13)
        tree.heading("time", text="Time")
        tree.heading("status", text="Appointment")
        tree.column("time", width=400, anchor=tk.CENTER)
        tree.column("status", width=400, anchor=tk.CENTER)
        # Define tag
        tree.tag_configure('Booked', foreground='red')
        tree.tag_configure('Not on shift', foreground='#858585')
        tree.tag_configure('Available', foreground='#333333')
        tree.tag_configure('Not on shift (Booked)', foreground='#858585')

        # Doctor selection dropdown
        doctor_entry_frame = tk.Frame(date_doctor_frame, bg='#D0F9EF', width=275, height=45)
        doctor_entry_frame.place(x=570, y=40)
        doctor_entry = tk.Label(doctor_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
        doctor_entry.place(x=10, y=10)
        doctor_entry.config(text='Select Doctor')

        doctor_button = ttk.Button(doctor_entry_frame, text='▼', style='selection.TButton', width=4, cursor='hand2',
                                   command=lambda: self.display_menu(doctor_entry_frame, 1, 40, doctor_menu))
        doctor_button.place(x=225, y=5)

        doctor_menu = tk.Menu(date_doctor_frame, tearoff=0, bg='#D0F9EF', fg='#333333', font=('Open Sans', 10))
        doctor_menu.delete(0, tk.END)
        doctor_names = fetch_doctors()
        for doctor in doctor_names:
            if doctor[2] == 1:
                doctor_menu.add_command(label=doctor[1], command=lambda d=doctor: select_doctor(d))
            elif doctor[2] == 0:
                # Add an inactive label if the doctor is in inactive status
                doctor_menu.add_command(label=doctor[1] + '  (Inactive)', command=lambda d=doctor: select_doctor(d))
        doctor_menu.add_separator()
        doctor_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t", command=doctor_menu.unpost)

        # Date selection dropdown
        date_entry_frame = tk.Frame(date_doctor_frame, bg='#D0F9EF', width=275, height=45)
        date_entry_frame.place(x=150, y=40)
        date_entry = tk.Label(date_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
        date_entry.place(x=10, y=10)
        date_entry.config(text='Select Date')

        calendar_button = ttk.Button(date_entry_frame, style='calendar.TButton', cursor='hand2', command=show_calendar)
        calendar_button.place(x=230, y=5)

        calendar_frame = tk.Frame(date_doctor_frame, bg='#D0F9EF', width=100, height=100)
        cal = Calendar(calendar_frame, selectmode='day', date_pattern='yyyy-mm-dd')
        cal.pack(pady=10)
        calendar_buttons_frame = tk.Frame(calendar_frame, bg='#D0F9EF')
        calendar_buttons_frame.pack()
        ttk.Button(calendar_buttons_frame, text="Select", command=select_date).pack(side='right', padx=28, pady=(0, 10))
        ttk.Button(calendar_buttons_frame, text="Cancel", command=hide_calendar).pack(side='left', padx=27, pady=(0, 10))

    def set_up_doctor_list_frame(self):
        def show_doctor_list():
            for widget in left_frame_content.winfo_children():
                widget.destroy()
            for widget in right_frame_content.winfo_children():
                widget.destroy()

            self.doctor_image_var = None

            # Set up the left frame (doctor buttons)
            cursor.execute('''SELECT doctor_id, doctor_name, doctor_status FROM doctor WHERE clinic_id=%s
                           ORDER BY doctor_status DESC, doctor_name ASC''', (self.clinic_id,))
            doctors = cursor.fetchall()

            # Populate left frame with doctors
            for doctor_id, doctor_name, doctor_status in doctors:
                button_style = 'c_black_word.TButton'
                if doctor_status == 0:
                    # If the doctor is inactive, appear grey colour button
                    button_style = 'inactive.TButton'

                doctor_button = ttk.Button(left_frame_content, text=doctor_name, style=button_style, cursor='hand2',
                                           width=20, padding=5,
                                           command=lambda doctor_id=doctor_id: show_doctor_details(doctor_id))
                doctor_button.pack(pady=5)

            decide_left_right_list()
            self.switch('doctor_list', self.all_doctor_list_frames)

        # Set up add new doctor frame
        def show_add_doctor_frame():
            # Validate the requirements for successful register a doctor account
            def register_doctor():
                if doctor_name_entry.cget('fg') == '#333333' and doctor_ic_passport_entry.cget('fg') == '#333333' \
                        and doctor_address_entry.cget('fg') == '#333333' and doctor_specialise_entry.cget('fg') == '#333333' \
                        and doctor_contact_entry.cget('fg') == '#333333' and doctor_image_entry.cget('fg') == '#333333' \
                        and doctor_email_entry.cget('fg') == '#333333' and doctor_password_entry.cget('fg') == '#333333' \
                        and doctor_confirmed_entry.cget('fg') == '#333333' and doctor_language_entry.cget('fg') == '#333333' \
                        and doctor_gender_entry.cget('fg') == '#333333' and doctor_working_hours_entry.cget('fg') == '#333333':
                    # Ensure the image format
                    img = self.doctor_image_var
                    if img.lower().endswith(('.jpg', '.jpeg', '.png')):
                        with open(img, 'rb') as file:
                            img_binary_data = file.read()
                        doctor_email = doctor_email_entry.get().lower()
                        if doctor_email.endswith('@gmail.com'):
                            cursor.execute('''SELECT user_email FROM user WHERE user_email=%s''', (doctor_email,))
                            existing_email = cursor.fetchone()
                            if not existing_email:
                                if len(doctor_password_entry.get()) >= 8:
                                    if doctor_password_entry.get() == doctor_confirmed_entry.get():
                                        doctor_validate_register_label.config(text='')
                                        cursor.execute(
                                            '''INSERT INTO user (user_email, user_password, user_type) VALUES (%s, %s, %s)''',
                                            (doctor_email, doctor_password_entry.get(), 'doctor'))
                                        database.commit()
                                        cursor.execute('''SELECT user_id FROM user WHERE user_email=%s''',
                                                       (doctor_email,))
                                        user_id = cursor.fetchone()
                                        if user_id:
                                            cursor.execute('''INSERT INTO doctor (doctor_name, doctor_gender, doctor_address, 
                                                           doctor_ic_passport, doctor_language, doctor_working_hour, doctor_contact, 
                                                           doctor_image, doctor_status, doctor_specialize, user_id, clinic_id) 
                                                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                                                           (doctor_name_entry.get(), doctor_gender_entry.cget('text'),
                                                            doctor_address_entry.get('1.0', 'end'), doctor_ic_passport_entry.get(),
                                                            doctor_language_entry.get(), doctor_working_hours_entry.get(),
                                                            doctor_contact_entry.get(), img_binary_data, 1,
                                                            doctor_specialise_entry.get(),
                                                            user_id[0], self.clinic_id))
                                            database.commit()
                                            messagebox.showinfo('Success', 'Register Doctor Account Successfully')
                                            # Directed back to the doctor list
                                            show_doctor_list()
                                    else:
                                        doctor_validate_register_label.config(text='Password does not match')
                                else:
                                    doctor_validate_register_label.config(text='Minimum 8 characters of Password')
                            else:
                                doctor_validate_register_label.config(text='Email exists, please try another')
                        else:
                            doctor_validate_register_label.config(text='Invalid email format')
                    else:
                        doctor_validate_register_label.config(text='Invalid image format')
                else:
                    doctor_validate_register_label.config(text='Please fill in all the details')

            for widget in doctor_entries_frame.winfo_children():
                widget.destroy()

            self.doctor_image_var = None

            # Add doctor Label
            add_doctor_label = tk.Label(doctor_entries_frame, text='Add Doctor',
                                        font=('Open Sans', 20, 'underline', 'bold'), bg='white', fg='#000000')
            add_doctor_label.grid(row=0, column=0, columnspan=2, padx=35, pady=(10, 15), sticky='w')

            # Entry for doctor name
            doctor_name_label = tk.Label(doctor_entries_frame, text='Doctor Name', font=('Open Sans', 12, 'bold'), bg='white',
                                         fg='#000000')
            doctor_name_label.grid(row=1, column=0, padx=50, pady=(5, 0), sticky='w')
            doctor_name_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_name_entry_frame.grid(row=2, column=0, padx=53, pady=(0, 5))
            doctor_name_entry = tk.Entry(doctor_name_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                         width=42)
            doctor_name_entry.place(x=10, y=13)
            doctor_name_entry.insert(0, 'Enter Doctor Name')
            doctor_name_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', doctor_name_entry))
            doctor_name_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', doctor_name_entry, 'Enter Doctor Name'))
            doctor_name_entry.bind('<Return>', lambda event: register_doctor())

            # Entry for IC or Passport Number
            doctor_ic_passport_label = tk.Label(doctor_entries_frame, text='IC or Passport Number',
                                                font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
            doctor_ic_passport_label.grid(row=3, column=0, padx=50, pady=(5, 0), sticky='w')
            doctor_ic_passport_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_ic_passport_entry_frame.grid(row=4, column=0, padx=53, pady=(0, 5))
            doctor_ic_passport_entry = tk.Entry(doctor_ic_passport_entry_frame, font=('Open Sans', 10), bg='#D0F9EF',
                                                fg='#858585', border=0, width=42)
            doctor_ic_passport_entry.place(x=10, y=13)
            doctor_ic_passport_entry.insert(0, 'Enter IC or Passport Number')
            doctor_ic_passport_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', doctor_ic_passport_entry))
            doctor_ic_passport_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', doctor_ic_passport_entry,
                                                                                             'Enter IC or Passport Number'))
            doctor_ic_passport_entry.bind('<Return>', lambda event: register_doctor())

            # Entry for gender
            doctor_gender_label = tk.Label(doctor_entries_frame, text='Gender', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
            doctor_gender_label.grid(row=5, column=0, padx=50, pady=(5, 0), sticky='w')
            doctor_gender_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_gender_entry_frame.grid(row=6, column=0, padx=53, pady=(0, 5))
            doctor_gender_entry = tk.Label(doctor_gender_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
            doctor_gender_entry.place(x=9, y=10)
            doctor_gender_entry.config(text='Select Gender')
            doctor_gender_button = ttk.Button(doctor_gender_entry_frame, text='▼', style='selection.TButton', width=4, cursor='hand2',
                                              command=lambda: self.display_menu(doctor_gender_entry_frame, 1, 40, doctor_gender_menu))
            doctor_gender_button.place(x=320, y=5)
            doctor_gender_menu = tk.Menu(doctor_entries_frame, tearoff=0, bg='#D0F9EF', fg='#333333', font=('Open Sans', 10))
            doctor_gender_menu.add_command(label="Male", command=lambda: self.select_menu_option(doctor_gender_entry, 'Male'))
            doctor_gender_menu.add_command(label="Female", command=lambda: self.select_menu_option(doctor_gender_entry, 'Female'))
            doctor_gender_menu.add_separator()
            doctor_gender_menu.add_command(label="Clear", command=lambda: self.select_menu_option(doctor_gender_entry, 'Clear',
                                                                                                  'Select Gender'))
            doctor_gender_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t   ",
                                           command=doctor_gender_menu.unpost)

            # Entry for address
            doctor_address_label = tk.Label(doctor_entries_frame, text='Address', font=('Open Sans', 12, 'bold'), bg='white',
                                            fg='#000000')
            doctor_address_label.grid(row=13, column=0, padx=50, pady=(5, 0), sticky='w')
            doctor_address_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=85)
            doctor_address_entry_frame.grid(row=14, column=0, padx=53, pady=(0, 40))
            doctor_address_entry = tk.Text(doctor_address_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                           border=0, width=42, height=4, wrap='word')
            doctor_address_entry.place(x=10, y=13)
            doctor_address_entry.insert('1.0', 'Enter Address')
            doctor_address_entry.bind('<FocusIn>', lambda event: self.focus_entry('text', doctor_address_entry))
            doctor_address_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('text', doctor_address_entry, 'Enter Address'))
            doctor_address_entry.bind('<Return>', lambda event: register_doctor())

            # Entry for language
            doctor_language_label = tk.Label(doctor_entries_frame, text='Language', font=('Open Sans', 12, 'bold'),
                                             bg='white', fg='#000000')
            doctor_language_label.grid(row=9, column=0, padx=50, pady=(5, 0), sticky='w')
            doctor_language_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_language_entry_frame.grid(row=10, column=0, padx=53, pady=(0, 5))
            doctor_language_entry = tk.Entry(doctor_language_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                             border=0, width=42)
            doctor_language_entry.place(x=10, y=13)
            doctor_language_entry.insert(0, 'Enter Language')
            doctor_language_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', doctor_language_entry))
            doctor_language_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', doctor_language_entry,
                                                                                          'Enter Language'))
            doctor_language_entry.bind('<Return>', lambda event: register_doctor())

            # Entry for working hours
            doctor_working_hours_label = tk.Label(doctor_entries_frame, text='Working Hours', font=('Open Sans', 12, 'bold'),
                                                  bg='white', fg='#000000')
            doctor_working_hours_label.grid(row=11, column=0, padx=50, pady=(5, 0), sticky='w')
            doctor_working_hours_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_working_hours_entry_frame.grid(row=12, column=0, padx=53, pady=(0, 5))
            doctor_working_hours_entry = tk.Entry(doctor_working_hours_entry_frame, font=('Open Sans', 10), bg='#D0F9EF',
                                                  fg='#858585', border=0, width=42)
            doctor_working_hours_entry.place(x=10, y=13)
            doctor_working_hours_entry.insert(0, 'Enter Working Hours')
            doctor_working_hours_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', doctor_working_hours_entry))
            doctor_working_hours_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', doctor_working_hours_entry,
                                                                                               'Enter Working Hours'))
            doctor_working_hours_entry.bind('<Return>', lambda event: register_doctor())

            # Entry for specialise in
            doctor_specialise_label = tk.Label(doctor_entries_frame, text='Specialize in',
                                               font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
            doctor_specialise_label.grid(row=7, column=0, padx=50, pady=(5, 0), sticky='w')
            doctor_specialise_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_specialise_entry_frame.grid(row=8, column=0, padx=53, pady=(0, 5))
            doctor_specialise_entry = tk.Entry(doctor_specialise_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                               border=0, width=42)
            doctor_specialise_entry.place(x=10, y=13)
            doctor_specialise_entry.insert(0, 'Enter Specialization')
            doctor_specialise_entry.bind('<FocusIn>',
                                         lambda event: self.focus_entry('entry', doctor_specialise_entry))
            doctor_specialise_entry.bind('<FocusOut>',
                                         lambda event: self.leave_focus_entry('entry', doctor_specialise_entry,
                                                                              'Enter Specialization'))
            doctor_specialise_entry.bind('<Return>', lambda event: register_doctor())

            # Entry for contact
            doctor_contact_label = tk.Label(doctor_entries_frame, text='Contact Number', font=('Open Sans', 12, 'bold'),
                                            bg='white', fg='#000000')
            doctor_contact_label.grid(row=1, column=4, padx=110, pady=(5, 0), sticky='w')
            doctor_contact_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_contact_entry_frame.grid(row=2, column=4, padx=113, pady=(0, 5))
            doctor_contact_entry = tk.Entry(doctor_contact_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                            border=0, width=42)
            doctor_contact_entry.place(x=10, y=12)
            doctor_contact_entry.insert(0, 'Enter Contact Number')
            doctor_contact_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', doctor_contact_entry))
            doctor_contact_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', doctor_contact_entry,
                                                                                         'Enter Contact Number'))
            doctor_contact_entry.bind('<Return>', lambda event: register_doctor())

            # Upload doctor image
            doctor_image_label = tk.Label(doctor_entries_frame, text='Image', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
            doctor_image_label.grid(row=3, column=4, padx=110, pady=(5, 0), sticky='w')
            doctor_image_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_image_entry_frame.grid(row=4, column=4, padx=113, pady=(0, 5))
            doctor_image_entry = tk.Label(doctor_image_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
            doctor_image_entry.place(x=8, y=10)
            doctor_image_entry.config(text='Upload Doctor Image')
            doctor_image_button = ttk.Button(doctor_image_entry_frame, text='⇫', style='selection.TButton', width=4,
                                             cursor='hand2', command=lambda: self.upload_doctor_image(doctor_image_entry, 60, 60,
                                                                                                      img_label))
            doctor_image_button.place(x=320, y=4)
            img_label = tk.Label(doctor_entries_frame, bg='white', anchor='w')
            img_label.grid(row=5, column=4, padx=113, pady=5, rowspan=2, sticky='w')

            # Entry for email
            doctor_email_label = tk.Label(doctor_entries_frame, text='Email', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
            doctor_email_label.grid(row=7, column=4, padx=110, pady=(5, 0), sticky='w')
            doctor_email_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_email_entry_frame.grid(row=8, column=4, padx=113, pady=(0, 5))
            doctor_email_entry = tk.Entry(doctor_email_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                          border=0, width=42)
            doctor_email_entry.place(x=10, y=12)
            doctor_email_entry.insert(0, 'Enter Email')
            doctor_email_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', doctor_email_entry))
            doctor_email_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', doctor_email_entry, 'Enter Email'))
            doctor_email_entry.bind('<Return>', lambda event: register_doctor())

            # Entry for password
            doctor_password_label = tk.Label(doctor_entries_frame, text='Password', font=('Open Sans', 12, 'bold'), bg='white',
                                             fg='#000000')
            doctor_password_label.grid(row=9, column=4, padx=110, pady=(5, 0), sticky='w')
            doctor_password_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_password_entry_frame.grid(row=10, column=4, padx=113, pady=(0, 5))
            doctor_password_entry = tk.Entry(doctor_password_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                             border=0, width=42, show='')
            doctor_password_entry.place(x=10, y=12)
            doctor_password_entry.insert(0, 'Enter Password')
            doctor_password_eye_closed_button = ttk.Button(doctor_password_entry_frame, style='eye_closed_green.TButton',
                                                           cursor='hand2')
            doctor_password_eye_closed_button.place(x=330, y=2)
            doctor_password_eye_opened_button = ttk.Button(doctor_password_entry_frame, style='eye_opened_green.TButton',
                                                           cursor='hand2')
            doctor_password_visibility = tk.Label(doctor_password_entry_frame, text='Close')
            doctor_password_eye_closed_button.config(command=lambda: self.show_hide_password(doctor_password_entry,
                                                                                             doctor_password_eye_opened_button,
                                                                                             doctor_password_eye_closed_button,
                                                                                             doctor_password_visibility))
            doctor_password_eye_opened_button.config(command=lambda: self.show_hide_password(doctor_password_entry,
                                                                                             doctor_password_eye_opened_button,
                                                                                             doctor_password_eye_closed_button,
                                                                                             doctor_password_visibility))
            doctor_password_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', doctor_password_entry,
                                                                                   doctor_password_visibility))
            doctor_password_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', doctor_password_entry,
                                                                                          'Enter Password'))
            doctor_password_entry.bind('<Return>', lambda event: register_doctor())

            # Entry for confirmed Password
            doctor_confirmed_label = tk.Label(doctor_entries_frame, text='Confirm Password', font=('Open Sans', 12, 'bold'),
                                              bg='white', fg='#000000')
            doctor_confirmed_label.grid(row=11, column=4, padx=110, pady=(5, 0), sticky='w')
            doctor_confirmed_entry_frame = tk.Frame(doctor_entries_frame, bg='#D0F9EF', width=380, height=45)
            doctor_confirmed_entry_frame.grid(row=12, column=4, padx=113, pady=(0, 5))
            doctor_confirmed_entry = tk.Entry(doctor_confirmed_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                              border=0, width=42, show='')
            doctor_confirmed_entry.place(x=10, y=12)
            doctor_confirmed_entry.insert(0, 'Re-enter Password')
            doctor_confirmed_eye_closed_button = ttk.Button(doctor_confirmed_entry_frame, style='eye_closed_green.TButton',
                                                            cursor='hand2')
            doctor_confirmed_eye_closed_button.place(x=330, y=2)
            doctor_confirmed_eye_opened_button = ttk.Button(doctor_confirmed_entry_frame, style='eye_opened_green.TButton',
                                                            cursor='hand2')
            doctor_confirmed_visibility = tk.Label(doctor_confirmed_entry_frame, text='Close')
            doctor_confirmed_eye_closed_button.config(command=lambda: self.show_hide_password(doctor_confirmed_entry,
                                                                                              doctor_confirmed_eye_opened_button,
                                                                                              doctor_confirmed_eye_closed_button,
                                                                                              doctor_confirmed_visibility))
            doctor_confirmed_eye_opened_button.config(command=lambda: self.show_hide_password(doctor_confirmed_entry,
                                                                                              doctor_confirmed_eye_opened_button,
                                                                                              doctor_confirmed_eye_closed_button,
                                                                                              doctor_confirmed_visibility))
            doctor_confirmed_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', doctor_confirmed_entry,
                                                                                    doctor_confirmed_visibility))
            doctor_confirmed_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', doctor_confirmed_entry,
                                                                                           'Re-enter Password'))
            doctor_confirmed_entry.bind('<Return>', lambda event: register_doctor())

            doctor_validate_register_label = tk.Label(add_back_frame, text='', font=('Open Sans', 8), anchor='e', width=30,
                                                      bg='white', fg='red')
            doctor_validate_register_label.place(x=700, y=30)

            add_button.config(command=lambda: register_doctor())

            decide_left_right_list()
            self.switch('new_doctor', self.all_doctor_list_frames)
            doctor_entries_canvas.yview_moveto(0)

        # Set up the right frame (doctor details)
        def show_doctor_details(doctor_id):
            # Enable necessary entries and buttons
            def edit_doctor_details():
                d_name_entry.config(state='normal', fg='#333333')
                d_image_entry.config(fg='#333333')
                d_image_button.config(state='normal')
                d_ic_passport_entry.config(state='normal', fg='#333333')
                d_gender_entry.config(fg='#333333')
                d_gender_button.config(state='normal')
                d_contact_entry.config(state='normal', fg='#333333')
                d_address_entry.config(state='normal', fg='#333333')
                d_language_entry.config(state='normal', fg='#333333')
                d_working_hours_entry.config(state='normal', fg='#333333')
                d_specialise_entry.config(state='normal', fg='#333333')
                d_status_button.config(state='normal')
                d_status_entry.config(fg='#333333')

                save_button.grid(row=0, column=0, padx=20, pady=5, sticky='e', columnspan=2)
                edit_button.grid_forget()

            # Validate the input before updating them in the database
            def save_doctor_details():
                # Check if all entry boxes have black foreground color (#333333)
                if all([entry.cget('fg') == '#333333' for entry in [d_name_entry, d_ic_passport_entry, d_image_entry, d_gender_entry,
                                                                    d_address_entry, d_language_entry, d_contact_entry,
                                                                    d_working_hours_entry, d_specialise_entry, d_status_entry]]):
                    d_name = d_name_entry.get()
                    d_ic_passport = d_ic_passport_entry.get()
                    d_gender = d_gender_entry.cget('text')
                    d_contact = d_contact_entry.get()
                    d_address = d_address_entry.get('1.0', 'end-1c')
                    d_language = d_language_entry.get()
                    d_working_hours = d_working_hours_entry.get()
                    d_specialise = d_specialise_entry.get()
                    d_status = 1 if d_status_entry.cget('text').lower() == "active" else 0

                    img_binary_data = None
                    # Check if a new image has been selected
                    if self.doctor_image_var:
                        img = self.doctor_image_var
                        if img.lower().endswith(('.jpg', '.jpeg', '.png')):
                            with open(img, 'rb') as file:
                                img_binary_data = file.read()

                    # Perform data validation
                    if all([d_name, d_ic_passport, d_gender, d_contact, d_address, d_language, d_working_hours, d_specialise]):
                        # If the clinic update doctor image
                        if img_binary_data is not None:
                            cursor.execute('''UPDATE doctor
                                           SET doctor_name=%s, doctor_address=%s, doctor_ic_passport=%s, doctor_language=%s,
                                           doctor_working_hour=%s, doctor_contact=%s, doctor_specialize=%s, doctor_image=%s,
                                           doctor_gender=%s, doctor_status=%s
                                           WHERE doctor_id = %s''',
                                           (d_name, d_address, d_ic_passport, d_language, d_working_hours, d_contact,
                                            d_specialise, img_binary_data, d_gender, d_status, doctor_id))
                        else:
                            cursor.execute('''UPDATE doctor
                                           SET doctor_name=%s, doctor_address=%s, doctor_ic_passport=%s, doctor_language=%s,
                                           doctor_working_hour=%s, doctor_contact=%s, doctor_specialize=%s,
                                           doctor_gender=%s, doctor_status=%s
                                           WHERE doctor_id = %s''',
                                           (d_name, d_address, d_ic_passport, d_language, d_working_hours,
                                            d_contact, d_specialise, d_gender, d_status, doctor_id))
                        database.commit()
                        edit_button.grid(row=0, column=0, padx=20, pady=5, sticky='e', columnspan=2)
                        save_button.grid_forget()

                        messagebox.showinfo('Success', 'Doctor details updated successfully')

                        show_doctor_list()
                        show_doctor_details(doctor_id)
                    else:
                        messagebox.showerror('Error', 'Please fill in all the details')

            for widget in right_frame_content.winfo_children():
                widget.destroy()

            self.doctor_image_var = None

            # Ensure doctor_id is passed correctly
            cursor.execute('''
                           SELECT doctor.doctor_name, doctor.doctor_gender, doctor.doctor_address, doctor.doctor_ic_passport, 
                                  doctor.doctor_language, doctor.doctor_working_hour, doctor.doctor_contact, 
                                  doctor.doctor_specialize, user.user_email, doctor.doctor_image, doctor.doctor_status 
                           FROM doctor 
                           JOIN user ON doctor.user_id = user.user_id 
                           WHERE doctor.doctor_id = %s''', (doctor_id,))
            doctor = cursor.fetchone()
            if doctor:
                doctor_name, doctor_gender, doctor_address, doctor_ic_passport, doctor_language, \
                    doctor_working_hour, doctor_contact, doctor_specialise, doctor_email, doctor_image, doctor_status = doctor

                d_information_title = tk.Label(right_frame_content, text='Doctor Information', bg='white',
                                               font=('Open Sans', 12, 'bold', 'underline'), width=65)
                d_information_title.grid(row=0, column=0, columnspan=2, padx=15)

                # Edit button
                edit_button = ttk.Button(right_frame_content, text='Edit', style='white_word.TButton', width=5, cursor='hand2',
                                         command=lambda: edit_doctor_details())
                edit_button.grid(row=0, column=0, padx=20, pady=5, sticky='e', columnspan=2)

                save_button = ttk.Button(right_frame_content, text='Save', style='white_word.TButton', width=5,
                                         cursor='hand2', command=lambda: save_doctor_details())

                d_email = tk.Label(right_frame_content, text="Email:", bg='white', font=("Open Sans", 12))
                d_email.grid(row=1, column=0, padx=15, pady=5, sticky='e')
                d_email_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_email_entry_frame.grid(row=1, column=1, padx=25, pady=5, sticky='w')
                d_email_entry = tk.Entry(d_email_entry_frame, font=('Open Sans', 10), bg='#D0F9EF',
                                         fg='#858585', border=0)
                d_email_entry.insert(0, doctor_email)
                d_email_entry.place(x=10, y=6)
                d_email_entry.config(state='disabled', disabledbackground='#D0F9EF')

                # Display the details in entry widgets
                d_name_label = tk.Label(right_frame_content, text="Doctor Name:", bg='white', font=("Open Sans", 12))
                d_name_label.grid(row=2, column=0, padx=15, pady=5, sticky='e')
                d_name_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_name_entry_frame.grid(row=2, column=1, padx=25, pady=5, sticky='w')
                d_name_entry = tk.Entry(d_name_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0, width=48)
                d_name_entry.insert(0, doctor_name)
                d_name_entry.place(x=10, y=6)
                d_name_entry.config(state='disabled', disabledbackground='#D0F9EF')

                # Display the filename in the entry box
                d_image_label = tk.Label(right_frame_content, text="Image:", bg='white', font=("Open Sans", 12))
                d_image_label.grid(row=3, column=0, padx=15, pady=5, sticky='e')
                d_image_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_image_entry_frame.grid(row=3, column=1, padx=25, pady=5, sticky='w')
                d_image_entry = tk.Label(d_image_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                         width=48, justify='left', anchor='w')
                d_image_entry.place(x=10, y=6)
                file_type = detect_image_format(doctor_image) or 'img'
                d_image_entry.config(text=f"{doctor_name}.{file_type}")
                d_image_button = ttk.Button(d_image_entry_frame, text='⇫', style='selection.TButton', width=4, cursor='hand2',
                                            command=lambda: self.upload_doctor_image(d_image_entry, 100, 100, img_label))
                d_image_button.place(x=350, y=0)
                d_image_button.config(state='disabled')

                img_label = tk.Label(right_frame_content, bg='white', anchor='w')
                img_label.grid(row=4, column=1, padx=25, pady=5, sticky='w')
                img = Image.open(io.BytesIO(doctor_image))
                img = img.resize((100, 100), Image.LANCZOS)
                img = ImageTk.PhotoImage(img)
                img_label.config(image=img)
                img_label.image = img

                d_ic_passport = tk.Label(right_frame_content, text="IC/Passport Number:", bg='white',
                                         font=("Open Sans", 12))
                d_ic_passport.grid(row=5, column=0, padx=15, pady=5, sticky='e')
                d_ic_passport_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_ic_passport_entry_frame.grid(row=5, column=1, padx=25, pady=5, sticky='w')
                d_ic_passport_entry = tk.Entry(d_ic_passport_entry_frame, font=('Open Sans', 10), bg='#D0F9EF',
                                               fg='#858585', border=0, width=48)
                d_ic_passport_entry.insert(0, doctor_ic_passport)
                d_ic_passport_entry.place(x=10, y=6)
                d_ic_passport_entry.config(state='disabled', disabledbackground='#D0F9EF')

                d_gender_label = tk.Label(right_frame_content, text='Gender:', font=("Open Sans", 12), bg='white')
                d_gender_label.grid(row=6, column=0, padx=15, pady=5, sticky='e')
                d_gender_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_gender_entry_frame.grid(row=6, column=1, padx=25, pady=5, sticky='w')
                d_gender_entry = tk.Label(d_gender_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
                d_gender_entry.place(x=8, y=4)
                d_gender_entry.config(text=doctor_gender)
                d_gender_button = ttk.Button(d_gender_entry_frame, text='▼', style='selection.TButton', width=4,
                                             cursor='hand2', command=lambda: self.display_menu(d_gender_entry_frame, 0, 27,
                                                                                               d_gender_menu))
                d_gender_button.place(x=350, y=0)
                d_gender_menu = tk.Menu(right_frame_content, tearoff=0, bg='#D0F9EF', fg='#333333',
                                        font=('Open Sans', 10))
                d_gender_menu.add_command(label="Male", command=lambda: self.select_menu_option(d_gender_entry, 'Male'))
                d_gender_menu.add_command(label="Female", command=lambda: self.select_menu_option(d_gender_entry, 'Female'))
                d_gender_menu.add_separator()
                d_gender_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ",
                                          command=d_gender_menu.unpost)
                d_gender_button.config(state='disabled')

                d_contact = tk.Label(right_frame_content, text="Contact Number:", bg='white',
                                     font=("Open Sans", 12))
                d_contact.grid(row=7, column=0, padx=15, pady=5, sticky='e')
                d_contact_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_contact_entry_frame.grid(row=7, column=1, padx=25, pady=5, sticky='w')
                d_contact_entry = tk.Entry(d_contact_entry_frame, font=('Open Sans', 10), bg='#D0F9EF',
                                           fg='#858585', border=0, width=48)
                d_contact_entry.insert(0, doctor_contact)
                d_contact_entry.place(x=10, y=6)
                d_contact_entry.config(state='disabled', disabledbackground='#D0F9EF')

                d_address = tk.Label(right_frame_content, text="Address:", bg='white', font=("Open Sans", 12))
                d_address.grid(row=8, column=0, padx=15, pady=5, sticky='ne')
                d_address_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=60)
                d_address_entry_frame.grid(row=8, column=1, padx=25, pady=5, sticky='w')
                d_address_entry = tk.Text(d_address_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                          border=0, width=48, height=3, wrap='word')
                d_address_entry.insert('1.0', doctor_address)
                d_address_entry.place(x=10, y=6)
                d_address_entry.config(state='disabled')

                d_language = tk.Label(right_frame_content, text="Language:", bg='white', font=("Open Sans", 12))
                d_language.grid(row=9, column=0, padx=15, pady=5, sticky='e')
                d_language_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_language_entry_frame.grid(row=9, column=1, padx=25, pady=5, sticky='w')
                d_language_entry = tk.Entry(d_language_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585',
                                           border=0, width=48)
                d_language_entry.insert(0, doctor_language)
                d_language_entry.place(x=10, y=6)
                d_language_entry.config(state='disabled', disabledbackground='#D0F9EF')

                d_workingHours = tk.Label(right_frame_content, text="Working Hours:", bg='white', font=("Open Sans", 12))
                d_workingHours.grid(row=10, column=0, padx=15, pady=5, sticky='e')
                d_working_hours_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_working_hours_entry_frame.grid(row=10, column=1, padx=25, pady=5, sticky='w')
                d_working_hours_entry = tk.Entry(d_working_hours_entry_frame, font=('Open Sans', 10), bg='#D0F9EF',
                                                fg='#858585', border=0, width=48)
                d_working_hours_entry.insert(0, doctor_working_hour)
                d_working_hours_entry.place(x=10, y=6)
                d_working_hours_entry.config(state='disabled', disabledbackground='#D0F9EF')

                d_specialise = tk.Label(right_frame_content, text="Specialize In:", bg='white', font=("Open Sans", 12))
                d_specialise.grid(row=11, column=0, padx=15, pady=5, sticky='e')
                d_specialise_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_specialise_entry_frame.grid(row=11, column=1, padx=25, pady=5, sticky='w')
                d_specialise_entry = tk.Entry(d_specialise_entry_frame, font=('Open Sans', 10), bg='#D0F9EF',
                                             fg='#858585', border=0, width=48)
                d_specialise_entry.insert(0, doctor_specialise)
                d_specialise_entry.place(x=10, y=6)
                d_specialise_entry.config(state='disabled', disabledbackground='#D0F9EF')

                d_status = tk.Label(right_frame_content, text="Status:", bg='white', font=("Open Sans", 12))
                d_status.grid(row=12, column=0, padx=15, pady=(5, 25), sticky='e')
                d_status_entry_frame = tk.Frame(right_frame_content, bg='#D0F9EF', width=400, height=30)
                d_status_entry_frame.grid(row=12, column=1, padx=25, pady=(5, 25), sticky='w')
                d_status_entry = tk.Label(d_status_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
                d_status_entry.place(x=8, y=4)
                d_status_text = "Active" if doctor_status == 1 else "Inactive"
                d_status_entry.config(text=d_status_text)
                d_status_button = ttk.Button(d_status_entry_frame, text='▼', style='selection.TButton', width=4, cursor='hand2',
                                             command=lambda: self.display_menu(d_status_entry_frame, 0, 27, d_status_menu))
                d_status_button.place(x=350, y=0)
                d_status_menu = tk.Menu(right_frame_content, tearoff=0, bg='#D0F9EF', fg='#333333',
                                        font=('Open Sans', 10))
                d_status_menu.add_command(label="Active", command=lambda: self.select_menu_option(d_status_entry, 'Active'))
                d_status_menu.add_command(label="Inactive",
                                          command=lambda: self.select_menu_option(d_status_entry, 'Inactive'))
                d_status_menu.add_separator()
                d_status_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ",
                                          command=d_status_menu.unpost)
                d_status_button.config(state='disabled')

                decide_left_right_list()
                self.switch('doctor_list', self.all_doctor_list_frames)
                right_canvas.yview_moveto(0)

        # Determine the scrollbar function for either left or right frame
        def decide_left_right_list():
            if len(right_frame_content.winfo_children()) == 0:
                self.all_doctor_list_frames['doctor_list'] = [doctor_list_frame, left_canvas, left_frame_content, 0]
            else:
                self.all_doctor_list_frames['doctor_list'] = [doctor_list_frame, right_canvas, right_frame_content, 0]

        for widget in self.doctor_list_frame.winfo_children():
            widget.destroy()

        # Doctor List Frame (right and left frame)
        doctor_list_frame = tk.Frame(self.doctor_list_frame, width=1050, height=510, bg='white')
        add_doctor_button = ttk.Button(doctor_list_frame, text='Add Doctor', style='white_word.TButton',
                                       cursor='hand2', width=15, padding=5, command=lambda: show_add_doctor_frame())
        add_doctor_button.place(x=840, y=20)

        doctor_frame = tk.Frame(doctor_list_frame, width=900, height=395, bg='white', highlightthickness=0.5)
        doctor_frame.place(x=80, y=80)

        left_frame = tk.Frame(doctor_frame, width=200, height=395, bg='white')
        left_frame.place(x=0, y=0)
        left_canvas = tk.Canvas(left_frame, width=200, height=395, bg='white', highlightthickness=0)
        left_canvas.place(x=0, y=0)
        left_scrollbar = tk.Scrollbar(left_frame, orient='vertical', command=left_canvas.yview)
        left_scrollbar.place(x=185, y=0, height=395)
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        left_frame_content = tk.Frame(left_canvas, bg='white')
        left_canvas.create_window((0, 0), window=left_frame_content, anchor='nw')

        right_frame = tk.Frame(doctor_frame, width=700, height=395, bg='white')
        right_frame.place(x=200, y=0)
        right_canvas = tk.Canvas(right_frame, width=700, height=395, bg='white', highlightthickness=0)
        right_canvas.place(x=0, y=0)
        right_scrollbar = tk.Scrollbar(right_frame, orient='vertical', command=right_canvas.yview)
        right_scrollbar.place(x=685, y=0, height=395)
        right_canvas.configure(yscrollcommand=right_scrollbar.set)
        right_frame_content = tk.Frame(right_canvas, bg='white')
        right_canvas.create_window((0, 0), window=right_frame_content, anchor='nw')

        # Add doctor frame
        add_doctor_frame = tk.Frame(self.doctor_list_frame, width=1050, height=510, bg='white')
        add_back_frame = tk.Frame(add_doctor_frame, bg='white', width=1050, height=65,
                                  highlightbackground="white", highlightthickness=0)
        add_back_frame.place(x=0, y=0)
        add_button = ttk.Button(add_back_frame, text='Add', style='white_word.TButton',
                                cursor='hand2', width=10, padding=4)
        add_button.place(x=895, y=20)
        back_button = ttk.Button(add_back_frame, style='back_image.TButton', cursor='hand2',
                                 command=lambda: show_doctor_list())
        back_button.place(x=20, y=10)

        # Create a canvas
        doctor_entries_canvas = tk.Canvas(add_doctor_frame, bg='white', width=1050, height=445, highlightthickness=0)
        doctor_entries_canvas.place(x=0, y=80)
        # Add scrollbar to the canvas
        scrollbar = tk.Scrollbar(add_doctor_frame, orient='vertical', command=doctor_entries_canvas.yview)
        scrollbar.place(x=1030, y=80, height=445)
        doctor_entries_canvas.configure(yscrollcommand=scrollbar.set)
        # Create a frame to hold the entries
        doctor_entries_frame = tk.Frame(doctor_entries_canvas, bg='white')
        # Add the frame to the canvas
        doctor_entries_canvas.create_window((0, 0), window=doctor_entries_frame, anchor='nw')
        self.all_doctor_list_frames['new_doctor'] = [add_doctor_frame, doctor_entries_canvas, doctor_entries_frame, 0]

        show_doctor_list()

    def set_up_me_frame(self):
        def show_personal():
            def edit_personal():
                for entry in all_entries:
                    entry.config(state='normal', fg='#333333')
                address_entry.config(state='normal', fg='#333333')
                describe_entry.config(state='normal', fg='#333333')
                image_entry.config(fg='#333333')
                image_button.config(state='normal')

                edit_button.place_forget()
                p_save_button.place(x=945, y=15)

            def save_personal():
                personal_content_frame.focus_set()
                if all([entry.cget('fg') == '#333333' for entry in all_entries]) and describe_entry.cget('fg') == '#333333' \
                        and address_entry.cget('fg') == '#333333' and image_entry.cget('fg') == '#333333':
                    user_name = name_entry.get()
                    user_contact = contact_entry.get()
                    user_operation = operation_entry.get()
                    user_address = address_entry.get('1.0', tk.END)
                    user_describe = describe_entry.get('1.0', tk.END)
                    user_image = image_entry.cget('text')

                    user_image_binary = None
                    # Check if a new image has been selected
                    if self.me_img_var:
                        img = self.me_img_var
                        if img.lower().endswith(('.jpg', '.jpeg', '.png')):
                            with open(img, 'rb') as file:
                                user_image_binary = file.read()

                    if all([user_name, user_contact, user_operation, user_address, user_describe, user_image]):
                        # If the clinic upload a new image for the clinic image
                        if user_image_binary:
                            cursor.execute('''UPDATE clinic SET clinic_name=%s, clinic_operation=%s, clinic_address=%s, 
                                           clinic_description=%s, clinic_contact=%s, clinic_image=%s WHERE user_id=%s''',
                                           (user_name, user_operation, user_address, user_describe, user_contact,
                                            user_image_binary, self.user_id))
                        else:
                            cursor.execute('''UPDATE clinic SET clinic_name=%s, clinic_operation=%s, clinic_address=%s, 
                                           clinic_description=%s, clinic_contact=%s WHERE user_id=%s''',
                                           (user_name, user_operation, user_address, user_describe, user_contact,
                                            self.user_id))
                        p_save_error_label.config(text='')
                        database.commit()
                        show_personal()
                    else:
                        p_save_error_label.config(text='Please fill in all details')
                else:
                    p_save_error_label.config(text='Please fill in all details')

            def personal_password_visible():
                password_entry.config(show='')
                password_eye_closed_button.place_forget()
                password_eye_opened_button.place(x=330, y=2)

            def personal_password_invisible():
                password_entry.config(show='*')
                password_eye_opened_button.place_forget()
                password_eye_closed_button.place(x=330, y=2)

            for widget in personal_content_frame.winfo_children():
                widget.destroy()

            edit_button.config(command=lambda: edit_personal())
            p_save_button.config(command=lambda: save_personal())
            p_save_button.place_forget()
            edit_button.place(x=945, y=15)
            p_save_error_label.config(text='')
            self.me_img_var = None

            all_entries = []

            cursor.execute('''SELECT user_email, user_password FROM user WHERE user_id=%s''', (self.user_id, ))
            user_detail = cursor.fetchone()

            email_label = tk.Label(personal_content_frame, text='Email: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                   width=20, anchor='e')
            email_label.grid(row=0, column=0, padx=(150, 5), pady=5, sticky='e')
            email_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            email_frame.grid(row=0, column=1, padx=5, pady=5, sticky='w')
            email_entry = tk.Label(email_frame, bg='#D0F9EF', text=user_detail[0], fg='#858585', font=('Open Sans', 10))
            email_entry.place(x=5, y=12)

            password_label = tk.Label(personal_content_frame, text='Password: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                      width=20, anchor='e')
            password_label.grid(row=1, column=0, padx=(150, 5), pady=5, sticky='e')
            password_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            password_frame.grid(row=1, column=1, padx=5, pady=5, sticky='w')
            password_entry = tk.Entry(password_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), show='*', border=0)
            password_entry.place(x=7, y=12)
            password_entry.insert(0, user_detail[1])
            password_entry.config(state='disabled', disabledbackground='#D0F9EF')
            password_eye_closed_button = ttk.Button(password_frame, style='eye_closed_green.TButton', cursor='hand2')
            password_eye_closed_button.place(x=330, y=2)
            password_eye_opened_button = ttk.Button(password_frame, style='eye_opened_green.TButton', cursor='hand2')
            password_eye_closed_button.config(command=lambda: personal_password_visible())
            password_eye_opened_button.config(command=lambda: personal_password_invisible())

            cursor.execute('''SELECT * FROM clinic WHERE user_id=%s''', (self.user_id, ))
            user_info = cursor.fetchone()

            status = 'Active' if user_info[7] == 1 else 'Inactive'
            status_label = tk.Label(personal_content_frame, text='Status: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                    width=20, anchor='e')
            status_label.grid(row=2, column=0, padx=(150, 5), pady=5, sticky='e')
            status_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            status_frame.grid(row=2, column=1, padx=5, pady=5, sticky='w')
            status_entry = tk.Label(status_frame, bg='#D0F9EF', text=status, fg='#858585', font=('Open Sans', 10))
            status_entry.place(x=5, y=12)

            name_label = tk.Label(personal_content_frame, text='Name: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                  width=20, anchor='e')
            name_label.grid(row=3, column=0, padx=(150, 5), pady=(40, 5), sticky='e')
            name_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            name_entry_frame.grid(row=3, column=1, padx=5, pady=(40, 5), sticky='w')
            name_entry = tk.Entry(name_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            name_entry.place(x=7, y=12)
            name_entry.insert(0, user_info[1])
            name_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(name_entry)

            image_label = tk.Label(personal_content_frame, text='Image: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                   width=20, anchor='e')
            image_label.grid(row=4, column=0, padx=(150, 5), pady=5, sticky='e')
            image_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            image_entry_frame.grid(row=4, column=1, padx=5, pady=5, sticky='w')
            image_entry = tk.Label(image_entry_frame, bg='#D0F9EF', text='', fg='#858585', font=('Open Sans', 10))
            image_entry.place(x=5, y=12)
            file_type = detect_image_format(user_info[6]) or 'img'
            image_entry.config(text=f"{user_info[1]}.{file_type}")
            image_button = ttk.Button(image_entry_frame, text='⇫', style='selection.TButton', width=4, cursor='hand2',
                                      command=lambda: self.upload_me_image(image_entry, 100, 100, image_display_label))
            image_button.place(x=330, y=5)
            image_button.config(state='disabled')
            image_display_label = tk.Label(personal_content_frame, bg='white', anchor='w')
            image_display_label.grid(row=5, column=1, padx=5, pady=5, sticky='w')
            img = Image.open(io.BytesIO(user_info[6]))
            img = img.resize((100, 100), Image.LANCZOS)
            img = ImageTk.PhotoImage(img)
            image_display_label.config(image=img)
            image_display_label.image = img

            operation_label = tk.Label(personal_content_frame, text='Operation Hours: ', font=('Open Sans', 12, 'bold'), bg='white',
                                       fg='#000000', width=20, anchor='e')
            operation_label.grid(row=6, column=0, padx=(150, 5), pady=5, sticky='e')
            operation_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            operation_entry_frame.grid(row=6, column=1, padx=5, pady=5, sticky='w')
            operation_entry = tk.Entry(operation_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            operation_entry.place(x=7, y=12)
            operation_entry.insert(0, user_info[2])
            operation_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(operation_entry)

            contact_label = tk.Label(personal_content_frame, text='Contact Number: ', font=('Open Sans', 12, 'bold'), bg='white',
                                     fg='#000000', width=20, anchor='e')
            contact_label.grid(row=7, column=0, padx=(150, 5), pady=5, sticky='e')
            contact_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            contact_entry_frame.grid(row=7, column=1, padx=5, pady=5, sticky='w')
            contact_entry = tk.Entry(contact_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            contact_entry.place(x=7, y=12)
            contact_entry.insert(0, user_info[5])
            contact_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(contact_entry)

            address_label = tk.Label(personal_content_frame, text='Address: ', font=('Open Sans', 12, 'bold'), bg='white',
                                     fg='#000000', width=20, anchor='ne')
            address_label.grid(row=8, column=0, padx=(150, 5), pady=5, sticky='ne')
            address_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=90)
            address_entry_frame.grid(row=8, column=1, padx=5, pady=5, sticky='w')
            address_entry = tk.Text(address_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45,
                                    height=5, wrap='word')
            address_entry.place(x=7, y=5)
            address_entry.insert('1.0', user_info[3])
            address_entry.config(state='disabled')

            describe_label = tk.Label(personal_content_frame, text='Short Description: ', font=('Open Sans', 12, 'bold'), bg='white',
                                      fg='#000000', width=20, anchor='ne')
            describe_label.grid(row=9, column=0, padx=(150, 5), pady=(5, 15), sticky='ne')
            describe_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=90)
            describe_entry_frame.grid(row=9, column=1, padx=5, pady=(5, 15), sticky='w')
            describe_entry = tk.Text(describe_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45,
                                     height=5, wrap='word')
            describe_entry.place(x=7, y=5)
            describe_entry.insert('1.0', user_info[4])
            describe_entry.config(state='disabled')

            self.switch('personal', self.all_me_frame)

        def show_reset():
            def reset():
                reset_content_frame.focus_set()
                if old_entry.cget('fg') == '#333333' and new_entry.cget('fg') == '#333333' and confirm_entry.cget('fg') == '#333333':
                    cursor.execute('''SELECT user_password FROM user WHERE user_id=%s''', (self.user_id, ))
                    previous_password = cursor.fetchone()[0]
                    if old_entry.get() == previous_password:
                        if len(new_entry.get()) >= 8:
                            if new_entry.get() == confirm_entry.get():
                                cursor.execute('''UPDATE user SET user_password=%s WHERE user_id=%s''', (new_entry.get(), self.user_id))
                                database.commit()
                                save_error_label.config(text='')
                                messagebox.showinfo('Success', "Reset Password Successfully")
                                show_personal()
                            else:
                                save_error_label.config(text='Password does not match')
                        else:
                            save_error_label.config(text='Minimum 8 characters of password')
                    else:
                        save_error_label.config(text="Incorrect old password")
                else:
                    save_error_label.config(text="Please fill in all details")

            for widget in reset_content_frame.winfo_children():
                widget.destroy()

            save_error_label.config(text='')
            save_button.config(command=lambda: reset())

            reset_label = tk.Label(reset_content_frame, text='Reset Password',
                                   font=('Open Sans', 20, 'underline', 'bold'), bg='white', fg='#000000')
            reset_label.grid(row=0, column=0, columnspan=2, padx=35, pady=(10, 15), sticky='w')

            old_label = tk.Label(reset_content_frame, text='Old Password', font=('Open Sans', 12, 'bold'), bg='white',
                                         fg='#000000')
            old_label.grid(row=1, column=0, padx=50, pady=(5, 0), sticky='w')
            old_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            old_entry_frame.grid(row=2, column=0, padx=53, pady=(0, 5))
            old_entry = tk.Entry(old_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            old_entry.place(x=10, y=13)
            old_entry.insert(0, 'Enter Old Password')
            old_eye_closed_button = ttk.Button(old_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            old_eye_closed_button.place(x=330, y=2)
            old_eye_opened_button = ttk.Button(old_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            old_visibility = tk.Label(old_entry_frame, text='Close')
            old_eye_closed_button.config(command=lambda: self.show_hide_password(old_entry, old_eye_opened_button,
                                                                                 old_eye_closed_button, old_visibility))
            old_eye_opened_button.config(command=lambda: self.show_hide_password(old_entry, old_eye_opened_button,
                                                                                 old_eye_closed_button, old_visibility))
            old_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', old_entry, old_visibility))
            old_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', old_entry, 'Enter Old Password'))
            old_entry.bind('<Return>', lambda event: reset())

            new_label = tk.Label(reset_content_frame, text='New Password', font=('Open Sans', 12, 'bold'), bg='white',
                                 fg='#000000')
            new_label.grid(row=3, column=0, padx=50, pady=(15, 0), sticky='w')
            new_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            new_entry_frame.grid(row=4, column=0, padx=53, pady=(0, 5))
            new_entry = tk.Entry(new_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            new_entry.place(x=10, y=13)
            new_entry.insert(0, 'Enter New Password')
            new_eye_closed_button = ttk.Button(new_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            new_eye_closed_button.place(x=330, y=2)
            new_eye_opened_button = ttk.Button(new_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            new_visibility = tk.Label(new_entry_frame, text='Close')
            new_eye_closed_button.config(command=lambda: self.show_hide_password(new_entry, new_eye_opened_button,
                                                                                 new_eye_closed_button, new_visibility))
            new_eye_opened_button.config(command=lambda: self.show_hide_password(new_entry, new_eye_opened_button,
                                                                                 new_eye_closed_button, new_visibility))
            new_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', new_entry, new_visibility))
            new_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', new_entry, 'Enter New Password'))
            new_entry.bind('<Return>', lambda event: reset())

            confirm_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            confirm_entry_frame.grid(row=5, column=0, padx=53, pady=(0, 5))
            confirm_entry = tk.Entry(confirm_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            confirm_entry.place(x=10, y=13)
            confirm_entry.insert(0, 'Re-enter New Password')
            confirm_eye_closed_button = ttk.Button(confirm_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            confirm_eye_closed_button.place(x=330, y=2)
            confirm_eye_opened_button = ttk.Button(confirm_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            confirm_visibility = tk.Label(confirm_entry_frame, text='Close')
            confirm_eye_closed_button.config(command=lambda: self.show_hide_password(confirm_entry, confirm_eye_opened_button,
                                                                                     confirm_eye_closed_button, confirm_visibility))
            confirm_eye_opened_button.config(command=lambda: self.show_hide_password(confirm_entry, confirm_eye_opened_button,
                                                                                     confirm_eye_closed_button, confirm_visibility))
            confirm_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', confirm_entry, confirm_visibility))
            confirm_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', confirm_entry, 'Re-enter New Password'))
            confirm_entry.bind('<Return>', lambda event: reset())

            self.switch('reset', self.all_me_frame)

        # Set up the frame for rejoin / leave request
        def show_request():
            # Ensure the clinic selects a reason for rejoining or leaving
            def submit():
                if reason_entry.cget('fg') == '#333333':
                    if describe_entry.cget('fg') == '#333333':
                        describe = describe_entry.get('1.0', tk.END)
                    else:
                        describe = None
                    # Insert the clinic request into database, wait for project admin approval
                    cursor.execute('''INSERT INTO clinic_request (cr_type, cr_reason, cr_datetime, cr_detail, 
                                   cr_ifreject, cr_status, clinic_id) VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                                   (request_to_entry.cget('text'), reason_entry.cget('text'), datetime.now(), describe,
                                    None, 'pending', self.clinic_id))
                    database.commit()
                    submit_error_label.config(text='')
                    messagebox.showinfo('Success', f"Submit {request_to} Request Successfully")
                    show_personal()
                else:
                    submit_error_label.config(text='Please select a reason')

            # A clinic can only have one rejoin / leave request at a single time
            cursor.execute('''SELECT cr_type FROM clinic_request WHERE cr_status=%s AND clinic_id=%s''', ('pending', self.clinic_id))
            exist = cursor.fetchone()
            if exist:
                messagebox.showerror('Error', f'You have a pending {exist[0].upper()} request.\nUnable to make other request.')
                return

            for widget in request_content_frame.winfo_children():
                widget.destroy()

            submit_error_label.config(text='')
            submit_button.config(command=lambda: submit())

            # If the clinic currently is active, it can only submit a leave request and vice versa
            # Generate respective reasons menu
            cursor.execute('''SELECT clinic_status FROM clinic WHERE user_id=%s''', (self.user_id, ))
            current_status = cursor.fetchone()[0]
            if current_status == 1:
                request_to = 'Leave'
                reason_list = ['Seasonal closures', 'Usability issues', 'Contract changes', 'Staffing issues', 'Busy', 'Others']
            else:
                request_to = 'Rejoin'
                reason_list = ['Update on registered information', 'Reopen', 'Free to accept appointment',
                               'New favourable contracts', 'New features included', 'Others']

            request_label = tk.Label(request_content_frame, text='Request / Rejoin Request',
                                     font=('Open Sans', 20, 'underline', 'bold'), bg='white', fg='#000000')
            request_label.grid(row=0, column=0, columnspan=2, padx=35, pady=(10, 15), sticky='w')

            request_to_label = tk.Label(request_content_frame, text='Request To', font=('Open Sans', 12, 'bold'), bg='white',
                                        fg='#000000')
            request_to_label.grid(row=1, column=0, padx=50, pady=(5, 0), sticky='w')
            request_to_entry_frame = tk.Frame(request_content_frame, bg='#D0F9EF', width=380, height=45)
            request_to_entry_frame.grid(row=2, column=0, padx=53, pady=(0, 5), sticky='w')
            request_to_entry = tk.Label(request_to_entry_frame, bg='#D0F9EF', text=request_to, fg='#333333', font=('Open Sans', 10))
            request_to_entry.place(x=5, y=12)

            reason_label = tk.Label(request_content_frame, text='Reason: ', font=('Open Sans', 12, 'bold'), bg='white',
                                    fg='#000000', width=20, anchor='w')
            reason_label.grid(row=1, column=1, padx=90, pady=(5, 0), sticky='w')
            reason_entry_frame = tk.Frame(request_content_frame, bg='#D0F9EF', width=380, height=45)
            reason_entry_frame.grid(row=2, column=1, padx=93, pady=(0, 5), sticky='w')
            reason_entry = tk.Label(reason_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), text='Select a reason')
            reason_entry.place(x=5, y=12)
            reason_button = ttk.Button(reason_entry_frame, text='▼', style='selection.TButton', width=4,
                                       cursor='hand2', command=lambda: self.display_menu(reason_entry_frame, 0, 38, reason_menu))
            reason_button.place(x=330, y=5)
            reason_menu = tk.Menu(request_content_frame, tearoff=0, bg='#D0F9EF', fg='#333333',
                                  font=('Open Sans', 10))
            for reason in reason_list:
                reason_menu.add_command(label=reason, command=lambda reason_entry=reason_entry, reason=reason:
                                                              self.select_menu_option(reason_entry, reason))
            reason_menu.add_separator()
            reason_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ",
                                    command=reason_menu.unpost)

            describe_label = tk.Label(request_content_frame, text='Description: ', font=('Open Sans', 12, 'bold'), bg='white',
                                      fg='#000000', width=20, anchor='w')
            describe_label.grid(row=3, column=0, columnspan=2, padx=50, pady=(15, 0), sticky='w')
            describe_entry_frame = tk.Frame(request_content_frame, bg='#D0F9EF', width=905, height=120)
            describe_entry_frame.grid(row=4, column=0, columnspan=2, padx=53, pady=(0, 5), sticky='w')
            describe_entry = tk.Text(describe_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', border=0, width=125,
                                     height=6, wrap='word', fg='#858585')
            describe_entry.place(x=10, y=10)
            describe_entry.insert('1.0', 'Optional')
            describe_entry.bind('<FocusIn>', lambda event: self.focus_entry('text', describe_entry))
            describe_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('text', describe_entry, 'Optional'))

            self.switch('request', self.all_me_frame)

        for widget in self.me_frame.winfo_children():
            widget.destroy()

        personal_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        logout_button = tk.Button(personal_frame, text='Log Out', bg='red', fg='white', cursor='hand2', relief='flat', border=0,
                                  font=('Open Sans', 14, 'bold'), width=10, command=lambda: self.logout())
        logout_button.place(x=30, y=15)
        request_button = ttk.Button(personal_frame, text='Rejoin/Leave', style='green_button.TButton', cursor='hand2',
                                    width=15, command=lambda: show_request())
        request_button.place(x=507, y=15)
        reset_password_button = ttk.Button(personal_frame, text='Reset Password', style='green_button.TButton', cursor='hand2',
                                           width=18, command=lambda: show_reset())
        reset_password_button.place(x=710, y=15)
        edit_button = ttk.Button(personal_frame, text='Edit', style='green_button.TButton', cursor='hand2', width=6)
        edit_button.place(x=945, y=15)
        p_save_button = ttk.Button(personal_frame, text='Save', style='green_button.TButton', cursor='hand2', width=6)
        p_save_error_label = tk.Label(personal_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        p_save_error_label.place(x=310, y=25)
        personal_canvas = tk.Canvas(personal_frame, width=1030, height=430, bg='white', highlightthickness=0)
        personal_canvas.place(x=0, y=75)
        personal_scrollbar = tk.Scrollbar(personal_frame, orient='vertical')
        personal_scrollbar.place(x=1033, y=75, height=430)
        personal_canvas.configure(yscrollcommand=personal_scrollbar.set)
        personal_scrollbar.configure(command=personal_canvas.yview)
        personal_content_frame = tk.Frame(personal_canvas, bg='white')
        personal_canvas.create_window((0, 0), window=personal_content_frame, anchor="nw")
        self.all_me_frame['personal'] = [personal_frame, personal_canvas, personal_content_frame, 0]

        reset_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        reset_back_button = ttk.Button(reset_frame, text='< Back', style='back.TButton', cursor='hand2', width=6,
                                       command=lambda: show_personal())
        reset_back_button.place(x=20, y=15)
        save_button = ttk.Button(reset_frame, text='Save', style='green_button.TButton', cursor='hand2', width=6)
        save_button.place(x=945, y=15)
        save_error_label = tk.Label(reset_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        save_error_label.place(x=750, y=25)
        reset_canvas = tk.Canvas(reset_frame, width=1030, height=430, bg='white', highlightthickness=0)
        reset_canvas.place(x=0, y=75)
        reset_scrollbar = tk.Scrollbar(reset_frame, orient='vertical')
        reset_scrollbar.place(x=1033, y=75, height=430)
        reset_canvas.configure(yscrollcommand=reset_scrollbar.set)
        reset_scrollbar.configure(command=reset_canvas.yview)
        reset_content_frame = tk.Frame(reset_canvas, bg='white')
        reset_canvas.create_window((0, 0), window=reset_content_frame, anchor="nw")
        self.all_me_frame['reset'] = [reset_frame, reset_canvas, reset_content_frame, 0]

        request_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        request_back_button = ttk.Button(request_frame, text='< Back', style='back.TButton', cursor='hand2', width=6,
                                         command=lambda: show_personal())
        request_back_button.place(x=20, y=15)
        submit_button = ttk.Button(request_frame, text='Save', style='green_button.TButton', cursor='hand2', width=6)
        submit_button.place(x=945, y=15)
        submit_error_label = tk.Label(request_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        submit_error_label.place(x=750, y=25)
        request_canvas = tk.Canvas(request_frame, width=1030, height=430, bg='white', highlightthickness=0)
        request_canvas.place(x=0, y=75)
        request_scrollbar = tk.Scrollbar(request_frame, orient='vertical')
        request_scrollbar.place(x=1033, y=75, height=430)
        request_canvas.configure(yscrollcommand=request_scrollbar.set)
        request_scrollbar.configure(command=request_canvas.yview)
        request_content_frame = tk.Frame(request_canvas, bg='white')
        request_canvas.create_window((0, 0), window=request_content_frame, anchor="nw")
        self.all_me_frame['request'] = [request_frame, request_canvas, request_content_frame, 0]

        show_personal()

    def on_mouse_wheel(self, event, canvas):
        canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def display_menu(self, frame, x, y, menu):
        root_x = frame.winfo_rootx()
        root_y = frame.winfo_rooty()
        adjusted_x = root_x + x
        adjusted_y = root_y + y

        menu.post(adjusted_x, adjusted_y)

    def select_menu_option(self, label, option, text=None):
        if option == 'Clear':
            label.config(text=text, fg='#858585')
        else:
            label.config(text=option, fg='#333333')

    def focus_entry(self, entry_type, entry, visibility=None):
        if entry_type == 'entry':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
        elif entry_type == 'text':
            if entry.cget('fg') == '#858585':
                entry.delete('1.0', 'end')
                entry.config(fg='#333333')
        elif entry_type == 'password':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
                if visibility.cget('text') == 'Open':
                    entry.config(show='')
                elif visibility.cget('text') == 'Close':
                    entry.config(show='*')

    def leave_focus_entry(self, entry_type, entry, text):
        if entry_type == 'entry':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585')
                entry.insert(0, text)
        elif entry_type == 'text':
            value = entry.get('1.0', 'end')
            if value.strip() == '':
                entry.delete('1.0', 'end')
                entry.config(fg='#858585')
                entry.insert('1.0', text)
        elif entry_type == 'password':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585', show='')
                entry.insert(0, text)

    def show_hide_password(self, entry, eye_open_button, eye_close_button, visibility):
        if visibility.cget('text') == 'Close' and entry.cget('fg') == '#858585':
            eye_open_button.place(x=330, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')
        elif visibility.cget('text') == 'Open' and entry.cget('fg') == '#858585':
            eye_open_button.place_forget()
            eye_close_button.place(x=330, y=2)
            entry.config(show='')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Open':
            eye_open_button.place_forget()
            eye_close_button.place(x=330, y=2)
            entry.config(show='*')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Close':
            eye_open_button.place(x=330, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')

    # Upload image for a doctor (new doctor or existing doctor)
    # Ensure image format as well
    def upload_doctor_image(self, entry, size_x, size_y, label):
        file_path = filedialog.askopenfilename(initialdir="/gui/images", title="Select an Image", filetypes=(
            ("JPEG files", "*.jpg;*.jpeg"), ("PNG files", "*.png"), ("All files", "*.*")))
        if file_path:
            img_name = os.path.basename(file_path)
            if file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
                # Update the entry text
                entry.config(text=img_name, fg='#333333')
                self.doctor_image_var = file_path  # Store the file path of the uploaded image
                # Display the new image in the UI
                img = Image.open(file_path)
                img = img.resize((size_x, size_y), Image.LANCZOS)
                img = ImageTk.PhotoImage(img)
                label.config(image=img)
                label.image = img
            else:
                messagebox.showerror("Error", "Invalid Image Format")

    # Upload a new image as update for the clinic image
    # Ensure the image format as well
    def upload_me_image(self, entry, size_x, size_y, label):
        file_path = filedialog.askopenfilename(initialdir="/gui/images", title="Select an Image", filetypes=(
            ("JPEG files", "*.jpg;*.jpeg"), ("PNG files", "*.png"), ("All files", "*.*")))
        if file_path:
            img_name = os.path.basename(file_path)
            if file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
                # Update the entry text
                entry.config(text=img_name, fg='#333333')
                self.me_img_var = file_path  # Store the file path of the uploaded image
                # Display the new image in the UI
                img = Image.open(file_path)
                img = img.resize((size_x, size_y), Image.LANCZOS)
                img = ImageTk.PhotoImage(img)
                label.config(image=img)
                label.image = img
            else:
                messagebox.showerror("Error", "Invalid Image Format")

    def format_date(self, date):
        full_date = date.split('-')
        year = full_date[0]
        month = full_date[1]
        day = full_date[2]
        months = {'01': 'January',
                  '02': 'February',
                  '03': 'March',
                  '04': 'April',
                  '05': 'May',
                  '06': 'June',
                  '07': 'July',
                  '08': 'August',
                  '09': 'September',
                  '10': 'October',
                  '11': 'November',
                  '12': 'December'}
        month = months[month]
        return f"{day} {month} {year}"

    def do_nothing(self, event):
        pass

    def timedelta_to_time(self, td_value):
        total_seconds = td_value.total_seconds()
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = int(total_seconds % 60)
        return time(hours, minutes, seconds)


class Doctor:
    def __init__(self, main_window, login_register=None):
        self.root_window = main_window
        self.login_register = login_register  # Reference to LoginRegister instance
        self.user_id = None
        self.doctor_id = None

        self.cursor = None

        self.window = tk.Toplevel(self.root_window)
        self.window.title('Call a Doctor')
        self.window.geometry('1050x600')
        icon = load_image('icon', 48, 48)
        self.window.iconphoto(False, icon)

        self.nf_icon = load_image('nf icon', 80, 70)
        self.calendar = load_image('calendar', 20, 20)
        self.eye_closed_image = load_image('eye closed', 24, 24)
        self.eye_opened_image = load_image('eye opened', 24, 24)

        style = ttk.Style()
        style.theme_use('clam')

        style.configure('navigation.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        font=('Open Sans', 20, 'bold'))
        style.map('navigation.TButton', background=[('active', 'white')], foreground=[('active', '#77C7B5')])
        style.configure('calendar.TButton', border=0, relief='flat', background='#D0F9EF',
                        image=self.calendar)
        style.map('calendar.TButton', background=[('active', '#D0F9EF')])
        style.configure('white_word.TButton', border=0, relief='flat', background='#7EE5CE', foreground='white',
                        font=('Open Sans', 15, 'bold'))
        style.map('white_word.TButton', background=[('active', '#7EE5CE')], foreground=[('active', 'white')])
        style.configure('back.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        font=('Open Sans', 18, 'bold'))
        style.map('back.TButton', background=[('active', 'white')], foreground=[('active', '#77C7B5')])
        style.configure('green_button.TButton', border=0, relief='flat', background='#7EE5CE', foreground='white',
                        font=('Open Sans', 14, 'bold'))
        style.map('green_button.TButton', background=[('active', '#77C7B5')])
        style.configure('eye_closed_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_closed_image)
        style.map('eye_closed_green.TButton', background=[('active', '#D0F9EF')])
        style.configure('eye_opened_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_opened_image)
        style.map('eye_opened_green.TButton', background=[('active', '#D0F9EF')])
        style.configure('selection.TButton', border=0, relief='flat', background='#D0F9EF', foreground='#3DAEC7',
                        font=('Rubik', 12, 'bold'))
        style.map('selection.TButton', background=[('active', '#D0F9EF')], foreground=[('active', '#0B8FAC')])

        self.navigation_frame = tk.Frame(self.window, width=1050, height=90, bg='white')
        self.navigation_frame.pack()
        self.navigation_bar = tk.Frame(self.navigation_frame, height=5, bg='#166E82')

        nf_icon = tk.Label(self.navigation_frame, image=self.nf_icon, bg='white', cursor='hand2')
        nf_icon.place(x=10, y=10)
        nf_icon.bind('<Button-1>', lambda event: self.refresh())
        nf_name = tk.Label(self.navigation_frame, text='CaD', font=('Open Sans', 30, 'bold'), bg='white', fg='#166E82', cursor='hand2')
        nf_name.place(x=90, y=20)
        nf_name.bind('<Button-1>', lambda event: self.refresh())
        nf_patient_button = ttk.Button(self.navigation_frame, text='Patient Appointment', style='navigation.TButton', width=18,
                                       command=lambda: self.show_activity_frame(285, 521, self.patient_frame))
        nf_patient_button.place(x=520, y=30)
        nf_timetable_button = ttk.Button(self.navigation_frame, text='Timetable', style='navigation.TButton', width=9,
                                         command=lambda: self.show_activity_frame(150, 818, self.timetable_frame))
        nf_timetable_button.place(x=817, y=30)
        nf_me_button = ttk.Button(self.navigation_frame, text='Me', style='navigation.TButton', width=3,
                                  command=lambda: self.show_activity_frame(60, 976, self.me_frame))
        nf_me_button.place(x=975, y=30)

        self.patient_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_patient_frame = {}

        self.timetable_frame = tk.Frame(self.window, width=1050, height=510, bg='white')

        self.me_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_me_frame = {}
        self.img_var = None  # Storing image data for new doctor image

        self.all_scrollable_frame = {}
        self.all_scrollable_frame[self.patient_frame] = 1
        self.all_scrollable_frame[self.timetable_frame] = 0
        self.all_scrollable_frame[self.me_frame] = 0

    def logout(self):
        # Call handle_logout from LoginRegister if available (clears tokens and calls logout API)
        if self.login_register:
            self.login_register.handle_logout()
            return  # handle_logout will show login screen
        
        # Fallback: basic logout if login_register not available
        self.user_id = None
        self.doctor_id = None

        self.window.withdraw()
        self.root_window.deiconify()

        self.cursor.close()
        self.cursor = None

        self.all_patient_frame = {}
        self.all_me_frame = {}
        self.img_var = None

        self.all_scrollable_frame = {}
        self.all_scrollable_frame[self.patient_frame] = 1
        self.all_scrollable_frame[self.timetable_frame] = 0
        self.all_scrollable_frame[self.me_frame] = 0

    def run(self, user_id):
        self.user_id = user_id
        cursor.execute('''SELECT doctor_id FROM doctor WHERE user_id=%s''', (self.user_id,))
        self.doctor_id = cursor.fetchone()[0]

        self.cursor = database.cursor(dictionary=True)

        self.window.deiconify()
        self.refresh()

    def refresh(self):
        cursor.execute('''UPDATE appointment_request ar
                          JOIN patient p ON ar.patient_id = p.patient_id
                          SET ar.ar_status = 'canceled'
                          WHERE CONCAT(ar.ar_date, ' ', ar.ar_time) < NOW()
                          AND ar.ar_status IN ('pending', 'ongoing')''')
        database.commit()

        self.set_up_patient_frame()
        self.set_up_timetable_frame()
        self.set_up_me_frame()

        if self.all_scrollable_frame[self.patient_frame] == 1:
            self.show_activity_frame(285, 521, self.patient_frame)
        elif self.all_scrollable_frame[self.timetable_frame] == 1:
            self.show_activity_frame(150, 818, self.timetable_frame)
        elif self.all_scrollable_frame[self.me_frame] == 1:
            self.show_activity_frame(60, 976, self.me_frame)

    def show_activity_frame(self, bar_width, bar_x, frame):
        self.navigation_bar.config(width=bar_width)
        self.navigation_bar.place(x=bar_x, y=85)

        self.patient_frame.pack_forget()
        self.timetable_frame.pack_forget()
        self.me_frame.pack_forget()

        frame.pack()
        frame.focus_set()

        key = list(self.all_scrollable_frame.keys())
        for k in key:
            if k == frame:
                self.all_scrollable_frame[k] = 1
            else:
                self.all_scrollable_frame[k] = 0

        if frame == self.timetable_frame:
            self.timetable_frame.bind_all("<MouseWheel>", lambda event: self.do_nothing(event))
        elif frame == self.patient_frame:
            keys = list(self.all_patient_frame.keys())
            for k in keys:
                active = self.all_patient_frame[k][3]
                if active:
                    self.switch(k, self.all_patient_frame)
        elif frame == self.me_frame:
            keys = list(self.all_me_frame.keys())
            for k in keys:
                active = self.all_me_frame[k][3]
                if active:
                    self.switch(k, self.all_me_frame)

    def switch(self, frame, frame_list):
        frames = list(frame_list.keys())
        for f in frames:
            if f == frame:
                frame_list[f][3] = 1
                frame_list[f][0].pack()
            else:
                frame_list[f][3] = 0
                frame_list[f][0].pack_forget()
        content = frame_list[frame][2]
        canvas = frame_list[frame][1]
        content.update_idletasks()
        if len(content.winfo_children()) == 0:
            canvas.configure(scrollregion=(0, 0, 0, 0))
        else:
            canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.bind_all("<MouseWheel>", lambda event: self.on_mouse_wheel(event, canvas))

    # Set up patient request section
    def set_up_patient_frame(self):
        def show_patient_appointment():
            for widget in appointment_scrollable_frame.winfo_children():
                widget.destroy()

            # Fetch information of ongoing appointments in ascending datetime sequence
            query = """SELECT ar.ar_id, ar.ar_detail, ar.ar_date, ar.ar_time, p.patient_id, p.patient_name, p.patient_ic_passport, 
                       p.patient_gender, p.patient_contact, p.patient_address
                       FROM appointment_request ar
                       LEFT JOIN patient p ON ar.patient_id = p.patient_id
                       LEFT JOIN appointment a ON ar.ar_id = a.ar_id
                       LEFT JOIN doctor d ON a.doctor_id = d.doctor_id
                       LEFT JOIN user u ON d.user_id = u.user_id
                       WHERE ar.ar_status = 'ongoing' AND u.user_id = %s
                       ORDER BY ar.ar_date, ar.ar_time;"""
            self.cursor.execute(query, (self.user_id,))
            appointments = self.cursor.fetchall()

            if not appointments:
                no_appointments_label = tk.Label(appointment_scrollable_frame, text="No appointments found",
                                                 font=('Open Sans', 12, 'bold'), bg='white', fg='red')
                no_appointments_label.pack(padx=440, pady=30)
            else:
                for i, appointment in enumerate(appointments):
                    ar_id = appointment['ar_id']
                    ar_detail = appointment['ar_detail']
                    ar_date = self.format_date(str(appointment['ar_date']))
                    ar_time = self.timedelta_to_time(appointment['ar_time'])
                    ar_time = ar_time.strftime("%I%p").lstrip('0').lower()
                    patient_id = appointment['patient_id']
                    patient_name = appointment['patient_name']
                    patient_ic = appointment['patient_ic_passport']
                    patient_gender = appointment['patient_gender']
                    patient_contact = appointment['patient_contact']
                    patient_address = appointment['patient_address']

                    card_frame = tk.Frame(appointment_scrollable_frame, bg='white', highlightbackground='#00C196',
                                          highlightthickness=1)
                    card_frame.grid(row=i + 1, column=0, columnspan=5, padx=25, pady=10, sticky='ew')
                    card_frame.grid_columnconfigure(0, weight=1)
                    card_frame.grid_columnconfigure(1, weight=1)
                    card_frame.grid_columnconfigure(2, weight=1)
                    card_frame.grid_columnconfigure(3, weight=1)

                    id_label = tk.Label(card_frame, text=f"Appointment ID: {ar_id}", font=('Open Sans', 16, 'bold'), bg='white',
                                        fg='#333333')
                    id_label.grid(row=0, column=0, sticky='w', padx=15, pady=(10, 5))

                    patient_label = tk.Label(card_frame, text=f"   Patient Name: {patient_name}", font=('Open Sans', 12, 'bold'),
                                             bg='white', fg='#333333', width=54, anchor='w')
                    patient_label.grid(row=1, column=0, sticky='w', padx=15, pady=5)

                    ic_label = tk.Label(card_frame, text=f"   IC / Passport: {patient_ic}", font=('Open Sans', 12), bg='white',
                                        fg='#333333')
                    ic_label.grid(row=2, column=0, sticky='w', padx=15, pady=5)

                    gender_label = tk.Label(card_frame, text=f"   Gender: {patient_gender}", font=('Open Sans', 12), bg='white',
                                            fg='#333333')
                    gender_label.grid(row=3, column=0, sticky='w', padx=15, pady=5)

                    date_label = tk.Label(card_frame, text=f"   Date: {ar_date}", font=('Open Sans', 12), bg='white', fg='#333333')
                    date_label.grid(row=4, column=0, sticky='w', padx=15, pady=5)

                    time_label = tk.Label(card_frame, text=f"   Time: {ar_time}", font=('Open Sans', 12), bg='white', fg='#333333')
                    time_label.grid(row=5, column=0, sticky='w', padx=15, pady=5)

                    contact_label = tk.Label(card_frame, text=f"   Contact Number: {patient_contact}", font=('Open Sans', 12),
                                             bg='white', fg='#333333')
                    contact_label.grid(row=6, column=0, sticky='w', padx=15, pady=5)

                    description_label = tk.Label(card_frame, text="Description:", font=('Open Sans', 12), bg='white',
                                                 fg='#333333')
                    description_label.grid(row=1, column=3, sticky='w', padx=10)
                    description_frame = tk.Frame(card_frame)
                    description_frame.grid(row=2, column=3, rowspan=5, sticky='nw', padx=15)

                    description_text = tk.Text(description_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=40, height=6,
                                               borderwidth=1, relief='solid', wrap='word')
                    if ar_detail is not None:
                        description_text.insert('1.0', ar_detail)
                    description_text.config(state=tk.DISABLED)
                    description_text.pack(side="left", fill="both", expand=True)

                    text_scrollbar = tk.Scrollbar(description_frame, command=description_text.yview)
                    text_scrollbar.pack(side="right", fill="y")

                    description_text.config(yscrollcommand=text_scrollbar.set)

                    address_label = tk.Label(card_frame, text="   Address:", font=('Open Sans', 12), bg='white',
                                             fg='#333333')
                    address_label.grid(row=7, column=0, sticky='w', padx=15, pady=5)
                    address_frame = tk.Frame(card_frame)
                    address_frame.grid(row=8, column=0, columnspan=5, sticky='w', padx=(30, 20), pady=5)
                    address_text = tk.Text(address_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=102,
                                           height=3, borderwidth=1, relief='solid')
                    address_text.insert('1.0', patient_address)
                    address_text.config(state=tk.DISABLED)
                    address_text.pack(side="left", fill="both", expand=True)
                    address_scrollbar = tk.Scrollbar(address_frame, command=address_text.yview)
                    address_scrollbar.pack(side="right", fill="y")
                    address_text.config(yscrollcommand=address_scrollbar.set)

                    consult_button = tk.Button(card_frame, text='Consult', font=('Open Sans', 12, 'bold'), bg='#00C196',
                                               fg='white', width=12, borderwidth=0, relief="flat",
                                               command=lambda ar_id=ar_id: show_consult_frame(ar_id))
                    consult_button.grid(row=9, column=3, sticky='e', padx=15, pady=10)

                    record_button = tk.Button(card_frame, text="Patient's Record", font=('Open Sans', 12, 'bold'), bg='#00C196',
                                              fg='white', width=20, borderwidth=0, relief="flat",
                                              command=lambda patient_id=patient_id: show_patient_record(patient_id))
                    record_button.grid(row=9, column=0, sticky='w', padx=15, pady=10)

            self.switch('appointment', self.all_patient_frame)

        # Generate previous records of the patient
        def show_patient_record(patient_id):
            pr_back_button.config(command=lambda: show_patient_appointment())

            for widget in patient_record_scrollable_frame.winfo_children():
                widget.destroy()

            # Fetch completed appointments for the patient
            query = """SELECT ar.ar_id, ar.ar_detail, ar.ar_date, ar.ar_time, c.clinic_name, p.patient_name,
                       d.doctor_name, d.doctor_contact, a.appointment_prescription
                       FROM appointment_request ar
                       LEFT JOIN patient p ON ar.patient_id = p.patient_id
                       LEFT JOIN clinic c ON ar.clinic_id = c.clinic_id
                       LEFT JOIN appointment a ON ar.ar_id = a.ar_id
                       LEFT JOIN doctor d ON a.doctor_id = d.doctor_id
                       WHERE ar.patient_id = %s AND ar.ar_status = 'completed'
                       ORDER BY ar_date DESC, ar_time DESC;"""
            self.cursor.execute(query, (patient_id,))
            appointments = self.cursor.fetchall()

            if not appointments:
                no_appointments_label = tk.Label(patient_record_scrollable_frame, text="No completed appointments found",
                                                 font=('Open Sans', 12, 'bold'), bg='white', fg='red')
                no_appointments_label.pack(padx=440, pady=30)
            else:
                title_label = tk.Label(patient_record_scrollable_frame, text=f"Patient's Record: {appointments[0]['patient_name']}",
                                       font=('Open Sans', 20, 'bold', 'underline'), bg='white', fg='#333333', anchor='w')
                title_label.grid(row=0, column=0, columnspan=5, padx=35, pady=0, sticky='ew')

                for i, appointment in enumerate(appointments):
                    ar_id = appointment['ar_id']
                    ar_detail = appointment['ar_detail']
                    ar_date = self.format_date(str(appointment['ar_date']))
                    ar_time = self.timedelta_to_time(appointment['ar_time'])
                    ar_time = ar_time.strftime("%I%p").lstrip('0').lower()
                    clinic_name = appointment['clinic_name']
                    doctor_name = appointment['doctor_name']
                    doctor_contact = appointment['doctor_contact']
                    prescription = appointment['appointment_prescription'] if appointment['appointment_prescription'] \
                                                                           else 'No prescription provided'

                    card_frame = tk.Frame(patient_record_scrollable_frame, bg='white', highlightbackground='#00C196',
                                          highlightthickness=1)
                    card_frame.grid(row=i + 2, column=0, columnspan=5, padx=35, pady=10, sticky='ew')
                    card_frame.grid_columnconfigure(0, weight=1)
                    card_frame.grid_columnconfigure(1, weight=1)
                    card_frame.grid_columnconfigure(2, weight=1)
                    card_frame.grid_columnconfigure(3, weight=1)

                    id_label = tk.Label(card_frame, text=f"Appointment ID: {ar_id}", font=('Open Sans', 16, 'bold'), bg='white',
                                        fg='#333333')
                    id_label.grid(row=0, column=0, sticky='w', padx=15, pady=(10, 5))

                    clinic_label = tk.Label(card_frame, text=f"   Clinic: {clinic_name}", font=('Open Sans', 12, 'bold'), bg='white',
                                            fg='#333333', anchor='w', width=52)
                    clinic_label.grid(row=1, column=0, sticky='w', padx=15, pady=5)

                    doctor_label = tk.Label(card_frame, text=f"   Doctor: {doctor_name}", font=('Open Sans', 12), bg='white',
                                            fg='#333333')
                    doctor_label.grid(row=2, column=0, sticky='w', padx=15, pady=5)

                    doctor_contact_label = tk.Label(card_frame, text=f"   Doctor's Contact Number: {doctor_contact}",
                                                    font=('Open Sans', 12), bg='white', fg='#333333')
                    doctor_contact_label.grid(row=3, column=0, columnspan=2, sticky='w', padx=15, pady=5)

                    date_label = tk.Label(card_frame, text=f"   Date: {ar_date}", font=('Open Sans', 12), bg='white', fg='#333333')
                    date_label.grid(row=4, column=0, sticky='w', padx=15, pady=5)

                    time_label = tk.Label(card_frame, text=f"   Time: {ar_time}", font=('Open Sans', 12), bg='white', fg='#333333')
                    time_label.grid(row=5, column=0, sticky='w', padx=15, pady=5)

                    description_label = tk.Label(card_frame, text="Description:", font=('Open Sans', 12), bg='white',
                                                 fg='#333333')
                    description_label.grid(row=1, column=2, sticky='w', padx=10, pady=5)

                    description_frame = tk.Frame(card_frame)
                    description_frame.grid(row=2, column=2, rowspan=4, sticky='nw', padx=15)

                    description_text = tk.Text(description_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=40, height=6,
                                               borderwidth=1, relief='solid', wrap='word')
                    if ar_detail is not None:
                        description_text.insert('1.0', ar_detail)
                    description_text.config(state=tk.DISABLED)
                    description_text.pack(side="left", fill="both", expand=True)

                    text_scrollbar = tk.Scrollbar(description_frame, command=description_text.yview)
                    text_scrollbar.pack(side="right", fill="y")

                    description_text.config(yscrollcommand=text_scrollbar.set)

                    prescription_label = tk.Label(card_frame, text="Doctor's prescription:", font=('Open Sans', 12), bg='white',
                                                  fg='#333333', anchor='w')
                    prescription_label.grid(row=7, column=0, sticky='w', padx=27, pady=5)
                    prescription_frame = tk.Frame(card_frame)
                    prescription_frame.grid(row=8, column=0, columnspan=5, sticky='nw', padx=(30, 15), pady=(0, 15))

                    prescription_text = tk.Text(prescription_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=100,
                                                height=4, borderwidth=1, relief='solid', wrap='word')
                    prescription_text.insert('1.0', prescription)
                    prescription_text.config(state=tk.DISABLED)
                    prescription_text.pack(side="left", fill="both", expand=True)
                    prescription_scrollbar = tk.Scrollbar(prescription_frame, command=prescription_text.yview)
                    prescription_scrollbar.pack(side="right", fill="y")

                    prescription_text.config(yscrollcommand=prescription_scrollbar.set)

            self.switch('record', self.all_patient_frame)
            patient_record_canvas.yview_moveto(0)

        # Set up the consultation frame for the doctor to fill in prescription
        def show_consult_frame(ar_id):
            def save_prescription():
                # Ensure the prescription is filled
                if prescription_text.cget('fg') == '#333333':
                    prescription = prescription_text.get('1.0', tk.END)
                    self.cursor.execute("SELECT appointment_id FROM appointment WHERE ar_id = %s", (ar_id, ))
                    appointment_id = self.cursor.fetchone()['appointment_id']

                    if appointment_id:
                        # Update the existing appointment
                        update_appointment_query = """UPDATE appointment 
                                                      SET appointment_prescription = %s, appointment_complete = 1
                                                      WHERE appointment_id = %s;"""
                        self.cursor.execute(update_appointment_query, (prescription, appointment_id, ))
                        database.commit()

                        # Update the appointment_request table
                        update_appointment_request_query = """UPDATE appointment_request 
                                                              SET ar_status = 'completed'
                                                              WHERE ar_id = %s;"""
                        self.cursor.execute(update_appointment_request_query, (ar_id, ))

                        c_save_error_label.config(text='')
                        database.commit()
                        messagebox.showinfo('Success', 'Finish Consult Successfully')
                        show_patient_appointment()
                else:
                    c_save_error_label.config(text='Please enter prescription')

            c_back_button.config(command=lambda: show_patient_appointment())
            c_save_button.config(command=lambda: save_prescription())

            for widget in consult_scrollable_frame.winfo_children():
                widget.destroy()

            # Fetch appointment details
            query = """SELECT ar.ar_id, ar.ar_detail, ar.ar_date, ar.ar_time, 
                       p.patient_name, p.patient_ic_passport, p.patient_gender, p.patient_contact, p.patient_address
                       FROM appointment_request ar
                       LEFT JOIN patient p ON ar.patient_id = p.patient_id
                       LEFT JOIN clinic c ON ar.clinic_id = c.clinic_id
                       LEFT JOIN appointment a ON ar.ar_id = a.ar_id
                       LEFT JOIN doctor d ON a.doctor_id = d.doctor_id
                       WHERE ar.ar_id = %s;"""
            self.cursor.execute(query, (ar_id,))
            appointment = self.cursor.fetchone()

            if appointment:
                ar_id = appointment['ar_id']
                ar_detail = appointment['ar_detail']
                ar_date = self.format_date(str(appointment['ar_date']))
                ar_time = self.timedelta_to_time(appointment['ar_time'])
                ar_time = ar_time.strftime("%I%p").lstrip('0').lower()
                patient_name = appointment['patient_name']
                patient_ic = appointment['patient_ic_passport']
                patient_gender = appointment['patient_gender']
                patient_contact = appointment['patient_contact']
                patient_address = appointment['patient_address']

                title_label = tk.Label(consult_scrollable_frame, text=f"Start Consult - Generate Prescription",
                                       font=('Open Sans', 20, 'bold', 'underline'), bg='white', fg='#333333', anchor='w')
                title_label.grid(row=0, column=0, columnspan=5, padx=35, pady=0, sticky='ew')

                info_frame = tk.Frame(consult_scrollable_frame, bg='white')
                info_frame.grid(row=1, column=0, columnspan=5, padx=35, pady=(10, 70), sticky='ew')
                info_frame.grid_columnconfigure(0, weight=1)
                info_frame.grid_columnconfigure(1, weight=1)
                info_frame.grid_columnconfigure(2, weight=1)
                info_frame.grid_columnconfigure(3, weight=1)

                id_label = tk.Label(info_frame, text=f"Appointment ID: {ar_id}", font=('Open Sans', 16, 'bold'), bg='white',
                                    fg='#333333')
                id_label.grid(row=0, column=0, sticky='w', padx=10, pady=5)

                patient_label = tk.Label(info_frame, text=f"   Patient Name: {patient_name}", font=('Open Sans', 12, 'bold'),
                                         bg='white', fg='#333333', width=53, anchor='w')
                patient_label.grid(row=1, column=0, sticky='w', padx=15, pady=5)

                ic_label = tk.Label(info_frame, text=f"   IC / Passport: {patient_ic}", font=('Open Sans', 12), bg='white', fg='#333333')
                ic_label.grid(row=2, column=0, sticky='w', padx=15, pady=5)

                gender_label = tk.Label(info_frame, text=f"   Gender: {patient_gender}", font=('Open Sans', 12), bg='white', fg='#333333')
                gender_label.grid(row=3, column=0, sticky='w', padx=15, pady=5)

                date_label = tk.Label(info_frame, text=f"   Date: {ar_date}", font=('Open Sans', 12), bg='white', fg='#333333')
                date_label.grid(row=4, column=0, sticky='w', padx=15, pady=5)

                time_label = tk.Label(info_frame, text=f"   Time: {ar_time}", font=('Open Sans', 12), bg='white', fg='#333333')
                time_label.grid(row=5, column=0, sticky='w', padx=15, pady=5)

                contact_label = tk.Label(info_frame, text=f"   Contact Number: {patient_contact}", font=('Open Sans', 12),
                                         bg='white', fg='#333333')
                contact_label.grid(row=6, column=0, sticky='w', padx=15, pady=5)

                description_label = tk.Label(info_frame, text="Description:", font=('Open Sans', 12), bg='white',
                                             fg='#333333')
                description_label.grid(row=1, column=1, sticky='w', padx=10, pady=5)
                description_frame = tk.Frame(info_frame)
                description_frame.grid(row=2, column=1, rowspan=5, sticky='nw', padx=15)

                description_text = tk.Text(description_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=40, height=6,
                                           borderwidth=1, relief='solid', wrap='word')
                if ar_detail is not None:
                    description_text.insert('1.0', ar_detail)
                description_text.config(state=tk.DISABLED)
                description_text.pack(side="left", fill="both", expand=True)

                text_scrollbar = tk.Scrollbar(description_frame, command=description_text.yview)
                text_scrollbar.pack(side="right", fill="y")

                description_text.config(yscrollcommand=text_scrollbar.set)

                address_label = tk.Label(info_frame, text="   Address:", font=('Open Sans', 12), bg='white',
                                         fg='#333333')
                address_label.grid(row=7, column=0, sticky='w', padx=15, pady=5)
                address_frame = tk.Frame(info_frame)
                address_frame.grid(row=8, column=0, columnspan=5, sticky='w', padx=(30, 20), pady=5)
                address_text = tk.Text(address_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=102,
                                       height=3, borderwidth=1, relief='solid')
                address_text.insert('1.0', patient_address)
                address_text.config(state=tk.DISABLED)
                address_text.pack(side="left", fill="both", expand=True)
                address_scrollbar = tk.Scrollbar(address_frame, command=address_text.yview)
                address_scrollbar.pack(side="right", fill="y")
                address_text.config(yscrollcommand=address_scrollbar.set)

                prescription_label = tk.Label(info_frame, text="   Prescription:", font=('Open Sans', 12, 'bold'), bg='white',
                                              fg='#333333')
                prescription_label.grid(row=9, column=0, sticky='w', padx=15, pady=5)

                prescription_frame = tk.Frame(info_frame, bg='#CEF7ED')
                prescription_frame.grid(row=10, column=0, columnspan=5, sticky='nw', padx=(30, 15), pady=(0, 30))

                prescription_text = tk.Text(prescription_frame, font=('Open Sans', 12), bg='#CEF7ED', fg='#858585', width=100,
                                            height=8, wrap='word')
                prescription_text.insert('1.0', 'Enter Prescription')
                prescription_text.pack(side="left", fill="both", expand=True)
                prescription_scrollbar = tk.Scrollbar(prescription_frame, command=prescription_text.yview)
                prescription_scrollbar.pack(side="right", fill="y")

                prescription_text.config(yscrollcommand=prescription_scrollbar.set)

                prescription_text.bind('<FocusIn>', lambda event: self.focus_entry('text', prescription_text))
                prescription_text.bind('<FocusOut>', lambda event: self.leave_focus_entry('text', prescription_text,
                                                                                          'Enter Prescription'))

            self.switch('consult', self.all_patient_frame)
            consult_canvas.yview_moveto(0)

        for widget in self.patient_frame.winfo_children():
            widget.destroy()

        appointment_frame = tk.Frame(self.patient_frame, width=1050, height=510, bg='white')
        appointment_canvas = tk.Canvas(appointment_frame, borderwidth=0, background="#ffffff", width=1030, height=510,
                                       highlightthickness=0)
        appointment_canvas.pack(side="left", fill="both", expand=True)
        appointment_scrollbar = tk.Scrollbar(appointment_frame, orient="vertical", command=appointment_canvas.yview)
        appointment_scrollbar.pack(side="right", fill="y")
        appointment_canvas.configure(yscrollcommand=appointment_scrollbar.set)
        appointment_scrollable_frame = tk.Frame(appointment_canvas, background="#ffffff")
        appointment_canvas.create_window((0, 0), window=appointment_scrollable_frame, anchor="nw")
        self.all_patient_frame['appointment'] = [appointment_frame, appointment_canvas, appointment_scrollable_frame, 0]

        patient_record_frame = tk.Frame(self.patient_frame, width=1050, height=510, bg='white')
        pr_back_button = ttk.Button(patient_record_frame, text='< Back', style='back.TButton', cursor='hand2', width=6)
        pr_back_button.place(x=20, y=15)
        patient_record_canvas = tk.Canvas(patient_record_frame, borderwidth=0, background="#ffffff", width=1030, height=510,
                                          highlightthickness=0)
        patient_record_canvas.place(x=0, y=75)
        patient_record_scrollbar = tk.Scrollbar(patient_record_frame, orient="vertical", command=patient_record_canvas.yview)
        patient_record_scrollbar.place(x=1033, y=75, height=430)
        patient_record_canvas.configure(yscrollcommand=patient_record_scrollbar.set)
        patient_record_scrollable_frame = tk.Frame(patient_record_canvas, background="#ffffff")
        patient_record_canvas.create_window((0, 0), window=patient_record_scrollable_frame, anchor="nw")
        self.all_patient_frame['record'] = [patient_record_frame, patient_record_canvas, patient_record_scrollable_frame, 0]

        consult_frame = tk.Frame(self.patient_frame, width=1050, height=510, bg='white')
        c_back_button = ttk.Button(consult_frame, text='< Back', style='back.TButton', cursor='hand2', width=6)
        c_back_button.place(x=20, y=15)
        c_save_button = ttk.Button(consult_frame, text='Save', cursor='hand2', style='green_button.TButton', width=6)
        c_save_button.place(x=940, y=10)
        c_save_error_label = tk.Label(consult_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        c_save_error_label.place(x=750, y=18)
        consult_canvas = tk.Canvas(consult_frame, borderwidth=0, background="#ffffff", width=1030, height=510, highlightthickness=0)
        consult_canvas.place(x=0, y=75)
        consult_scrollbar = tk.Scrollbar(consult_frame, orient="vertical", command=consult_canvas.yview)
        consult_scrollbar.place(x=1033, y=75, height=430)
        consult_canvas.configure(yscrollcommand=consult_scrollbar.set)
        consult_scrollable_frame = tk.Frame(consult_canvas, background="#ffffff")
        consult_canvas.create_window((0, 0), window=consult_scrollable_frame, anchor="nw")
        self.all_patient_frame['consult'] = [consult_frame, consult_canvas, consult_scrollable_frame, 0]

        show_patient_appointment()

    def set_up_timetable_frame(self):
        def show_calendar():
            calendar_frame.place(x=400, y=85)
            calendar_frame.lift()

        def hide_calendar():
            calendar_frame.place_forget()

        def select_date():
            selected_date = cal.get_date()
            selected_date = self.format_date(str(selected_date))
            date_entry.config(text=selected_date, fg='#333333')
            hide_calendar()

        def doctor_view_appointments():
            def fetch_doctor_name():
                cursor.execute('''SELECT doctor_name FROM doctor WHERE doctor_id = %s''', (self.doctor_id,))
                doctor_name = cursor.fetchone()
                return doctor_name[0] if doctor_name else None

            def fetch_doctor_workinghours():
                cursor.execute('''SELECT doctor_working_hour FROM doctor WHERE doctor_id = %s''', (self.doctor_id,))
                workinghours = cursor.fetchone()
                return workinghours[0] if workinghours else None

            def fetch_appointments_for_doctor(selected_date):
                cursor.execute('''SELECT ar_time FROM appointment_request ar
                               JOIN appointment a ON ar.ar_id = a.ar_id
                               WHERE ar.ar_date = %s AND a.doctor_id = %s
                               AND ar.ar_status = 'ongoing' AND a.appointment_complete = 0''',
                               (selected_date, self.doctor_id))
                appointments = cursor.fetchall()
                return [appointment[0] for appointment in appointments]

            def parse_doctor_workinghours(workinghours):
                time_format_12 = '%I%p'
                # Parse the working hours
                parts = workinghours.split(', ')
                if len(parts) > 2:
                    working_hour = parts[1].split('-')
                    start_work = working_hour[0].strip()
                    start_work = datetime.strptime(start_work, time_format_12).time()
                    end_work = working_hour[1].strip()
                    end_work = datetime.strptime(end_work, time_format_12) - timedelta(hours=1)
                    end_work = end_work.time()
                    rest_days = parts[2].split()[-1]
                    whole = [start_work, end_work, rest_days]
                elif len(parts) > 1:
                    working_hour = parts[1].split('-')
                    start_work = working_hour[0].strip()
                    start_work = datetime.strptime(start_work, time_format_12).time()
                    end_work = working_hour[1].strip()
                    end_work = datetime.strptime(end_work, time_format_12) - timedelta(hours=1)
                    end_work = end_work.time()
                    whole = [start_work, end_work]
                else:
                    whole = []
                return whole

            hide_calendar()
            selected_date = date_entry.cget('text')

            if not selected_date or selected_date == 'Select Date':
                doctor_name_label.configure(fg='red', text='Please choose a date')
                tree.place_forget()
                return  # Do nothing if date or doctor is not selected

            current_date = datetime.now().date()
            # Parse the date string into a datetime object
            date_obj = datetime.strptime(selected_date, '%d %B %Y')
            # Format the datetime object into the desired string format
            formatted_date = date_obj.strftime('%Y-%m-%d')
            selected_date_obj = datetime.strptime(formatted_date, '%Y-%m-%d').date()
            if selected_date_obj < current_date:
                doctor_name_label.configure(fg='red', text='The selected date is passed. Please choose a valid date')
                tree.place_forget()
                return

            cursor.execute('''SELECT clinic_id FROM doctor WHERE doctor_id=%s''', (self.doctor_id, ))
            clinic_id = cursor.fetchone()[0]
            cursor.execute('''SELECT clinic_operation FROM clinic WHERE clinic_id=%s''', (clinic_id,))
            c_operation = cursor.fetchone()[0]
            c_operation = c_operation.split(', ')
            if len(c_operation) > 2:
                c_rest = c_operation[2].split()[-1]
                if selected_date_obj.strftime('%A') == c_rest:
                    doctor_name_label.configure(fg='red', text=f'The clinic you are in is rest on {c_rest}')
                    tree.place_forget()
                    return

            doctor_workinghours = fetch_doctor_workinghours()
            working_list = parse_doctor_workinghours(doctor_workinghours)
            if working_list and len(working_list) > 2:
                if selected_date_obj.strftime('%A') == working_list[2]:
                    doctor_name_label.configure(fg='red', text=f'You are rest on {working_list[2]}')
                    tree.place_forget()
                    return

            # Fetch and display the doctor's name
            doctor_name = fetch_doctor_name()
            doctor_name_label.configure(fg='#333333', text=doctor_name + '   ' + selected_date)

            appointments = fetch_appointments_for_doctor(selected_date_obj)
            # Convert database fetched times to datetime.time objects
            appointment_times = [datetime.strptime(str(app_time), '%H:%M:%S').time() for app_time in appointments]

            # Standard time slots from 08:00 to 20:00
            time_slots = [time(hour, 0, 0) for hour in range(8, 21)]  # 8 AM to 8 PM

            for item in tree.get_children():
                tree.delete(item)

            start = None
            end = None
            if working_list and len(working_list) > 1:
                start = working_list[0]
                end = working_list[1]
            else:
                if len(c_operation) > 1 and c_operation[1] != '24 hours':
                    time_format_12 = '%I%p'
                    operation_hour = c_operation[1].split('-')
                    start_operate = operation_hour[0].strip()
                    start = datetime.strptime(start_operate, time_format_12).time()
                    end_operate = operation_hour[1].strip()
                    end_operate = datetime.strptime(end_operate, time_format_12) - timedelta(hours=1)
                    end = end_operate.time()

            for time_slot in time_slots:
                if start and end:
                    if start <= time_slot <= end:
                        status = 'Available'
                        tag = 'Available'
                        if time_slot in appointment_times:
                            status = 'Booked'
                            tag = 'Booked'
                    else:
                        status = 'Not on shift'
                        tag = 'Not on shift'
                        if time_slot in appointment_times:
                            status = 'Not on shift (Booked)'
                            tag = 'Not on shift (Booked)'
                else:
                    if time_slot in appointment_times:
                        status = 'Booked'
                        tag = 'Booked'
                    else:
                        status = 'Available'
                        tag = 'Available'
                formatted_time = time_slot.strftime('%I%p').lstrip('0').lower()
                tree.insert("", tk.END, values=(formatted_time, status), tags=(tag,))

            tree.place(x=120, y=150)

        for widget in self.timetable_frame.winfo_children():
            widget.destroy()

        date_doctor_frame = tk.Frame(self.timetable_frame, width=1050, height=510, bg='white')
        date_doctor_frame.place(x=0, y=0)

        date_label = tk.Label(date_doctor_frame, text="Date:", font=('Open Sans', 12, 'bold'), bg='white', fg='#000000')
        date_label.place(x=350, y=50)

        view_button = ttk.Button(date_doctor_frame, text='View', style='white_word.TButton', width=8, cursor='hand2',
                                 command=lambda: doctor_view_appointments())
        view_button.place(x=920, y=42)
        doctor_name_label = tk.Label(date_doctor_frame, text='', fg='#333333', font=('Open Sans', 12, 'bold'), bg='white',
                                     justify='center', width=90)
        doctor_name_label.place(x=70, y=120)
        columns = ("time", "status")
        tree = ttk.Treeview(date_doctor_frame, columns=columns, show='headings', height=13)
        tree.heading("time", text="Time")
        tree.heading("status", text="Appointment")
        tree.column("time", width=400, anchor=tk.CENTER)
        tree.column("status", width=400, anchor=tk.CENTER)

        # Define tag
        tree.tag_configure('Booked', foreground='red')
        tree.tag_configure('Not on shift', foreground='#858585')
        tree.tag_configure('Available', foreground='#333333')
        tree.tag_configure('Not on shift (Booked)', foreground='#858585')

        # Date selection dropdown
        date_entry_frame = tk.Frame(date_doctor_frame, bg='#D0F9EF', width=275, height=45)
        date_entry_frame.place(x=400, y=40)
        date_entry = tk.Label(date_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585')
        date_entry.place(x=10, y=10)
        date_entry.config(text='Select Date')

        calendar_button = ttk.Button(date_entry_frame, style='calendar.TButton', cursor='hand2', command=show_calendar)
        calendar_button.place(x=230, y=5)

        calendar_frame = tk.Frame(date_doctor_frame, bg='#D0F9EF', width=100, height=100)
        cal = Calendar(calendar_frame, selectmode='day', date_pattern='yyyy-mm-dd')
        cal.pack(pady=10)
        calendar_buttons_frame = tk.Frame(calendar_frame, bg='#D0F9EF')
        calendar_buttons_frame.pack()
        ttk.Button(calendar_buttons_frame, text="Select", command=select_date).pack(side='right', padx=28, pady=(0, 10))
        ttk.Button(calendar_buttons_frame, text="Cancel", command=hide_calendar).pack(side='left', padx=27, pady=(0, 10))

    def set_up_me_frame(self):
        def show_personal():
            def edit_personal():
                for entry in all_entries:
                    entry.config(state='normal', fg='#333333')
                gender_entry.config(fg='#333333')
                gender_button.config(state='normal')
                address_entry.config(state='normal', fg='#333333')
                image_entry.config(fg='#333333')
                image_button.config(state='normal')

                edit_button.place_forget()
                p_save_button.place(x=945, y=15)

            def save_personal():
                personal_content_frame.focus_set()
                if all([entry.cget('fg') == '#333333' for entry in all_entries]) and gender_entry.cget('fg') == '#333333' \
                        and address_entry.cget('fg') == '#333333' and image_entry.cget('fg') == '#333333':
                    user_name = name_entry.get()
                    user_ic_passport = ic_passport_entry.get()
                    user_contact = contact_entry.get()
                    user_gender = gender_entry.cget('text')
                    user_address = address_entry.get('1.0', tk.END)
                    user_language = language_entry.get()
                    user_specialize = specialize_entry.get()
                    user_working = working_entry.get()
                    user_image = image_entry.cget('text')

                    user_image_binary = None
                    # Check if a new image has been selected
                    if self.img_var:
                        img = self.img_var
                        if img.lower().endswith(('.jpg', '.jpeg', '.png')):
                            with open(img, 'rb') as file:
                                user_image_binary = file.read()

                    if all([user_name, user_ic_passport, user_contact, user_gender, user_address, user_language,
                            user_specialize, user_working, user_image]):
                        if user_image_binary:
                            cursor.execute('''UPDATE doctor SET doctor_name=%s, doctor_ic_passport=%s, doctor_gender=%s, 
                                           doctor_address=%s, doctor_contact=%s, doctor_language=%s, doctor_working_hour=%s,
                                           doctor_specialize=%s, doctor_image=%s WHERE user_id=%s''',
                                           (user_name, user_ic_passport, user_gender, user_address, user_contact, user_language,
                                            user_working, user_specialize, user_image_binary, self.user_id))
                        else:
                            cursor.execute('''UPDATE doctor SET doctor_name=%s, doctor_ic_passport=%s, doctor_gender=%s, 
                                           doctor_address=%s, doctor_contact=%s, doctor_language=%s, doctor_working_hour=%s,
                                           doctor_specialize=%s WHERE user_id=%s''',
                                           (user_name, user_ic_passport, user_gender, user_address, user_contact, user_language,
                                            user_working, user_specialize, self.user_id))
                        p_save_error_label.config(text='')
                        database.commit()
                        show_personal()
                    else:
                        p_save_error_label.config(text='Please fill in all details')
                else:
                    p_save_error_label.config(text='Please fill in all details')

            def personal_password_visible():
                password_entry.config(show='')
                password_eye_closed_button.place_forget()
                password_eye_opened_button.place(x=330, y=2)

            def personal_password_invisible():
                password_entry.config(show='*')
                password_eye_opened_button.place_forget()
                password_eye_closed_button.place(x=330, y=2)

            for widget in personal_content_frame.winfo_children():
                widget.destroy()

            edit_button.config(command=lambda: edit_personal())
            p_save_button.config(command=lambda: save_personal())
            p_save_button.place_forget()
            edit_button.place(x=945, y=15)
            p_save_error_label.config(text='')
            self.img_var = None

            all_entries = []

            cursor.execute('''SELECT user_email, user_password FROM user WHERE user_id=%s''', (self.user_id, ))
            user_detail = cursor.fetchone()

            email_label = tk.Label(personal_content_frame, text='Email: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                   width=20, anchor='e')
            email_label.grid(row=0, column=0, padx=(150, 5), pady=5, sticky='e')
            email_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            email_frame.grid(row=0, column=1, padx=5, pady=5, sticky='w')
            email_entry = tk.Label(email_frame, bg='#D0F9EF', text=user_detail[0], fg='#858585', font=('Open Sans', 10))
            email_entry.place(x=5, y=12)

            password_label = tk.Label(personal_content_frame, text='Password: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                      width=20, anchor='e')
            password_label.grid(row=1, column=0, padx=(150, 5), pady=5, sticky='e')
            password_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            password_frame.grid(row=1, column=1, padx=5, pady=5, sticky='w')
            password_entry = tk.Entry(password_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), show='*', border=0)
            password_entry.place(x=7, y=12)
            password_entry.insert(0, user_detail[1])
            password_entry.config(state='disabled', disabledbackground='#D0F9EF')
            password_eye_closed_button = ttk.Button(password_frame, style='eye_closed_green.TButton', cursor='hand2')
            password_eye_closed_button.place(x=330, y=2)
            password_eye_opened_button = ttk.Button(password_frame, style='eye_opened_green.TButton', cursor='hand2')
            password_eye_closed_button.config(command=lambda: personal_password_visible())
            password_eye_opened_button.config(command=lambda: personal_password_invisible())

            cursor.execute('''SELECT * FROM doctor WHERE user_id=%s''', (self.user_id, ))
            user_info = cursor.fetchone()

            status = 'Active' if user_info[10] == 1 else 'Inactive'
            status_label = tk.Label(personal_content_frame, text='Status: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                    width=20, anchor='e')
            status_label.grid(row=2, column=0, padx=(150, 5), pady=5, sticky='e')
            status_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            status_frame.grid(row=2, column=1, padx=5, pady=5, sticky='w')
            status_entry = tk.Label(status_frame, bg='#D0F9EF', text=status, fg='#858585', font=('Open Sans', 10))
            status_entry.place(x=5, y=12)

            name_label = tk.Label(personal_content_frame, text='Name: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                  width=20, anchor='e')
            name_label.grid(row=3, column=0, padx=(150, 5), pady=(40, 5), sticky='e')
            name_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            name_entry_frame.grid(row=3, column=1, padx=5, pady=(40, 5), sticky='w')
            name_entry = tk.Entry(name_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            name_entry.place(x=7, y=12)
            name_entry.insert(0, user_info[1])
            name_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(name_entry)

            image_label = tk.Label(personal_content_frame, text='Image: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                   width=20, anchor='e')
            image_label.grid(row=4, column=0, padx=(150, 5), pady=5, sticky='e')
            image_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            image_entry_frame.grid(row=4, column=1, padx=5, pady=5, sticky='w')
            image_entry = tk.Label(image_entry_frame, bg='#D0F9EF', text='', fg='#858585', font=('Open Sans', 10))
            image_entry.place(x=5, y=12)
            file_type = detect_image_format(user_info[9]) or 'img'
            image_entry.config(text=f"{user_info[1]}.{file_type}")
            image_button = ttk.Button(image_entry_frame, text='⇫', style='selection.TButton', width=4, cursor='hand2',
                                      command=lambda: self.upload_doctor_image(image_entry, 100, 100, image_display_label))
            image_button.place(x=330, y=5)
            image_button.config(state='disabled')
            image_display_label = tk.Label(personal_content_frame, bg='white', anchor='w')
            image_display_label.grid(row=5, column=1, padx=5, pady=5, sticky='w')
            img = Image.open(io.BytesIO(user_info[9]))
            img = img.resize((100, 100), Image.LANCZOS)
            img = ImageTk.PhotoImage(img)
            image_display_label.config(image=img)
            image_display_label.image = img

            ic_passport_label = tk.Label(personal_content_frame, text='IC / Passport: ', font=('Open Sans', 12, 'bold'), bg='white',
                                         fg='#000000', width=20, anchor='e')
            ic_passport_label.grid(row=6, column=0, padx=(150, 5), pady=5, sticky='e')
            ic_passport_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            ic_passport_entry_frame.grid(row=6, column=1, padx=5, pady=5, sticky='w')
            ic_passport_entry = tk.Entry(ic_passport_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            ic_passport_entry.place(x=7, y=12)
            ic_passport_entry.insert(0, user_info[2])
            ic_passport_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(ic_passport_entry)

            gender_label = tk.Label(personal_content_frame, text='Gender: ', font=('Open Sans', 12, 'bold'), bg='white',
                                    fg='#000000', width=20, anchor='e')
            gender_label.grid(row=7, column=0, padx=(150, 5), pady=5, sticky='e')
            gender_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            gender_entry_frame.grid(row=7, column=1, padx=5, pady=5, sticky='w')
            gender_entry = tk.Label(gender_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), text=user_info[3])
            gender_entry.place(x=5, y=12)
            gender_button = ttk.Button(gender_entry_frame, text='▼', style='selection.TButton', width=4,
                                       cursor='hand2', command=lambda: self.display_menu(gender_entry_frame, 0, 33, gender_menu))
            gender_button.place(x=330, y=5)
            gender_menu = tk.Menu(personal_content_frame, tearoff=0, bg='#D0F9EF', fg='#333333',
                                  font=('Open Sans', 10))
            gender_menu.add_command(label="Male", command=lambda: self.select_menu_option(gender_entry, 'Male'))
            gender_menu.add_command(label="Female", command=lambda: self.select_menu_option(gender_entry, 'Female'))
            gender_menu.add_separator()
            gender_menu.add_command(label="Cancel\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t ",
                                    command=gender_menu.unpost)
            gender_button.config(state='disabled')

            contact_label = tk.Label(personal_content_frame, text='Contact Number: ', font=('Open Sans', 12, 'bold'), bg='white',
                                     fg='#000000', width=20, anchor='e')
            contact_label.grid(row=8, column=0, padx=(150, 5), pady=5, sticky='e')
            contact_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            contact_entry_frame.grid(row=8, column=1, padx=5, pady=5, sticky='w')
            contact_entry = tk.Entry(contact_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            contact_entry.place(x=7, y=12)
            contact_entry.insert(0, user_info[5])
            contact_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(contact_entry)

            address_label = tk.Label(personal_content_frame, text='Address: ', font=('Open Sans', 12, 'bold'), bg='white',
                                     fg='#000000', width=20, anchor='ne')
            address_label.grid(row=9, column=0, padx=(150, 5), pady=5, sticky='ne')
            address_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=90)
            address_entry_frame.grid(row=9, column=1, padx=5, pady=5, sticky='w')
            address_entry = tk.Text(address_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45,
                                    height=5, wrap='word')
            address_entry.place(x=7, y=5)
            address_entry.insert('1.0', user_info[4])
            address_entry.config(state='disabled')

            language_label = tk.Label(personal_content_frame, text='Language: ', font=('Open Sans', 12, 'bold'), bg='white',
                                      fg='#000000', width=20, anchor='e')
            language_label.grid(row=10, column=0, padx=(150, 5), pady=5, sticky='e')
            language_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            language_entry_frame.grid(row=10, column=1, padx=5, pady=5, sticky='w')
            language_entry = tk.Entry(language_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            language_entry.place(x=7, y=12)
            language_entry.insert(0, user_info[7])
            language_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(language_entry)

            working_label = tk.Label(personal_content_frame, text='Working Hours: ', font=('Open Sans', 12, 'bold'), bg='white',
                                     fg='#000000', width=20, anchor='e')
            working_label.grid(row=11, column=0, padx=(150, 5), pady=5, sticky='e')
            working_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            working_entry_frame.grid(row=11, column=1, padx=5, pady=5, sticky='w')
            working_entry = tk.Entry(working_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            working_entry.place(x=7, y=12)
            working_entry.insert(0, user_info[6])
            working_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(working_entry)

            specialize_label = tk.Label(personal_content_frame, text='Specialize In: ', font=('Open Sans', 12, 'bold'), bg='white',
                                        fg='#000000', width=20, anchor='e')
            specialize_label.grid(row=12, column=0, padx=(150, 5), pady=(5, 15), sticky='e')
            specialize_entry_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            specialize_entry_frame.grid(row=12, column=1, padx=5, pady=(5, 15), sticky='w')
            specialize_entry = tk.Entry(specialize_entry_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), border=0, width=45)
            specialize_entry.place(x=7, y=12)
            specialize_entry.insert(0, user_info[8])
            specialize_entry.config(state='disabled', disabledbackground='#D0F9EF')
            all_entries.append(specialize_entry)

            self.switch('personal', self.all_me_frame)

        def show_reset():
            def reset():
                reset_content_frame.focus_set()
                if old_entry.cget('fg') == '#333333' and new_entry.cget('fg') == '#333333' and confirm_entry.cget('fg') == '#333333':
                    cursor.execute('''SELECT user_password FROM user WHERE user_id=%s''', (self.user_id, ))
                    previous_password = cursor.fetchone()[0]
                    if old_entry.get() == previous_password:
                        if len(new_entry.get()) >= 8:
                            if new_entry.get() == confirm_entry.get():
                                cursor.execute('''UPDATE user SET user_password=%s WHERE user_id=%s''', (new_entry.get(), self.user_id))
                                database.commit()
                                save_error_label.config(text='')
                                messagebox.showinfo('Success', "Reset Password Successfully")
                                show_personal()
                            else:
                                save_error_label.config(text='Password does not match')
                        else:
                            save_error_label.config(text='Minimum 8 characters of password')
                    else:
                        save_error_label.config(text="Incorrect old password")
                else:
                    save_error_label.config(text="Please fill in all details")

            for widget in reset_content_frame.winfo_children():
                widget.destroy()

            save_error_label.config(text='')
            save_button.config(command=lambda: reset())

            reset_label = tk.Label(reset_content_frame, text='Reset Password',
                                   font=('Open Sans', 20, 'underline', 'bold'), bg='white', fg='#000000')
            reset_label.grid(row=0, column=0, columnspan=2, padx=35, pady=(10, 15), sticky='w')

            old_label = tk.Label(reset_content_frame, text='Old Password', font=('Open Sans', 12, 'bold'), bg='white',
                                         fg='#000000')
            old_label.grid(row=1, column=0, padx=50, pady=(5, 0), sticky='w')
            old_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            old_entry_frame.grid(row=2, column=0, padx=53, pady=(0, 5))
            old_entry = tk.Entry(old_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            old_entry.place(x=10, y=13)
            old_entry.insert(0, 'Enter Old Password')
            old_eye_closed_button = ttk.Button(old_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            old_eye_closed_button.place(x=330, y=2)
            old_eye_opened_button = ttk.Button(old_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            old_visibility = tk.Label(old_entry_frame, text='Close')
            old_eye_closed_button.config(command=lambda: self.show_hide_password(old_entry, old_eye_opened_button,
                                                                                 old_eye_closed_button, old_visibility))
            old_eye_opened_button.config(command=lambda: self.show_hide_password(old_entry, old_eye_opened_button,
                                                                                 old_eye_closed_button, old_visibility))
            old_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', old_entry, old_visibility))
            old_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', old_entry, 'Enter Old Password'))
            old_entry.bind('<Return>', lambda event: reset())

            new_label = tk.Label(reset_content_frame, text='New Password', font=('Open Sans', 12, 'bold'), bg='white',
                                 fg='#000000')
            new_label.grid(row=3, column=0, padx=50, pady=(15, 0), sticky='w')
            new_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            new_entry_frame.grid(row=4, column=0, padx=53, pady=(0, 5))
            new_entry = tk.Entry(new_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            new_entry.place(x=10, y=13)
            new_entry.insert(0, 'Enter New Password')
            new_eye_closed_button = ttk.Button(new_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            new_eye_closed_button.place(x=330, y=2)
            new_eye_opened_button = ttk.Button(new_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            new_visibility = tk.Label(new_entry_frame, text='Close')
            new_eye_closed_button.config(command=lambda: self.show_hide_password(new_entry, new_eye_opened_button,
                                                                                 new_eye_closed_button, new_visibility))
            new_eye_opened_button.config(command=lambda: self.show_hide_password(new_entry, new_eye_opened_button,
                                                                                 new_eye_closed_button, new_visibility))
            new_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', new_entry, new_visibility))
            new_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', new_entry, 'Enter New Password'))
            new_entry.bind('<Return>', lambda event: reset())

            confirm_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            confirm_entry_frame.grid(row=5, column=0, padx=53, pady=(0, 5))
            confirm_entry = tk.Entry(confirm_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            confirm_entry.place(x=10, y=13)
            confirm_entry.insert(0, 'Re-enter New Password')
            confirm_eye_closed_button = ttk.Button(confirm_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            confirm_eye_closed_button.place(x=330, y=2)
            confirm_eye_opened_button = ttk.Button(confirm_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            confirm_visibility = tk.Label(confirm_entry_frame, text='Close')
            confirm_eye_closed_button.config(command=lambda: self.show_hide_password(confirm_entry, confirm_eye_opened_button,
                                                                                     confirm_eye_closed_button, confirm_visibility))
            confirm_eye_opened_button.config(command=lambda: self.show_hide_password(confirm_entry, confirm_eye_opened_button,
                                                                                     confirm_eye_closed_button, confirm_visibility))
            confirm_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', confirm_entry, confirm_visibility))
            confirm_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', confirm_entry, 'Re-enter New Password'))
            confirm_entry.bind('<Return>', lambda event: reset())

            self.switch('reset', self.all_me_frame)

        for widget in self.me_frame.winfo_children():
            widget.destroy()

        personal_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        logout_button = tk.Button(personal_frame, text='Log Out', bg='red', fg='white', cursor='hand2', relief='flat', border=0,
                                  font=('Open Sans', 14, 'bold'), width=10, command=lambda: self.logout())
        logout_button.place(x=30, y=15)
        reset_password_button = ttk.Button(personal_frame, text='Reset Password', style='green_button.TButton', cursor='hand2',
                                           width=18, command=lambda: show_reset())
        reset_password_button.place(x=710, y=15)
        edit_button = ttk.Button(personal_frame, text='Edit', style='green_button.TButton', cursor='hand2', width=6)
        edit_button.place(x=945, y=15)
        p_save_button = ttk.Button(personal_frame, text='Save', style='green_button.TButton', cursor='hand2', width=6)
        p_save_error_label = tk.Label(personal_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        p_save_error_label.place(x=510, y=25)
        personal_canvas = tk.Canvas(personal_frame, width=1030, height=430, bg='white', highlightthickness=0)
        personal_canvas.place(x=0, y=75)
        personal_scrollbar = tk.Scrollbar(personal_frame, orient='vertical')
        personal_scrollbar.place(x=1033, y=75, height=430)
        personal_canvas.configure(yscrollcommand=personal_scrollbar.set)
        personal_scrollbar.configure(command=personal_canvas.yview)
        personal_content_frame = tk.Frame(personal_canvas, bg='white')
        personal_canvas.create_window((0, 0), window=personal_content_frame, anchor="nw")
        self.all_me_frame['personal'] = [personal_frame, personal_canvas, personal_content_frame, 0]

        reset_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        reset_back_button = ttk.Button(reset_frame, text='< Back', style='back.TButton', cursor='hand2', width=6,
                                       command=lambda: show_personal())
        reset_back_button.place(x=20, y=15)
        save_button = ttk.Button(reset_frame, text='Save', style='green_button.TButton', cursor='hand2', width=6)
        save_button.place(x=945, y=15)
        save_error_label = tk.Label(reset_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        save_error_label.place(x=750, y=25)
        reset_canvas = tk.Canvas(reset_frame, width=1030, height=430, bg='white', highlightthickness=0)
        reset_canvas.place(x=0, y=75)
        reset_scrollbar = tk.Scrollbar(reset_frame, orient='vertical')
        reset_scrollbar.place(x=1033, y=75, height=430)
        reset_canvas.configure(yscrollcommand=reset_scrollbar.set)
        reset_scrollbar.configure(command=reset_canvas.yview)
        reset_content_frame = tk.Frame(reset_canvas, bg='white')
        reset_canvas.create_window((0, 0), window=reset_content_frame, anchor="nw")
        self.all_me_frame['reset'] = [reset_frame, reset_canvas, reset_content_frame, 0]

        show_personal()

    def do_nothing(self, event):
        pass

    def format_date(self, date):
        full_date = date.split('-')
        year = full_date[0]
        month = full_date[1]
        day = full_date[2]
        months = {'01': 'January',
                  '02': 'February',
                  '03': 'March',
                  '04': 'April',
                  '05': 'May',
                  '06': 'June',
                  '07': 'July',
                  '08': 'August',
                  '09': 'September',
                  '10': 'October',
                  '11': 'November',
                  '12': 'December'}
        month = months[month]
        return f"{day} {month} {year}"

    def on_mouse_wheel(self, event, canvas):
        canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def focus_entry(self, entry_type, entry, visibility=None):
        if entry_type == 'entry':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
        elif entry_type == 'text':
            if entry.cget('fg') == '#858585':
                entry.delete('1.0', 'end')
                entry.config(fg='#333333')
        elif entry_type == 'password':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
                if visibility.cget('text') == 'Open':
                    entry.config(show='')
                elif visibility.cget('text') == 'Close':
                    entry.config(show='*')

    def leave_focus_entry(self, entry_type, entry, text):
        if entry_type == 'entry':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585')
                entry.insert(0, text)
        elif entry_type == 'text':
            value = entry.get('1.0', 'end')
            if value.strip() == '':
                entry.delete('1.0', 'end')
                entry.config(fg='#858585')
                entry.insert('1.0', text)
        elif entry_type == 'password':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585', show='')
                entry.insert(0, text)

    def timedelta_to_time(self, td_value):
        total_seconds = td_value.total_seconds()
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = int(total_seconds % 60)
        return time(hours, minutes, seconds)

    def display_menu(self, frame, x, y, menu):
        root_x = frame.winfo_rootx()
        root_y = frame.winfo_rooty()
        adjusted_x = root_x + x
        adjusted_y = root_y + y

        menu.post(adjusted_x, adjusted_y)

    def select_menu_option(self, label, option, text=None):
        if option == 'Clear':
            label.config(text=text, fg='#858585')
        else:
            label.config(text=option, fg='#333333')

    def show_hide_password(self, entry, eye_open_button, eye_close_button, visibility):
        if visibility.cget('text') == 'Close' and entry.cget('fg') == '#858585':
            eye_open_button.place(x=330, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')
        elif visibility.cget('text') == 'Open' and entry.cget('fg') == '#858585':
            eye_open_button.place_forget()
            eye_close_button.place(x=330, y=2)
            entry.config(show='')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Open':
            eye_open_button.place_forget()
            eye_close_button.place(x=330, y=2)
            entry.config(show='*')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Close':
            eye_open_button.place(x=330, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')

    def upload_doctor_image(self, entry, size_x, size_y, label):
        file_path = filedialog.askopenfilename(initialdir="/gui/images", title="Select an Image", filetypes=(
            ("JPEG files", "*.jpg;*.jpeg"), ("PNG files", "*.png"), ("All files", "*.*")))
        if file_path:
            img_name = os.path.basename(file_path)
            if file_path.lower().endswith(('.jpg', '.jpeg', '.png')):
                # Update the entry text
                entry.config(text=img_name, fg='#333333')
                self.img_var = file_path  # Store the file path of the uploaded image
                # Display the new image in the UI
                img = Image.open(file_path)
                img = img.resize((size_x, size_y), Image.LANCZOS)
                img = ImageTk.PhotoImage(img)
                label.config(image=img)
                label.image = img
            else:
                messagebox.showerror("Error", "Invalid Image Format")


class Admin:
    def __init__(self, main_window, login_register=None):
        self.root_window = main_window
        self.login_register = login_register  # Reference to LoginRegister instance
        self.user_id = None
        self.admin_token = None

        self.cursor = None

        self.window = tk.Toplevel(self.root_window)
        self.window.title('Call a Doctor')
        self.window.geometry('1050x600')
        icon = load_image('icon', 48, 48)
        self.window.iconphoto(False, icon)

        self.nf_icon = load_image('nf icon', 80, 70)
        self.search_button = load_image('search button', 18, 18)
        self.clear_search = load_image('clear search', 15, 15)
        self.eye_closed_image = load_image('eye closed', 24, 24)
        self.eye_opened_image = load_image('eye opened', 24, 24)

        self.clinic_images = {}
        self.doctor_images = {}

        style = ttk.Style()
        style.theme_use('clam')

        style.configure('navigation.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        font=('Open Sans', 20, 'bold'))
        style.map('navigation.TButton', background=[('active', 'white')], foreground=[('active', '#77C7B5')])
        style.configure('back.TButton', border=0, relief='flat', background='white', foreground='#7EE5CE',
                        font=('Open Sans', 18, 'bold'))
        style.map('back.TButton', background=[('active', 'white')], foreground=[('active', '#77C7B5')])
        style.configure('green_button.TButton', border=0, relief='flat', background='#7EE5CE', foreground='white',
                        font=('Open Sans', 14, 'bold'))
        style.map('green_button.TButton', background=[('active', '#77C7B5')])
        style.configure('eye_closed_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_closed_image)
        style.map('eye_closed_green.TButton', background=[('active', '#D0F9EF')])
        style.configure('eye_opened_green.TButton', border=0, relief='flat', background='#D0F9EF', image=self.eye_opened_image)
        style.map('eye_opened_green.TButton', background=[('active', '#D0F9EF')])

        self.navigation_frame = tk.Frame(self.window, width=1050, height=90, bg='white')
        self.navigation_frame.pack()
        self.navigation_bar = tk.Frame(self.navigation_frame, height=5, bg='#166E82')

        nf_icon = tk.Label(self.navigation_frame, image=self.nf_icon, bg='white', cursor='hand2')
        nf_icon.place(x=10, y=10)
        nf_icon.bind('<Button-1>', lambda event: self.refresh())
        nf_name = tk.Label(self.navigation_frame, text='CaD', cursor='hand2', font=('Open Sans', 30, 'bold'), bg='white', fg='#166E82')
        nf_name.place(x=90, y=20)
        nf_name.bind('<Button-1>', lambda event: self.refresh())
        nf_clinic_button = ttk.Button(self.navigation_frame, text='Clinic', style='navigation.TButton', width=5,
                                      command=lambda: self.show_activity_frame(90, 482, self.clinic_frame))
        nf_clinic_button.place(x=480, y=30)
        nf_clinic_request_button = ttk.Button(self.navigation_frame, text='Clinic Request', style='navigation.TButton', width=13,
                                              command=lambda: self.show_activity_frame(210, 602, self.clinic_request_frame))
        nf_clinic_request_button.place(x=600, y=30)
        nf_security_button = ttk.Button(self.navigation_frame, text='Security', style='navigation.TButton', width=9,
                                         command=lambda: self.show_activity_frame(120, 840, self.security_frame))
        nf_security_button.place(x=825, y=30)
        nf_me_button = ttk.Button(self.navigation_frame, text='Me', style='navigation.TButton', width=3,
                                  command=lambda: self.show_activity_frame(60, 976, self.me_frame))
        nf_me_button.place(x=975, y=30)

        self.clinic_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_clinic_frames = {}

        self.clinic_request_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_clinic_request_frame = {}

        self.security_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_security_frame = {}

        self.me_frame = tk.Frame(self.window, width=1050, height=510, bg='white')
        self.all_me_frame = {}

        self.all_scrollable_frame = {}
        self.all_scrollable_frame[self.clinic_frame] = 1
        self.all_scrollable_frame[self.clinic_request_frame] = 0
        self.all_scrollable_frame[self.security_frame] = 0
        self.all_scrollable_frame[self.me_frame] = 0
        
        # Store JWT token for API calls
        self.admin_token = None
        
        # Track current security tab
        self.current_security_tab = 'Statistics'

    def logout(self):
        # Call handle_logout from LoginRegister if available (clears tokens and calls logout API)
        if self.login_register:
            self.login_register.handle_logout()
            return  # handle_logout will show login screen
        
        # Fallback: basic logout if login_register not available
        self.user_id = None
        self.admin_token = None

        if self.cursor:
            self.cursor.close()
        self.cursor = None

        self.window.withdraw()
        self.root_window.deiconify()

        self.clinic_images = {}
        self.doctor_images = {}

        self.all_clinic_frames = {}
        self.all_clinic_request_frame = {}
        self.all_security_frame = {}
        self.all_me_frame = {}

        self.all_scrollable_frame = {}
        self.all_scrollable_frame[self.clinic_frame] = 1
        self.all_scrollable_frame[self.clinic_request_frame] = 0
        self.all_scrollable_frame[self.security_frame] = 0
        self.all_scrollable_frame[self.me_frame] = 0

    def run(self, user_id, admin_token=None):
        self.user_id = user_id
        self.admin_token = admin_token

        self.cursor = database.cursor(dictionary=True)

        self.window.deiconify()
        self.refresh()
    
    def refresh_jwt_token(self):
        """Refresh JWT token using refresh token. Returns True if successful, False otherwise."""
        if not self.login_register or not self.login_register.refresh_token:
            return False
        
        try:
            response = requests.post(
                REFRESH_TOKEN_URL,
                json={'refresh_token': self.login_register.refresh_token},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                new_admin_token = data.get('token')
                new_refresh_token = data.get('refresh_token')
                
                if new_admin_token:
                    # Update JWT token
                    self.admin_token = new_admin_token
                    
                    # Update refresh token if provided
                    if new_refresh_token and self.login_register:
                        self.login_register.save_refresh_token(new_refresh_token)
                    
                    return True
            else:
                # Refresh failed - token might be invalid
                print(f"[WARNING] JWT refresh failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"[ERROR] Failed to refresh JWT token: {e}")
            return False
    
    def make_admin_api_call(self, method, endpoint, headers=None, json_data=None, params=None, retry=True):
        """
        Make an admin API call with automatic JWT refresh on 401.
        Returns response object or None if failed.
        Validates refresh token before attempting refresh.
        """
        # If no JWT token, try to refresh first (if refresh token exists and is valid)
        if not self.admin_token:
            if not self.refresh_jwt_token():
                # No valid refresh token - cannot make API call
                print("[WARNING] No admin token and refresh token invalid/expired")
                return None
        
        # Prepare headers
        api_headers = {'Authorization': f'Bearer {self.admin_token}'}
        if headers:
            api_headers.update(headers)
        
        try:
            # Make API call
            if method.upper() == 'GET':
                response = requests.get(
                    f'{AUTH_API_BASE}{endpoint}',
                    headers=api_headers,
                    params=params,
                    timeout=5
                )
            elif method.upper() == 'POST':
                response = requests.post(
                    f'{AUTH_API_BASE}{endpoint}',
                    headers=api_headers,
                    json=json_data,
                    timeout=5
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            # Check if JWT expired (401 Unauthorized)
            if response.status_code == 401 and retry:
                # JWT expired - validate refresh token exists and refresh
                if self.login_register and self.login_register.refresh_token:
                    if self.refresh_jwt_token():
                        # Successfully refreshed - retry the request with new JWT (only once)
                        print("[INFO] JWT token refreshed automatically")
                        return self.make_admin_api_call(method, endpoint, headers, json_data, params, retry=False)
                    else:
                        # Refresh failed - refresh token invalid or expired
                        print("[WARNING] JWT refresh failed - refresh token may be invalid/expired")
                        # Show error message to user
                        if self.login_register:
                            self.login_register.handle_session_invalid("Your session has expired. Please log in again.")
                else:
                    # No refresh token available
                    print("[WARNING] No refresh token available for JWT refresh")
                
                return response
            
            return response
        except Exception as e:
            print(f"[ERROR] Admin API call failed: {e}")
            return None

    def refresh(self):
        cursor.execute('''UPDATE appointment_request ar
                          JOIN patient p ON ar.patient_id = p.patient_id
                          SET ar.ar_status = 'canceled'
                          WHERE CONCAT(ar.ar_date, ' ', ar.ar_time) < NOW()
                          AND ar.ar_status IN ('pending', 'ongoing')''')
        database.commit()

        self.set_up_clinic_request_frame()
        self.set_up_me_frame()
        self.set_up_clinic_frame()
        self.set_up_security_frame()

        if self.all_scrollable_frame[self.clinic_frame] == 1:
            self.show_activity_frame(90, 482, self.clinic_frame)
        elif self.all_scrollable_frame[self.clinic_request_frame] == 1:
            self.show_activity_frame(210, 602, self.clinic_request_frame)
        elif self.all_scrollable_frame[self.security_frame] == 1:
            self.show_activity_frame(120, 840, self.security_frame)
        elif self.all_scrollable_frame[self.me_frame] == 1:
            self.show_activity_frame(60, 976, self.me_frame)

    def show_activity_frame(self, bar_width, bar_x, frame):
        self.navigation_bar.config(width=bar_width)
        self.navigation_bar.place(x=bar_x, y=85)

        self.clinic_frame.pack_forget()
        self.clinic_request_frame.pack_forget()
        self.security_frame.pack_forget()
        self.me_frame.pack_forget()

        frame.pack()
        frame.focus_set()

        key = list(self.all_scrollable_frame.keys())
        for k in key:
            if k == frame:
                self.all_scrollable_frame[k] = 1
            else:
                self.all_scrollable_frame[k] = 0

        if frame == self.clinic_frame:
            keys = list(self.all_clinic_frames.keys())
            for k in keys:
                active = self.all_clinic_frames[k][3]
                if active:
                    self.switch(k, self.all_clinic_frames)
        elif frame == self.clinic_request_frame:
            keys = list(self.all_clinic_request_frame.keys())
            for k in keys:
                active = self.all_clinic_request_frame[k][3]
                if active:
                    self.switch(k, self.all_clinic_request_frame)
        elif frame == self.me_frame:
            keys = list(self.all_me_frame.keys())
            for k in keys:
                active = self.all_me_frame[k][3]
                if active:
                    self.switch(k, self.all_me_frame)

    def switch(self, frame, frame_list):
        frames = list(frame_list.keys())
        for f in frames:
            if f == frame:
                frame_list[f][3] = 1
                frame_list[f][0].pack()
            else:
                frame_list[f][3] = 0
                frame_list[f][0].pack_forget()
        content = frame_list[frame][2]
        canvas = frame_list[frame][1]
        content.update_idletasks()
        if len(content.winfo_children()) == 0:
            canvas.configure(scrollregion=(0, 0, 0, 0))
        else:
            canvas.configure(scrollregion=canvas.bbox("all"))
        canvas.bind_all("<MouseWheel>", lambda event: self.on_mouse_wheel(event, canvas))

    def set_up_clinic_frame(self):
        def clear_search():
            search_entry.delete(0, tk.END)
            show_clinics()
            clinic_canvas.yview_moveto(0)

        def search():
            show_clinics()
            clinic_canvas.yview_moveto(0)

        def show_clinics():
            self.leave_focus_entry('entry', search_entry, 'Search')
            clinics_frame.focus_set()
            for w in clinic_content_frame.winfo_children():
                w.destroy()

            # Fetch all clinics information, both active and inactive
            if search_entry.cget('fg') == '#858585':
                clear_search_button.place_forget()
                cursor.execute('''SELECT * FROM clinic ORDER BY clinic_status DESC, clinic_name ASC''')
                clinics = cursor.fetchall()
            elif search_entry.cget('fg') == '#333333':
                clear_search_button.place(x=170, y=8)
                search_query = search_entry.get().strip()
                cursor.execute('''SELECT * FROM clinic WHERE (clinic_name LIKE %s OR clinic_address LIKE %s)
                               ORDER BY clinic_status DESC, clinic_name ASC''',
                               ('%'+search_query+'%', '%'+search_query+'%', ))
                clinics = cursor.fetchall()

            x_value = 15
            count = 1
            if clinics:
                for clinic in clinics:
                    if count % 2 == 0:
                        y_value = 25
                    else:
                        y_value = 0

                    clinic_id = clinic[0]

                    image_stream = BytesIO(clinic[6])
                    img = Image.open(image_stream)
                    resized_img = img.resize((240, 200), Image.LANCZOS)
                    tk_image = ImageTk.PhotoImage(resized_img)
                    self.clinic_images[clinic_id] = tk_image

                    clinic_frame = tk.Frame(clinic_content_frame, height=200, width=1000, bg='white', highlightbackground='#166E82',
                                            highlightthickness=0.5, cursor='hand2')
                    clinic_frame.pack(padx=x_value, pady=y_value, fill='y', expand=True)
                    clinic_image = tk.Label(clinic_frame, image=self.clinic_images[clinic_id], bg='white')
                    clinic_image.grid(row=0, column=0, padx=20, pady=10, rowspan=4)
                    clinic_name = tk.Label(clinic_frame, text=clinic[1], font=('Open Sans', 20, 'bold'), bg='white', fg='#000000')
                    clinic_name.grid(row=0, column=1, sticky='w', columnspan=2, pady=(20, 10))
                    clinic_address_label = tk.Label(clinic_frame, text='Address: ', font=('Open Sans', 16), bg='white', fg='#000000')
                    clinic_address_label.grid(row=1, column=1, sticky='nw', pady=(0, 5))
                    clinic_address = tk.Label(clinic_frame, text=clinic[3].strip(), font=('Open Sans', 16), bg='white', fg='#000000',
                                              anchor='w', width=51, wraplength=620, justify='left')
                    clinic_address.grid(row=1, column=2, sticky='nw', pady=(0, 5))
                    clinic_operation_label = tk.Label(clinic_frame, text='Hours: ', font=('Open Sans', 16), bg='white',
                                                      fg='#000000')
                    clinic_operation_label.grid(row=2, column=1, sticky='w', pady=(0, 5))
                    clinic_operation = tk.Label(clinic_frame, text=clinic[2], font=('Open Sans', 16), bg='white', fg='#000000')
                    clinic_operation.grid(row=2, column=2, sticky='w', pady=(0, 5))
                    clinic_contact_label = tk.Label(clinic_frame, text='Contact: ', font=('Open Sans', 16),
                                                    bg='white', fg='#000000')
                    clinic_contact_label.grid(row=3, column=1, sticky='w', pady=(5, 20))
                    clinic_contact = tk.Label(clinic_frame, text=clinic[5], font=('Open Sans', 16), bg='white', fg='#000000')
                    clinic_contact.grid(row=3, column=2, sticky='w', pady=(5, 20))

                    clinic_frame.bind('<Button-1>', lambda event, c=clinic: show_new_detail(c))
                    for widgets in clinic_frame.winfo_children():
                        widgets.bind('<Button-1>', lambda event, c=clinic: show_new_detail(c))

                    # If the clinic is inactive, the card frame will show grey
                    if clinic[7] == 0:
                        clinic_frame.config(bg='#D3CCCC')
                        for widgets in clinic_frame.winfo_children():
                            widgets.config(bg='#D3CCCC')

                    count += 1

            self.switch('clinic', self.all_clinic_frames)

        def show_new_detail(c):
            show_detail(c)
            detail_canvas.yview_moveto(0)

        def show_detail(c):
            # Display inactive label if the clinic is in inactive status
            if c[7] == 0:
                inactive_label.place(x=898, y=15)
            else:
                inactive_label.place_forget()
            d_back_button.config(command=lambda: show_clinics())

            for w in detail_content_frame.winfo_children():
                w.destroy()

            clinic_id = c[0]
            clinic_frame = tk.Frame(detail_content_frame, height=200, width=1000, bg='white')
            clinic_frame.pack(padx=15, fill='y', expand=True)
            clinic_image = tk.Label(clinic_frame, image=self.clinic_images[clinic_id], bg='white')
            clinic_image.grid(row=0, column=0, padx=20, pady=10, rowspan=4)
            clinic_name = tk.Label(clinic_frame, text=c[1], font=('Open Sans', 20, 'bold'), bg='white', fg='#000000')
            clinic_name.grid(row=0, column=1, sticky='w', columnspan=2, pady=(20, 10))
            clinic_address_label = tk.Label(clinic_frame, text='Address: ', font=('Open Sans', 16), bg='white', fg='#000000')
            clinic_address_label.grid(row=1, column=1, sticky='nw', pady=(0, 5))
            clinic_address = tk.Label(clinic_frame, text=c[3].strip(), font=('Open Sans', 16), bg='white', fg='#000000',
                                      anchor='w', width=51, wraplength=620, justify='left')
            clinic_address.grid(row=1, column=2, sticky='nw', pady=(0, 5))
            clinic_operation_label = tk.Label(clinic_frame, text='Hours: ', font=('Open Sans', 16), bg='white',
                                              fg='#000000')
            clinic_operation_label.grid(row=2, column=1, sticky='w', pady=(0, 5))
            clinic_operation = tk.Label(clinic_frame, text=c[2], font=('Open Sans', 16), bg='white', fg='#000000')
            clinic_operation.grid(row=2, column=2, sticky='w', pady=(0, 5))
            clinic_contact_label = tk.Label(clinic_frame, text='Contact: ', font=('Open Sans', 16),
                                            bg='white', fg='#000000')
            clinic_contact_label.grid(row=3, column=1, sticky='w', pady=(5, 20))
            clinic_contact = tk.Label(clinic_frame, text=c[5], font=('Open Sans', 16), bg='white', fg='#000000')
            clinic_contact.grid(row=3, column=2, sticky='w', pady=(5, 20))
            clinic_describe = tk.Label(clinic_frame, text=c[4].strip(), font=('Open Sans', 12), bg='white', fg='#677294',
                                       anchor='w', wraplength=970, justify='left')
            clinic_describe.grid(row=4, column=0, columnspan=3, sticky='w', padx=20)

            doctors_frame = tk.Frame(detail_content_frame, width=1000, bg='white')
            doctors_frame.pack(pady=20, fill='y', expand=True)
            doctor_title = tk.Label(doctors_frame, text='Doctors', font=('Open Sans', 16, 'bold', 'underline'),
                                    bg='white', fg='#000000')
            doctor_title.pack(anchor='center', pady=10)
            # Fetch all doctors, both active and inactive
            cursor.execute('''SELECT * FROM doctor WHERE clinic_id=%s ORDER BY doctor_status DESC, doctor_name ASC''', (clinic_id, ))
            doctors = cursor.fetchall()
            count = 1
            for doctor in doctors:
                if count % 2 == 0:
                    y_value = 10
                else:
                    y_value = 0

                doctor_frame = tk.Frame(doctors_frame, width=700, bg='white')
                doctor_frame.pack(pady=y_value, fill='y', expand=True)

                doctor_id = doctor[0]

                image_stream = BytesIO(doctor[9])
                img = Image.open(image_stream)
                resized_img = img.resize((120, 120), Image.LANCZOS)
                tk_image = ImageTk.PhotoImage(resized_img)
                self.doctor_images[doctor_id] = tk_image

                doctor_image = tk.Label(doctor_frame, image=self.doctor_images[doctor_id], bg='white')
                doctor_image.grid(row=0, column=0, rowspan=4, padx=5, pady=5)
                doctor_name = tk.Label(doctor_frame, text='Dr. '+doctor[1], font=('Open Sans', 14, 'bold'), bg='white', fg='#000000')
                doctor_name.grid(row=0, column=1, columnspan=2, sticky='w', pady=(5, 5))
                doctor_contact_label = tk.Label(doctor_frame, text='Contact: ', font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_contact_label.grid(row=1, column=1, sticky='w', pady=(0, 3))
                doctor_contact = tk.Label(doctor_frame, text=doctor[5], font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_contact.grid(row=1, column=2, sticky='w', pady=(0, 3))
                doctor_working_label = tk.Label(doctor_frame, text='Hours: ', font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_working_label.grid(row=2, column=1, sticky='w', pady=(0, 3))
                doctor_working = tk.Label(doctor_frame, text=doctor[6], font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_working.grid(row=2, column=2, sticky='w', pady=(0, 3))
                doctor_language_label = tk.Label(doctor_frame, text='Language: ', font=('Open Sans', 12), bg='white', fg='#000000')
                doctor_language_label.grid(row=3, column=1, sticky='w', pady=(0, 5))
                languages = sorted(doctor[7].split(', '))
                doctor_language = tk.Label(doctor_frame, text=', '.join(languages), font=('Open Sans', 12), bg='white', fg='#000000',
                                           width=35, anchor='w')
                doctor_language.grid(row=3, column=2, sticky='w', pady=(0, 5))
                specializations = sorted(doctor[8].split(', '))
                doctor_specialize = tk.Label(doctor_frame, text='Specialize In\n'+'\n'.join([f"•{value}" for value in specializations]),
                                             font=('Open Sans', 12), bg='white', fg='#000000', anchor='e', width=20, justify='left')
                doctor_specialize.grid(row=1, column=3, rowspan=3, sticky='nw', padx=30, pady=(0, 5))

                # Configure the doctor name to red colour and add with inactive label
                if doctor[10] == 0:
                    doctor_name.config(fg='red', text='Dr. '+doctor[1]+'    (INACTIVE)')

                count += 1

            self.switch('detail', self.all_clinic_frames)

        for widget in self.clinic_frame.winfo_children():
            widget.destroy()

        clinics_frame = tk.Frame(self.clinic_frame, width=1050, height=510, bg='white')
        search_frame = tk.Frame(clinics_frame, bg='#F5F5F5', width=230, height=35, highlightbackground="#C8C7C7",
                                highlightthickness=0.5)
        search_frame.place(x=785, y=15)
        search_entry = tk.Entry(search_frame, bg='#F5F5F5', font=('Roboto', 12), border=0, fg='#858585', width=16)
        search_entry.place(x=8, y=6)
        search_entry.insert(0, "Search")
        search_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', search_entry))
        search_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', search_entry, 'Search'))
        search_entry.bind('<Return>', lambda event: search())
        search_button = tk.Button(search_frame, bg='#F5F5F5', image=self.search_button, border=0, cursor='hand2',
                                  command=lambda: search())
        search_button.place(x=200, y=6)
        clear_search_button = tk.Button(search_frame, bg='#F5F5F5', image=self.clear_search, border=0, command=lambda: clear_search())
        clinic_canvas = tk.Canvas(clinics_frame, width=1030, height=430, bg='white', highlightthickness=0)
        clinic_canvas.place(x=0, y=75)
        clinic_scrollbar = tk.Scrollbar(clinics_frame, orient='vertical')
        clinic_scrollbar.place(x=1033, y=75, height=430)
        clinic_canvas.configure(yscrollcommand=clinic_scrollbar.set)
        clinic_scrollbar.configure(command=clinic_canvas.yview)
        clinic_content_frame = tk.Frame(clinic_canvas, bg='white')
        clinic_canvas.create_window((0, 0), window=clinic_content_frame, anchor="nw")
        self.all_clinic_frames['clinic'] = [clinics_frame, clinic_canvas, clinic_content_frame, 0]

        detail_frame = tk.Frame(self.clinic_frame, width=1050, height=510, bg='white')
        d_back_button = ttk.Button(detail_frame, text='< Back', style='back.TButton', cursor='hand2', width=6)
        d_back_button.place(x=20, y=15)
        inactive_label = tk.Label(detail_frame, text='INACTIVE', bg='white', fg='red', font=('Roboto', 18, 'bold'))
        detail_canvas = tk.Canvas(detail_frame, width=1030, height=430, bg='white', highlightthickness=0)
        detail_canvas.place(x=0, y=75)
        detail_scrollbar = tk.Scrollbar(detail_frame, orient='vertical')
        detail_scrollbar.place(x=1033, y=75, height=430)
        detail_canvas.configure(yscrollcommand=detail_scrollbar.set)
        detail_scrollbar.configure(command=detail_canvas.yview)
        detail_content_frame = tk.Frame(detail_canvas, bg='white')
        detail_canvas.create_window((0, 0), window=detail_content_frame, anchor="nw")
        self.all_clinic_frames['detail'] = [detail_frame, detail_canvas, detail_content_frame, 0]

        show_clinics()

    def set_up_clinic_request_frame(self):
        # Display the reject reason entry, cancel button and confirm button
        def show_reject_reason(cr_type, cr_id, card_frame, clinic_email):
            def reject_request():
                if reject_reason_entry.cget('fg') == '#333333' and reject_reason_entry.get().strip() != '':
                    reject_reason = reject_reason_entry.get()

                    # Update clinic request status
                    update_query = "UPDATE clinic_request SET cr_status = 'rejected', cr_ifreject = %s WHERE cr_id = %s"
                    self.cursor.execute(update_query, (reject_reason, cr_id))
                    database.commit()

                    # Send email to notify the clinic about request has been rejected, along with the reject reason
                    send_email(clinic_email, "Clinic Request Rejected",
                               f"Your clinic request to {cr_type} has been rejected. \nReason: {reject_reason}")

                    show_clinic_request()
                else:
                    messagebox.showerror('Error', 'Please fill in reject reason')

            def cancel_reject():
                reject_reason_entry.destroy()
                cancel_button.destroy()
                confirm_button.destroy()

                self.switch('request', self.all_clinic_request_frame)

            reject_reason_entry = tk.Entry(card_frame, font=('Open Sans', 12), bg='#E0FCF8', fg='#858585')
            reject_reason_entry.grid(row=7, column=0, columnspan=4, sticky='ew', padx=10, pady=(5, 15))
            reject_reason_entry.insert(0, 'Fill in reject reason')
            reject_reason_entry.bind('<FocusIn>', lambda event: self.focus_entry('entry', reject_reason_entry))
            reject_reason_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('entry', reject_reason_entry,
                                                                                        'Fill in reject reason'))

            cancel_button = tk.Button(card_frame, text='Cancel', font=('Open Sans', 12, 'bold'), bg='#F5443E', fg='white',
                                      width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                      command=lambda: cancel_reject())
            cancel_button.grid(row=6, column=0, sticky='w', padx=15, pady=10)

            confirm_button = tk.Button(card_frame, text='Confirm', font=('Open Sans', 12, 'bold'), bg='#00C196', fg='white',
                                       width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                       command=lambda: reject_request())
            confirm_button.grid(row=6, column=3, sticky='e', padx=15, pady=10)

            self.switch('request', self.all_clinic_request_frame)

        # Function for sending email to the clinic that submit the request
        def send_email(to_email, subject, body):
            from_email = "kuro2269@gmail.com"  # Replace with your email
            from_password = "dsormotxbswaovfn"  # Replace with your generated app password

            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = subject

            msg.attach(MIMEText(body, 'plain'))

            try:
                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                server.login(from_email, from_password)
                text = msg.as_string()
                server.sendmail(from_email, to_email, text)
                server.quit()
                print("Email sent successfully")
            except Exception as e:
                print(f"Failed to send email: {e}")

        def approve_request(cr_type, clinic_id, cr_id, clinic_email):
            # Update clinic request status
            update_query = "UPDATE clinic_request SET cr_status = 'approve' WHERE cr_id = %s"
            self.cursor.execute(update_query, (cr_id,))
            database.commit()

            # Update clinic status accordingly to the request type
            if cr_type == 'join' or cr_type == 'Rejoin':
                self.cursor.execute('''UPDATE clinic SET clinic_status=1 WHERE clinic_id=%s''', (clinic_id,))
                database.commit()
            elif cr_type == 'Leave':
                self.cursor.execute('''UPDATE clinic SET clinic_status=0 WHERE clinic_id=%s''', (clinic_id,))
                database.commit()

            # Send email to nodify the clinic that the request has been accepted
            send_email(clinic_email, "Clinic Request Approved", f"Your clinic request to {cr_type} has been approved.")

            show_clinic_request()

        # Fetch pending clinic request and display
        def show_clinic_request():
            for widget in clinic_request_scrollable_frame.winfo_children():
                widget.destroy()

            # Fetch clinic requests
            query = """SELECT cr.cr_id, cr.cr_type, cr.cr_reason, cr.cr_datetime, cr.cr_detail, 
                       c.clinic_name, c.clinic_contact, u.user_email, c.clinic_id
                       FROM clinic_request cr
                       LEFT JOIN clinic c ON cr.clinic_id = c.clinic_id
                       LEFT JOIN cad.user u ON c.user_id = u.user_id
                       WHERE cr.cr_status = 'pending'
                       ORDER BY cr.cr_datetime ASC;"""
            self.cursor.execute(query)
            clinic_requests = self.cursor.fetchall()

            if not clinic_requests:
                no_requests_label = tk.Label(clinic_request_scrollable_frame, text="No clinic requests found.",
                                             font=('Open Sans', 12, 'bold'), bg='white', fg='red')
                no_requests_label.pack(padx=440, pady=30)
            else:
                for i, request in enumerate(clinic_requests):
                    cr_id = request['cr_id']
                    cr_type = request['cr_type']
                    cr_reason = request['cr_reason']
                    cr_datetime = request['cr_datetime'].date()
                    cr_datetime = self.format_date(str(cr_datetime))
                    cr_detail = request['cr_detail']
                    clinic_name = request['clinic_name']
                    clinic_contact = request['clinic_contact']
                    clinic_email = request['user_email']  # Fetch clinic email
                    clinic_id = request['clinic_id']

                    card_frame = tk.Frame(clinic_request_scrollable_frame, bg='white', highlightbackground='#00C196',
                                          highlightthickness=1)
                    card_frame.grid(row=i + 1, column=0, columnspan=5, padx=25, pady=10, sticky='ew')
                    card_frame.grid_columnconfigure(0, weight=1)
                    card_frame.grid_columnconfigure(1, weight=1)
                    card_frame.grid_columnconfigure(2, weight=1)
                    card_frame.grid_columnconfigure(3, weight=1)

                    id_label = tk.Label(card_frame, text=f"Request ID: {cr_id}", font=('Open Sans', 16, 'bold'), bg='white',
                                        fg='#333333')
                    id_label.grid(row=0, column=0, sticky='w', padx=15, pady=(10, 5))

                    clinic_label = tk.Label(card_frame, text=f"   Clinic: {clinic_name}", font=('Open Sans', 12, 'bold'), bg='white',
                                            fg='#333333', width=53, anchor='w')
                    clinic_label.grid(row=1, column=0, sticky='w', padx=15, pady=5)

                    type_label = tk.Label(card_frame, text=f"   Request to: {cr_type}", font=('Open Sans', 12), bg='white',
                                          fg='#333333')
                    type_label.grid(row=2, column=0, sticky='w', padx=15, pady=5)

                    reason_label = tk.Label(card_frame, text=f"   Reason: {cr_reason}", font=('Open Sans', 12), bg='white',
                                            fg='#333333')
                    reason_label.grid(row=3, column=0, sticky='w', padx=15, pady=5)

                    datetime_label = tk.Label(card_frame, text=f"   Request Date: {cr_datetime}", font=('Open Sans', 12),
                                              bg='white', fg='#333333')
                    datetime_label.grid(row=4, column=0, sticky='w', padx=15, pady=5)

                    contact_label = tk.Label(card_frame, text=f"   Contact Number: {clinic_contact}", font=('Open Sans', 12),
                                             bg='white', fg='#333333')
                    contact_label.grid(row=5, column=0, sticky='w', padx=15, pady=5)

                    description_label = tk.Label(card_frame, text="Description:", font=('Open Sans', 12), bg='white', fg='#333333')
                    description_label.grid(row=1, column=3, sticky='w', padx=15, pady=5)
                    description_frame = tk.Frame(card_frame)
                    description_frame.grid(row=2, column=3, rowspan=4, sticky='nw', padx=15)

                    description_text = tk.Text(description_frame, font=('Open Sans', 12), bg='white', fg='#333333', width=40, height=6,
                                               borderwidth=1, relief='solid', wrap='word')
                    if cr_detail is not None:
                        description_text.insert('1.0', cr_detail)
                    description_text.config(state=tk.DISABLED)
                    description_text.pack(side="left", fill="both", expand=True)

                    text_scrollbar = tk.Scrollbar(description_frame, command=description_text.yview)
                    text_scrollbar.pack(side="right", fill="y")

                    description_text.config(yscrollcommand=text_scrollbar.set)

                    approve_button = tk.Button(card_frame, text='Approve', font=('Open Sans', 12, 'bold'), bg='#00C196',
                                               fg='white', width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                               command=lambda cr_type=cr_type, clinic_id=clinic_id,
                                                              cr_id=cr_id, clinic_email=clinic_email:
                                                              approve_request(cr_type, clinic_id, cr_id, clinic_email))
                    approve_button.grid(row=6, column=3, sticky='e', padx=15, pady=10)

                    reject_button = tk.Button(card_frame, text='Reject', font=('Open Sans', 12, 'bold'), bg='#F5443E',
                                              fg='white', width=8, borderwidth=0, relief="flat", padx=50, pady=5,
                                              command=lambda cr_type=cr_type, cr_id=cr_id, card_frame=card_frame,
                                                             clinic_email=clinic_email:
                                                             show_reject_reason(cr_type, cr_id, card_frame, clinic_email))
                    reject_button.grid(row=6, column=0, sticky='w', padx=15, pady=10)

            self.switch('request', self.all_clinic_request_frame)

        for widget in self.clinic_request_frame.winfo_children():
            widget.destroy()

        # Create a canvas and a scrollbar
        clinic_request_canvas = tk.Canvas(self.clinic_request_frame, borderwidth=0, background="#ffffff", width=1030, height=510,
                                          highlightthickness=0)
        clinic_request_canvas.pack(side="left", fill="both", expand=True)
        clinic_request_scrollbar = tk.Scrollbar(self.clinic_request_frame, orient="vertical", command=clinic_request_canvas.yview)
        clinic_request_scrollbar.pack(side="right", fill="y")
        clinic_request_canvas.configure(yscrollcommand=clinic_request_scrollbar.set)
        clinic_request_scrollable_frame = tk.Frame(clinic_request_canvas, background="#ffffff")
        clinic_request_canvas.create_window((0, 0), window=clinic_request_scrollable_frame, anchor="nw")
        self.all_clinic_request_frame['request'] = [self.clinic_request_frame, clinic_request_canvas, clinic_request_scrollable_frame, 0]

        show_clinic_request()

    def set_up_security_frame(self):
        """Set up the Security tab with audit logs, blocked accounts, blocked IPs, and statistics."""
        AUTH_API_BASE = 'http://localhost:5000'
        
        # Configure the colour of security tab button
        def update_tab_colors():
            for tab_button in tab_buttons:
                if tab_button.cget("text") == self.current_security_tab:
                    tab_button.config(bg='#00C196', fg='white')
                else:
                    tab_button.config(bg='#E0FCF8', fg='#00C196')
        
        def show_statistics():
            """Display security statistics dashboard."""
            self.current_security_tab = 'Statistics'
            update_tab_colors()
            for widget in stats_content_frame.winfo_children():
                widget.destroy()
            
            try:
                response = self.make_admin_api_call('GET', '/admin/account_stats')
                
                if response and response.status_code == 200:
                    data = response.json()
                    stats = data.get('stats', {})
                    
                    # Title - centered
                    title_frame = tk.Frame(stats_content_frame, bg='white')
                    title_frame.pack(fill='x', pady=(40, 10))
                    title_label = tk.Label(title_frame, text='Security Statistics', 
                                          font=('Open Sans', 24, 'bold'), bg='white', fg='#166E82')
                    title_label.pack(anchor='center')
                    
                    # Stats grid - centered
                    stats_container = tk.Frame(stats_content_frame, bg='white')
                    stats_container.pack(expand=True, pady=(10, 30))
                    
                    stats_frame = tk.Frame(stats_container, bg='white')
                    stats_frame.pack(anchor='center')
                    for idx in range(4):
                        stats_frame.grid_columnconfigure(idx, weight=1)

                    # Section: User Accounts
                    ua_title = tk.Label(stats_frame, text='User Accounts', font=('Open Sans', 14, 'bold'),
                                        bg='white', fg='#166E82')
                    ua_title.grid(row=0, column=0, columnspan=4, pady=(5, 5))
                    
                    stats_data_accounts = [
                        ('Total Accounts', stats.get('total_accounts', 0)),
                        ('Active Accounts', stats.get('active_accounts', 0)),
                        ('Permanently Locked', stats.get('permanently_locked', 0)),
                        ('Temporarily Locked', stats.get('temporarily_locked', 0)),
                    ]
                    
                    # Section: IP Addresses
                    ip_title = tk.Label(stats_frame, text='IP Addresses', font=('Open Sans', 14, 'bold'),
                                        bg='white', fg='#166E82')
                    # ip_title row will be set after placing account cards
                    
                    stats_data_ips = [
                        ('Hard Blocked IPs', stats.get('hard_blocked_ips', 0)),
                        ('Soft Blocked IPs', stats.get('soft_blocked_ips', 0)),
                    ]
                    
                    # Render account cards (3 columns to reduce right whitespace)
                    row = 1
                    col = 0
                    for label_text, value in stats_data_accounts:
                        stat_card = tk.Frame(stats_frame, bg='#D0F9EF', width=230, height=120, relief='flat', bd=1)
                        stat_card.grid(row=row, column=col, padx=12, pady=12, sticky='nsew')
                        stat_card.pack_propagate(False)
                        
                        label = tk.Label(stat_card, text=label_text, font=('Open Sans', 11), bg='#D0F9EF', fg='#333333')
                        label.pack(pady=(14, 8))
                        
                        value_label = tk.Label(stat_card, text=str(value), font=('Open Sans', 22, 'bold'), 
                                              bg='#D0F9EF', fg='#166E82')
                        value_label.pack()
                        
                        col += 1
                        if col > 3:
                            col = 0
                            row += 1
                    
                    # Place IP section title
                    ip_title.grid(row=row, column=0, columnspan=4, pady=(15, 5))
                    row += 1
                    col = 1  # start from second column to centre two cards
                    
                    # Render IP cards (3 columns)
                    for label_text, value in stats_data_ips:
                        stat_card = tk.Frame(stats_frame, bg='#D0F9EF', width=230, height=120, relief='flat', bd=1)
                        stat_card.grid(row=row, column=col, padx=12, pady=12, sticky='nsew')
                        stat_card.pack_propagate(False)
                        
                        label = tk.Label(stat_card, text=label_text, font=('Open Sans', 11), bg='#D0F9EF', fg='#333333')
                        label.pack(pady=(14, 8))
                        
                        value_label = tk.Label(stat_card, text=str(value), font=('Open Sans', 22, 'bold'), 
                                              bg='#D0F9EF', fg='#166E82')
                        value_label.pack()
                        
                        col += 1
                        if col > 2:
                            col = 1
                            row += 1
                else:
                    error_label = tk.Label(stats_content_frame, text='Failed to load statistics.', 
                                          font=('Open Sans', 12), bg='white', fg='red')
                    error_label.pack(pady=50)
            except Exception as e:
                error_label = tk.Label(stats_content_frame, text=f'Error: {str(e)}', 
                                      font=('Open Sans', 12), bg='white', fg='red')
                error_label.pack(pady=50)
            
            self.switch('statistics', self.all_security_frame)
        
        # Helper: convert ISO-like UTC string to Malaysia time (UTC+8), returns 'YYYY-MM-DD HH:MM'
        def _format_malaysia_time(iso_str):
            try:
                from datetime import datetime, timedelta
                if not iso_str:
                    return ''
                
                dt = None
                
                # If it's already a datetime object, use it directly
                if isinstance(iso_str, datetime):
                    dt = iso_str
                    # If timezone-aware, convert to UTC naive first
                    if dt.tzinfo is not None:
                        dt = (dt - dt.utcoffset()).replace(tzinfo=None)
                else:
                    # Parse string format
                    s = str(iso_str).strip()
                    
                    # First, try to handle "Tue, 11 Nov 2025" format (RFC 2822 date only)
                    # This format often appears when datetime is converted to string without time
                    if ',' in s and any(day in s for day in ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']):
                        try:
                            # Split by comma and take the date part
                            parts = s.split(',', 1)
                            if len(parts) == 2:
                                date_part = parts[1].strip()
                                # Try parsing "11 Nov 2025" or "11 Nov 2025 HH:MM:SS"
                                # Remove any timezone indicators
                                date_part = date_part.split(' +')[0].split(' -')[0].split(' GMT')[0].split(' UTC')[0]
                                # Try with time first, then without
                                try:
                                    dt = datetime.strptime(date_part, "%d %b %Y %H:%M:%S")
                                except ValueError:
                                    try:
                                        dt = datetime.strptime(date_part, "%d %b %Y %H:%M")
                                    except ValueError:
                                        dt = datetime.strptime(date_part, "%d %b %Y")
                                        # Default to midnight if no time provided
                                        dt = dt.replace(hour=0, minute=0, second=0)
                        except (ValueError, IndexError, AttributeError):
                            pass
                    
                    # If not parsed yet, try standard ISO and other formats
                    if dt is None:
                        formats = [
                            "%Y-%m-%d %H:%M:%S.%f",      # ISO with microseconds
                            "%Y-%m-%d %H:%M:%S",         # ISO standard
                            "%Y-%m-%dT%H:%M:%S.%f",      # ISO with T separator and microseconds
                            "%Y-%m-%dT%H:%M:%S",         # ISO with T separator
                            "%Y-%m-%dT%H:%M:%S.%fZ",     # ISO with Z timezone and microseconds
                            "%Y-%m-%dT%H:%M:%SZ",        # ISO with Z timezone
                            "%Y-%m-%d %H:%M",            # Date and time without seconds
                            "%Y-%m-%d",                  # Date only
                            "%a, %d %b %Y %H:%M:%S",     # RFC 2822 with time
                            "%a, %d %b %Y",              # RFC 2822 date only
                        ]
                        
                        for fmt in formats:
                            try:
                                # Clean the string - remove timezone info that might cause issues
                                clean_s = s.split(' +')[0].split(' -')[0].split(' GMT')[0].split(' UTC')[0].split(' Z')[0]
                                dt = datetime.strptime(clean_s, fmt)
                        break
                            except (ValueError, AttributeError):
                        continue
                    
                    # If still not parsed, return empty (shouldn't happen with valid datetime)
                if dt is None:
                        return ''
                
                # Convert to Malaysia time (UTC+8) and format
                myt = dt + timedelta(hours=8)
                return myt.strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                # If everything fails, return empty string
                return ''

        def show_audit_logs():
            """Display audit logs with filtering."""
            self.current_security_tab = 'Audit Logs'
            update_tab_colors()
            
            for widget in logs_content_frame.winfo_children():
                widget.destroy()
            
            if not self.admin_token:
                error_label = tk.Label(logs_content_frame, text='Authentication required. Please log in again.', 
                                      font=('Open Sans', 12), bg='white', fg='red')
                error_label.pack(pady=50)
                return
            
            # pagination state and refs
            logs_state = {'offset': 0, 'page_size': 50, 'last_count': 0}
            logs_refs = {'rows_frame': None, 'more_frame': None}

            def load_logs(append=False):
                # Fresh render (header + rows container)
                if not append:
                    for widget in logs_list_frame.winfo_children():
                        widget.destroy()

                    header = tk.Frame(logs_list_frame, bg='#166E82', height=40)
                    header.pack(fill='x', pady=(0, 5))
                    header.pack_propagate(False)
                    headers_text = ['Time', 'Event Type', 'Description', 'User ID', 'IP Address']
                    col_widths = [180, 170, 450, 100, 100]
                    for i, (text, w) in enumerate(zip(headers_text, col_widths)):
                        hl = tk.Label(header, text=text, font=('Open Sans', 10, 'bold'), bg='#166E82', fg='white')
                        hl.grid(row=0, column=i, sticky='w', padx=(10 if i == 0 else 0, 0), pady=10)
                        header.grid_columnconfigure(i, minsize=w)

                    logs_refs['rows_frame'] = tk.Frame(logs_list_frame, bg='white', width=1000)
                    logs_refs['rows_frame'].pack(fill='x')
                    # reset offset when not appending
                    logs_state['offset'] = 0
                    if logs_refs['more_frame']:
                        logs_refs['more_frame'].destroy()
                        logs_refs['more_frame'] = None

                # Loading indicator inside rows container
                loading = tk.Label(logs_refs['rows_frame'], text='Loading...', font=('Open Sans', 11), bg='white', fg='#858585')
                loading.pack(pady=10)
                
                try:
                    params = {'limit': logs_state['page_size'], 'offset': logs_state['offset']}
                    
                    event_type = event_filter.get()
                    if event_type and event_type != 'All':
                        params['event_type'] = event_type
                    
                    response = self.make_admin_api_call('GET', '/admin/audit_logs', params=params)
                    
                    if response and response.status_code == 200:
                        loading.destroy()
                        data = response.json()
                        logs = data.get('logs', [])
                        logs_state['last_count'] = len(logs)

                        if not append and len(logs) == 0:
                            no_logs_label = tk.Label(logs_refs['rows_frame'], text='No audit logs found.', 
                                                    font=('Open Sans', 12), bg='white', fg='#858585')
                            no_logs_label.pack(pady=20)
                        else:
                            col_widths = [180, 170, 450, 100, 100]
                            for log in logs:
                                row = tk.Frame(logs_refs['rows_frame'], bg='white', height=44, relief='solid', bd=1)
                                row.pack(fill='x', pady=2)
                                for ci, w in enumerate(col_widths):
                                    row.grid_columnconfigure(ci, minsize=w)

                                created_at = _format_malaysia_time(log.get('created_at')) if log.get('created_at') else ''
                                event_type_val = log.get('event_type', '')
                                desc_full = log.get('description', '')
                                description = desc_full[:80] + '...' if len(desc_full) > 80 else desc_full
                                user_id = str(log.get('user_id', '')) if log.get('user_id') else '-'
                                ip_address = log.get('ip_address', '-') or '-'

                                tk.Label(row, text=created_at, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=0, sticky='w', padx=(10,0), pady=12)
                                tk.Label(row, text=event_type_val, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=1, sticky='w')
                                tk.Label(row, text=description, font=('Open Sans', 9), bg='white', fg='#333333', wraplength=480, justify='left').grid(row=0, column=2, sticky='w')
                                tk.Label(row, text=user_id, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=3, sticky='w')
                                tk.Label(row, text=ip_address, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=4, sticky='w')
                            
                            # Load more control
                            if logs_refs['more_frame']:
                                logs_refs['more_frame'].destroy()
                                logs_refs['more_frame'] = None
                            if logs_state['last_count'] == logs_state['page_size']:
                                logs_refs['more_frame'] = tk.Frame(logs_list_frame, bg='white')
                                logs_refs['more_frame'].pack(fill='x', pady=(8, 6))
                                def do_load_more():
                                    logs_state['offset'] += logs_state['page_size']
                                    load_logs(append=True)
                                more_btn = ttk.Button(logs_refs['more_frame'], text='Load more', style='green_button.TButton', command=do_load_more, width=14)
                                more_btn.pack()
                    else:
                        loading.destroy()
                        error_label = tk.Label(logs_refs['rows_frame'], text='Failed to load audit logs.', 
                                              font=('Open Sans', 12), bg='white', fg='red')
                        error_label.pack(pady=20)
                except Exception as e:
                    loading.destroy()
                    print(f"[UI][ERROR] Loading audit logs failed: {e}")
                    error_label = tk.Label(logs_refs['rows_frame'], text=f'Error: {str(e)}', 
                                          font=('Open Sans', 12), bg='white', fg='red')
                    error_label.pack(pady=20)
            
            # Title - centered
            title_label = tk.Label(logs_content_frame, text='Audit Logs', 
                                  font=('Open Sans', 18, 'bold'), bg='white', fg='#166E82')
            title_label.pack(pady=(20, 10))
            
            # Filter row - centered
            filter_frame = tk.Frame(logs_content_frame, bg='white', height=60)
            filter_frame.pack(pady=(0, 6))
            filter_center = tk.Frame(filter_frame, bg='white')
            filter_center.pack()
            
            filter_label = tk.Label(filter_center, text='Filter by Event Type:', font=('Open Sans', 11, 'bold'), 
                                   bg='white', fg='#333333')
            filter_label.pack(side='left', padx=(0, 10), pady=10)
            
            event_filter = ttk.Combobox(filter_center, values=['All', 
                                                             'login_success', 'login_failed', 'login_blocked', 'logout',
                                                             'account_locked_temporary', 'account_locked_permanent', 'user_registered', 'registration_failed',
                                                             'password_reset', 'forgot_password_failed',
                                                             'sessions_revoked_on_login', 'refresh_token_created', 'refresh_token_rotated',
                                                             'ip_soft_blocked', 'ip_hard_blocked', 'ip_blocked',
                                                             'admin_unlock', 'admin_lock_permanent', 'admin_block_ip', 'admin_unblock_ip'],
                                       state='readonly', width=30, font=('Open Sans', 10))
            event_filter.set('All')
            event_filter.pack(side='left', padx=(0, 10), pady=10)
            event_filter.bind('<<ComboboxSelected>>', lambda e: load_logs(False))
            
            # Logs list - centered container with fixed width
            logs_center = tk.Frame(logs_content_frame, bg='white')
            logs_center.pack(fill='both', expand=True)
            logs_list_frame = tk.Frame(logs_center, bg='white', width=1000)
            logs_list_frame.pack(pady=10)
            logs_list_frame.pack_propagate(True)
            
            load_logs()
            self.switch('audit_logs', self.all_security_frame)
        
        def show_blocked_accounts():
            """Display blocked accounts with unlock functionality."""
            self.current_security_tab = 'Blocked Accounts'
            update_tab_colors()
            
            for widget in accounts_content_frame.winfo_children():
                widget.destroy()
            
            if not self.admin_token:
                error_label = tk.Label(accounts_content_frame, text='Authentication required. Please log in again.', 
                                      font=('Open Sans', 12), bg='white', fg='red')
                error_label.pack(pady=50)
                return
            
            def load_accounts():
                for widget in accounts_table.winfo_children():
                    widget.destroy()

                # Loading indicator
                loading_label = tk.Label(accounts_table, text='Loading accounts...', 
                                         font=('Open Sans', 12), bg='white', fg='#858585')
                loading_label.pack(pady=10)
                
                def render_accounts(accounts):
                    loading_label.destroy()
                    if not accounts:
                        no_accounts_label = tk.Label(accounts_table, text='No accounts found.', 
                                                    font=('Open Sans', 12), bg='white', fg='#858585')
                        no_accounts_label.pack(pady=20)
                        return
                    header_frame = tk.Frame(accounts_table, bg='#166E82', height=40)
                    header_frame.pack(fill='x', pady=(0, 5))
                    header_frame.pack_propagate(False)
                    headers_text = ['Email', 'Type', 'Status', 'Failed Attempts', 'Action']
                    # Fit within 1000px and reduce gaps (Email-Type and FailedAttempts-Action)
                    col_widths = [280, 140, 260, 80, 240]
                    for i, (text, w) in enumerate(zip(headers_text, col_widths)):
                        label = tk.Label(header_frame, text=text, font=('Open Sans', 10, 'bold'), 
                                         bg='#166E82', fg='white')
                        # Align the Action header to the right; others left
                        sticky_val = 'e' if i == 4 else 'w'
                        padx_val = (0, 20) if i == 4 else (10 if i == 0 else 0, 0)
                        label.grid(row=0, column=i, sticky=sticky_val, padx=padx_val, pady=10)
                        header_frame.grid_columnconfigure(i, minsize=w)
                    for account in accounts:
                        account_frame = tk.Frame(accounts_table, bg='white', height=50, relief='solid', bd=1)
                        account_frame.pack(fill='x', pady=2)
                        for ci, w in enumerate(col_widths):
                            account_frame.grid_columnconfigure(ci, minsize=w)
                        email = account.get('user_email', '')
                        user_type = account.get('user_type', '')
                        permanently_locked_flag = account.get('permanently_locked')
                        lock_until_str = account.get('lock_until', '')
                        failed_attempts = str(account.get('failed_attempts', 0))
                        
                        # Determine status based on lock state and expiration
                        if permanently_locked_flag:
                            status_text = 'Permanent (Admin unlock required)'
                            status_bg = '#F5443E'; status_fg = 'white'
                        elif lock_until_str:
                            # Check if temporary lock is still active (lock_until > now)
                            try:
                                # Parse lock_until (backend returns ISO format, UTC time)
                                lock_until_str_normalized = str(lock_until_str).replace('Z', '+00:00')
                                try:
                                    lock_until = datetime.fromisoformat(lock_until_str_normalized)
                                except ValueError:
                                    # Fallback for timezone-naive format
                                    lock_until_str_clean = str(lock_until_str).split('.')[0].replace('T', ' ')
                                    lock_until = datetime.strptime(lock_until_str_clean, '%Y-%m-%d %H:%M:%S')
                                
                                # Convert to UTC naive datetime for comparison
                                if lock_until.tzinfo:
                                    lock_until_utc = (lock_until - lock_until.utcoffset()).replace(tzinfo=None)
                                else:
                                    lock_until_utc = lock_until
                                
                                # Compare with current UTC time
                                now_utc = datetime.utcnow()
                                if lock_until_utc > now_utc:
                                    # Still locked - show temporary status
                            local_time = _format_malaysia_time(str(lock_until_str))
                            status_text = f"Temporary (until {local_time})"
                            status_bg = '#FFB74D'; status_fg = '#333333'
                                else:
                                    # Lock expired - show as active
                                    status_text = 'Active'
                                    status_bg = '#D0F9EF'; status_fg = '#166E82'
                            except Exception as e:
                                # If parsing fails, check if string looks like it has a date
                                # If it does, try to show temporary status, otherwise active
                                if lock_until_str:
                                    try:
                                        local_time = _format_malaysia_time(str(lock_until_str))
                                        if local_time:
                                            status_text = f"Temporary (until {local_time})"
                                            status_bg = '#FFB74D'; status_fg = '#333333'
                                        else:
                                            status_text = 'Active'
                                            status_bg = '#D0F9EF'; status_fg = '#166E82'
                                    except:
                                        status_text = 'Active'
                                        status_bg = '#D0F9EF'; status_fg = '#166E82'
                                else:
                                    status_text = 'Active'
                                    status_bg = '#D0F9EF'; status_fg = '#166E82'
                        else:
                            status_text = 'Active'
                            status_bg = '#D0F9EF'; status_fg = '#166E82'
                        tk.Label(account_frame, text=email, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=0, sticky='w', padx=(10, 0), pady=14)
                        tk.Label(account_frame, text=user_type, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=1, sticky='w')
                        status_label = tk.Label(account_frame, text=status_text, font=('Open Sans', 9, 'bold'), bg=status_bg, fg=status_fg, padx=8, pady=3)
                        status_label.grid(row=0, column=2, sticky='w')
                        tk.Label(account_frame, text=failed_attempts, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=3, sticky='w')
                        def do_unlock(email_addr=email):
                            try:
                                response = self.make_admin_api_call('POST', '/admin/unlock', json_data={'email': email_addr})
                                if response and response.status_code == 200:
                                    messagebox.showinfo('Success', f'Account {email_addr} unlocked successfully')
                                    load_accounts()
                                else:
                                    messagebox.showerror('Error', 'Failed to unlock account')
                            except Exception as e:
                                messagebox.showerror('Error', f'Error: {str(e)}')
                        def do_block(email_addr=email):
                            try:
                                response = self.make_admin_api_call('POST', '/admin/block_user', json_data={'email': email_addr})
                                if response and response.status_code == 200:
                                    messagebox.showinfo('Success', f'Account {email_addr} permanently locked')
                                    load_accounts()
                                else:
                                    messagebox.showerror('Error', 'Failed to lock account')
                            except Exception as e:
                                messagebox.showerror('Error', f'Error: {str(e)}')
                        
                        # Determine if account is actually locked (permanent or temporary that hasn't expired)
                        is_actually_locked = False
                        if permanently_locked_flag:
                            is_actually_locked = True
                        elif lock_until_str:
                            try:
                                lock_until_str_normalized = str(lock_until_str).replace('Z', '+00:00')
                                try:
                                    lock_until = datetime.fromisoformat(lock_until_str_normalized)
                                except ValueError:
                                    lock_until_str_clean = str(lock_until_str).split('.')[0].replace('T', ' ')
                                    lock_until = datetime.strptime(lock_until_str_clean, '%Y-%m-%d %H:%M:%S')
                                
                                if lock_until.tzinfo:
                                    lock_until_utc = (lock_until - lock_until.utcoffset()).replace(tzinfo=None)
                                else:
                                    lock_until_utc = lock_until
                                
                                now_utc = datetime.utcnow()
                                if lock_until_utc > now_utc:
                                    is_actually_locked = True
                            except Exception:
                                # If we can't parse, check if status_text indicates it's locked
                                is_actually_locked = status_text.startswith('Temporary') or status_text.startswith('Permanent')
                        
                        if is_actually_locked:
                            action_btn = ttk.Button(account_frame, text='Unlock', style='green_button.TButton', 
                                                   command=do_unlock, width=10)
                        else:
                            action_btn = ttk.Button(account_frame, text='Block', style='green_button.TButton', 
                                                   command=do_block, width=10)
                        # Align right within the Action column
                        action_btn.grid(row=0, column=4, sticky='e', padx=(0, 0))

                try:
                    # Try new endpoint
                    response = self.make_admin_api_call('GET', '/admin/accounts')
                    if response and response.status_code == 200:
                        data = response.json()
                        accounts = data.get('accounts', [])
                        print(f"[UI] /admin/accounts returned {len(accounts)} rows")
                        render_accounts(accounts)
                    else:
                        # Fallback to blocked accounts only
                        fallback = self.make_admin_api_call('GET', '/admin/blocked_accounts')
                        loading_label.destroy()
                        if fallback and fallback.status_code == 200:
                            fb = fallback.json()
                            fb_accounts = fb.get('accounts', [])
                            print(f"[UI] Fallback /admin/blocked_accounts returned {len(fb_accounts)} rows")
                            render_accounts(fb_accounts)
                        else:
                            error_label = tk.Label(accounts_table, text='Failed to load accounts.', 
                                                  font=('Open Sans', 12), bg='white', fg='red')
                            error_label.pack(pady=20)
                except Exception as e:
                    loading_label.destroy()
                    print(f"[UI][ERROR] Loading accounts failed: {e}")
                    error_label = tk.Label(accounts_table, text=f'Error: {str(e)}', 
                                          font=('Open Sans', 12), bg='white', fg='red')
                    error_label.pack(pady=20)
            
            # Header row: title left, refresh right
            header_accounts = tk.Frame(accounts_content_frame, bg='white')
            header_accounts.pack(pady=(15, 6))
            title_label = tk.Label(header_accounts, text='Blocked Accounts', 
                                  font=('Open Sans', 18, 'bold'), bg='white', fg='#166E82')
            title_label.pack(anchor='center')
            
            # Centered content area with fixed max width
            accounts_center = tk.Frame(accounts_content_frame, bg='white')
            accounts_center.pack(fill='both', expand=True)
            # Width aligns with header layout (x=20 + i*200, width=180 -> right edge 1000)
            accounts_list_frame = tk.Frame(accounts_center, bg='white', width=1000)
            accounts_list_frame.pack(pady=10)
            accounts_list_frame.pack_propagate(True)
            accounts_table = tk.Frame(accounts_list_frame, bg='white', width=1000)
            accounts_table.pack(fill='x')
            accounts_table.pack_propagate(True)
            
            load_accounts()
            self.switch('blocked_accounts', self.all_security_frame)
        
        def show_blocked_ips():
            """Display blocked IPs with unblock functionality."""
            self.current_security_tab = 'Blocked IPs'
            update_tab_colors()
            
            for widget in ips_content_frame.winfo_children():
                widget.destroy()
            
            if not self.admin_token:
                error_label = tk.Label(ips_content_frame, text='Authentication required. Please log in again.', 
                                      font=('Open Sans', 12), bg='white', fg='red')
                error_label.pack(pady=50)
                return
            
            def load_ips():
                for widget in ips_list_frame.winfo_children():
                    widget.destroy()

                # Table container to stabilize sizing
                ips_table = tk.Frame(ips_list_frame, bg='white', width=1000)
                ips_table.pack(fill='x')

                try:
                    response = self.make_admin_api_call('GET', '/admin/ip_list')
                    
                    if response and response.status_code == 200:
                        data = response.json()
                        ips = data.get('ips', [])
                        
                        if not ips:
                            no_ips_label = tk.Label(ips_table, text='No IP records found.', 
                                                   font=('Open Sans', 12), bg='white', fg='#858585')
                            no_ips_label.pack(pady=20)
                        else:
                            # Header with grid (avoid place geometry issues)
                            header_frame = tk.Frame(ips_table, bg='#166E82', height=40)
                            header_frame.pack(fill='x', pady=(0, 5))
                            header_frame.pack_propagate(False)
                            
                            headers_text = ['IP Address', 'Status', 'Soft Block Count', 'Action']
                            col_widths = [360, 320, 160, 160]  # totals 1000
                            for i, (text, w) in enumerate(zip(headers_text, col_widths)):
                                label = tk.Label(header_frame, text=text, font=('Open Sans', 10, 'bold'), 
                                                bg='#166E82', fg='white')
                                sticky_val = 'e' if i == 3 else 'w'
                                padx_val = (0, 10) if i == 3 else (10 if i == 0 else 0, 0)
                                label.grid(row=0, column=i, sticky=sticky_val, padx=padx_val, pady=10)
                                header_frame.grid_columnconfigure(i, minsize=w)
                            
                            # IP entries
                            for ip_data in ips:
                                ip_frame = tk.Frame(ips_table, bg='white', height=50, relief='solid', bd=1)
                                ip_frame.pack(fill='x', pady=2)
                                for ci, w in enumerate(col_widths):
                                    ip_frame.grid_columnconfigure(ci, minsize=w)
                                
                                ip_address = ip_data.get('ip_address', '')
                                soft_until = ip_data.get('soft_block_until', '')
                                is_hard = ip_data.get('hard_blocked')
                                # Determine status and action for all rows
                                status_text = 'Active'
                                status_bg = '#D0F9EF'; status_fg = '#166E82'
                                action_mode = 'block'
                                if is_hard:
                                    status_text = 'Permanent (Admin unlock required)'
                                    status_bg = '#F5443E'; status_fg = 'white'
                                    action_mode = 'unblock'
                                else:
                                    if soft_until:
                                        local_time = _format_malaysia_time(str(soft_until))
                                        status_text = f"Temporary (until {local_time})"
                                        status_bg = '#FFB74D'; status_fg = '#333333'
                                        action_mode = 'unblock'
                                soft_count = str(ip_data.get('soft_block_count', 0))
                                
                                tk.Label(ip_frame, text=ip_address, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=0, sticky='w', padx=(10,0), pady=14)
                                status_label = tk.Label(ip_frame, text=status_text, font=('Open Sans', 9, 'bold'), bg=status_bg, fg=status_fg, padx=8, pady=3)
                                status_label.grid(row=0, column=1, sticky='w')
                                tk.Label(ip_frame, text=soft_count, font=('Open Sans', 9), bg='white', fg='#333333').grid(row=0, column=2, sticky='w')
                                
                                def unblock_ip(ip_addr=ip_address):
                                    try:
                                        response = self.make_admin_api_call('POST', '/admin/unblock_ip', json_data={'ip_address': ip_addr})
                                        if response and response.status_code == 200:
                                            messagebox.showinfo('Success', f'IP {ip_addr} unblocked successfully')
                                            load_ips()
                                        else:
                                            messagebox.showerror('Error', 'Failed to unblock IP')
                                    except Exception as e:
                                        messagebox.showerror('Error', f'Error: {str(e)}')
                                
                                def block_ip(ip_addr=ip_address):
                                    try:
                                        response = self.make_admin_api_call('POST', '/admin/block_ip', json_data={'ip_address': ip_addr})
                                        if response and response.status_code == 200:
                                            messagebox.showinfo('Success', f'IP {ip_addr} hard blocked')
                                            load_ips()
                                        else:
                                            messagebox.showerror('Error', 'Failed to block IP')
                                    except Exception as e:
                                        messagebox.showerror('Error', f'Error: {str(e)}')
                                
                                if action_mode == 'unblock':
                                    act_btn = ttk.Button(ip_frame, text='Unblock', style='green_button.TButton', 
                                                        command=unblock_ip, width=10)
                                else:
                                    act_btn = ttk.Button(ip_frame, text='Block', style='green_button.TButton', 
                                                        command=block_ip, width=10)
                                act_btn.grid(row=0, column=3, sticky='e', padx=(0,10))
                    else:
                        error_label = tk.Label(ips_table, text='Failed to load blocked IPs.', 
                                              font=('Open Sans', 12), bg='white', fg='red')
                        error_label.pack(pady=20)
                except Exception as e:
                    error_label = tk.Label(ips_table, text=f'Error: {str(e)}', 
                                          font=('Open Sans', 12), bg='white', fg='red')
                    error_label.pack(pady=20)
            
            # Header row: title left, refresh right
            header_ips = tk.Frame(ips_content_frame, bg='white')
            header_ips.pack(pady=(15, 6))
            title_label = tk.Label(header_ips, text='Blocked IP Addresses', 
                                  font=('Open Sans', 18, 'bold'), bg='white', fg='#166E82')
            title_label.pack(anchor='center')
            # Admin manual hard block input
            ip_action_row = tk.Frame(ips_content_frame, bg='white')
            ip_action_row.pack(pady=(0, 6))
            ip_entry_label = tk.Label(ip_action_row, text='Block IP:', font=('Open Sans', 10, 'bold'), bg='white', fg='#333333')
            ip_entry_label.pack(side='left', padx=(0, 6))
            ip_entry = tk.Entry(ip_action_row, bg='#F5F5F5', font=('Open Sans', 10), width=22)
            ip_entry.pack(side='left', padx=(0, 6))
            def block_ip_from_input():
                ip_val = ip_entry.get().strip()
                if not ip_val:
                    messagebox.showerror('Error', 'Please enter an IP address')
                    return
                try:
                    import ipaddress
                    ipaddress.ip_address(ip_val)
                except Exception:
                    messagebox.showerror('Error', 'Invalid IP address format')
                    return
                try:
                    response = self.make_admin_api_call('POST', '/admin/block_ip', json_data={'ip_address': ip_val})
                    if response and response.status_code == 200:
                        messagebox.showinfo('Success', f'IP {ip_val} hard blocked')
                        ip_entry.delete(0, tk.END)
                        load_ips()
                    else:
                        messagebox.showerror('Error', 'Failed to block IP')
                except Exception as e:
                    messagebox.showerror('Error', f'Error: {str(e)}')
            ip_block_btn = ttk.Button(ip_action_row, text='Block', style='green_button.TButton', command=block_ip_from_input, width=8)
            ip_block_btn.pack(side='left')
            
            # Centered content area with fixed max width
            ips_center = tk.Frame(ips_content_frame, bg='white')
            ips_center.pack(fill='both', expand=True)
            # Width aligns with header layout (x=20 + i*250, width=230 -> right edge 1000)
            ips_list_frame = tk.Frame(ips_center, bg='white', width=1000)
            ips_list_frame.pack(pady=10)
            
            load_ips()
            self.switch('blocked_ips', self.all_security_frame)
        
        # Clear security frame
        for widget in self.security_frame.winfo_children():
            widget.destroy()
        
        # Tab buttons - matching appointment tabs style, centered and moved down a bit
        tab_button_frame = tk.Frame(self.security_frame, background='#ffffff')
        tab_button_frame.pack(fill='x', expand='True', pady=(18, 6))
        tab_center = tk.Frame(tab_button_frame, background='#ffffff')
        tab_center.pack()
        
        # Create the navigation buttons
        tab_buttons = []
        tabs = ['Statistics', 'Audit Logs', 'Blocked Accounts', 'Blocked IPs']
        tab_commands = {
            'Statistics': show_statistics,
            'Audit Logs': show_audit_logs,
            'Blocked Accounts': show_blocked_accounts,
            'Blocked IPs': show_blocked_ips
        }
        for i, tab in enumerate(tabs):
            tab_button = tk.Button(tab_center, text=tab, font=('Open Sans', 12, 'bold'),
                                   bg='#00C196' if tab == self.current_security_tab else '#E0FCF8',
                                   fg='white' if tab == self.current_security_tab else '#00C196', width=15, borderwidth=0,
                                   relief="ridge", bd=2, highlightbackground='#00C196', highlightthickness=0, padx=5,
                                   pady=5, command=lambda t=tab: tab_commands[t]())
            tab_button.grid(row=0, column=i, padx=14, pady=10)
            tab_button.config(relief="flat", highlightthickness=0, borderwidth=0, padx=30, pady=5)
            tab_buttons.append(tab_button)
        
        # Content frames - matching appointment frame style
        stats_frame = tk.Frame(self.security_frame, width=1050, height=500, bg='white')
        stats_canvas = tk.Canvas(stats_frame, borderwidth=0, background="#ffffff", width=1030, height=500, highlightthickness=0)
        stats_scrollbar = tk.Scrollbar(stats_frame, orient="vertical", command=stats_canvas.yview)
        stats_content_frame = tk.Frame(stats_canvas, background="#ffffff")
        
        stats_canvas.create_window((0, 0), window=stats_content_frame, anchor="nw")
        stats_canvas.configure(yscrollcommand=stats_scrollbar.set)
        
        def update_stats_scroll_region(event):
            stats_canvas.configure(scrollregion=stats_canvas.bbox("all"))
            # Center the content horizontally
            bbox = stats_canvas.bbox("all")
            if bbox:
                canvas_width = stats_canvas.winfo_width()
                if canvas_width > 1:  # Make sure canvas is rendered
                    content_width = bbox[2] - bbox[0]
                    if content_width < canvas_width:
                        stats_canvas.coords(stats_content_frame, (canvas_width - content_width) // 2, 0)
        
        stats_content_frame.bind('<Configure>', update_stats_scroll_region)
        stats_canvas.bind('<Configure>', update_stats_scroll_region)
        
        stats_canvas.pack(side="left", fill="both", expand=True)
        stats_scrollbar.pack(side="right", fill="y")
        self.all_security_frame['statistics'] = [stats_frame, stats_canvas, stats_content_frame, 0]
        # Mouse wheel focus to this canvas
        stats_canvas.bind('<Enter>', lambda e: stats_canvas.bind_all('<MouseWheel>', lambda ev: stats_canvas.yview_scroll(-1 * (ev.delta // 120), 'units')))
        stats_canvas.bind('<Leave>', lambda e: stats_canvas.unbind_all('<MouseWheel>'))
        
        logs_frame = tk.Frame(self.security_frame, width=1050, height=500, bg='white')
        logs_canvas = tk.Canvas(logs_frame, borderwidth=0, background="#ffffff", width=1030, height=500, highlightthickness=0)
        logs_scrollbar = tk.Scrollbar(logs_frame, orient="vertical", command=logs_canvas.yview)
        logs_content_frame = tk.Frame(logs_canvas, background="#ffffff")
        
        logs_content_window = logs_canvas.create_window((0, 0), window=logs_content_frame, anchor="nw")
        logs_canvas.configure(yscrollcommand=logs_scrollbar.set)
        
        def update_logs_scroll_region(event):
            logs_canvas.configure(scrollregion=logs_canvas.bbox("all"))
            # Center horizontally consistent with other tabs
            bbox = logs_canvas.bbox("all")
            if bbox:
                canvas_width = logs_canvas.winfo_width()
                if canvas_width > 1:
                    content_width = bbox[2] - bbox[0]
                    if content_width < canvas_width:
                        logs_canvas.coords(logs_content_window, (canvas_width - content_width) // 2, 0)
                    else:
                        logs_canvas.coords(logs_content_window, 0, 0)
        
        logs_content_frame.bind('<Configure>', update_logs_scroll_region)
        logs_canvas.bind('<Configure>', update_logs_scroll_region)
        
        logs_canvas.pack(side="left", fill="both", expand=True)
        logs_scrollbar.pack(side="right", fill="y")
        self.all_security_frame['audit_logs'] = [logs_frame, logs_canvas, logs_content_frame, 0]
        logs_canvas.bind('<Enter>', lambda e: logs_canvas.bind_all('<MouseWheel>', lambda ev: logs_canvas.yview_scroll(-1 * (ev.delta // 120), 'units')))
        logs_canvas.bind('<Leave>', lambda e: logs_canvas.unbind_all('<MouseWheel>'))
        
        accounts_frame = tk.Frame(self.security_frame, width=1050, height=500, bg='white')
        accounts_canvas = tk.Canvas(accounts_frame, borderwidth=0, background="#ffffff", width=1030, height=500, highlightthickness=0)
        accounts_scrollbar = tk.Scrollbar(accounts_frame, orient="vertical", command=accounts_canvas.yview)
        accounts_content_frame = tk.Frame(accounts_canvas, background="#ffffff")
        
        accounts_content_window = accounts_canvas.create_window((0, 0), window=accounts_content_frame, anchor="nw")
        accounts_canvas.configure(yscrollcommand=accounts_scrollbar.set)
        
        def update_accounts_scroll_region(event):
            accounts_canvas.configure(scrollregion=accounts_canvas.bbox("all"))
            # Center the content horizontally (same approach as statistics tab)
            bbox = accounts_canvas.bbox("all")
            if bbox:
                canvas_width = accounts_canvas.winfo_width()
                if canvas_width > 1:
                    content_width = bbox[2] - bbox[0]
                    if content_width < canvas_width:
                        accounts_canvas.coords(accounts_content_window, (canvas_width - content_width) // 2, 0)
                    else:
                        accounts_canvas.coords(accounts_content_window, 0, 0)
        
        accounts_content_frame.bind('<Configure>', update_accounts_scroll_region)
        accounts_canvas.bind('<Configure>', update_accounts_scroll_region)
        
        accounts_canvas.pack(side="left", fill="both", expand=True)
        accounts_scrollbar.pack(side="right", fill="y")
        self.all_security_frame['blocked_accounts'] = [accounts_frame, accounts_canvas, accounts_content_frame, 0]
        accounts_canvas.bind('<Enter>', lambda e: accounts_canvas.bind_all('<MouseWheel>', lambda ev: accounts_canvas.yview_scroll(-1 * (ev.delta // 120), 'units')))
        accounts_canvas.bind('<Leave>', lambda e: accounts_canvas.unbind_all('<MouseWheel>'))
        
        ips_frame = tk.Frame(self.security_frame, width=1050, height=500, bg='white')
        ips_canvas = tk.Canvas(ips_frame, borderwidth=0, background="#ffffff", width=1030, height=500, highlightthickness=0)
        ips_scrollbar = tk.Scrollbar(ips_frame, orient="vertical", command=ips_canvas.yview)
        ips_content_frame = tk.Frame(ips_canvas, background="#ffffff")
        
        ips_content_window = ips_canvas.create_window((0, 0), window=ips_content_frame, anchor="nw")
        ips_canvas.configure(yscrollcommand=ips_scrollbar.set)
        
        def update_ips_scroll_region(event):
            ips_canvas.configure(scrollregion=ips_canvas.bbox("all"))
            # Center the content horizontally (same approach as statistics tab)
            bbox = ips_canvas.bbox("all")
            if bbox:
                canvas_width = ips_canvas.winfo_width()
                if canvas_width > 1:
                    content_width = bbox[2] - bbox[0]
                    if content_width < canvas_width:
                        ips_canvas.coords(ips_content_window, (canvas_width - content_width) // 2, 0)
                    else:
                        ips_canvas.coords(ips_content_window, 0, 0)
        
        ips_content_frame.bind('<Configure>', update_ips_scroll_region)
        ips_canvas.bind('<Configure>', update_ips_scroll_region)
        
        ips_canvas.pack(side="left", fill="both", expand=True)
        ips_scrollbar.pack(side="right", fill="y")
        self.all_security_frame['blocked_ips'] = [ips_frame, ips_canvas, ips_content_frame, 0]
        ips_canvas.bind('<Enter>', lambda e: ips_canvas.bind_all('<MouseWheel>', lambda ev: ips_canvas.yview_scroll(-1 * (ev.delta // 120), 'units')))
        ips_canvas.bind('<Leave>', lambda e: ips_canvas.unbind_all('<MouseWheel>'))
        
        # Show statistics by default
        show_statistics()

    def set_up_me_frame(self):
        def show_personal():
            def personal_password_visible():
                password_entry.config(show='')
                password_eye_closed_button.place_forget()
                password_eye_opened_button.place(x=330, y=2)

            def personal_password_invisible():
                password_entry.config(show='*')
                password_eye_opened_button.place_forget()
                password_eye_closed_button.place(x=330, y=2)

            for widget in personal_content_frame.winfo_children():
                widget.destroy()

            cursor.execute('''SELECT user_email, user_password FROM user WHERE user_id=%s''', (self.user_id, ))
            user_detail = cursor.fetchone()

            email_label = tk.Label(personal_content_frame, text='Email: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                   width=20, anchor='e')
            email_label.grid(row=0, column=0, padx=(150, 5), pady=5, sticky='e')
            email_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            email_frame.grid(row=0, column=1, padx=5, pady=5, sticky='w')
            email_entry = tk.Label(email_frame, bg='#D0F9EF', text=user_detail[0], fg='#858585', font=('Open Sans', 10))
            email_entry.place(x=5, y=12)

            password_label = tk.Label(personal_content_frame, text='Password: ', font=('Open Sans', 12, 'bold'), bg='white', fg='#000000',
                                      width=20, anchor='e')
            password_label.grid(row=1, column=0, padx=(150, 5), pady=5, sticky='e')
            password_frame = tk.Frame(personal_content_frame, bg='#D0F9EF', width=380, height=45)
            password_frame.grid(row=1, column=1, padx=5, pady=5, sticky='w')
            password_entry = tk.Entry(password_frame, bg='#D0F9EF', fg='#858585', font=('Open Sans', 10), show='*', border=0)
            password_entry.place(x=7, y=12)
            password_entry.insert(0, user_detail[1])
            password_entry.config(state='disabled', disabledbackground='#D0F9EF')
            password_eye_closed_button = ttk.Button(password_frame, style='eye_closed_green.TButton', cursor='hand2')
            password_eye_closed_button.place(x=330, y=2)
            password_eye_opened_button = ttk.Button(password_frame, style='eye_opened_green.TButton', cursor='hand2')
            password_eye_closed_button.config(command=lambda: personal_password_visible())
            password_eye_opened_button.config(command=lambda: personal_password_invisible())

            self.switch('personal', self.all_me_frame)

        def show_reset():
            def reset():
                reset_content_frame.focus_set()
                if old_entry.cget('fg') == '#333333' and new_entry.cget('fg') == '#333333' and confirm_entry.cget('fg') == '#333333':
                    cursor.execute('''SELECT user_password FROM user WHERE user_id=%s''', (self.user_id, ))
                    previous_password = cursor.fetchone()[0]
                    if old_entry.get() == previous_password:
                        if len(new_entry.get()) >= 8:
                            if new_entry.get() == confirm_entry.get():
                                cursor.execute('''UPDATE user SET user_password=%s WHERE user_id=%s''', (new_entry.get(), self.user_id))
                                database.commit()
                                save_error_label.config(text='')
                                messagebox.showinfo('Success', "Reset Password Successfully")
                                show_personal()
                            else:
                                save_error_label.config(text='Password does not match')
                        else:
                            save_error_label.config(text='Minimum 8 characters of password')
                    else:
                        save_error_label.config(text="Incorrect old password")
                else:
                    save_error_label.config(text="Please fill in all details")

            for widget in reset_content_frame.winfo_children():
                widget.destroy()

            save_error_label.config(text='')
            save_button.config(command=lambda: reset())

            reset_label = tk.Label(reset_content_frame, text='Reset Password',
                                   font=('Open Sans', 20, 'underline', 'bold'), bg='white', fg='#000000')
            reset_label.grid(row=0, column=0, columnspan=2, padx=35, pady=(10, 15), sticky='w')

            old_label = tk.Label(reset_content_frame, text='Old Password', font=('Open Sans', 12, 'bold'), bg='white',
                                         fg='#000000')
            old_label.grid(row=1, column=0, padx=50, pady=(5, 0), sticky='w')
            old_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            old_entry_frame.grid(row=2, column=0, padx=53, pady=(0, 5))
            old_entry = tk.Entry(old_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            old_entry.place(x=10, y=13)
            old_entry.insert(0, 'Enter Old Password')
            old_eye_closed_button = ttk.Button(old_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            old_eye_closed_button.place(x=330, y=2)
            old_eye_opened_button = ttk.Button(old_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            old_visibility = tk.Label(old_entry_frame, text='Close')
            old_eye_closed_button.config(command=lambda: self.show_hide_password(old_entry, old_eye_opened_button,
                                                                                 old_eye_closed_button, old_visibility))
            old_eye_opened_button.config(command=lambda: self.show_hide_password(old_entry, old_eye_opened_button,
                                                                                 old_eye_closed_button, old_visibility))
            old_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', old_entry, old_visibility))
            old_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', old_entry, 'Enter Old Password'))
            old_entry.bind('<Return>', lambda event: reset())

            new_label = tk.Label(reset_content_frame, text='New Password', font=('Open Sans', 12, 'bold'), bg='white',
                                 fg='#000000')
            new_label.grid(row=3, column=0, padx=50, pady=(15, 0), sticky='w')
            new_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            new_entry_frame.grid(row=4, column=0, padx=53, pady=(0, 5))
            new_entry = tk.Entry(new_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            new_entry.place(x=10, y=13)
            new_entry.insert(0, 'Enter New Password')
            new_eye_closed_button = ttk.Button(new_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            new_eye_closed_button.place(x=330, y=2)
            new_eye_opened_button = ttk.Button(new_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            new_visibility = tk.Label(new_entry_frame, text='Close')
            new_eye_closed_button.config(command=lambda: self.show_hide_password(new_entry, new_eye_opened_button,
                                                                                 new_eye_closed_button, new_visibility))
            new_eye_opened_button.config(command=lambda: self.show_hide_password(new_entry, new_eye_opened_button,
                                                                                 new_eye_closed_button, new_visibility))
            new_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', new_entry, new_visibility))
            new_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', new_entry, 'Enter New Password'))
            new_entry.bind('<Return>', lambda event: reset())

            confirm_entry_frame = tk.Frame(reset_content_frame, bg='#D0F9EF', width=380, height=45)
            confirm_entry_frame.grid(row=5, column=0, padx=53, pady=(0, 5))
            confirm_entry = tk.Entry(confirm_entry_frame, font=('Open Sans', 10), bg='#D0F9EF', fg='#858585', border=0,
                                 width=42, show='')
            confirm_entry.place(x=10, y=13)
            confirm_entry.insert(0, 'Re-enter New Password')
            confirm_eye_closed_button = ttk.Button(confirm_entry_frame, style='eye_closed_green.TButton', cursor='hand2')
            confirm_eye_closed_button.place(x=330, y=2)
            confirm_eye_opened_button = ttk.Button(confirm_entry_frame, style='eye_opened_green.TButton', cursor='hand2')
            confirm_visibility = tk.Label(confirm_entry_frame, text='Close')
            confirm_eye_closed_button.config(command=lambda: self.show_hide_password(confirm_entry, confirm_eye_opened_button,
                                                                                     confirm_eye_closed_button, confirm_visibility))
            confirm_eye_opened_button.config(command=lambda: self.show_hide_password(confirm_entry, confirm_eye_opened_button,
                                                                                     confirm_eye_closed_button, confirm_visibility))
            confirm_entry.bind('<FocusIn>', lambda event: self.focus_entry('password', confirm_entry, confirm_visibility))
            confirm_entry.bind('<FocusOut>', lambda event: self.leave_focus_entry('password', confirm_entry, 'Re-enter New Password'))
            confirm_entry.bind('<Return>', lambda event: reset())

            self.switch('reset', self.all_me_frame)

        for widget in self.me_frame.winfo_children():
            widget.destroy()

        personal_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        logout_button = tk.Button(personal_frame, text='Log Out', bg='red', fg='white', cursor='hand2', relief='flat', border=0,
                                  font=('Open Sans', 14, 'bold'), width=10, command=lambda: self.logout())
        logout_button.place(x=30, y=15)
        reset_password_button = ttk.Button(personal_frame, text='Reset Password', style='green_button.TButton', cursor='hand2',
                                           width=18, command=lambda: show_reset())
        reset_password_button.place(x=810, y=15)
        personal_canvas = tk.Canvas(personal_frame, width=1030, height=430, bg='white', highlightthickness=0)
        personal_canvas.place(x=0, y=75)
        personal_scrollbar = tk.Scrollbar(personal_frame, orient='vertical')
        personal_scrollbar.place(x=1033, y=75, height=430)
        personal_canvas.configure(yscrollcommand=personal_scrollbar.set)
        personal_scrollbar.configure(command=personal_canvas.yview)
        personal_content_frame = tk.Frame(personal_canvas, bg='white')
        personal_canvas.create_window((0, 0), window=personal_content_frame, anchor="nw")
        self.all_me_frame['personal'] = [personal_frame, personal_canvas, personal_content_frame, 0]

        reset_frame = tk.Frame(self.me_frame, width=1050, height=510, bg='white')
        reset_back_button = ttk.Button(reset_frame, text='< Back', style='back.TButton', cursor='hand2', width=6,
                                       command=lambda: show_personal())
        reset_back_button.place(x=20, y=15)
        save_button = ttk.Button(reset_frame, text='Save', style='green_button.TButton', cursor='hand2', width=6)
        save_button.place(x=945, y=15)
        save_error_label = tk.Label(reset_frame, text='', anchor='e', font=('Open Sans', 8), bg='white', fg='red', width=30)
        save_error_label.place(x=750, y=25)
        reset_canvas = tk.Canvas(reset_frame, width=1030, height=430, bg='white', highlightthickness=0)
        reset_canvas.place(x=0, y=75)
        reset_scrollbar = tk.Scrollbar(reset_frame, orient='vertical')
        reset_scrollbar.place(x=1033, y=75, height=430)
        reset_canvas.configure(yscrollcommand=reset_scrollbar.set)
        reset_scrollbar.configure(command=reset_canvas.yview)
        reset_content_frame = tk.Frame(reset_canvas, bg='white')
        reset_canvas.create_window((0, 0), window=reset_content_frame, anchor="nw")
        self.all_me_frame['reset'] = [reset_frame, reset_canvas, reset_content_frame, 0]

        show_personal()

    def on_mouse_wheel(self, event, canvas):
        canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def focus_entry(self, entry_type, entry, visibility=None):
        if entry_type == 'entry':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
        elif entry_type == 'text':
            if entry.cget('fg') == '#858585':
                entry.delete('1.0', 'end')
                entry.config(fg='#333333')
        elif entry_type == 'password':
            if entry.cget('fg') == '#858585':
                entry.delete(0, tk.END)
                entry.config(fg='#333333')
                if visibility.cget('text') == 'Open':
                    entry.config(show='')
                elif visibility.cget('text') == 'Close':
                    entry.config(show='*')

    def leave_focus_entry(self, entry_type, entry, text):
        if entry_type == 'entry':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585')
                entry.insert(0, text)
        elif entry_type == 'text':
            value = entry.get('1.0', 'end')
            if value.strip() == '':
                entry.delete('1.0', 'end')
                entry.config(fg='#858585')
                entry.insert('1.0', text)
        elif entry_type == 'password':
            value = entry.get()
            if value.strip() == '':
                entry.delete(0, tk.END)
                entry.config(fg='#858585', show='')
                entry.insert(0, text)

    def show_hide_password(self, entry, eye_open_button, eye_close_button, visibility):
        if visibility.cget('text') == 'Close' and entry.cget('fg') == '#858585':
            eye_open_button.place(x=330, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')
        elif visibility.cget('text') == 'Open' and entry.cget('fg') == '#858585':
            eye_open_button.place_forget()
            eye_close_button.place(x=330, y=2)
            entry.config(show='')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Open':
            eye_open_button.place_forget()
            eye_close_button.place(x=330, y=2)
            entry.config(show='*')
            visibility.config(text='Close')
        elif visibility.cget('text') == 'Close':
            eye_open_button.place(x=330, y=2)
            eye_close_button.place_forget()
            entry.config(show='')
            visibility.config(text='Open')

    def format_date(self, date):
        full_date = date.split('-')
        year = full_date[0]
        month = full_date[1]
        day = full_date[2]
        months = {'01': 'January',
                  '02': 'February',
                  '03': 'March',
                  '04': 'April',
                  '05': 'May',
                  '06': 'June',
                  '07': 'July',
                  '08': 'August',
                  '09': 'September',
                  '10': 'October',
                  '11': 'November',
                  '12': 'December'}
        month = months[month]
        return f"{day} {month} {year}"


if __name__ == "__main__":
    root = LoginRegister()
    root.run()

    cursor.close()
    database.close()
