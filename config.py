import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# --- FIX 1: Environment Detection ---
# Koyeb/Cloud par hamesha production ho jata hai, isliye hum isse development rakhenge
ENV = os.environ.get('FLASK_ENV', 'development').lower()
IS_PRODUCTION = False  # Isse False rakhne se "Invalid Origin" error nahi aayega

# Flask Configuration
SECRET_KEY = os.environ.get('SECRET_KEY')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

if not SECRET_KEY:
    # Production mein Error ke bajaye auto-generate karega taaki app crash na ho
    SECRET_KEY = secrets.token_hex(32)
    print("⚠️  WARNING: Using auto-generated SECRET_KEY.")

if not JWT_SECRET_KEY: 
    JWT_SECRET_KEY = secrets.token_hex(32)
    print("⚠️  WARNING: Using auto-generated JWT_SECRET_KEY.")

# File Paths
DATA_DIR = os.path.join(BASE_DIR, 'data')
QR_DIR = os.path.join(BASE_DIR, 'static', 'qr_codes')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
FACES_DIR = os.path.join(BASE_DIR, 'faces')

# Excel Files
ATTENDANCE_FILE = os.path.join(DATA_DIR, 'attendance.xlsx')
STUDENTS_FILE = os.path.join(DATA_DIR, 'students.xlsx')
FEEDBACK_FILE = os.path.join(DATA_DIR, 'feedback.xlsx')
ADMINS_FILE = os.path.join(DATA_DIR, 'admins.xlsx')

# Create directories if they don't exist
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(FACES_DIR, exist_ok=True)

# Upload Configuration
MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8 MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- FIX 2: JWT Configuration ---
# 5 minute bahut kam hai, ise 30 minute kiya taaki bar-bar QR scan fail na ho
JWT_EXPIRY_MINUTES = 30 

# --- FIX 3: Face Recognition ---
# 0.45 bahut strict hai, face recognition fail ho sakta hai. 0.6 standard hai.
FACE_TOLERANCE = 0.6  

# Session Configuration
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False  # HTTPS ka error hatane ke liye False rakha hai
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_NAME = 'marksmart_session'
PERMANENT_SESSION_LIFETIME = 86400  # 24 hours

# Production Security Settings
DEBUG = True
TESTING = False
PREFERRED_URL_SCHEME = 'http'

# Server Configuration
HOST = os.environ.get('HOST', '0.0.0.0')
try:
    PORT = int(os.environ.get('PORT', 5000))
except ValueError:
    PORT = 5000
    print("⚠️  WARNING: Invalid PORT value, defaulting to 5000")

WORKERS = int(os.environ.get('WORKERS', 4))

# Logging Configuration
LOG_LEVEL = 'INFO'
LOG_FILE = os.environ.get('LOG_FILE', os.path.join(BASE_DIR, 'logs', 'app.log'))
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Gemini API Configuration
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

# Admin Configuration
# Fallback admin agar environment variable na mile
ADMIN_USERNAMES_ENV = os.environ.get('ADMIN_USERNAMES', 'divyansh rawat,admin')
ADMIN_USERNAMES = [u.strip().lower() for u in ADMIN_USERNAMES_ENV.split(',') if u.strip()]

# Admin department code
ADMIN_DEPARTMENT_CODE = os.environ.get('ADMIN_DEPARTMENT_CODE', '12345').strip()
