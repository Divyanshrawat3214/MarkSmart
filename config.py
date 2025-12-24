import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Environment Detection
ENV = os.environ.get('FLASK_ENV', 'development').lower()
IS_PRODUCTION = False 

# Flask Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))

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

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(FACES_DIR, exist_ok=True)

MAX_CONTENT_LENGTH = 8 * 1024 * 1024
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
JWT_EXPIRY_MINUTES = 30
FACE_TOLERANCE = 0.6  

# Session Configuration
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_NAME = 'marksmart_session'
PERMANENT_SESSION_LIFETIME = 86400

# Server Configuration
DEBUG = True
TESTING = False
PREFERRED_URL_SCHEME = 'http'
HOST = os.environ.get('HOST', '0.0.0.0')
try:
    PORT = int(os.environ.get('PORT', 5000))
except ValueError:
    PORT = 5000

# --- FIX: Logging Configuration (Missing attributes added here) ---
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOG_FILE = os.environ.get('LOG_FILE', os.path.join(BASE_DIR, 'logs', 'app.log'))
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB (Ye missing tha)
LOG_BACKUP_COUNT = 5              # (Ye bhi missing tha)

# Logs directory create karein
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# Gemini API Configuration
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

# Admin Configuration
ADMIN_USERNAMES_ENV = os.environ.get('ADMIN_USERNAMES', 'divyansh rawat,admin')
ADMIN_USERNAMES = [u.strip().lower() for u in ADMIN_USERNAMES_ENV.split(',') if u.strip()]
ADMIN_DEPARTMENT_CODE = os.environ.get('ADMIN_DEPARTMENT_CODE', '12345').strip()
