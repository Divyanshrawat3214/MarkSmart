import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Environment Detection
ENV = os.environ.get('FLASK_ENV', 'development').lower()
IS_PRODUCTION = ENV == 'production'

# Flask Configuration
# In production, SECRET_KEY and JWT_SECRET_KEY MUST be set as environment variables
# Generate strong keys: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY = os.environ.get('SECRET_KEY')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

if not SECRET_KEY:
    if IS_PRODUCTION:
        raise ValueError("SECRET_KEY environment variable must be set in production!")
    SECRET_KEY = secrets.token_hex(32)
    print("⚠️  WARNING: Using auto-generated SECRET_KEY. Set SECRET_KEY environment variable in production!")

if not JWT_SECRET_KEY:
    if IS_PRODUCTION:
        raise ValueError("JWT_SECRET_KEY environment variable must be set in production!")
    JWT_SECRET_KEY = secrets.token_hex(32)
    print("⚠️  WARNING: Using auto-generated JWT_SECRET_KEY. Set JWT_SECRET_KEY environment variable in production!")

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

# JWT Configuration
JWT_EXPIRY_MINUTES = 5  # Reduced from 10 to 5 minutes for better security

# Face Recognition
FACE_TOLERANCE = 0.45  # Lower = stricter matching (0.45 recommended for security)

# Session Configuration
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = IS_PRODUCTION  # True in production (requires HTTPS)
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_NAME = 'marksmart_session'
PERMANENT_SESSION_LIFETIME = 86400  # 24 hours in seconds

# Production Security Settings
if IS_PRODUCTION:
    # Force HTTPS in production
    PREFERRED_URL_SCHEME = 'https'
    # Disable debug mode
    DEBUG = False
    TESTING = False
else:
    DEBUG = True
    TESTING = False
    PREFERRED_URL_SCHEME = 'http'

# Server Configuration
HOST = os.environ.get('HOST', '0.0.0.0' if IS_PRODUCTION else '127.0.0.1')
PORT = int(os.environ.get('PORT', 5000))
WORKERS = int(os.environ.get('WORKERS', 4))  # For production WSGI servers

# Logging Configuration
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO' if IS_PRODUCTION else 'DEBUG')
LOG_FILE = os.environ.get('LOG_FILE', os.path.join(BASE_DIR, 'logs', 'app.log'))
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Gemini API Configuration
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'AIzaSyBWbyGz34tmP0Ttc9o0NScKnFas-e1H_pQ')
if not GEMINI_API_KEY and IS_PRODUCTION:
    raise ValueError("GEMINI_API_KEY environment variable must be set in production!")

# Admin Configuration
ADMIN_USERNAMES = os.environ.get('ADMIN_USERNAMES', '').split(',')
ADMIN_USERNAMES = [u.strip().lower() for u in ADMIN_USERNAMES if u.strip()]

# Admin department code (used for admin auth in unified auth page)
ADMIN_DEPARTMENT_CODE = os.environ.get('ADMIN_DEPARTMENT_CODE', '').strip()

