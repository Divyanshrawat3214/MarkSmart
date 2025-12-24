import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

ENV = os.environ.get('FLASK_ENV', 'development').lower()
IS_PRODUCTION = ENV == 'production'

SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))

DATA_DIR = os.path.join(BASE_DIR, 'data')
QR_DIR = os.path.join(BASE_DIR, 'static', 'qr_codes')
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
FACES_DIR = os.path.join(BASE_DIR, 'faces')

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

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = IS_PRODUCTION
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_NAME = 'marksmart_session'
PERMANENT_SESSION_LIFETIME = 86400

DEBUG = not IS_PRODUCTION
TESTING = False
PREFERRED_URL_SCHEME = 'https' if IS_PRODUCTION else 'http'

HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', 5000))

# --- LOGGING FIX ---
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
LOG_FILE = os.environ.get('LOG_FILE', os.path.join(BASE_DIR, 'logs', 'app.log'))
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
ADMIN_USERNAMES = [u.strip().lower() for u in os.environ.get('ADMIN_USERNAMES', '').split(',') if u.strip()]
ADMIN_DEPARTMENT_CODE = os.environ.get('ADMIN_DEPARTMENT_CODE', '').strip()
