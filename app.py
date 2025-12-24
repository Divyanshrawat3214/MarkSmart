import os
import io
import datetime
import secrets
import uuid
import jwt
import cv2
import numpy as np
import qrcode
import face_recognition
import bcrypt
import shutil
import pandas as pd
from flask import Flask, Blueprint, render_template, request, send_file, jsonify, redirect, url_for, flash
from flask_wtf. csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from PIL import Image
import zipfile
import config
from models import StudentModel, AttendanceModel, FeedbackModel, UserModel, compute_face_embedding
from auth import init_auth, login_required, login_manager, User
from functools import wraps
from flask_login import current_user, UserMixin, login_user as flask_login_user, logout_user
from student_auth import validate_password, hash_password, verify_password
from database import get_db, init_database
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE
app. config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME
app.config['PREFERRED_URL_SCHEME'] = config.PREFERRED_URL_SCHEME
app.config['JSON_SORT_KEYS'] = False

# Production security:  Disable debug mode
if config.IS_PRODUCTION:
    app. config['DEBUG'] = False
    app.config['TESTING'] = False

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize database
init_database()

# Student User class for Flask-Login
class StudentUser(UserMixin):
    def __init__(self, enroll_no):
        self.id = f"student:{enroll_no}"
        self.enroll_no = enroll_no
        self.user_type = "student"
        self.is_authenticated = True
        self.is_active = True
        self.is_anonymous = False

# Initialize authentication (admin)
init_auth(app)

# Override user_loader to handle both students and admins
@login_manager.user_loader
def load_user(user_id):
    """Load user from session"""
    try:
        if user_id. startswith("student:"):
            enroll_no = user_id. split(":", 1)[1]
            student = StudentModel.get_by_enroll(enroll_no)
            if student and student.get('password_hash'):
                return StudentUser(enroll_no)
        else:
            # Admin user
            user = UserModel.get_by_username(user_id)
            if user: 
                return User(user_id)
    except Exception as e:
        app.logger.error(f"Error loading user:  {str(e)}")
    return None

# Add security headers middleware
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    if config.IS_PRODUCTION: 
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        if config.SESSION_COOKIE_SECURE: 
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdn.datatables.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.datatables.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = (
            'geolocation=(self), '
            'camera=(self), '
            'microphone=(), '
            'payment=()'
        )
    return response

# Force HTTPS in production
@app.before_request
def force_https():
    """Force HTTPS redirection in production"""
    if config.IS_PRODUCTION and not request.is_secure:
        host = request.host. split(':', 1)[0]
        if host in ('localhost', '127.0.0.1'):
            return None

        if request.headers.get('X-Forwarded-Proto') == 'https':
            return None

        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# Main blueprint for dashboard routes
main_bp = Blueprint('main', __name__)

def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
        
        if not hasattr(current_user, 'username'):
            return jsonify({'status':  'error', 'message':  'Admin access required'}), 403
        
        username = current_user.username. lower()
        admin_usernames = getattr(config, 'ADMIN_USERNAMES', [])
        if not admin_usernames or username not in admin_usernames:
            app.logger.warning(f"Non-admin user '{current_user.username}' attempted admin endpoint")
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    """Check if file extension is allowed"""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    allowed = getattr(config, 'ALLOWED_EXTENSIONS', {'jpg', 'jpeg', 'png', 'gif'})
    return ext in allowed

def generate_qr_token():
    """Generate JWT token for QR code"""
    now = datetime.datetime.now()
    expiry_minutes = getattr(config, 'JWT_EXPIRY_MINUTES', 30)
    payload = {
        'date': now.strftime('%Y-%m-%d'),
        'nonce': secrets.token_hex(16),
        'iss': 'marksmart',
        'aud': 'attendance',
        'exp': int((now + datetime.timedelta(minutes=expiry_minutes)).timestamp())
    }
    token = jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')
    return token

def verify_qr_token(token):
    """Verify JWT token from QR code"""
    try: 
        payload = jwt.decode(
            token,
            config.JWT_SECRET_KEY,
            algorithms=['HS256'],
            audience='attendance',
            issuer='marksmart'
        )
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError) as e:
        app.logger.debug(f"Token verification failed: {str(e)}")
        return None
    except Exception as e:
        app.logger.error(f"Error verifying token: {str(e)}")
        return None

@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')

@main_bp.route('/generate_qr', methods=['GET', 'POST'])
@login_required
def generate_qr():
    """Generate QR code with JWT token"""
    if request.method == 'POST': 
        try:
            token = generate_qr_token()
            qr_data = f"{request.url_root}scan? token={token}"
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qr_data)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            
            qr_dir = getattr(config, 'QR_DIR', 'static/qr_codes')
            os.makedirs(qr_dir, exist_ok=True)
            
            today = datetime.date.today().strftime('%Y-%m-%d')
            qr_filename = f"{today}_{secrets.token_hex(8)}.png"
            qr_path = os.path.join(qr_dir, qr_filename)
            img.save(qr_path)
            
            expiry_minutes = getattr(config, 'JWT_EXPIRY_MINUTES', 30)
            return jsonify({
                'status': 'success',
                'qr_url': f'/static/qr_codes/{qr_filename}',
                'token': token,
                'expires_in': expiry_minutes * 60
            })
        except Exception as e:
            app. logger.error(f"Error generating QR code: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Failed to generate QR code'}), 500
    
    return render_template('qr_generate.html')

@app.route('/scan')
def scan():
    """Scan page - verify token and show camera (public route)"""
    token = request. args.get('token')
    if not token:
        return render_template('scan.html', error='No token provided.  Please scan the QR code. ', token=None)
    
    payload = verify_qr_token(token)
    if not payload: 
        return render_template('scan.html', error='Invalid or expired token. Please scan a fresh QR code.', token=None)
    
    return render_template('scan.html', token=token, date=payload.get('date'))

@app.route('/api/attendance/verify', methods=['POST'])
@csrf.exempt
@limiter.limit("5 per minute")
def verify_attendance():
    """Verify attendance with face recognition and liveness"""
    if config.IS_PRODUCTION:
        origin = request.headers.get('Origin') or request.headers.get('Referer', '')
        if origin and not origin.startswith(request.url_root. rstrip('/')):
            app.logger.warning(f"Invalid origin attempt from {get_remote_address()}: {origin}")
    
    token = request.form.get('token')
    if not token:
        app.logger.warning(f"Attendance verification attempt without token from IP {get_remote_address()}")
        return jsonify({'status': 'error', 'message': 'No token provided'}), 400
    
    payload = verify_qr_token(token)
    if not payload: 
        return jsonify({'status':  'error', 'message':  'Invalid or expired token'}), 400
    
    liveness_passed = request.form.get('liveness_passed', 'false').lower() == 'true'
    liveness_score = request.form.get('liveness_score', '0')
    
    if not liveness_passed: 
        return jsonify({'status':  'error', 'message':  'Liveness check failed'}), 400
    
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    
    if not latitude or not longitude:
        app.logger.warning(f"Attendance verification without location from IP {get_remote_address()}")
        return jsonify({'status': 'error', 'message': 'Location is required to mark attendance'}), 400
    
    try:
        latitude_float = float(latitude)
        longitude_float = float(longitude)
        
        if not (-90 <= latitude_float <= 90):
            return jsonify({'status': 'error', 'message': 'Invalid latitude value'}), 400
        
        if not (-180 <= longitude_float <= 180):
            return jsonify({'status': 'error', 'message': 'Invalid longitude value'}), 400
        
        latitude = str(latitude_float)
        longitude = str(longitude_float)
    except (ValueError, TypeError):
        app.logger.warning(f"Non-numeric location values from IP {get_remote_address()}")
        return jsonify({'status': 'error', 'message': 'Invalid location format'}), 400
    
    file = request.files.get('photo')
    if not file:
        return jsonify({'status': 'error', 'message': 'No photo uploaded'}), 400

    img_bytes = file.read()
    if not img_bytes:
        return jsonify({'status': 'error', 'message': 'Empty file uploaded'}), 400
    
    if len(img_bytes) < 10000:
        return jsonify({
            'status': 'error',
            'message': 'Image quality too low. Please ensure you are using a live camera (not a photo).'
        }), 400
    
    try:
        npimg = np.frombuffer(img_bytes, dtype=np. uint8)
        img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)
        if img is None:
            return jsonify({'status': 'error', 'message': 'Could not decode image'}), 400
    except Exception as e:
        app.logger.error(f"Error decoding image: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Could not process image'}), 400
    
    height, width = img.shape[:2]
    if width < 200 or height < 200:
        return jsonify({
            'status': 'error',
            'message': 'Image resolution too low. Please use a live camera with good quality.'
        }), 400
    
    rgb = img[:, :, ::-1]

    try:
        faces = face_recognition.face_locations(rgb)
        app.logger.info(f"Face detection:  Found {len(faces)} face(s)")
        
        if len(faces) > 1:
            app.logger.warning(f"Multiple faces detected ({len(faces)})")
            return jsonify({
                'status': 'error',
                'message': 'Multiple faces detected. Please ensure only one person is in the frame.'
            }), 400
        
        encodings = face_recognition.face_encodings(rgb, faces)
        
        if len(encodings) == 0:
            app.logger.warning("No face detected in image")
            return jsonify({
                'status': 'error',
                'message': 'No face found in image. Please ensure your face is clearly visible and try again.'
            }), 400
    except Exception as e:
        app.logger.error(f"Error during face detection: {str(e)}", exc_info=not config.IS_PRODUCTION)
        return jsonify({'status': 'error', 'message': 'Face detection error.  Please try again.'}), 500
    
    try:
        student_embeddings, student_names, student_enrolls = StudentModel.get_all_embeddings()
        
        if len(student_embeddings) == 0:
            app.logger.error("No enrolled students found in database")
            return jsonify({
                'status': 'error',
                'message': 'No enrolled students found. Please add students first via the admin panel.'
            }), 500
        
        app.logger.info(f"Face verification: Found {len(student_embeddings)} embeddings")
    except Exception as e:
        app.logger.error(f"Error retrieving student embeddings: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Database error. Please try again.'}), 500
    
    best_distance_overall = float('inf')
    best_match_enroll = None
    best_match_name = None
    face_tolerance = getattr(config, 'FACE_TOLERANCE', 0.6)
    
    for detected_encoding in encodings:
        try:
            distances = face_recognition.face_distance(student_embeddings, detected_encoding)
            min_idx = int(np.argmin(distances))
            min_distance = float(distances[min_idx])
            
            app.logger.debug(f"Face encoding comparison: min_distance={min_distance:.4f}")
            
            if min_distance < best_distance_overall:
                best_distance_overall = min_distance
                best_match_enroll = student_enrolls[min_idx]
                best_match_name = student_names[min_idx]
        
        except Exception as ex:
            app.logger.error(f"Error during face comparison: {str(ex)}", exc_info=not config.IS_PRODUCTION)
            return jsonify({
                'status':  'error',
                'message': 'Face recognition error. Please try again.'
            }), 500
    
    if best_match_enroll is None or best_distance_overall > face_tolerance: 
        app.logger.warning(f"Failed face match: distance={best_distance_overall:.4f}")
        return jsonify({
            'status': 'error',
            'message': 'No matching student found. Please ensure:\n- You are enrolled in the system\n- Your face is clearly visible\n- Good lighting conditions'
        }), 404
    
    match_enroll = best_match_enroll
    match_name = best_match_name
    app.logger.info(f"Face matched: {match_name} ({match_enroll})")
    
    try:
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        today_records = AttendanceModel.get_by_date(today)
        for record in today_records:
            if record.get('enroll_no') == match_enroll:
                return jsonify({
                    'status': 'warning',
                    'message': f'Attendance already marked for {match_name} today',
                    'student_name': match_name
                }), 200
    except Exception as e:
        app.logger.error(f"Error checking attendance: {str(e)}")
    
    try:
        now = datetime.datetime.now()
        date_str = now.strftime('%Y-%m-%d')
        time_str = now.strftime('%H:%M:%S')
        
        AttendanceModel.add(
            enroll_no=match_enroll,
            name=match_name,
            date=date_str,
            time=time_str,
            latitude=latitude,
            longitude=longitude,
            liveness_score=liveness_score
        )
    except Exception as e:
        app.logger.error(f"Error adding attendance:  {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to save attendance'}), 500
    
    return jsonify({
        'status': 'success',
        'message': f'Attendance marked successfully for {match_name}',
        'student_name':  match_name,
        'enroll_no': match_enroll,
        'time': time_str
    })

@main_bp.route('/api/students', methods=['GET'])
@login_required
def get_students():
    """Get all students"""
    try:
        students = StudentModel. get_all()
        return jsonify({'status': 'success', 'students': students})
    except Exception as e:
        app.logger.error(f"Error retrieving students: {str(e)}")
        return jsonify({'status':  'error', 'message':  'Failed to retrieve students'}), 500

@main_bp. route('/api/students/add', methods=['POST'])
@login_required
def add_student():
    """Add new student"""
    try:
        enroll_no = request.form. get('enroll_no', '').strip()
        name = request.form.get('name', '').strip()
        class_name = request.form.get('class', '').strip()
        metadata = request.form.get('metadata', '').strip()
        
        if not enroll_no or not name or not class_name: 
            return jsonify({'status':  'error', 'message':  'Missing required fields'}), 400
        
        photo = request.files.get('photo')
        if not photo: 
            return jsonify({'status': 'error', 'message': 'Photo is required'}), 400
        
        if not allowed_file(photo.filename):
            return jsonify({'status':  'error', 'message':  'Invalid file type'}), 400
        
        uploads_dir = getattr(config, 'UPLOADS_DIR', 'uploads')
        os.makedirs(uploads_dir, exist_ok=True)
        
        file_ext = os.path.splitext(photo. filename)[1] if '.' in photo.filename else '. jpg'
        random_id = uuid.uuid4().hex
        filename = secure_filename(f"{enroll_no}_{random_id}{file_ext}")
        photo_path = os.path.join(uploads_dir, filename)
        photo.save(photo_path)
        
        face_embedding = compute_face_embedding(photo_path)
        if face_embedding is None:
            if os.path.exists(photo_path):
                os.remove(photo_path)
            return jsonify({'status': 'error', 'message': 'Could not detect face in photo'}), 400
        
        success, message = StudentModel.add(
            enroll_no=enroll_no,
            name=name,
            class_name=class_name,
            photo_filename=filename,
            face_embedding=face_embedding,
            metadata=metadata
        )
        
        if success:
            return jsonify({'status': 'success', 'message': message})
        else:
            if os.path.exists(photo_path):
                os.remove(photo_path)
            return jsonify({'status': 'error', 'message': message}), 400
    except Exception as e:
        app. logger.error(f"Error adding student: {str(e)}")
        return jsonify({'status':  'error', 'message':  'Failed to add student'}), 500

@main_bp.route('/api/students/edit/<enroll_no>', methods=['POST'])
@login_required
def edit_student(enroll_no):
    """Edit student"""
    try:
        name = request.form.get('name', '').strip()
        class_name = request.form.get('class', '').strip()
        metadata = request.form.get('metadata', '').strip()
        
        face_embedding = None
        photo_filename = None
        
        photo = request.files.get('photo')
        if photo and allowed_file(photo.filename):
            uploads_dir = getattr(config, 'UPLOADS_DIR', 'uploads')
            os.makedirs(uploads_dir, exist_ok=True)
            
            file_ext = os.path. splitext(photo.filename)[1] if '.' in photo.filename else '.jpg'
            random_id = uuid.uuid4().hex
            filename = secure_filename(f"{enroll_no}_{random_id}{file_ext}")
            photo_path = os. path.join(uploads_dir, filename)
            photo.save(photo_path)
            photo_filename = filename
            face_embedding = compute_face_embedding(photo_path)
            
            if face_embedding is None:
                if os.path. exists(photo_path):
                    os.remove(photo_path)
                return jsonify({'status': 'error', 'message': 'Could not detect face in photo'}), 400
        
        success, message = StudentModel.update(
            enroll_no=enroll_no,
            name=name if name else None,
            class_name=class_name if class_name else None,
            photo_filename=photo_filename,
            face_embedding=face_embedding,
            metadata=metadata if metadata else None
        )
        
        if success:
            return jsonify({'status': 'success', 'message': message})
        else:
            return jsonify({'status': 'error', 'message': message}), 400
    except Exception as e:
        app.logger.error(f"Error editing student: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to edit student'}), 500

@main_bp.route('/api/students/delete/<enroll_no>', methods=['POST'])
@login_required
def delete_student(enroll_no):
    """Delete student"""
    try: 
        success, message = StudentModel.delete(enroll_no)
        if success:
            return jsonify({'status': 'success', 'message': message})
        else:
            return jsonify({'status':  'error', 'message':  message}), 400
    except Exception as e:
        app. logger.error(f"Error deleting student: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to delete student'}), 500

@main_bp.route('/api/students/bulk_upload', methods=['POST'])
@login_required
def bulk_upload_students():
    """Bulk upload students from Excel"""
    excel_file = request.files.get('excel_file')
    if not excel_file:
        return jsonify({'status': 'error', 'message': 'No Excel file provided'}), 400
    
    uploads_dir = getattr(config, 'UPLOADS_DIR', 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)
    
    excel_path = os.path.join(uploads_dir, f"temp_{secrets.token_hex(8)}.xlsx")
    excel_file.save(excel_path)
    
    try:
        df = pd.read_excel(excel_path)
        required_columns = ['enroll_no', 'name', 'class']
        if not all(col in df.columns for col in required_columns):
            return jsonify({'status': 'error', 'message': f'Excel must have columns:  {", ".join(required_columns)}'}), 400
        
        photos_zip = request.files.get('photos_zip')
        photos_dict = {}
        zip_path = None
        if photos_zip:
            zip_path = os.path.join(uploads_dir, f"temp_{secrets.token_hex(8)}.zip")
            photos_zip.save(zip_path)
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref. extractall(uploads_dir)
                    for file in zip_ref.namelist():
                        if file.lower().endswith(('.jpg', '. jpeg', '.png')):
                            enroll_no_from_zip = os.path.splitext(os.path.basename(file))[0]
                            photos_dict[enroll_no_from_zip] = os.path.join(uploads_dir, file)
            except zipfile.BadZipFile:
                return jsonify({'status': 'error', 'message': 'Invalid ZIP file'}), 400
        
        success_count = 0
        error_count = 0
        errors = []
        
        for _, row in df.iterrows():
            enroll_no = str(row['enroll_no']).strip()
            name = str(row['name']).strip()
            class_name = str(row['class']).strip()
            photo_filename = str(row. get('photo_filename', '')).strip()
            metadata = str(row.get('metadata', '')).strip()
            
            photo_path = None
            if enroll_no in photos_dict: 
                photo_path = photos_dict[enroll_no]
            elif photo_filename:
                photo_path = os.path.join(uploads_dir, photo_filename)
                if not os.path.exists(photo_path):
                    photo_path = None
            
            if not photo_path or not os.path.exists(photo_path):
                errors.append(f"{enroll_no}: Photo not found")
                error_count += 1
                continue
            
            face_embedding = compute_face_embedding(photo_path)
            if face_embedding is None:
                errors.append(f"{enroll_no}:  No face detected in photo")
                error_count += 1
                continue
            
            file_ext = os.path.splitext(photo_path)[1] if '.' in photo_path else '.jpg'
            random_id = uuid.uuid4().hex
            final_filename = secure_filename(f"{enroll_no}_{random_id}{file_ext}")
            final_path = os.path.join(uploads_dir, final_filename)
            
            try:
                shutil.copy2(photo_path, final_path)
            except Exception as e:
                errors.append(f"{enroll_no}: Failed to copy photo")
                error_count += 1
                continue
            
            success, message = StudentModel.add(
                enroll_no=enroll_no,
                name=name,
                class_name=class_name,
                photo_filename=final_filename,
                face_embedding=face_embedding,
                metadata=metadata
            )
            
            if success: 
                success_count += 1
            else:
                errors.append(f"{enroll_no}: {message}")
                error_count += 1
        
        if os.path.exists(excel_path):
            os.remove(excel_path)
        if zip_path and os.path.exists(zip_path):
            os.remove(zip_path)
        
        return jsonify({
            'status': 'success',
            'message': f'Processed {success_count} students, {error_count} errors',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors[: 10]
        })
        
    except Exception as e: 
        app.logger.error(f"Error processing bulk upload: {str(e)}", exc_info=True)
        if os.path.exists(excel_path):
            os.remove(excel_path)
        error_msg = 'Error processing file. Please check format.' if config.IS_PRODUCTION else str(e)
        return jsonify({'status': 'error', 'message': error_msg}), 500

@main_bp.route('/api/attendance', methods=['GET'])
@login_required
def get_attendance():
    """Get attendance records with optional filters"""
    try:
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        enroll_no = request.args. get('enroll_no')
        
        filters = {}
        if date_from:
            filters['date_from'] = date_from
        if date_to:
            filters['date_to'] = date_to
        if enroll_no:
            filters['enroll_no'] = enroll_no
        
        records = AttendanceModel.get_all()
        
        if filters: 
            filtered = []
            for record in records: 
                if 'date_from' in filters and record. get('date', '') < filters['date_from']:
                    continue
                if 'date_to' in filters and record. get('date', '') > filters['date_to']:
                    continue
                if 'enroll_no' in filters and record.get('enroll_no', '') != filters['enroll_no']: 
                    continue
                filtered.append(record)
            records = filtered
        
        return jsonify({'status': 'success', 'records': records})
    except Exception as e:
        app.logger.error(f"Error retrieving attendance: {str(e)}")
        return jsonify({'status':  'error', 'message':  'Failed to retrieve attendance'}), 500

@main_bp. route('/api/attendance/today', methods=['GET'])
@login_required
def get_today_attendance():
    """Get today's attendance"""
    try:
        records = AttendanceModel.get_today()
        return jsonify({'status': 'success', 'records': records, 'count': len(records)})
    except Exception as e:
        app.logger.error(f"Error retrieving attendance:  {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to retrieve attendance'}), 500

@main_bp.route('/api/attendance/delete/<int:index>', methods=['POST'])
@login_required
def delete_attendance(index):
    """Delete attendance record by index"""
    try:
        success = AttendanceModel.delete_by_index(index)
        if success:
            return jsonify({'status': 'success', 'message': 'Attendance record deleted'})
        else:
            return jsonify({'status': 'error', 'message': 'Record not found'}), 404
    except Exception as e:
        app.logger.error(f"Error deleting attendance: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to delete'}), 500

@main_bp.route('/api/attendance/export', methods=['GET'])
@login_required
def export_attendance():
    """Export attendance to Excel"""
    try:
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        enroll_no = request.args. get('enroll_no')
        
        filters = {}
        if date_from:
            filters['date_from'] = date_from
        if date_to:
            filters['date_to'] = date_to
        if enroll_no: 
            filters['enroll_no'] = enroll_no
        
        df = AttendanceModel.export_filtered(filters)
        
        output = io.BytesIO()
        df.to_excel(output, index=False, engine='openpyxl')
        output.seek(0)
        
        filename = f"attendance_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        as_attachment=True, download_name=filename)
    except Exception as e:
        app.logger.error(f"Error exporting attendance: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to export'}), 500

@main_bp.route('/api/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    """Get dashboard statistics"""
    try:
        records = AttendanceModel.get_all()
        students = StudentModel.get_all()
        
        student_stats = []
        for student in students: 
            enroll_no = student.get('enroll_no', '')
            student_records = [r for r in records if r. get('enroll_no') == enroll_no]
            total_days = len(set([r.get('date') for r in student_records]))
            student_stats.append({
                'enroll_no': enroll_no,
                'name': student.get('name', ''),
                'total_days': total_days
            })
        
        monthly_stats = {}
        for record in records:
            date_str = record.get('date', '')
            if date_str: 
                try:
                    date_obj = datetime.datetime.strptime(date_str, '%Y-%m-%d')
                    month_key = date_obj.strftime('%Y-%m')
                    monthly_stats[month_key] = monthly_stats.get(month_key, 0) + 1
                except ValueError:
                    pass
        
        return jsonify({
            'status': 'success',
            'student_stats': student_stats,
            'monthly_stats':  monthly_stats
        })
    except Exception as e:
        app.logger.error(f"Error computing stats: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to compute stats'}), 500

@main_bp.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    """Feedback page"""
    if request.method == 'POST':
        try:
            name = request.form.get('name', '').strip()
            message = request.form.get('message', '').strip()
            
            if not name or not message: 
                return jsonify({'status':  'error', 'message':  'Name and message required'}), 400
            
            FeedbackModel.add(name, message)
            return jsonify({'status': 'success', 'message': 'Feedback submitted'})
        except Exception as e:
            app.logger.error(f"Error submitting feedback:  {str(e)}")
            return jsonify({'status': 'error', 'message': 'Failed to submit feedback'}), 500
    
    return render_template('feedback.html')

@main_bp.route('/student/register', methods=['GET', 'POST'])
def student_register():
    """Student self-registration"""
    if request. method == 'POST':
        try:
            enroll_no = request.form. get('enroll_no', '').strip()
            name = request.form.get('name', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            email = request.form.get('email', '').strip().lower()
            class_name = request.form.get('class', '').strip()
            
            if not enroll_no or not name or not password: 
                return jsonify({'status':  'error', 'message':  'Missing required fields'}), 400
            
            if password != confirm_password:
                return jsonify({'status': 'error', 'message': 'Passwords do not match'}), 400
            
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                return jsonify({'status': 'error', 'message': error_msg}), 400
            
            existing_student = StudentModel.get_by_enroll(enroll_no)
            if existing_student:
                if existing_student.get('password_hash'):
                    return jsonify({'status': 'error', 'message': 'Already registered'}), 400
                else:
                    password_hash = hash_password(password)
                    success, message = StudentModel.update(enroll_no, name=name, class_name=class_name or None)
                    if success:
                        with get_db() as conn:
                            cursor = conn.cursor()
                            cursor.execute('UPDATE students SET password_hash = ?, email = ?  WHERE enroll_no = ?',
                                         (password_hash, email if email else None, enroll_no))
                            conn.commit()
                        app.logger.info(f"Student registered:  {enroll_no}")
                        return jsonify({'status': 'success', 'message': 'Registration successful'})
                    return jsonify({'status': 'error', 'message': message}), 400
            
            password_hash = hash_password(password)
            success, message = StudentModel.add(
                enroll_no=enroll_no,
                name=name,
                class_name=class_name,
                photo_filename='',
                face_embedding=None,
                password_hash=password_hash,
                email=email if email else None,
                metadata=''
            )
            
            if success:
                app.logger.info(f"Student registered: {enroll_no}")
                return jsonify({'status':  'success', 'message':  'Registration successful'})
            else:
                return jsonify({'status': 'error', 'message': message}), 400
        except Exception as e:
            app.logger.error(f"Error during registration: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Registration failed'}), 500
    
    return render_template('student_register.html')

@main_bp.route('/student/login', methods=['GET', 'POST'])
def student_login():
    """Student login"""
    if request.method == 'POST':
        try:
            enroll_no = request.form. get('enroll_no', '').strip()
            password = request.form.get('password', '')
            
            if not enroll_no or not password:
                return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
            
            student = StudentModel.get_by_enroll(enroll_no)
            if not student:
                app.logger.warning(f"Login attempt for non-existent:  {enroll_no}")
                return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
            
            password_hash = student.get('password_hash')
            if not password_hash:
                return jsonify({'status': 'error', 'message': 'Account not activated'}), 401
            
            if not verify_password(password, password_hash):
                app.logger.warning(f"Failed login for: {enroll_no}")
                return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401
            
            student_user = StudentUser(enroll_no)
            flask_login_user(student_user, remember=True)
            app.logger.info(f"Student logged in: {enroll_no}")
            return jsonify({'status': 'success', 'message': 'Login successful', 'redirect':  url_for('main.student_dashboard')})
        except Exception as e: 
            app.logger.error(f"Error during login: {str(e)}")
            return jsonify({'status': 'error', 'message': 'Login failed'}), 500
    
    return render_template('student_login.html')

@main_bp.route('/student/logout')
def student_logout():
    """Student logout"""
    if current_user.is_authenticated:
        logout_user()
    return redirect(url_for('main.student_login'))

def student_required(f):
    """Decorator to require student login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
            return redirect(url_for('main.student_login'))
        
        if not hasattr(current_user, 'user_type') or current_user.user_type != 'student':
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'Student access required'}), 403
            return redirect(url_for('main.student_login'))
        
        try:
            enroll_no = current_user.enroll_no
            student = StudentModel.get_by_enroll(enroll_no)
            if not student or not student.get('password_hash'):
                if request.is_json:
                    return jsonify({'status': 'error', 'message': 'Access required'}), 403
                return redirect(url_for('main.student_login'))
        except Exception as e:
            app.logger.error(f"Error in student_required: {str(e)}")
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'Access required'}), 403
            return redirect(url_for('main.student_login'))
        
        return f(*args, **kwargs)
    return decorated_function

@main_bp.route('/student/dashboard')
@student_required
def student_dashboard():
    """Student personal dashboard"""
    try:
        from chatbot_utils import compute_student_statistics
        
        enroll_no = current_user.enroll_no
        stats = compute_student_statistics(enroll_no)
        
        if not stats:
            return jsonify({'status': 'error', 'message': 'Student data not found'}), 404
        
        student = stats['student']
        
        if request.headers.get('Accept', '').startswith('text/html'):
            return render_template('student_dashboard.html')
        
        return jsonify({
            'status': 'success',
            'student': {
                'enroll_no':  student.get('enroll_no'),
                'name': student.get('name'),
                'class':  student.get('class', ''),
                'email': student.get('email')
            },
            'statistics':  {
                'total_days_present': stats['total_days_present'],
                'total_days_absent': stats['total_days_absent'],
                'total_days_in_period': stats['total_days_in_period'],
                'attendance_percentage': stats['attendance_percentage'],
                'first_attendance_date': stats['first_attendance_date'],
                'last_attendance_date': stats['last_attendance_date'],
                'monthly_breakdown': stats['monthly_breakdown']
            }
        })
    except Exception as e:
        app.logger. error(f"Error loading dashboard: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Failed to load'}), 500

@app.route('/auth', methods=['GET'])
def unified_auth_page():
    """Unified authentication page"""
    if current_user.is_authenticated:
        if hasattr(current_user, "user_type") and current_user.user_type == "student": 
            return redirect(url_for("main.student_dashboard"))
        return redirect(url_for("main. dashboard"))
    return render_template("auth_unified.html")

@app.route('/api/auth', methods=['POST'])
@limiter.limit("10 per minute")
def unified_auth_api():
    """Unified authentication endpoint"""
    try:
        role = (request.form.get("role") or "").strip().lower()
        mode = (request.form.get("mode") or "").strip().lower()

        if role not in ("admin", "student") or mode not in ("login", "register"):
            return jsonify({"status": "error", "message": "Invalid role or mode"}), 400

        email = (request.form.get("email") or "").strip().lower()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm_password = request.form.get("confirm_password") or ""
        department_code = (request.form.get("department_code") or "").strip()

        if not email or not username or not password: 
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        valid, msg = validate_password(password)
        if not valid:
            return jsonify({"status": "error", "message": msg}), 400

        if mode == "register":
            if password != confirm_password:
                return jsonify({"status": "error", "message": "Passwords do not match"}), 400

        if role == "student":
            enroll_no = username

            if mode == "register":
                existing = StudentModel.get_by_enroll(enroll_no)
                if existing and existing.get("password_hash"):
                    return jsonify({"status": "error", "message": "Already registered"}), 400

                password_hash = hash_password(password)

                if existing:
                    success, message = StudentModel.update(
                        enroll_no=enroll_no,
                        name=existing.get("name"),
                        class_name=existing.get("class", ""),
                        photo_filename=existing.get("photo_filename", ""),
                        face_embedding=None,
                        metadata=existing.get("metadata", ""),
                    )
                    if not success:
                        return jsonify({"status": "error", "message": message}), 400

                    with get_db() as conn:
                        cursor = conn.cursor()
                        cursor.execute(
                            "UPDATE students SET password_hash = ?, email = ?  WHERE enroll_no = ?",
                            (password_hash, email, str(enroll_no)),
                        )
                        conn.commit()
                    app. logger.info(f"Student registered: {enroll_no}")
                    return jsonify({"status": "success", "message": "Registration successful"})

                password_hash = hash_password(password)
                success, message = StudentModel. add(
                    enroll_no=enroll_no,
                    name=username,
                    class_name="",
                    photo_filename="",
                    face_embedding=None,
                    password_hash=password_hash,
                    email=email if email else None,
                    metadata="",
                )
                if success:
                    app.logger. info(f"Student registered: {enroll_no}")
                    return jsonify({"status": "success", "message": "Registration successful"})
                return jsonify({"status": "error", "message": message}), 400

            # Login
            student = StudentModel.get_by_enroll(enroll_no)
            if not student: 
                app.logger.warning(f"Login for non-existent: {enroll_no}")
                return jsonify({"status": "error", "message": "Invalid credentials"}), 401

            password_hash = student.get("password_hash")
            if not password_hash: 
                return jsonify({"status": "error", "message": "Not activated"}), 401

            if not verify_password(password, password_hash):
                app.logger.warning(f"Failed login:  {enroll_no}")
                return jsonify({"status": "error", "message": "Invalid credentials"}), 401

            student_user = StudentUser(enroll_no)
            flask_login_user(student_user, remember=True)
            app.logger.info(f"Student logged in: {enroll_no}")
            return jsonify(
                {"status": "success", "message": "Login successful", "redirect": url_for("main.student_dashboard")}
            )

        # Admin
        if not department_code: 
            return jsonify({"status": "error", "message": "Department code required"}), 400

        admin_dept_code = getattr(config, 'ADMIN_DEPARTMENT_CODE', None)
        if admin_dept_code and department_code != admin_dept_code:
            return jsonify({"status": "error", "message":  "Invalid department code"}), 401

        if mode == "register":
            blocked_usernames = ["admin", "administrator", "root", "system", "service", "support"]
            if username. lower() in blocked_usernames: 
                return jsonify({"status": "error", "message": "Username not allowed"}), 400

            if UserModel.get_by_email(email):
                return jsonify({"status": "error", "message": "Email already registered"}), 400
            if UserModel.get_by_username(username):
                return jsonify({"status": "error", "message": "Username taken"}), 400

            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
            success, message = UserModel.add(email, username, password_hash)
            if success:
                app.logger.info(f"Admin registered: {username}")
                return jsonify({"status": "success", "message":  "Registration successful"})
            return jsonify({"status": "error", "message": message}), 400

        # Admin login
        user = UserModel.get_by_username(username)
        if user: 
            password_hash = user. get("password_hash", "")
            try:
                if bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
                    user_obj = User(username)
                    flask_login_user(user_obj, remember=True)
                    app.logger. info(f"Admin logged in:  {username}")
                    return jsonify(
                        {"status": "success", "message": "Login successful", "redirect": url_for("main. dashboard")}
                    )
                else:
                    app. logger.warning(f"Failed admin login: {username}")
                    return jsonify({"status": "error", "message": "Invalid credentials"}), 401
            except Exception as e:
                app.logger.error(f"Error checking password: {str(e)}", exc_info=True)
                return jsonify({"status": "error", "message": "Auth error"}), 500

        app.logger.warning(f"Login for non-existent admin: {username}")
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    except Exception as e:
        app. logger.error(f"Error in auth:  {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Auth error"}), 500

@main_bp.route('/admin/chatbot', methods=['GET'])
@admin_required
def chatbot_page():
    """Admin-only chatbot page"""
    return render_template('admin_chatbot.html')

@main_bp.route('/api/admin/chatbot/student-summary', methods=['POST'])
@admin_required
@limiter.limit("20 per hour")
def chatbot_student_summary():
    """Admin chatbot endpoint"""
    try:
        from chatbot_utils import get_student_by_enroll_or_name, compute_student_statistics, generate_gemini_summary
        
        data = request.get_json()
        if not data: 
            return jsonify({'status': 'error', 'message': 'Invalid request'}), 400
        
        query = data.get('query', '').strip()
        if not query:
            return jsonify({'status': 'error', 'message': 'Query required'}), 400
        
        app.logger.info(f"Chatbot query from '{current_user.username}': {query}")
        
        student = get_student_by_enroll_or_name(query)
        if not student:
            return jsonify({'status': 'error', 'message': 'Student not found'}), 404
        
        enroll_no = student.get('enroll_no')
        stats = compute_student_statistics(enroll_no)
        
        if not stats:
            return jsonify({'status': 'error', 'message': 'Failed to compute'}), 500
        
        summary = generate_gemini_summary(stats)
        
        app.logger.info(f"Summary for {enroll_no} generated")
        
        return jsonify({
            'status': 'success',
            'student': {
                'name': stats['student']. get('name'),
                'enroll_no': stats['student']. get('enroll_no'),
                'class': stats['student']. get('class')
            },
            'statistics':  {
                'total_days_present': stats['total_days_present'],
                'total_days_absent': stats['total_days_absent'],
                'total_days_in_period': stats['total_days_in_period'],
                'attendance_percentage': stats['attendance_percentage'],
                'first_attendance_date': stats['first_attendance_date'],
                'last_attendance_date': stats['last_attendance_date'],
                'monthly_breakdown': stats['monthly_breakdown']
            },
            'summary': summary
        })
    except Exception as e:
        app.logger.error(f"Error in chatbot:  {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'Chatbot error'}), 500

# Register blueprint
app.register_blueprint(main_bp)

# Serve uploaded files
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    """Serve uploaded photos"""
    try:
        filename = secure_filename(filename)
        uploads_dir = getattr(config, 'UPLOADS_DIR', 'uploads')
        file_path = os.path.join(uploads_dir, filename)
        
        if not os.path.exists(file_path) or not os.path.abspath(file_path).startswith(os.path.abspath(uploads_dir)):
            app.logger.warning(f"Unauthorized access attempt:  {filename}")
            return jsonify({'status': 'error', 'message': 'Not found'}), 404
        
        return send_file(file_path)
    except Exception as e: 
        app.logger.error(f"Error serving file:  {str(e)}")
        return jsonify({'status':  'error', 'message':  'Not found'}), 404

# Routes
@app.route('/')
def index():
    """Root endpoint"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('unified_auth_page'))

@app.route('/home')
@login_required
def home():
    """Home endpoint"""
    return redirect(url_for('main.dashboard'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404"""
    if request.is_json:
        return jsonify({'status': 'error', 'message': 'Not found'}), 404
    flash('Page not found. ', 'error')
    return redirect(url_for('main.dashboard')), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500"""
    app.logger.error(f"Internal error: {str(error)}", exc_info=True)
    if request.is_json:
        msg = 'Error occurred' if config.IS_PRODUCTION else str(error)
        return jsonify({'status': 'error', 'message': msg}), 500
    flash('An error occurred. ', 'error')
    return redirect(url_for('main. dashboard')), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all exceptions"""
    app.logger. error(f"Exception:  {str(error)}", exc_info=True)
    if request.is_json:
        msg = 'Error occurred' if config.IS_PRODUCTION else str(error)
        return jsonify({'status': 'error', 'message': msg}), 500
    flash('An error occurred.', 'error')
    return redirect(url_for('main.dashboard')), 500

if __name__ == "__main__":
    import sys
    
    if config.IS_PRODUCTION:
        print("=" * 60)
        print("⚠️  PRODUCTION MODE")
        print("=" * 60)
        print("For production, use WSGI server:")
        print("  Windows: waitress-serve --host=0.0.0.0 --port=5000 wsgi: app")
        print("  Linux:    gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app")
        print("=" * 60)
        response = input("Continue with dev server? [y/N]: ")
        if response.lower() != 'y':
            print("Exiting.")
            sys.exit(0)
    
    print("=" * 60)
    print("MarkSmart - Starting Server")
    print("=" * 60)
    print(f"\nEnvironment: {config.ENV}")
    print(f"Debug: {not config.IS_PRODUCTION}")
    print(f"\nServer: http://{config.HOST}:{config.PORT}")
    print("\nPress Ctrl+C to stop")
    print("=" * 60)
    print()
    
    app.run(
        debug=not config.IS_PRODUCTION,
        host=config.HOST,
        port=config.PORT,
        use_reloader=not config.IS_PRODUCTION
    )
