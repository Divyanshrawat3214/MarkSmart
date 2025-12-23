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
from flask import Flask, Blueprint, render_template, request, send_file, jsonify, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from PIL import Image
import zipfile
import config
from models import StudentModel, AttendanceModel, FeedbackModel, compute_face_embedding, UserModel
from auth import init_auth, login_required
from functools import wraps
from flask_login import current_user, LoginManager, UserMixin, login_user as flask_login_user, logout_user
from student_auth import validate_password, hash_password, verify_password
from database import get_db
import re
import bcrypt
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH
app.config['SESSION_COOKIE_HTTPONLY'] = config.SESSION_COOKIE_HTTPONLY
app.config['SESSION_COOKIE_SECURE'] = config.SESSION_COOKIE_SECURE
app.config['SESSION_COOKIE_SAMESITE'] = config.SESSION_COOKIE_SAMESITE
app.config['PERMANENT_SESSION_LIFETIME'] = config.PERMANENT_SESSION_LIFETIME
app.config['PREFERRED_URL_SCHEME'] = config.PREFERRED_URL_SCHEME

# Production security: Disable debug mode
if config.IS_PRODUCTION:
    app.config['DEBUG'] = False
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
from database import init_database
init_database()

# Student User class for Flask-Login
class StudentUser(UserMixin):
    def __init__(self, enroll_no):
        self.id = f"student:{enroll_no}"
        self.enroll_no = enroll_no
        self.user_type = "student"
        # Provide a username attribute so code that expects current_user.username works
        self.username = str(enroll_no)

# Initialize authentication (admin) - this sets up the main login_manager
init_auth(app)

# Override user_loader to handle both students and admins
from auth import login_manager, User
@login_manager.user_loader
def load_user(user_id):
    if not user_id:
        return None

    # Student users are stored with id "student:<enroll_no>"
    if user_id.startswith("student:"):
        enroll_no = user_id.split(":", 1)[1]
        try:
            student = StudentModel.get_by_enroll(enroll_no)
            if student and student.get('password_hash'):
                return StudentUser(enroll_no)
        except Exception:
            # Fail silently: return None if lookup fails
            return None
    else:
        # Admin user
        try:
            user = UserModel.get_by_username(user_id)
            if user:
                return User(user_id)
        except Exception:
            return None
    return None

# Add security headers middleware
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    if config.IS_PRODUCTION:
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Enable XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Strict Transport Security (HSTS) - only if HTTPS
        if config.SESSION_COOKIE_SECURE:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdn.datatables.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.datatables.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        # Referrer Policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Permissions Policy
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
        # Allow plain HTTP for local access (no reverse proxy / TLS)
        host = request.host.split(':', 1)[0]
        if host in ('localhost', '127.0.0.1'):
            return None

        # Check if request came through a proxy (X-Forwarded-Proto header)
        if request.headers.get('X-Forwarded-Proto') == 'https':
            return None  # Already HTTPS via proxy

        # Redirect to HTTPS only for real external hosts
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

        # Use getattr to avoid AttributeError when current_user doesn't have username
        username = getattr(current_user, 'username', '') or ''
        username_lower = username.lower() if isinstance(username, str) else ''

        # Enforce ADMIN_USERNAMES only if configured (non-empty)
        if config.ADMIN_USERNAMES:
            try:
                allowed = [u.lower() for u in config.ADMIN_USERNAMES]
            except Exception:
                allowed = []
            if username_lower not in allowed:
                app.logger.warning(f"Non-admin user '{username}' attempted to access admin-only endpoint")
                return jsonify({'status': 'error', 'message': 'Admin access required'}), 403

        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

def generate_qr_token():
    """Generate JWT token for QR code with enhanced security"""
    now = datetime.datetime.now()
    payload = {
        'date': now.strftime('%Y-%m-%d'),
        'nonce': secrets.token_hex(16),
        'iss': 'marksmart',  # Issuer
        'aud': 'attendance',  # Audience
        'exp': int((now + datetime.timedelta(minutes=config.JWT_EXPIRY_MINUTES)).timestamp())
    }
    token = jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')
    return token

def verify_qr_token(token):
    """Verify JWT token from QR code with enhanced security"""
    try:
        payload = jwt.decode(
            token,
            config.JWT_SECRET_KEY,
            algorithms=['HS256'],
            audience='attendance',
            issuer='marksmart'
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
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
        # CSRF token is automatically validated by Flask-WTF
        token = generate_qr_token()
        qr_data = f"{request.url_root}scan?token={token}"

        # Generate QR code image
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")

        # Save QR code
        today = datetime.date.today().strftime('%Y-%m-%d')
        qr_filename = f"{today}_{secrets.token_hex(8)}.png"
        qr_path = os.path.join(config.QR_DIR, qr_filename)
        img.save(qr_path)

        # Do not expose raw token unless explicitly required
        return jsonify({
            'status': 'success',
            'qr_url': f'/static/qr_codes/{qr_filename}',
            'expires_in': config.JWT_EXPIRY_MINUTES * 60
        })

    return render_template('qr_generate.html')

@app.route('/scan')
def scan():
    """Scan page - verify token and show camera (public route)"""
    token = request.args.get('token')
    if not token:
        return render_template('scan.html', error='No token provided. Please scan the QR code.', token=None)

    payload = verify_qr_token(token)
    if not payload:
        return render_template('scan.html', error='Invalid or expired token. Please scan a fresh QR code.', token=None)

    return render_template('scan.html', token=token, date=payload.get('date'))

@app.route('/api/attendance/verify', methods=['POST'])
@csrf.exempt  # Exempt from CSRF since it's a public API using JWT tokens
@limiter.limit("5 per minute")  # Rate limit: 5 requests per minute per IP
def verify_attendance():
    """Verify attendance with face recognition and liveness"""
    # Harden CSRF-exempt endpoint with Origin validation
    if config.IS_PRODUCTION:
        origin = request.headers.get('Origin') or request.headers.get('Referer', '')
        # Allow requests from same origin or trusted origins
        if origin and not origin.startswith(request.url_root.rstrip('/')):
            app.logger.warning(f"Invalid origin attempt from {get_remote_address()}: {origin}")
            return jsonify({'status': 'error', 'message': 'Invalid origin'}), 403

    token = request.form.get('token')
    if not token:
        app.logger.warning(f"Attendance verification attempt without token from IP {get_remote_address()}")
        return jsonify({'status': 'error', 'message': 'No token provided'}), 400

    # Verify token
    payload = verify_qr_token(token)
    if not payload:
        return jsonify({'status': 'error', 'message': 'Invalid or expired token'}), 400

    # Get liveness result
    liveness_passed = request.form.get('liveness_passed', 'false').lower() == 'true'
    liveness_score = request.form.get('liveness_score', '0')

    if not liveness_passed:
        return jsonify({'status': 'error', 'message': 'Liveness check failed'}), 400

    # Get location - REQUIRED for attendance
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')

    if not latitude or not longitude:
        app.logger.warning(f"Attendance verification attempt without location from IP {get_remote_address()}")
        return jsonify({'status': 'error', 'message': 'Location is required to mark attendance'}), 400

    # Validate latitude and longitude
    try:
        latitude_float = float(latitude)
        longitude_float = float(longitude)

        if not (-90 <= latitude_float <= 90):
            app.logger.warning(f"Invalid latitude value: {latitude} from IP {get_remote_address()}")
            return jsonify({'status': 'error', 'message': 'Invalid latitude value'}), 400

        if not (-180 <= longitude_float <= 180):
            app.logger.warning(f"Invalid longitude value: {longitude} from IP {get_remote_address()}")
            return jsonify({'status': 'error', 'message': 'Invalid longitude value'}), 400

        latitude = str(latitude_float)
        longitude = str(longitude_float)
    except (ValueError, TypeError):
        app.logger.warning(f"Non-numeric location values: lat={latitude}, lng={longitude} from IP {get_remote_address()}")
        return jsonify({'status': 'error', 'message': 'Invalid location format'}), 400

    # Get photo
    file = request.files.get('photo')
    if not file:
        return jsonify({'status': 'error', 'message': 'No photo uploaded'}), 400

    # Read image
    img_bytes = file.read()
    if not img_bytes:
        return jsonify({'status': 'error', 'message': 'Empty file uploaded'}), 400

    # Check image size (too small might be a photo, not live capture)
    if len(img_bytes) < 10000:  # Less than 10KB is suspicious
        return jsonify({
            'status': 'error',
            'message': 'Image quality too low. Please ensure you are using a live camera (not a photo).'
        }), 400

    npimg = np.frombuffer(img_bytes, dtype=np.uint8)
    img = cv2.imdecode(npimg, cv2.IMREAD_COLOR)
    if img is None:
        return jsonify({'status': 'error', 'message': 'Could not decode image'}), 400

    # Check image dimensions (live camera should have reasonable resolution)
    height, width = img.shape[:2]
    if width < 200 or height < 200:
        return jsonify({
            'status': 'error',
            'message': 'Image resolution too low. Please use a live camera with good quality.'
        }), 400

    rgb = img[:, :, ::-1]

    # Detect faces and compute encoding
    faces = face_recognition.face_locations(rgb)
    app.logger.info(f"Face detection: Found {len(faces)} face(s) in image from IP {get_remote_address()}")

    # Reject multiple faces explicitly for security
    if len(faces) > 1:
        app.logger.warning(f"Multiple faces detected ({len(faces)}) from IP {get_remote_address()} - rejecting")
        return jsonify({
            'status': 'error',
            'message': 'Multiple faces detected. Please ensure only one person is in the frame.'
        }), 400

    encodings = face_recognition.face_encodings(rgb, faces)
    app.logger.info(f"Face encoding: Generated {len(encodings)} encoding(s)")

    if len(encodings) == 0:
        app.logger.warning(f"No face detected in image from IP {get_remote_address()}")
        return jsonify({
            'status': 'error',
            'message': 'No face found in image. Please ensure your face is clearly visible and try again.'
        }), 400

    # Get all student embeddings
    # Note: Currently returns one embedding per student, but logic supports multiple embeddings per student
    student_embeddings, student_names, student_enrolls = StudentModel.get_all_embeddings()

    if len(student_embeddings) == 0:
        app.logger.error("No enrolled students found in database")
        return jsonify({
            'status': 'error',
            'message': 'No enrolled students found. Please add students first via the admin panel.'
        }), 500

    app.logger.info(f"Face verification: Found {len(student_embeddings)} student embeddings from {len(set(student_enrolls))} unique students")

    # Face matching logic:
    # 1. Evaluate ALL detected face encodings (even though we reject multiple faces, we check the one we have)
    # 2. Compare against ALL student embeddings (supports multiple embeddings per student)
    # 3. Track global minimum distance across all comparisons
    # 4. Accept match ONLY if best_distance_overall <= FACE_TOLERANCE

    best_distance_overall = float('inf')
    best_match_enroll = None
    best_match_name = None

    # Compare each detected encoding against ALL student embeddings
    for detected_encoding in encodings:
        try:
            # face_distance returns array of distances: one distance per student embedding
            # This supports multiple embeddings per student (each embedding gets its own distance)
            distances = face_recognition.face_distance(student_embeddings, detected_encoding)

            # Find the minimum distance for this detected encoding across all student embeddings
            min_idx = int(np.argmin(distances))
            min_distance = float(distances[min_idx])

            app.logger.debug(f"Face encoding comparison: min_distance={min_distance:.4f} for student {student_enrolls[min_idx]}")

            # Track global minimum across ALL detected encodings and ALL student embeddings
            if min_distance < best_distance_overall:
                best_distance_overall = min_distance
                best_match_enroll = student_enrolls[min_idx]
                best_match_name = student_names[min_idx]

        except Exception as ex:
            app.logger.error(f"Error during face comparison: {str(ex)}", exc_info=not config.IS_PRODUCTION)
            # Encoding failure: reject
            return jsonify({
                'status': 'error',
                'message': 'Face recognition error. Please try again.'
            }), 500

    # Accept match ONLY if best_distance_overall <= FACE_TOLERANCE
    if best_match_enroll is None or best_distance_overall > config.FACE_TOLERANCE:
        app.logger.warning(f"Failed face match: best_distance={best_distance_overall:.4f}, threshold={config.FACE_TOLERANCE}, IP={get_remote_address()}")
        return jsonify({
            'status': 'error',
            'message': 'No matching student found. Please ensure:\n- You are enrolled in the system\n- Your face is clearly visible\n- Good lighting conditions'
        }), 404

    # Match found and verified
    match_enroll = best_match_enroll
    match_name = best_match_name
    app.logger.info(f"Face matched successfully: {match_name} ({match_enroll}) with distance {best_distance_overall:.4f}")

    # Check if already marked present today
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    today_records = AttendanceModel.get_by_date(today)
    for record in today_records:
        if record.get('enroll_no') == match_enroll:
            return jsonify({
                'status': 'warning',
                'message': f'Attendance already marked for {match_name} today',
                'student_name': match_name
            }), 200

    # Add attendance
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

    return jsonify({
        'status': 'success',
        'message': f'Attendance marked successfully for {match_name}',
        'student_name': match_name,
        'enroll_no': match_enroll,
        'time': time_str
    })

@main_bp.route('/api/students', methods=['GET'])
@login_required
def get_students():
    """Get all students"""
    students = StudentModel.get_all()
    return jsonify({'status': 'success', 'students': students})

@main_bp.route('/api/students/add', methods=['POST'])
@login_required
def add_student():
    """Add new student"""
    enroll_no = request.form.get('enroll_no', '').strip()
    name = request.form.get('name', '').strip()
    class_name = request.form.get('class', '').strip()
    metadata = request.form.get('metadata', '').strip()

    if not enroll_no or not name or not class_name:
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

    # Handle photo upload
    photo = request.files.get('photo')
    if not photo:
        return jsonify({'status': 'error', 'message': 'Photo is required'}), 400

    if not allowed_file(photo.filename):
        return jsonify({'status': 'error', 'message': 'Invalid file type'}), 400

    # Save photo with random UUID for security (non-guessable filename)
    file_ext = os.path.splitext(photo.filename)[1] if '.' in photo.filename else '.jpg'
    random_id = uuid.uuid4().hex
    filename = secure_filename(f"{enroll_no}_{random_id}{file_ext}")
    photo_path = os.path.join(config.UPLOADS_DIR, filename)
    photo.save(photo_path)

    # Compute face embedding
    face_embedding = compute_face_embedding(photo_path)
    if face_embedding is None:
        return jsonify({'status': 'error', 'message': 'Could not detect face in photo'}), 400

    # Add student
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
        return jsonify({'status': 'error', 'message': message}), 400

@main_bp.route('/api/students/edit/<enroll_no>', methods=['POST'])
@login_required
def edit_student(enroll_no):
    """Edit student"""
    name = request.form.get('name', '').strip()
    class_name = request.form.get('class', '').strip()
    metadata = request.form.get('metadata', '').strip()

    face_embedding = None
    photo_filename = None

    # Handle photo update if provided
    photo = request.files.get('photo')
    if photo and allowed_file(photo.filename):
        # Save photo with random UUID for security (non-guessable filename)
        file_ext = os.path.splitext(photo.filename)[1] if '.' in photo.filename else '.jpg'
        random_id = uuid.uuid4().hex
        filename = secure_filename(f"{enroll_no}_{random_id}{file_ext}")
        photo_path = os.path.join(config.UPLOADS_DIR, filename)
        photo.save(photo_path)
        photo_filename = filename
        face_embedding = compute_face_embedding(photo_path)

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

@main_bp.route('/api/students/delete/<enroll_no>', methods=['POST'])
@login_required
def delete_student(enroll_no):
    """Delete student"""
    success, message = StudentModel.delete(enroll_no)
    if success:
        return jsonify({'status': 'success', 'message': message})
    else:
        return jsonify({'status': 'error', 'message': message}), 400

@main_bp.route('/api/students/bulk_upload', methods=['POST'])
@login_required
def bulk_upload_students():
    """Bulk upload students from Excel"""
    excel_file = request.files.get('excel_file')
    if not excel_file:
        return jsonify({'status': 'error', 'message': 'No Excel file provided'}), 400

    # Save Excel file temporarily
    import pandas as pd
    excel_path = os.path.join(config.UPLOADS_DIR, f"temp_{secrets.token_hex(8)}.xlsx")
    excel_file.save(excel_path)

    try:
        df = pd.read_excel(excel_path)
        required_columns = ['enroll_no', 'name', 'class']
        if not all(col in df.columns for col in required_columns):
            return jsonify({'status': 'error', 'message': f'Excel must have columns: {", ".join(required_columns)}'}), 400

        # Handle photos ZIP if provided
        photos_zip = request.files.get('photos_zip')
        photos_dict = {}
        if photos_zip:
            zip_path = os.path.join(config.UPLOADS_DIR, f"temp_{secrets.token_hex(8)}.zip")
            photos_zip.save(zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(config.UPLOADS_DIR)
                for file in zip_ref.namelist():
                    if file.lower().endswith(('.jpg', '.jpeg', '.png')):
                        enroll_no = os.path.splitext(os.path.basename(file))[0]
                        photos_dict[enroll_no] = os.path.join(config.UPLOADS_DIR, file)
            os.remove(zip_path)

        # Process each row
        success_count = 0
        error_count = 0
        errors = []

        for _, row in df.iterrows():
            enroll_no = str(row['enroll_no']).strip()
            name = str(row['name']).strip()
            class_name = str(row['class']).strip()
            photo_filename = str(row.get('photo_filename', '')).strip()
            metadata = str(row.get('metadata', '')).strip()

            # Find photo
            photo_path = None
            if enroll_no in photos_dict:
                photo_path = photos_dict[enroll_no]
            elif photo_filename:
                photo_path = os.path.join(config.UPLOADS_DIR, photo_filename)
                if not os.path.exists(photo_path):
                    photo_path = None

            if not photo_path or not os.path.exists(photo_path):
                errors.append(f"{enroll_no}: Photo not found")
                error_count += 1
                continue

            # Compute face embedding
            face_embedding = compute_face_embedding(photo_path)
            if face_embedding is None:
                errors.append(f"{enroll_no}: No face detected in photo")
                error_count += 1
                continue

            # Save photo with random UUID for security (non-guessable filename)
            file_ext = os.path.splitext(photo_path)[1] if '.' in photo_path else '.jpg'
            random_id = uuid.uuid4().hex
            final_filename = secure_filename(f"{enroll_no}_{random_id}{file_ext}")
            final_path = os.path.join(config.UPLOADS_DIR, final_filename)
            import shutil
            shutil.copy2(photo_path, final_path)

            # Add student
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

        os.remove(excel_path)

        return jsonify({
            'status': 'success',
            'message': f'Processed {success_count} students successfully, {error_count} errors',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors[:10]  # Limit errors shown
        })

    except Exception as e:
        app.logger.error(f"Error processing bulk upload: {str(e)}", exc_info=True)
        error_msg = 'Error processing file. Please check the file format and try again.' if config.IS_PRODUCTION else str(e)
        # Attempt to clean up temp file if it exists
        try:
            if os.path.exists(excel_path):
                os.remove(excel_path)
        except Exception:
            pass
        return jsonify({'status': 'error', 'message': error_msg}), 500

@main_bp.route('/api/attendance', methods=['GET'])
@login_required
def get_attendance():
    """Get attendance records with optional filters"""
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    enroll_no = request.args.get('enroll_no')

    filters = {}
    if date_from:
        filters['date_from'] = date_from
    if date_to:
        filters['date_to'] = date_to
    if enroll_no:
        filters['enroll_no'] = enroll_no

    records = AttendanceModel.get_all()

    # Apply filters
    if filters:
        filtered = []
        for record in records:
            if 'date_from' in filters and record.get('date', '') < filters['date_from']:
                continue
            if 'date_to' in filters and record.get('date', '') > filters['date_to']:
                continue
            if 'enroll_no' in filters and record.get('enroll_no', '') != filters['enroll_no']:
                continue
            filtered.append(record)
        records = filtered

    return jsonify({'status': 'success', 'records': records})

@main_bp.route('/api/attendance/today', methods=['GET'])
@login_required
def get_today_attendance():
    """Get today's attendance"""
    records = AttendanceModel.get_today()
    return jsonify({'status': 'success', 'records': records, 'count': len(records)})

@main_bp.route('/api/attendance/delete/<int:index>', methods=['POST'])
@login_required
def delete_attendance(index):
    """Delete attendance record by index"""
    success = AttendanceModel.delete_by_index(index)
    if success:
        return jsonify({'status': 'success', 'message': 'Attendance record deleted'})
    else:
        return jsonify({'status': 'error', 'message': 'Record not found'}), 404

@main_bp.route('/api/attendance/export', methods=['GET'])
@login_required
def export_attendance():
    """Export attendance to Excel"""
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    enroll_no = request.args.get('enroll_no')

    filters = {}
    if date_from:
        filters['date_from'] = date_from
    if date_to:
        filters['date_to'] = date_to
    if enroll_no:
        filters['enroll_no'] = enroll_no

    df = AttendanceModel.export_filtered(filters)

    # Create Excel in memory
    output = io.BytesIO()
    df.to_excel(output, index=False, engine='openpyxl')
    output.seek(0)

    filename = f"attendance_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                    as_attachment=True, download_name=filename)

@main_bp.route('/api/dashboard/stats', methods=['GET'])
@login_required
def dashboard_stats():
    """Get dashboard statistics for charts"""
    import pandas as pd
    from datetime import datetime, timedelta

    records = AttendanceModel.get_all()
    students = StudentModel.get_all()

    # Calculate attendance percentage per student
    student_stats = []
    for student in students:
        enroll_no = student.get('enroll_no', '')
        student_records = [r for r in records if r.get('enroll_no') == enroll_no]
        total_days = len(set([r.get('date') for r in student_records]))
        student_stats.append({
            'enroll_no': enroll_no,
            'name': student.get('name', ''),
            'total_days': total_days
        })

    # Monthly summary (last 6 months)
    monthly_stats = {}
    for record in records:
        date_str = record.get('date', '')
        if date_str:
            try:
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                month_key = date_obj.strftime('%Y-%m')
                monthly_stats[month_key] = monthly_stats.get(month_key, 0) + 1
            except:
                pass

    return jsonify({
        'status': 'success',
        'student_stats': student_stats,
        'monthly_stats': monthly_stats
    })

@main_bp.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    """Feedback page"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        message = request.form.get('message', '').strip()

        if not name or not message:
            return jsonify({'status': 'error', 'message': 'Name and message are required'}), 400

        FeedbackModel.add(name, message)
        return jsonify({'status': 'success', 'message': 'Feedback submitted successfully'})

    return render_template('feedback.html')

@main_bp.route('/student/register', methods=['GET', 'POST'])
def student_register():
    """Student self-registration"""
    if request.method == 'POST':
        enroll_no = request.form.get('enroll_no', '').strip()
        name = request.form.get('name', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        email = request.form.get('email', '').strip().lower()
        class_name = request.form.get('class', '').strip()

        if not enroll_no or not name or not password:
            return jsonify({'status': 'error', 'message': 'Enrollment number, name, and password are required'}), 400

        if password != confirm_password:
            return jsonify({'status': 'error', 'message': 'Passwords do not match'}), 400

        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return jsonify({'status': 'error', 'message': error_msg}), 400

        existing_student = StudentModel.get_by_enroll(enroll_no)
        if existing_student:
            if existing_student.get('password_hash'):
                return jsonify({'status': 'error', 'message': 'This enrollment number is already registered'}), 400
            else:
                password_hash = hash_password(password)
                success, message = StudentModel.update(enroll_no, name=name, class_name=class_name or None)
                if success:
                    with get_db() as conn:
                        cursor = conn.cursor()
                        cursor.execute('UPDATE students SET password_hash = ?, email = ? WHERE enroll_no = ?',
                                     (password_hash, email if email else None, enroll_no))
                        conn.commit()
                    app.logger.info(f"Student registered (existing record updated): {enroll_no}")
                    return jsonify({'status': 'success', 'message': 'Registration successful. Please login.'})
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
            return jsonify({'status': 'success', 'message': 'Registration successful. Please login.'})
        else:
            return jsonify({'status': 'error', 'message': message}), 400

    return render_template('student_register.html')

@main_bp.route('/student/login', methods=['GET', 'POST'])
def student_login():
    """Student login"""
    if request.method == 'POST':
        enroll_no = request.form.get('enroll_no', '').strip()
        password = request.form.get('password', '')

        if not enroll_no or not password:
            return jsonify({'status': 'error', 'message': 'Enrollment number and password are required'}), 400

        student = StudentModel.get_by_enroll(enroll_no)
        if not student:
            app.logger.warning(f"Student login attempt for non-existent enrollment: {enroll_no}")
            return jsonify({'status': 'error', 'message': 'Invalid enrollment number or password'}), 401

        password_hash = student.get('password_hash')
        if not password_hash:
            return jsonify({'status': 'error', 'message': 'Account not activated. Please register first.'}), 401

        if not verify_password(password, password_hash):
            app.logger.warning(f"Failed student login attempt for: {enroll_no}")
            return jsonify({'status': 'error', 'message': 'Invalid enrollment number or password'}), 401

        student_user = StudentUser(enroll_no)
        flask_login_user(student_user, remember=True)
        app.logger.info(f"Student logged in: {enroll_no}")
        return jsonify({'status': 'success', 'message': 'Login successful', 'redirect': url_for('main.student_dashboard')})

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
                    return jsonify({'status': 'error', 'message': 'Student access required'}), 403
                return redirect(url_for('main.student_login'))
        except Exception:
            if request.is_json:
                return jsonify({'status': 'error', 'message': 'Student access required'}), 403
            return redirect(url_for('main.student_login'))

        return f(*args, **kwargs)
    return decorated_function

@main_bp.route('/student/dashboard')
@student_required
def student_dashboard():
    """Student personal dashboard"""
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
            'enroll_no': student.get('enroll_no'),
            'name': student.get('name'),
            'class': student.get('class', ''),
            'email': student.get('email')
        },
        'statistics': {
            'total_days_present': stats['total_days_present'],
            'total_days_absent': stats['total_days_absent'],
            'total_days_in_period': stats['total_days_in_period'],
            'attendance_percentage': stats['attendance_percentage'],
            'first_attendance_date': stats['first_attendance_date'],
            'last_attendance_date': stats['last_attendance_date'],
            'monthly_breakdown': stats['monthly_breakdown']
        }
    })


@app.route('/auth', methods=['GET'])
def unified_auth_page():
    """Single-page unified authentication (admin + student, login + register)."""
    if current_user.is_authenticated:
        # Redirect authenticated users to appropriate dashboard
        if hasattr(current_user, "user_type") and current_user.user_type == "student":
            return redirect(url_for("main.student_dashboard"))
        return redirect(url_for("main.dashboard"))
    return render_template("auth_unified.html")


@app.route('/api/auth', methods=['POST'])
@limiter.limit("10 per minute")
def unified_auth_api():
    """
    Unified authentication endpoint for admin & student login/register.
    Expects form-urlencoded data with:
    - role: 'admin' or 'student'
    - mode: 'login' or 'register'
    """
    role = (request.form.get("role") or "").strip().lower()
    mode = (request.form.get("mode") or "").strip().lower()

    if role not in ("admin", "student") or mode not in ("login", "register"):
        return jsonify({"status": "error", "message": "Invalid role or mode"}), 400

    email = (request.form.get("email") or "").strip().lower()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirm_password = request.form.get("confirm_password") or ""
    department_code = (request.form.get("department_code") or "").strip()

    # Common validations
    # Require username & password for both login and register
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    # Email is required for registration only
    if mode == "register" and not email:
        return jsonify({"status": "error", "message": "Email is required for registration"}), 400

    # Password rules only enforced during registration
    if mode == "register":
        valid, msg = validate_password(password)
        if not valid:
            return jsonify({"status": "error", "message": msg}), 400

    # Registration-only validations
    if mode == "register":
        if password != confirm_password:
            return jsonify({"status": "error", "message": "Passwords do not match"}), 400

    if role == "student":
        # Username is enrollment number
        enroll_no = username

        if mode == "register":
            # Prevent duplicate enrollment
            existing = StudentModel.get_by_enroll(enroll_no)
            if existing and existing.get("password_hash"):
                return jsonify({"status": "error", "message": "Student already registered"}), 400

            password_hash = hash_password(password)

            if existing:
                # Update existing student record (created by admin) with credentials
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

                # Manually set credentials
                with get_db() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE students SET password_hash = ?, email = ? WHERE enroll_no = ?",
                        (password_hash, email if email else None, str(enroll_no)),
                    )
                    conn.commit()
                app.logger.info(f"Student registered (existing record updated): {enroll_no}")
                return jsonify({"status": "success", "message": "Registration successful. Please login."})

            # Fresh student registration
            password_hash = hash_password(password)
            success, message = StudentModel.add(
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
                app.logger.info(f"Student registered via unified auth: {enroll_no}")
                return jsonify({"status": "success", "message": "Registration successful. Please login."})
            return jsonify({"status": "error", "message": message}), 400

        # mode == "login"
        student = StudentModel.get_by_enroll(enroll_no)
        if not student:
            app.logger.warning(f"Unified student login for non-existent enrollment: {enroll_no}")
            return jsonify({"status": "error", "message": "Invalid enrollment number or password"}), 401

        password_hash = student.get("password_hash")
        if not password_hash:
            return jsonify({"status": "error", "message": "Account not activated. Please register first."}), 401

        if not verify_password(password, password_hash):
            app.logger.warning(f"Unified student login failed for: {enroll_no}")
            return jsonify({"status": "error", "message": "Invalid enrollment number or password"}), 401

        student_user = StudentUser(enroll_no)
        flask_login_user(student_user, remember=True)
        app.logger.info(f"Unified student logged in: {enroll_no}")
        return jsonify(
            {"status": "success", "message": "Login successful", "redirect": url_for("main.student_dashboard")}
        )

    # role == "admin"
    # Department code is mandatory for admin flows
    if not department_code:
        return jsonify({"status": "error", "message": "Department code is required for admin"}), 400

    # If ADMIN_DEPARTMENT_CODE is configured, enforce it
    if config.ADMIN_DEPARTMENT_CODE:
        if department_code != config.ADMIN_DEPARTMENT_CODE:
            return jsonify({"status": "error", "message": "Invalid department code"}), 401

    from models import UserModel

    if mode == "register":
        # Prevent reserved usernames
        blocked_usernames = ["admin", "administrator", "root", "system", "service", "support"]
        if username.lower() in blocked_usernames:
            return jsonify({"status": "error", "message": "This username is not allowed. Please choose another."}), 400

        # Check duplicates
        if UserModel.get_by_email(email):
            return jsonify(
                {
                    "status": "error",
                    "message": "This email is already registered. Please use 'Forgot Password' if needed.",
                }
            ), 400
        if UserModel.get_by_username(username):
            return jsonify({"status": "error", "message": "Username already taken. Please choose another."}), 400

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        success, message = UserModel.add(email, username, password_hash)
        if success:
            app.logger.info(f"Admin registered via unified auth: {username}")
            return jsonify({"status": "success", "message": "Registration successful. Please login."})
        return jsonify({"status": "error", "message": message}), 400

    # mode == "login" for admin
    user = UserModel.get_by_username(username)
    if user:
        password_hash = user.get("password_hash", "")
        try:
            if bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
                user_obj = User(username)
                flask_login_user(user_obj, remember=True)
                app.logger.info(f"Unified admin login success: {username}")
                return jsonify(
                    {"status": "success", "message": "Login successful", "redirect": url_for("main.dashboard")}
                )
            else:
                app.logger.warning(f"Unified admin login failed for username: {username}")
                return jsonify({"status": "error", "message": "Invalid username, password, or department code"}), 401
        except Exception as e:
            app.logger.error(f"Error checking admin password: {str(e)}", exc_info=True)
            return jsonify({"status": "error", "message": "Authentication error. Please try again."}), 500

    app.logger.warning(f"Unified admin login for non-existent username: {username}")
    return jsonify({"status": "error", "message": "Invalid username, password, or department code"}), 401

@main_bp.route('/admin/chatbot', methods=['GET'])
@admin_required
def chatbot_page():
    """Admin-only chatbot page"""
    return render_template('admin_chatbot.html')

@main_bp.route('/api/admin/chatbot/student-summary', methods=['POST'])
@admin_required
@limiter.limit("20 per hour")
def chatbot_student_summary():
    """Admin-only chatbot endpoint for student statistical summary"""
    from chatbot_utils import get_student_by_enroll_or_name, compute_student_statistics, generate_gemini_summary

    data = request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'Invalid request'}), 400

    query = data.get('query', '').strip()
    if not query:
        return jsonify({'status': 'error', 'message': 'Student enrollment number or name is required'}), 400

    app.logger.info(f"Admin chatbot query from user '{getattr(current_user, 'username', 'unknown')}': {query}")

    student = get_student_by_enroll_or_name(query)
    if not student:
        app.logger.warning(f"Student not found for query '{query}' by admin '{getattr(current_user, 'username', 'unknown')}'")
        return jsonify({
            'status': 'error',
            'message': f'Student not found. Please check the enrollment number or name.'
        }), 404

    enroll_no = student.get('enroll_no')
    stats = compute_student_statistics(enroll_no)

    if not stats:
        return jsonify({'status': 'error', 'message': 'Error computing statistics'}), 500

    summary = generate_gemini_summary(stats)

    app.logger.info(f"Admin '{getattr(current_user, 'username', 'unknown')}' queried statistics for student '{enroll_no}'")

    return jsonify({
        'status': 'success',
        'student': {
            'name': stats['student'].get('name'),
            'enroll_no': stats['student'].get('enroll_no'),
            'class': stats['student'].get('class')
        },
        'statistics': {
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

# Register blueprint
app.register_blueprint(main_bp)

# Serve uploaded files - SECURED: requires authentication
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    """Serve uploaded student photos - authentication required"""
    # Additional security: sanitize filename to prevent directory traversal
    filename = secure_filename(filename)
    file_path = os.path.join(config.UPLOADS_DIR, filename)

    # Ensure file exists and is within uploads directory (prevent directory traversal)
    uploads_abspath = os.path.abspath(config.UPLOADS_DIR)
    file_abspath = os.path.abspath(file_path)
    if not os.path.exists(file_path) or not file_abspath.startswith(uploads_abspath):
        app.logger.warning(f"Unauthorized file access attempt: {filename} from user {request.remote_addr}")
        return jsonify({'status': 'error', 'message': 'File not found'}), 404

    return send_file(file_path)

# Redirect root to unified auth if not authenticated, otherwise dashboards
@app.route('/')
def index():
    from flask_login import current_user
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('unified_auth_page'))

# Also handle /home for convenience
@app.route('/home')
@login_required
def home():
    return redirect(url_for('main.dashboard'))

# Global error handlers - return generic messages in production
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    if request.is_json:
        return jsonify({'status': 'error', 'message': 'Resource not found'}), 404
    flash('Page not found.', 'error')
    return redirect(url_for('main.dashboard')), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    app.logger.error(f"Internal server error: {str(error)}", exc_info=True)
    if request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'An internal error occurred. Please try again later.' if config.IS_PRODUCTION else str(error)
        }), 500
    flash('An internal error occurred. Please try again later.' if config.IS_PRODUCTION else str(error), 'error')
    return redirect(url_for('main.dashboard')), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle all exceptions"""
    # Preserve HTTP exceptions (so 404/401/etc. are not converted to 500)
    if isinstance(error, HTTPException):
        return error
    app.logger.error(f"Unhandled exception: {str(error)}", exc_info=True)
    if request.is_json:
        return jsonify({
            'status': 'error',
            'message': 'An error occurred. Please try again later.' if config.IS_PRODUCTION else str(error)
        }), 500
    flash('An error occurred. Please try again later.' if config.IS_PRODUCTION else str(error), 'error')
    return redirect(url_for('main.dashboard')), 500

if __name__ == "__main__":
    import sys

    if config.IS_PRODUCTION:
        print("=" * 60)
        print("⚠️  WARNING: Running in PRODUCTION mode!")
        print("=" * 60)
        print("This development server will not start in production mode.")
        print("Use a WSGI server such as:")
        print("  Windows: waitress-serve --host=0.0.0.0 --port=5000 wsgi:app")
        print("  Linux:   gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app")
        print("=" * 60)
        sys.exit(1)

    print("=" * 60)
    print("MarkSmart - Starting Development Server")
    print("=" * 60)
    print(f"\nEnvironment: {config.ENV}")
    print(f"Debug Mode: {not config.IS_PRODUCTION}")
    print("\nServer will be available at:")
    print(f"  - http://{config.HOST}:{config.PORT}")
    print("\n⚠️  This is a DEVELOPMENT server.")
    print("   For production, use: waitress-serve or gunicorn")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60)
    print()

    app.run(
        debug=not config.IS_PRODUCTION,
        host=config.HOST,
        port=config.PORT,
        use_reloader=not config.IS_PRODUCTION
    )
