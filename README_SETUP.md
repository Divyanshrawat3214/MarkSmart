# MarkSmart - Setup Guide

**Mark attendance smartly.**

## Overview
MarkSmart is a secure attendance management system built with Flask, OpenCV, face recognition, and Excel-based storage. Features include:
- Admin authentication with bcrypt password hashing
- Daily QR code generation with JWT tokens
- Live face detection with liveness checks (blink/head-turn)
- Student management with face embedding storage
- Attendance tracking with geolocation
- Feedback system
- Dashboard with visualizations

## Installation

### 1. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 2. Create Admin Account
Before running the application, create the first admin account:
```bash
python setup_admin.py
```
Follow the prompts to set a username and password.

### 3. Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Usage

### Admin Login
1. Navigate to `http://localhost:5000`
2. Login with the admin credentials created in step 2

### Generate QR Code for Attendance
1. Go to the "QR for Attendance" tab
2. Click "Generate Today's QR Code"
3. Download or display the QR code for students to scan

### Add Students
1. Go to the "Students" tab
2. Click "Add Student" to add individual students
   - Upload a photo (face must be clearly visible)
   - System will automatically compute face embeddings
3. Or use "Bulk Upload" to upload multiple students via Excel
   - Excel should have columns: enroll_no, name, class, photo_filename, metadata
   - Optionally upload a ZIP file with student photos

### Mark Attendance
1. Students scan the QR code with their phone
2. Camera opens automatically
3. System performs liveness check (blink and head turn)
4. Face is matched against enrolled students
5. Attendance is recorded with timestamp and location

### View Attendance
- **Attendance Data**: View all attendance records with filters
- **View Today's Attendance**: See today's attendance only
- Export filtered data to Excel

### Feedback
- Navigate to the "Feedback" tab
- Submit feedback that is saved to Excel

## File Structure

```
Chatgpt/
├── app.py                 # Main Flask application
├── config.py              # Configuration settings
├── models.py              # Data models and Excel operations
├── auth.py                # Authentication logic
├── setup_admin.py         # Admin account setup script
├── requirements.txt       # Python dependencies
├── data/                  # Excel files (auto-created)
│   ├── attendance.xlsx
│   ├── students.xlsx
│   ├── feedback.xlsx
│   └── admins.xlsx
├── uploads/               # Student photos
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   ├── scan.js        # Face detection and liveness
│   │   ├── dashboard.js   # Dashboard functionality
│   │   └── students.js    # Student management
│   └── qr_codes/          # Generated QR codes
└── templates/
    ├── base.html
    ├── login.html
    ├── dashboard.html
    ├── scan.html
    ├── feedback.html
    └── qr_generate.html
```

## Security Features

- **Password Hashing**: bcrypt for secure password storage
- **JWT Tokens**: QR codes use signed JWT tokens with 10-minute expiry
- **CSRF Protection**: Flask-WTF CSRF tokens on all forms
- **Session Security**: Secure session cookies
- **File Locking**: Prevents concurrent Excel write conflicts
- **Input Validation**: All inputs are validated and sanitized

## Face Recognition

- Uses `face_recognition` library (dlib backend)
- Face embeddings stored as base64 in Excel
- Matching tolerance: 0.5 (configurable in config.py)
- Liveness detection via face-api.js (client-side)

## Notes

- Excel files are created automatically on first use
- Student photos should be clear front-facing images
- QR codes expire after 10 minutes for security
- Location capture requires browser geolocation permission
- Face-api.js models load from CDN (may take a few seconds)

## Troubleshooting

### "No enrolled students found"
- Add students via the Students tab
- Ensure photos contain clear faces

### "Models failed to load"
- Check internet connection (models load from CDN)
- Refresh the page

### "Camera access denied"
- Grant camera permissions in browser settings
- Use HTTPS in production (required for camera access)

### Excel file errors
- Ensure files are not open in another program
- Check file permissions in the `data/` directory

## Production Deployment

1. Set environment variables:
   - `SECRET_KEY`: Flask secret key
   - `JWT_SECRET_KEY`: JWT signing key
2. Set `SESSION_COOKIE_SECURE = True` in config.py (requires HTTPS)
3. Use a production WSGI server (e.g., Gunicorn)
4. Configure reverse proxy (e.g., Nginx)
5. Enable HTTPS for camera access

