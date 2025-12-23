# MarkSmart - Production Quick Start Guide

## 🚀 Quick Start (3 Steps)

### Step 1: Set Environment Variables

**Windows PowerShell:**
```powershell
$env:FLASK_ENV="production"
$env:SECRET_KEY="your-64-character-secret-key-here"
$env:JWT_SECRET_KEY="your-64-character-jwt-secret-key-here"
```

**Linux/Mac:**
```bash
export FLASK_ENV=production
export SECRET_KEY="your-64-character-secret-key-here"
export JWT_SECRET_KEY="your-64-character-jwt-secret-key-here"
```

**Generate Keys:**
```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))"
```

### Step 2: Install Production Server

```bash
pip install waitress  # Windows (recommended)
# or
pip install gunicorn  # Linux/Unix
```

### Step 3: Start Production Server

**Option A: Using Waitress (Windows/Cross-platform)**
```bash
waitress-serve --host=0.0.0.0 --port=5000 --threads=4 wsgi:app
```

**Option B: Using Gunicorn (Linux/Unix)**
```bash
gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app
```

**Option C: Using PowerShell Script (Windows)**
```powershell
.\start_production.ps1
```

## 🔒 Security Checklist

- ✅ Set `FLASK_ENV=production`
- ✅ Set `SECRET_KEY` environment variable
- ✅ Set `JWT_SECRET_KEY` environment variable
- ✅ Use HTTPS (SSL certificate)
- ✅ Use production WSGI server (Waitress/Gunicorn)
- ✅ Configure reverse proxy (Nginx/Apache)
- ✅ Enable firewall rules
- ✅ Regular backups

## 📋 Production Features Enabled

- ✅ Secure session cookies (HTTPS only)
- ✅ Security headers (X-Frame-Options, CSP, HSTS, etc.)
- ✅ CSRF protection
- ✅ Password hashing (bcrypt)
- ✅ JWT token expiry (10 minutes)
- ✅ File locking for thread safety
- ✅ Logging with rotation
- ✅ Debug mode disabled

## 🌐 Reverse Proxy Setup

### Nginx (Recommended)

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 📝 Full Documentation

See `DEPLOYMENT.md` for complete deployment guide.

## ⚠️ Important Notes

1. **NEVER** run `python app.py` in production - use WSGI server
2. **NEVER** commit secret keys to version control
3. **ALWAYS** use HTTPS in production
4. **ALWAYS** set environment variables before starting server
5. Debug mode is automatically disabled in production

## 🆘 Troubleshooting

**Port already in use:**
```bash
export PORT=8000  # Change port
```

**Permission denied:**
- Check file permissions
- Run with appropriate user permissions

**SSL errors:**
- Verify certificate paths
- Check certificate permissions

**Import errors:**
- Activate virtual environment
- Install requirements: `pip install -r requirements.txt`

