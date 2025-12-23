# MarkSmart - Production Deployment Guide

This guide covers deploying MarkSmart to a production environment with proper security and performance configurations.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Setup](#environment-setup)
3. [Security Configuration](#security-configuration)
4. [Production Server Setup](#production-server-setup)
5. [HTTPS/SSL Configuration](#httpsssl-configuration)
6. [Reverse Proxy Setup](#reverse-proxy-setup)
7. [Monitoring and Logging](#monitoring-and-logging)
8. [Backup and Maintenance](#backup-and-maintenance)

## Prerequisites

- Python 3.8 or higher
- Virtual environment
- Production server (Windows Server, Linux, or cloud platform)
- Domain name (for HTTPS)
- SSL certificate (Let's Encrypt recommended)

## Environment Setup

### 1. Install Dependencies

```bash
# Activate virtual environment
.\venv311\Scripts\Activate.ps1  # Windows PowerShell
# or
source venv/bin/activate  # Linux/Mac

# Install production dependencies
pip install -r requirements.txt
```

### 2. Set Environment Variables

**Windows PowerShell:**
```powershell
$env:FLASK_ENV="production"
$env:SECRET_KEY="your-64-character-hex-secret-key"
$env:JWT_SECRET_KEY="your-64-character-hex-jwt-secret-key"
$env:HOST="0.0.0.0"
$env:PORT="5000"
$env:WORKERS="4"
```

**Linux/Mac:**
```bash
export FLASK_ENV=production
export SECRET_KEY="your-64-character-hex-secret-key"
export JWT_SECRET_KEY="your-64-character-hex-jwt-secret-key"
export HOST=0.0.0.0
export PORT=5000
export WORKERS=4
```

**Generate Secure Keys:**
```python
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))"
```

### 3. Create Required Directories

```bash
mkdir logs
mkdir data
mkdir uploads
mkdir static/qr_codes
```

## Security Configuration

### 1. Secure Secret Keys

**NEVER commit secret keys to version control!**

- Use environment variables for all secrets
- Generate strong, random keys (64+ characters)
- Rotate keys periodically
- Use different keys for development and production

### 2. File Permissions

**Linux:**
```bash
chmod 600 .env  # If using .env file
chmod 755 data uploads static/qr_codes logs
```

### 3. Firewall Configuration

Only allow necessary ports:
- **HTTPS**: 443
- **HTTP**: 80 (redirect to HTTPS)
- **SSH**: 22 (if remote access needed)

## Production Server Setup

### Option 1: Waitress (Windows/Cross-platform)

```bash
# Install Waitress
pip install waitress

# Start server
waitress-serve --host=0.0.0.0 --port=5000 --threads=4 wsgi:app

# Or use the startup script
python start_production.py
```

### Option 2: Gunicorn (Linux/Unix)

```bash
# Install Gunicorn
pip install gunicorn

# Start server
gunicorn -w 4 -b 0.0.0.0:5000 --timeout 120 wsgi:app

# With more options
gunicorn -w 4 -b 0.0.0.0:5000 \
    --timeout 120 \
    --access-logfile logs/access.log \
    --error-logfile logs/error.log \
    --log-level info \
    wsgi:app
```

### Option 3: Using the Production Script

```bash
# Set environment variables first, then:
python start_production.py
```

## HTTPS/SSL Configuration

### 1. Obtain SSL Certificate

**Using Let's Encrypt (Free):**
```bash
# Install Certbot
sudo apt-get install certbot  # Ubuntu/Debian
# or
sudo yum install certbot  # CentOS/RHEL

# Obtain certificate
sudo certbot certonly --standalone -d yourdomain.com
```

### 2. Configure Flask for HTTPS

The application automatically enables secure cookies when `FLASK_ENV=production` and `SESSION_COOKIE_SECURE=True`.

## Reverse Proxy Setup

### Nginx Configuration

Create `/etc/nginx/sites-available/marksmart`:

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Logging
    access_log /var/log/nginx/marksmart_access.log;
    error_log /var/log/nginx/marksmart_error.log;

    # Client max body size (for file uploads)
    client_max_body_size 10M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        
        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static files
    location /static {
        alias /path/to/marksmart/static;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/marksmart /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Apache Configuration

Create `/etc/apache2/sites-available/marksmart.conf`:

```apache
<VirtualHost *:80>
    ServerName yourdomain.com
    Redirect permanent / https://yourdomain.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName yourdomain.com
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/yourdomain.com/privkey.pem
    
    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/
    
    # Security headers
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
</VirtualHost>
```

Enable modules and site:
```bash
sudo a2enmod ssl proxy proxy_http headers
sudo a2ensite marksmart
sudo systemctl restart apache2
```

## Monitoring and Logging

### 1. Application Logs

Logs are automatically written to `logs/app.log` with rotation:
- Max file size: 10 MB
- Backup count: 5 files
- Log level: INFO (production) or DEBUG (development)

### 2. System Service (Linux)

Create `/etc/systemd/system/marksmart.service`:

```ini
[Unit]
Description=MarkSmart Attendance Management System
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/marksmart
Environment="FLASK_ENV=production"
Environment="SECRET_KEY=your-secret-key"
Environment="JWT_SECRET_KEY=your-jwt-secret-key"
ExecStart=/path/to/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 wsgi:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable marksmart
sudo systemctl start marksmart
sudo systemctl status marksmart
```

## Backup and Maintenance

### 1. Regular Backups

**Backup Script (`backup.sh`):**
```bash
#!/bin/bash
BACKUP_DIR="/backups/marksmart"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR

# Backup data files
tar -czf $BACKUP_DIR/data_$DATE.tar.gz data/

# Backup uploads
tar -czf $BACKUP_DIR/uploads_$DATE.tar.gz uploads/

# Keep only last 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete
```

**Schedule with Cron:**
```bash
# Daily backup at 2 AM
0 2 * * * /path/to/backup.sh
```

### 2. Database Maintenance

- Regularly clean old QR codes from `static/qr_codes/`
- Archive old attendance records if needed
- Monitor Excel file sizes

### 3. Security Updates

- Keep Python packages updated: `pip install --upgrade -r requirements.txt`
- Monitor security advisories
- Update system packages regularly

## Performance Optimization

### 1. Worker Configuration

Adjust workers based on server resources:
- **CPU cores**: Use 2-4x CPU cores
- **Memory**: ~100-200 MB per worker
- **Example**: 4-core server → 4-8 workers

### 2. Caching

Consider adding Redis for session storage in high-traffic scenarios.

### 3. Static Files

Serve static files directly from Nginx/Apache for better performance.

## Troubleshooting

### Common Issues

1. **Port already in use**: Change PORT environment variable
2. **Permission denied**: Check file permissions and user ownership
3. **SSL errors**: Verify certificate paths and permissions
4. **Import errors**: Ensure virtual environment is activated

### Debug Mode

**NEVER enable debug mode in production!**

If you need to debug:
1. Check logs: `tail -f logs/app.log`
2. Check server logs: `journalctl -u marksmart -f`
3. Check Nginx/Apache error logs

## Support

For issues or questions:
1. Check application logs
2. Review server logs
3. Verify environment variables
4. Test with development server first

---

**Security Reminders:**
- ✅ Always use HTTPS in production
- ✅ Never commit secrets to version control
- ✅ Keep dependencies updated
- ✅ Use strong, unique secret keys
- ✅ Regularly backup data
- ✅ Monitor logs for suspicious activity

