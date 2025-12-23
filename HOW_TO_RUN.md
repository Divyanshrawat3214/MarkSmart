# How to Run MarkSmart

## 🚀 Quick Start

### Option 1: Development Server (For Testing)

1. **Activate Virtual Environment:**
   ```powershell
   .\venv311\Scripts\Activate.ps1
   ```

2. **Run the Server:**
   ```powershell
   python app.py
   ```

3. **Open in Browser:**
   - Go to: `http://localhost:5000`
   - Login with: `admin` / `admin123`

4. **Stop Server:**
   - Press `Ctrl+C` in the terminal

---

### Option 2: Production Server (Recommended)

1. **Activate Virtual Environment:**
   ```powershell
   .\venv311\Scripts\Activate.ps1
   ```

2. **Set Environment Variables:**
   ```powershell
   $env:FLASK_ENV="production"
   $env:SECRET_KEY="your-64-character-secret-key"
   $env:JWT_SECRET_KEY="your-64-character-jwt-secret-key"
   ```
   
   **Generate Keys (if needed):**
   ```powershell
   python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
   python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_hex(32))"
   ```

3. **Start Production Server:**
   ```powershell
   waitress-serve --host=0.0.0.0 --port=5000 --threads=4 wsgi:app
   ```
   
   **OR use the PowerShell script:**
   ```powershell
   .\start_production.ps1
   ```

4. **Open in Browser:**
   - Go to: `http://localhost:5000`
   - Login with: `admin` / `admin123`

5. **Stop Server:**
   - Press `Ctrl+C` in the terminal

---

## 📋 Step-by-Step (First Time Setup)

### 1. Install Dependencies (If Not Done)
```powershell
.\venv311\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Create Admin Account (If Not Done)
```powershell
python setup_admin.py
```
Or use the default:
```powershell
python create_default_admin.py
```

### 3. Run the Server

**For Development:**
```powershell
python app.py
```

**For Production:**
```powershell
# Set environment variables first
$env:FLASK_ENV="production"
$env:SECRET_KEY="your-secret-key"
$env:JWT_SECRET_KEY="your-jwt-secret-key"

# Then start server
waitress-serve --host=0.0.0.0 --port=5000 --threads=4 wsgi:app
```

---

## 🌐 Access the Website

Once the server is running:

- **Local:** http://localhost:5000
- **Network:** http://127.0.0.1:5000
- **From other devices:** http://YOUR_IP_ADDRESS:5000

---

## 🔑 Default Login

- **Username:** `admin`
- **Password:** `admin123`

**⚠️ Change password after first login in Settings!**

---

## ⚠️ Troubleshooting

### Port Already in Use
```powershell
# Use a different port
$env:PORT=8000
python app.py
```

### Module Not Found
```powershell
# Activate virtual environment
.\venv311\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### Server Won't Start
1. Check if another process is using port 5000
2. Make sure virtual environment is activated
3. Verify all dependencies are installed

---

## 📝 Notes

- **Development Server:** Use `python app.py` for testing only
- **Production Server:** Use `waitress-serve` or `gunicorn` for deployment
- **Environment Variables:** Required for production mode
- **HTTPS:** Configure SSL certificate for production (see DEPLOYMENT.md)

---

## 🆘 Need Help?

- See `README_SETUP.md` for detailed setup
- See `DEPLOYMENT.md` for production deployment
- See `PRODUCTION_QUICKSTART.md` for quick production guide

