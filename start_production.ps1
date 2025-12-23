# MarkSmart Production Server Startup Script (PowerShell)
# This script sets environment variables and starts the production server

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "MarkSmart - Production Server Setup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check if environment variables are set
$secretKey = $env:SECRET_KEY
$jwtSecretKey = $env:JWT_SECRET_KEY

if (-not $secretKey -or -not $jwtSecretKey) {
    Write-Host "⚠️  WARNING: Environment variables not set!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Generating secure keys..." -ForegroundColor Yellow
    
    # Generate keys
    $secretKey = python -c "import secrets; print(secrets.token_hex(32))"
    $jwtSecretKey = python -c "import secrets; print(secrets.token_hex(32))"
    
    Write-Host ""
    Write-Host "Please set these environment variables:" -ForegroundColor Yellow
    Write-Host "  `$env:SECRET_KEY='$secretKey'" -ForegroundColor White
    Write-Host "  `$env:JWT_SECRET_KEY='$jwtSecretKey'" -ForegroundColor White
    Write-Host ""
    Write-Host "Or run this script with:" -ForegroundColor Yellow
    Write-Host "  `$env:SECRET_KEY='your-key'; `$env:JWT_SECRET_KEY='your-key'; .\start_production.ps1" -ForegroundColor White
    Write-Host ""
    
    # Set them for this session
    $env:SECRET_KEY = $secretKey
    $env:JWT_SECRET_KEY = $jwtSecretKey
    Write-Host "✓ Keys set for this session" -ForegroundColor Green
}

# Set production environment
$env:FLASK_ENV = "production"

Write-Host ""
Write-Host "Starting production server with Waitress..." -ForegroundColor Green
Write-Host "Server will be available at: http://0.0.0.0:5000" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Activate virtual environment and start server
& ".\venv311\Scripts\Activate.ps1"
waitress-serve --host=0.0.0.0 --port=5000 --threads=4 wsgi:app

