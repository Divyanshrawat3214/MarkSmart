#!/usr/bin/env python
"""
Production Server Startup Script for MarkSmart
This script starts the application using Waitress (Windows) or Gunicorn (Linux)

Usage:
    Windows: python start_production.py
    Linux:   python start_production.py
"""
import os
import sys
import subprocess
import platform

def check_environment():
    """Check if required environment variables are set"""
    required_vars = ['SECRET_KEY', 'JWT_SECRET_KEY']
    missing = []
    
    for var in required_vars:
        if not os.environ.get(var):
            missing.append(var)
    
    if missing:
        print("=" * 60)
        print("❌ ERROR: Missing required environment variables!")
        print("=" * 60)
        print("Please set the following environment variables:")
        for var in missing:
            print(f"  - {var}")
        print("\nExample (Windows PowerShell):")
        print("  $env:SECRET_KEY='your-secret-key-here'")
        print("  $env:JWT_SECRET_KEY='your-jwt-secret-key-here'")
        print("\nExample (Linux/Mac):")
        print("  export SECRET_KEY='your-secret-key-here'")
        print("  export JWT_SECRET_KEY='your-jwt-secret-key-here'")
        print("=" * 60)
        return False
    
    # Set production environment
    os.environ['FLASK_ENV'] = 'production'
    return True

def generate_secret_keys():
    """Generate secure secret keys"""
    import secrets
    print("\n" + "=" * 60)
    print("Generating Secure Secret Keys")
    print("=" * 60)
    secret_key = secrets.token_hex(32)
    jwt_secret = secrets.token_hex(32)
    
    print("\nAdd these to your environment variables:")
    print(f"\nSECRET_KEY={secret_key}")
    print(f"JWT_SECRET_KEY={jwt_secret}")
    print("\n" + "=" * 60)
    return secret_key, jwt_secret

def start_waitress(host='0.0.0.0', port=5000, threads=4):
    """Start server using Waitress (Windows compatible)"""
    try:
        # Import waitress separately so we only treat its ImportError
        # as "waitress not installed", and not errors from our app.
        try:
            from waitress import serve
        except ImportError:
            print("❌ Waitress not installed. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "waitress"])
            # Try again after installation
            return start_waitress(host, port, threads)

        # Now import the WSGI application.
        # If this fails, we want to SEE the real error instead of
        # pretending waitress is missing.
        try:
            from wsgi import application
        except Exception as e:
            import traceback
            print("\n❌ Error importing WSGI application from 'wsgi.py':")
            print(f"   {e}")
            print("\nStack trace:")
            traceback.print_exc()
            print("\nFix the error above in 'wsgi.py' or its imports, then rerun.")
            sys.exit(1)

        print("=" * 60)
        print("MarkSmart - Production Server (Waitress)")
        print("=" * 60)
        print(f"\nServer starting on: http://{host}:{port}")
        print(f"Threads: {threads}")
        print(f"Environment: {os.environ.get('FLASK_ENV', 'production')}")
        print("\nPress Ctrl+C to stop the server")
        print("=" * 60)
        print()

        serve(
            application,
            host=host,
            port=port,
            threads=threads,
            channel_timeout=120
        )
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        sys.exit(1)

def start_gunicorn(host='0.0.0.0', port=5000, workers=4):
    """Start server using Gunicorn (Linux/Unix)"""
    try:
        import gunicorn.app.wsgiapp as wsgi
        
        print("=" * 60)
        print("MarkSmart - Production Server (Gunicorn)")
        print("=" * 60)
        print(f"\nServer starting on: http://{host}:{port}")
        print(f"Workers: {workers}")
        print(f"Environment: {os.environ.get('FLASK_ENV', 'production')}")
        print("\nPress Ctrl+C to stop the server")
        print("=" * 60)
        print()
        
        sys.argv = [
            'gunicorn',
            '-w', str(workers),
            '-b', f'{host}:{port}',
            '--timeout', '120',
            '--access-logfile', '-',
            '--error-logfile', '-',
            'wsgi:app'
        ]
        wsgi.run()
    except ImportError:
        print("❌ Gunicorn not installed. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "gunicorn"])
        start_gunicorn(host, port, workers)
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        sys.exit(1)

def main():
    """Main entry point"""
    # Check if we're in production mode
    if not check_environment():
        print("\nWould you like to generate secret keys? (y/n): ", end='')
        response = input().strip().lower()
        if response == 'y':
            generate_secret_keys()
        sys.exit(1)
    
    # Get configuration
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    workers = int(os.environ.get('WORKERS', 4))
    
    # Choose server based on platform
    system = platform.system().lower()
    
    if system == 'windows':
        start_waitress(host, port, workers)
    else:
        # Try Gunicorn first, fallback to Waitress
        try:
            start_gunicorn(host, port, workers)
        except:
            print("Gunicorn not available, using Waitress...")
            start_waitress(host, port, workers)

if __name__ == "__main__":
    main()

