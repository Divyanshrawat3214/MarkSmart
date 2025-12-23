from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required as flask_login_required, current_user
from werkzeug.security import check_password_hash
import bcrypt
from models import UserModel

# Export login_required for use in app.py
login_required = flask_login_required

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.username = username

@login_manager.user_loader
def load_user(username):
    user = UserModel.get_by_username(username)
    if user:
        return User(username)
    return None

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signin', methods=['GET'])
def signin():
    """Redirect /signin to /login"""
    return redirect(url_for('auth.login'))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login (Sign In)"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please provide both username and password.', 'error')
            return render_template('login.html')
        
        user = UserModel.get_by_username(username)
        if user:
            # Check password using bcrypt
            password_hash = user.get('password_hash', '')
            try:
                if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
                    user_obj = User(username)
                    login_user(user_obj, remember=True)
                    current_app.logger.info(f"Successful login: {username}")
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('main.dashboard'))
                else:
                    current_app.logger.warning(f"Failed login attempt for username: {username}")
                    flash('Invalid username or password.', 'error')
            except Exception as e:
                current_app.logger.error(f"Error checking password: {str(e)}", exc_info=True)
                flash('Authentication error. Please try again.', 'error')
        else:
            current_app.logger.warning(f"Failed login attempt for non-existent username: {username}")
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Settings page to change username and password"""
    if request.method == 'POST':
        action = request.form.get('action')
        username = current_user.username
        
        if action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not current_password or not new_password or not confirm_password:
                flash('All password fields are required.', 'error')
                return render_template('settings.html')
            
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return render_template('settings.html')
            
            # Verify current password
            user = UserModel.get_by_username(username)
            if user:
                password_hash = user.get('password_hash', '')
                try:
                    if not bcrypt.checkpw(current_password.encode('utf-8'), password_hash.encode('utf-8')):
                        current_app.logger.warning(f"Failed password change attempt for user: {username}")
                        flash('Current password is incorrect.', 'error')
                        return render_template('settings.html')
                except Exception as e:
                    current_app.logger.error(f"Error checking password: {str(e)}", exc_info=True)
                    flash('Error verifying current password.', 'error')
                    return render_template('settings.html')
            
            # Update password
            current_app.logger.info(f"Password changed for user: {username}")
            new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            success, message = UserModel.update_password_by_username(username, new_password_hash)
            
            if success:
                flash('Password changed successfully!', 'success')
            else:
                flash(f'Error: {message}', 'error')
        
        elif action == 'change_username':
            current_password = request.form.get('current_password_username', '')
            new_username = request.form.get('new_username', '').strip()
            
            if not current_password or not new_username:
                flash('All fields are required.', 'error')
                return render_template('settings.html')
            
            if new_username == username:
                flash('New username must be different from current username.', 'error')
                return render_template('settings.html')
            
            # Verify current password
            user = UserModel.get_by_username(username)
            if user:
                password_hash = user.get('password_hash', '')
                try:
                    if not bcrypt.checkpw(current_password.encode('utf-8'), password_hash.encode('utf-8')):
                        current_app.logger.warning(f"Failed username change attempt for user: {username}")
                        flash('Current password is incorrect.', 'error')
                        return render_template('settings.html')
                except Exception as e:
                    current_app.logger.error(f"Error checking password: {str(e)}", exc_info=True)
                    flash('Error verifying current password.', 'error')
                    return render_template('settings.html')
            
            # Update username
            current_app.logger.info(f"Username change: {username} -> {new_username}")
            success, message = UserModel.update_username(username, new_username)
            
            if success:
                # Logout user - they need to login again with new username
                logout_user()
                flash('Username changed successfully! Please log in again with your new username.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash(f'Error: {message}', 'error')
    
    return render_template('settings.html')

@auth_bp.route('/signup', methods=['GET'])
def signup():
    """Redirect /signup to /register"""
    return redirect(url_for('auth.register'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration (Sign Up)"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not email or not username or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        # Block default/reserved usernames for security
        blocked_usernames = ['admin', 'administrator', 'root', 'system', 'service', 'support']
        if username.lower() in blocked_usernames:
            flash('This username is not allowed. Please choose another.', 'error')
            return render_template('register.html')
        
        # Check if email already exists
        existing_user = UserModel.get_by_email(email)
        if existing_user:
            flash('This email is already registered. Please use "Forgot Password" if you forgot your credentials.', 'error')
            return render_template('register.html')
        
        # Check if username already exists
        if UserModel.get_by_username(username):
            flash('Username already taken. Please choose another.', 'error')
            return render_template('register.html')
        
        # Hash password and create user
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        success, message = UserModel.add(email, username, password_hash)
        
        if success:
            flash('Registration successful! Please login with your credentials.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash(f'Registration failed: {message}', 'error')
    
    return render_template('register.html')

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Forgot password - reset password by email"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('forgot_password.html')
        
        # Check if email exists
        user = UserModel.get_by_email(email)
        if not user:
            flash('Email not found. Please check your email or register a new account.', 'error')
            return render_template('forgot_password.html')
        
        # If new password provided, update it
        if new_password:
            if new_password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('forgot_password.html', email=email)
            
            if len(new_password) < 6:
                flash('Password must be at least 6 characters long.', 'error')
                return render_template('forgot_password.html', email=email)
            
            # Update password
            password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            success, message = UserModel.update_password(email, password_hash)
            
            if success:
                flash('Password reset successful! Please login with your new password.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash(f'Password reset failed: {message}', 'error')
        else:
            # Show password reset form
            return render_template('forgot_password.html', email=email, show_reset=True)
    
    return render_template('forgot_password.html')

def init_auth(app):
    """Initialize authentication with Flask app"""
    login_manager.init_app(app)
    app.register_blueprint(auth_bp)

