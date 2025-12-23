"""
Student authentication utilities
"""
import re
import bcrypt
import logging
from models import StudentModel

logger = logging.getLogger(__name__)

def validate_password(password):
    """Validate password against rules"""
    if len(password) < 8 or len(password) > 16:
        return False, "Password must be 8-16 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    special_chars = r'!@#$%^&*(),.?":{}|<>'
    if not any(char in password for char in special_chars):
        return False, f"Password must contain at least one special character ({special_chars})"
    
    return True, "Valid"

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception as e:
        logger.error(f"Error verifying password: {str(e)}", exc_info=True)
        return False

