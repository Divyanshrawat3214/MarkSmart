"""
Setup script to create the first admin account.
Run this script once to initialize the admin system.
"""
import bcrypt
import getpass
from models import UserModel

def create_admin():
    print("=" * 50)
    print("Admin Account Setup")
    print("=" * 50)
    
    email = input("Enter email address: ").strip().lower()
    if not email:
        print("Error: Email cannot be empty.")
        return
    
    username = input("Enter username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return
    
    # Check if email already exists
    existing = UserModel.get_by_email(email)
    if existing:
        print(f"Error: Email '{email}' is already registered.")
        return
    
    # Check if username already exists
    if UserModel.get_by_username(username):
        print(f"Error: Username '{username}' already exists.")
        return
    
    password = getpass.getpass("Enter password: ")
    if not password:
        print("Error: Password cannot be empty.")
        return
    
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("Error: Passwords do not match.")
        return
    
    # Hash password with bcrypt
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Save user
    success, message = UserModel.add(email, username, password_hash)
    if success:
        print(f"\n✓ User '{username}' created successfully!")
        print(f"Email: {email}")
        print("You can now log in to the system.")
    else:
        print(f"\n✗ Error: {message}")

if __name__ == '__main__':
    create_admin()

