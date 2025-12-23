"""
Migration script to migrate data from Excel files to SQLite database
Run this once to migrate existing data
"""
import os
import pandas as pd
import base64
import numpy as np
import bcrypt
from database import init_database, get_db
from models import UserModel, StudentModel, AttendanceModel, FeedbackModel
import config

def decode_excel_embedding(encoded_str):
    """Decode base64 string from Excel to numpy array"""
    if pd.isna(encoded_str) or encoded_str is None or encoded_str == '':
        return None
    try:
        bytes_data = base64.b64decode(encoded_str)
        return np.frombuffer(bytes_data, dtype=np.float64)
    except:
        return None

def migrate_students():
    """Migrate students from Excel to database"""
    if not os.path.exists(config.STUDENTS_FILE):
        print("Students Excel file not found. Skipping migration.")
        return 0
    
    df = pd.read_excel(config.STUDENTS_FILE)
    count = 0
    
    for _, row in df.iterrows():
        enroll_no = str(row.get('enroll_no', ''))
        if not enroll_no:
            continue
        
        # Check if already exists
        existing = StudentModel.get_by_enroll(enroll_no)
        if existing:
            print(f"Student {enroll_no} already exists, skipping...")
            continue
        
        # Decode embedding from Excel format
        embedding_str = row.get('face_embedding', '')
        face_embedding = decode_excel_embedding(embedding_str)
        
        success, message = StudentModel.add(
            enroll_no=enroll_no,
            name=str(row.get('name', '')),
            class_name=str(row.get('class', '')),
            photo_filename=str(row.get('photo_filename', '')),
            face_embedding=face_embedding,
            metadata=str(row.get('metadata', ''))
        )
        
        if success:
            count += 1
        else:
            print(f"Error migrating student {enroll_no}: {message}")
    
    return count

def migrate_attendance():
    """Migrate attendance from Excel to database"""
    if not os.path.exists(config.ATTENDANCE_FILE):
        print("Attendance Excel file not found. Skipping migration.")
        return 0
    
    df = pd.read_excel(config.ATTENDANCE_FILE)
    count = 0
    
    for _, row in df.iterrows():
        enroll_no = str(row.get('enroll_no', ''))
        if not enroll_no:
            continue
        
        success = AttendanceModel.add(
            enroll_no=enroll_no,
            name=str(row.get('name', '')),
            date=str(row.get('date', '')),
            time=str(row.get('time', '')),
            latitude=str(row.get('latitude', '')) if pd.notna(row.get('latitude')) else None,
            longitude=str(row.get('longitude', '')) if pd.notna(row.get('longitude')) else None,
            liveness_score=str(row.get('liveness_score', '')) if pd.notna(row.get('liveness_score')) else None
        )
        
        if success:
            count += 1
        else:
            print(f"Error migrating attendance record for {enroll_no}")
    
    return count

def migrate_users():
    """Migrate users/admins from Excel to database"""
    if not os.path.exists(config.ADMINS_FILE):
        print("Admins Excel file not found. Skipping migration.")
        return 0
    
    df = pd.read_excel(config.ADMINS_FILE)
    count = 0
    
    for _, row in df.iterrows():
        email = str(row.get('email', '')).lower().strip()
        username = str(row.get('username', '')).strip()
        password_hash = str(row.get('password_hash', ''))
        
        if not email or not username or not password_hash:
            continue
        
        # Check if already exists
        existing = UserModel.get_by_email(email)
        if existing:
            print(f"User {email} already exists, skipping...")
            continue
        
        success, message = UserModel.add(email, username, password_hash)
        
        if success:
            count += 1
        else:
            print(f"Error migrating user {email}: {message}")
    
    return count

def migrate_feedback():
    """Migrate feedback from Excel to database"""
    if not os.path.exists(config.FEEDBACK_FILE):
        print("Feedback Excel file not found. Skipping migration.")
        return 0
    
    df = pd.read_excel(config.FEEDBACK_FILE)
    count = 0
    
    for _, row in df.iterrows():
        name = str(row.get('name', ''))
        message = str(row.get('message', ''))
        
        if not name or not message:
            continue
        
        success = FeedbackModel.add(name, message)
        
        if success:
            count += 1
        else:
            print(f"Error migrating feedback from {name}")
    
    return count

def main():
    """Main migration function"""
    print("=" * 60)
    print("MarkSmart - Excel to SQLite Migration")
    print("=" * 60)
    print()
    
    # Initialize database
    print("Initializing database...")
    init_database()
    print("Database initialized.")
    print()
    
    # Migrate data
    print("Migrating data from Excel files to SQLite database...")
    print()
    
    students_count = migrate_students()
    print(f"Migrated {students_count} students")
    
    attendance_count = migrate_attendance()
    print(f"Migrated {attendance_count} attendance records")
    
    users_count = migrate_users()
    print(f"Migrated {users_count} users")
    
    feedback_count = migrate_feedback()
    print(f"Migrated {feedback_count} feedback entries")
    
    print()
    print("=" * 60)
    print("Migration completed!")
    print("=" * 60)
    print()
    print("Note: Excel files are kept as backup. You can delete them after verifying the migration.")
    print("Database file: data/marksmart.db")

if __name__ == '__main__':
    main()

