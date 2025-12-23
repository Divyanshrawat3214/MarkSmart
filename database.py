"""
Database module for MarkSmart - SQLite database operations
Replaces Excel-based storage with proper database
"""
import sqlite3
import os
import base64
import numpy as np
import logging
import contextlib
import threading
from datetime import datetime
import config

logger = logging.getLogger(__name__)

# Thread-local storage for database connections
_thread_local = threading.local()

def get_db_path():
    """Get SQLite database path"""
    return os.path.join(config.DATA_DIR, 'marksmart.db')

def get_connection():
    """Get thread-local database connection"""
    if not hasattr(_thread_local, 'connection'):
        db_path = get_db_path()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        _thread_local.connection = sqlite3.connect(db_path, check_same_thread=False)
        _thread_local.connection.row_factory = sqlite3.Row  # Return rows as dict-like objects
        # Enable foreign keys
        _thread_local.connection.execute('PRAGMA foreign_keys = ON')
    return _thread_local.connection

@contextlib.contextmanager
def get_db():
    """Context manager for database connections with transaction handling"""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        # Don't close connection in thread-local storage
        pass

def init_database():
    """Initialize database tables"""
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users/Admins table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Students table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS students (
                enroll_no TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                class TEXT DEFAULT '',
                photo_filename TEXT DEFAULT '',
                face_embedding BLOB,
                password_hash TEXT,
                email TEXT,
                metadata TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Add password_hash and email columns if they don't exist (migration)
        try:
            cursor.execute('ALTER TABLE students ADD COLUMN password_hash TEXT')
        except:
            pass
        try:
            cursor.execute('ALTER TABLE students ADD COLUMN email TEXT')
        except:
            pass
        try:
            cursor.execute('ALTER TABLE students ADD COLUMN class TEXT DEFAULT ""')
        except:
            pass
        try:
            cursor.execute('ALTER TABLE students ADD COLUMN photo_filename TEXT DEFAULT ""')
        except:
            pass
        
        # Attendance table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enroll_no TEXT NOT NULL,
                name TEXT NOT NULL,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                latitude TEXT,
                longitude TEXT,
                liveness_score TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Feedback table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attendance_enroll ON attendance(enroll_no)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_students_class ON students(class)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
        
        conn.commit()
        logger.info("Database initialized successfully")

def encode_embedding(embedding):
    """Encode numpy array embedding to bytes for SQLite storage"""
    if embedding is None:
        return None
    return embedding.tobytes()

def decode_embedding(blob_data):
    """Decode bytes to numpy array embedding"""
    if blob_data is None:
        return None
    try:
        return np.frombuffer(blob_data, dtype=np.float64)
    except Exception as e:
        logger.error(f"Error decoding embedding: {str(e)}", exc_info=True)
        return None

