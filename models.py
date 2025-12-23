"""
Database models for MarkSmart using SQLite
This file replaces the Excel-based storage with proper database operations
"""
import os
from datetime import datetime
import face_recognition
from PIL import Image
import logging
from database import get_db, encode_embedding, decode_embedding

logger = logging.getLogger(__name__)

def compute_face_embedding(image_path):
    """Compute face embedding from image file"""
    try:
        image = face_recognition.load_image_file(image_path)
        encodings = face_recognition.face_encodings(image)
        if len(encodings) > 0:
            return encodings[0]
        return None
    except Exception as e:
        logger.error(f"Error computing face embedding from {image_path}: {str(e)}", exc_info=True)
        return None

class StudentModel:
    @staticmethod
    def get_all():
        """Get all students"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT enroll_no, name, class, photo_filename, face_embedding, password_hash, email, metadata FROM students')
            rows = cursor.fetchall()
            return [{
                'enroll_no': row['enroll_no'],
                'name': row['name'],
                'class': row.get('class', '') or '',
                'photo_filename': row.get('photo_filename', '') or '',
                'face_embedding': row.get('face_embedding'),  # Keep as blob for storage
                'password_hash': row.get('password_hash'),
                'email': row.get('email'),
                'metadata': row.get('metadata', '') or ''
            } for row in rows]
    
    @staticmethod
    def get_by_enroll(enroll_no):
        """Get student by enrollment number"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT enroll_no, name, class, photo_filename, face_embedding, password_hash, email, metadata FROM students WHERE enroll_no = ?', (str(enroll_no),))
            row = cursor.fetchone()
            if row:
                return {
                    'enroll_no': row['enroll_no'],
                    'name': row['name'],
                    'class': row.get('class', '') or '',
                    'photo_filename': row.get('photo_filename', '') or '',
                    'face_embedding': row.get('face_embedding'),
                    'password_hash': row.get('password_hash'),
                    'email': row.get('email'),
                    'metadata': row.get('metadata', '') or ''
                }
            return None
    
    @staticmethod
    def add(enroll_no, name, class_name='', photo_filename='', face_embedding=None, password_hash=None, email=None, metadata=''):
        """Add new student"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                # Check if enroll_no already exists
                cursor.execute('SELECT enroll_no FROM students WHERE enroll_no = ?', (str(enroll_no),))
                if cursor.fetchone():
                    return False, "Enrollment number already exists"
                
                # Encode embedding
                embedding_blob = encode_embedding(face_embedding) if face_embedding is not None else None
                
                cursor.execute('''
                    INSERT INTO students (enroll_no, name, class, photo_filename, face_embedding, password_hash, email, metadata, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (str(enroll_no), str(name), str(class_name), str(photo_filename), embedding_blob, password_hash, email, str(metadata)))
                conn.commit()
                return True, "Student added successfully"
        except Exception as e:
            logger.error(f"Error adding student: {str(e)}", exc_info=True)
            return False, f"Error adding student: {str(e)}"
    
    @staticmethod
    def update(enroll_no, name=None, class_name=None, photo_filename=None, face_embedding=None, metadata=None):
        """Update student"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                # Check if student exists
                cursor.execute('SELECT enroll_no FROM students WHERE enroll_no = ?', (str(enroll_no),))
                if not cursor.fetchone():
                    return False, "Student not found"
                
                # Build update query dynamically
                updates = []
                params = []
                
                if name is not None:
                    updates.append('name = ?')
                    params.append(str(name))
                if class_name is not None:
                    updates.append('class = ?')
                    params.append(str(class_name))
                if photo_filename is not None:
                    updates.append('photo_filename = ?')
                    params.append(str(photo_filename))
                if face_embedding is not None:
                    updates.append('face_embedding = ?')
                    params.append(encode_embedding(face_embedding))
                if metadata is not None:
                    updates.append('metadata = ?')
                    params.append(str(metadata))
                
                if not updates:
                    return False, "No fields to update"
                
                updates.append('updated_at = CURRENT_TIMESTAMP')
                params.append(str(enroll_no))
                
                query = f'UPDATE students SET {", ".join(updates)} WHERE enroll_no = ?'
                cursor.execute(query, params)
                conn.commit()
                return True, "Student updated successfully"
        except Exception as e:
            logger.error(f"Error updating student: {str(e)}", exc_info=True)
            return False, f"Error updating student: {str(e)}"
    
    @staticmethod
    def delete(enroll_no):
        """Delete student"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM students WHERE enroll_no = ?', (str(enroll_no),))
                conn.commit()
                return True, "Student deleted successfully"
        except Exception as e:
            logger.error(f"Error deleting student: {str(e)}", exc_info=True)
            return False, f"Error deleting student: {str(e)}"
    
    @staticmethod
    def get_all_embeddings():
        """Get all face embeddings for matching"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT enroll_no, name, face_embedding FROM students WHERE face_embedding IS NOT NULL')
            rows = cursor.fetchall()
            
            embeddings = []
            names = []
            enroll_nos = []
            
            for row in rows:
                embedding = decode_embedding(row['face_embedding'])
                if embedding is not None:
                    embeddings.append(embedding)
                    names.append(row['name'] or 'Unknown')
                    enroll_nos.append(row['enroll_no'])
            
            return embeddings, names, enroll_nos

class AttendanceModel:
    @staticmethod
    def get_all():
        """Get all attendance records"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT enroll_no, name, date, time, latitude, longitude, liveness_score FROM attendance ORDER BY date DESC, time DESC')
            rows = cursor.fetchall()
            return [{
                'enroll_no': row['enroll_no'],
                'name': row['name'],
                'date': row['date'],
                'time': row['time'],
                'latitude': row['latitude'] or '',
                'longitude': row['longitude'] or '',
                'liveness_score': row['liveness_score'] or ''
            } for row in rows]
    
    @staticmethod
    def get_by_date(date_str):
        """Get attendance records for a specific date"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT enroll_no, name, date, time, latitude, longitude, liveness_score FROM attendance WHERE date = ? ORDER BY time DESC', (str(date_str),))
            rows = cursor.fetchall()
            return [{
                'enroll_no': row['enroll_no'],
                'name': row['name'],
                'date': row['date'],
                'time': row['time'],
                'latitude': row['latitude'] or '',
                'longitude': row['longitude'] or '',
                'liveness_score': row['liveness_score'] or ''
            } for row in rows]
    
    @staticmethod
    def get_today():
        """Get today's attendance records"""
        today = datetime.now().strftime('%Y-%m-%d')
        return AttendanceModel.get_by_date(today)
    
    @staticmethod
    def add(enroll_no, name, date, time, latitude=None, longitude=None, liveness_score=None):
        """Add attendance record"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO attendance (enroll_no, name, date, time, latitude, longitude, liveness_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(enroll_no),
                    str(name),
                    str(date),
                    str(time),
                    str(latitude) if latitude is not None else None,
                    str(longitude) if longitude is not None else None,
                    str(liveness_score) if liveness_score is not None else None
                ))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error adding attendance: {str(e)}", exc_info=True)
            return False
    
    @staticmethod
    def delete_by_index(index):
        """Delete attendance record by index (ordered by date DESC, time DESC)"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                # Get all records ordered
                cursor.execute('SELECT id FROM attendance ORDER BY date DESC, time DESC')
                rows = cursor.fetchall()
                if index < len(rows):
                    record_id = rows[index]['id']
                    cursor.execute('DELETE FROM attendance WHERE id = ?', (record_id,))
                    conn.commit()
                    return True
                return False
        except Exception as e:
            logger.error(f"Error deleting attendance: {str(e)}", exc_info=True)
            return False
    
    @staticmethod
    def export_filtered(filters=None):
        """Export filtered attendance records as DataFrame"""
        import pandas as pd
        
        with get_db() as conn:
            query = 'SELECT enroll_no, name, date, time, latitude, longitude, liveness_score FROM attendance WHERE 1=1'
            params = []
            
            if filters:
                if 'date_from' in filters and filters['date_from']:
                    query += ' AND date >= ?'
                    params.append(filters['date_from'])
                if 'date_to' in filters and filters['date_to']:
                    query += ' AND date <= ?'
                    params.append(filters['date_to'])
                if 'enroll_no' in filters and filters['enroll_no']:
                    query += ' AND enroll_no = ?'
                    params.append(str(filters['enroll_no']))
            
            query += ' ORDER BY date DESC, time DESC'
            df = pd.read_sql_query(query, conn, params=params)
            return df

class FeedbackModel:
    @staticmethod
    def add(name, message):
        """Add feedback"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT INTO feedback (name, message) VALUES (?, ?)', (str(name), str(message)))
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error adding feedback: {str(e)}", exc_info=True)
            return False

class UserModel:
    @staticmethod
    def get_all():
        """Get all users"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT email, username, password_hash FROM users')
            rows = cursor.fetchall()
            return [{
                'email': row['email'],
                'username': row['username'],
                'password_hash': row['password_hash']
            } for row in rows]
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT email, username, password_hash FROM users WHERE email = ?', (str(email).lower().strip(),))
            row = cursor.fetchone()
            if row:
                return {
                    'email': row['email'],
                    'username': row['username'],
                    'password_hash': row['password_hash']
                }
            return None
    
    @staticmethod
    def get_by_username(username):
        """Get user by username"""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT email, username, password_hash FROM users WHERE username = ?', (str(username),))
            row = cursor.fetchone()
            if row:
                return {
                    'email': row['email'],
                    'username': row['username'],
                    'password_hash': row['password_hash']
                }
            return None
    
    @staticmethod
    def add(email, username, password_hash):
        """Add new user"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                email_lower = str(email).lower().strip()
                
                # Check if email already exists
                cursor.execute('SELECT email FROM users WHERE email = ?', (email_lower,))
                if cursor.fetchone():
                    return False, "Email already registered"
                
                # Check if username already exists
                cursor.execute('SELECT username FROM users WHERE username = ?', (str(username),))
                if cursor.fetchone():
                    return False, "Username already exists"
                
                cursor.execute('INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)', 
                             (email_lower, str(username), str(password_hash)))
                conn.commit()
                return True, "User registered successfully"
        except Exception as e:
            logger.error(f"Error adding user: {str(e)}", exc_info=True)
            return False, f"Error adding user: {str(e)}"
    
    @staticmethod
    def update_password(email, new_password_hash):
        """Update user password by email"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                email_lower = str(email).lower().strip()
                cursor.execute('UPDATE users SET password_hash = ? WHERE email = ?', (str(new_password_hash), email_lower))
                conn.commit()
                if cursor.rowcount > 0:
                    return True, "Password updated successfully"
                return False, "User not found"
        except Exception as e:
            logger.error(f"Error updating password: {str(e)}", exc_info=True)
            return False, f"Error updating password: {str(e)}"
    
    @staticmethod
    def update_password_by_username(username, new_password_hash):
        """Update user password by username"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password_hash = ? WHERE username = ?', (str(new_password_hash), str(username)))
                conn.commit()
                if cursor.rowcount > 0:
                    return True, "Password updated successfully"
                return False, "User not found"
        except Exception as e:
            logger.error(f"Error updating password: {str(e)}", exc_info=True)
            return False, f"Error updating password: {str(e)}"
    
    @staticmethod
    def update_username(old_username, new_username):
        """Update username"""
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                # Check if new username already exists
                cursor.execute('SELECT username FROM users WHERE username = ?', (str(new_username),))
                if cursor.fetchone():
                    return False, "New username already exists"
                
                cursor.execute('UPDATE users SET username = ? WHERE username = ?', (str(new_username), str(old_username)))
                conn.commit()
                if cursor.rowcount > 0:
                    return True, "Username updated successfully"
                return False, "User not found"
        except Exception as e:
            logger.error(f"Error updating username: {str(e)}", exc_info=True)
            return False, f"Error updating username: {str(e)}"

