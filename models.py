"""
Database models for MarkSmart using SQLite
This file replaces the Excel-based storage with proper database operations
"""
import os
import logging
from typing import Optional, Dict, List, Tuple, Any
from datetime import datetime
import face_recognition
from PIL import Image
import pandas as pd
import numpy as np

from database import get_db, encode_embedding, decode_embedding

logger = logging.getLogger(__name__)


def compute_face_embedding(image_path: str) -> Optional[np.ndarray]:
    """
    Compute face embedding from image file
    
    Args:
        image_path: Path to the image file
        
    Returns: 
        numpy array with face encoding or None if no face found
    """
    try:
        if not os.path.exists(image_path):
            logger.warning(f"Image file not found:  {image_path}")
            return None
            
        image = face_recognition.load_image_file(image_path)
        encodings = face_recognition.face_encodings(image)
        
        if len(encodings) > 0:
            return encodings[0]
        
        logger.warning(f"No face detected in image: {image_path}")
        return None
        
    except Exception as e:
        logger.error(f"Error computing face embedding from {image_path}: {str(e)}", exc_info=True)
        return None


class StudentModel:
    """Model for student database operations"""
    
    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """
        Get all students from database
        
        Returns:
            List of student dictionaries
        """
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT enroll_no, name, class, photo_filename, face_embedding, 
                           password_hash, email, metadata 
                    FROM students
                ''')
                rows = cursor.fetchall()
                
                return [{
                    'enroll_no': row['enroll_no'],
                    'name': row['name'],
                    'class': row. get('class') or '',
                    'photo_filename':  row.get('photo_filename') or '',
                    'face_embedding': row.get('face_embedding'),
                    'password_hash':  row.get('password_hash'),
                    'email': row. get('email'),
                    'metadata': row.get('metadata') or ''
                } for row in rows]
                
        except Exception as e:
            logger.error(f"Error fetching all students: {str(e)}", exc_info=True)
            return []
    
    @staticmethod
    def get_by_enroll(enroll_no: str) -> Optional[Dict[str, Any]]:
        """
        Get student by enrollment number
        
        Args:
            enroll_no:  Student enrollment number
            
        Returns: 
            Student dictionary or None if not found
        """
        try: 
            with get_db() as conn:
                cursor = conn. cursor()
                cursor.execute('''
                    SELECT enroll_no, name, class, photo_filename, face_embedding, 
                           password_hash, email, metadata 
                    FROM students 
                    WHERE enroll_no = ?
                ''', (str(enroll_no).strip(),))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'enroll_no': row['enroll_no'],
                        'name':  row['name'],
                        'class': row.get('class') or '',
                        'photo_filename': row.get('photo_filename') or '',
                        'face_embedding': row.get('face_embedding'),
                        'password_hash': row.get('password_hash'),
                        'email': row.get('email'),
                        'metadata': row. get('metadata') or ''
                    }
                return None
                
        except Exception as e:
            logger.error(f"Error fetching student {enroll_no}: {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def add(enroll_no: str, name:  str, class_name: str = '', photo_filename: str = '', 
            face_embedding: Optional[np.ndarray] = None, password_hash: Optional[str] = None, 
            email: Optional[str] = None, metadata: str = '') -> Tuple[bool, str]:
        """
        Add new student to database
        
        Args:
            enroll_no:  Student enrollment number
            name: Student name
            class_name: Student class
            photo_filename:  Filename of student photo
            face_embedding: Face encoding numpy array
            password_hash:  Hashed password
            email: Student email
            metadata: Additional metadata
            
        Returns:
            Tuple of (success:  bool, message: str)
        """
        try:
            enroll_no = str(enroll_no).strip()
            name = str(name).strip()
            
            if not enroll_no or not name:
                return False, "Enrollment number and name are required"
            
            with get_db() as conn:
                cursor = conn.cursor()
                
                # Check if enroll_no already exists
                cursor.execute('SELECT enroll_no FROM students WHERE enroll_no = ?', (enroll_no,))
                if cursor.fetchone():
                    return False, "Enrollment number already exists"
                
                # Encode embedding
                embedding_blob = encode_embedding(face_embedding) if face_embedding is not None else None
                
                cursor.execute('''
                    INSERT INTO students 
                    (enroll_no, name, class, photo_filename, face_embedding, 
                     password_hash, email, metadata, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    enroll_no,
                    name,
                    str(class_name).strip(),
                    str(photo_filename).strip(),
                    embedding_blob,
                    password_hash,
                    email. lower().strip() if email else None,
                    str(metadata).strip()
                ))
                conn.commit()
                logger.info(f"Student {enroll_no} added successfully")
                return True, "Student added successfully"
                
        except Exception as e:
            logger.error(f"Error adding student:  {str(e)}", exc_info=True)
            return False, f"Error adding student: {str(e)}"
    
    @staticmethod
    def update(enroll_no: str, name: Optional[str] = None, class_name: Optional[str] = None, 
               photo_filename: Optional[str] = None, face_embedding: Optional[np.ndarray] = None, 
               metadata: Optional[str] = None) -> Tuple[bool, str]:
        """
        Update student information
        
        Args: 
            enroll_no: Student enrollment number
            name: Updated name
            class_name: Updated class
            photo_filename: Updated photo filename
            face_embedding: Updated face embedding
            metadata: Updated metadata
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            enroll_no = str(enroll_no).strip()
            
            with get_db() as conn:
                cursor = conn.cursor()
                
                # Check if student exists
                cursor.execute('SELECT enroll_no FROM students WHERE enroll_no = ?', (enroll_no,))
                if not cursor.fetchone():
                    return False, "Student not found"
                
                # Build update query dynamically
                updates = []
                params = []
                
                if name is not None:
                    updates.append('name = ? ')
                    params.append(str(name).strip())
                    
                if class_name is not None:
                    updates.append('class = ?')
                    params.append(str(class_name).strip())
                    
                if photo_filename is not None:
                    updates.append('photo_filename = ?')
                    params.append(str(photo_filename).strip())
                    
                if face_embedding is not None:
                    updates. append('face_embedding = ?')
                    params.append(encode_embedding(face_embedding))
                    
                if metadata is not None:
                    updates.append('metadata = ?')
                    params.append(str(metadata).strip())
                
                if not updates:
                    return False, "No fields to update"
                
                updates. append('updated_at = CURRENT_TIMESTAMP')
                params.append(enroll_no)
                
                query = f'UPDATE students SET {", ".join(updates)} WHERE enroll_no = ? '
                cursor.execute(query, params)
                conn.commit()
                logger.info(f"Student {enroll_no} updated successfully")
                return True, "Student updated successfully"
                
        except Exception as e:
            logger.error(f"Error updating student: {str(e)}", exc_info=True)
            return False, f"Error updating student: {str(e)}"
    
    @staticmethod
    def delete(enroll_no:  str) -> Tuple[bool, str]:
        """
        Delete student from database
        
        Args:
            enroll_no:  Student enrollment number
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            enroll_no = str(enroll_no).strip()
            
            with get_db() as conn:
                cursor = conn. cursor()
                cursor.execute('DELETE FROM students WHERE enroll_no = ?', (enroll_no,))
                
                if cursor.rowcount > 0:
                    conn. commit()
                    logger.info(f"Student {enroll_no} deleted successfully")
                    return True, "Student deleted successfully"
                else:
                    return False, "Student not found"
                    
        except Exception as e:
            logger.error(f"Error deleting student: {str(e)}", exc_info=True)
            return False, f"Error deleting student: {str(e)}"
    
    @staticmethod
    def get_all_embeddings() -> Tuple[List[np.ndarray], List[str], List[str]]:
        """
        Get all face embeddings for facial recognition matching
        
        Returns:
            Tuple of (embeddings, names, enroll_nos)
        """
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT enroll_no, name, face_embedding 
                    FROM students 
                    WHERE face_embedding IS NOT NULL
                ''')
                rows = cursor. fetchall()
                
                embeddings = []
                names = []
                enroll_nos = []
                
                for row in rows:
                    embedding = decode_embedding(row['face_embedding'])
                    if embedding is not None:
                        embeddings.append(embedding)
                        names.append(row['name'] or 'Unknown')
                        enroll_nos.append(row['enroll_no'])
                
                logger.debug(f"Retrieved {len(embeddings)} face embeddings")
                return embeddings, names, enroll_nos
                
        except Exception as e: 
            logger.error(f"Error getting embeddings: {str(e)}", exc_info=True)
            return [], [], []


class AttendanceModel:
    """Model for attendance database operations"""
    
    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """
        Get all attendance records
        
        Returns:
            List of attendance record dictionaries
        """
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT enroll_no, name, date, time, latitude, longitude, liveness_score 
                    FROM attendance 
                    ORDER BY date DESC, time DESC
                ''')
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
                
        except Exception as e:
            logger.error(f"Error fetching all attendance:  {str(e)}", exc_info=True)
            return []
    
    @staticmethod
    def get_by_date(date_str: str) -> List[Dict[str, Any]]: 
        """
        Get attendance records for a specific date
        
        Args:
            date_str:  Date string in format YYYY-MM-DD
            
        Returns:
            List of attendance records for that date
        """
        try: 
            with get_db() as conn:
                cursor = conn. cursor()
                cursor.execute('''
                    SELECT enroll_no, name, date, time, latitude, longitude, liveness_score 
                    FROM attendance 
                    WHERE date = ?  
                    ORDER BY time DESC
                ''', (str(date_str).strip(),))
                
                rows = cursor.fetchall()
                return [{
                    'enroll_no': row['enroll_no'],
                    'name': row['name'],
                    'date': row['date'],
                    'time': row['time'],
                    'latitude': row['latitude'] or '',
                    'longitude': row['longitude'] or '',
                    'liveness_score':  row['liveness_score'] or ''
                } for row in rows]
                
        except Exception as e:
            logger.error(f"Error fetching attendance for date {date_str}: {str(e)}", exc_info=True)
            return []
    
    @staticmethod
    def get_today() -> List[Dict[str, Any]]:
        """
        Get today's attendance records
        
        Returns:
            List of today's attendance records
        """
        today = datetime.now().strftime('%Y-%m-%d')
        return AttendanceModel.get_by_date(today)
    
    @staticmethod
    def add(enroll_no: str, name: str, date: str, time: str, latitude: Optional[str] = None, 
            longitude: Optional[str] = None, liveness_score: Optional[float] = None) -> Tuple[bool, str]:
        """
        Add attendance record
        
        Args: 
            enroll_no: Student enrollment number
            name: Student name
            date: Date in format YYYY-MM-DD
            time: Time in format HH: MM: SS
            latitude: Latitude coordinate
            longitude: Longitude coordinate
            liveness_score: Liveness detection score
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            enroll_no = str(enroll_no).strip()
            name = str(name).strip()
            date = str(date).strip()
            time = str(time).strip()
            
            if not enroll_no or not name or not date or not time:
                return False, "Enrollment number, name, date, and time are required"
            
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO attendance (enroll_no, name, date, time, latitude, longitude, liveness_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    enroll_no,
                    name,
                    date,
                    time,
                    str(latitude).strip() if latitude is not None else None,
                    str(longitude).strip() if longitude is not None else None,
                    float(liveness_score) if liveness_score is not None else None
                ))
                conn.commit()
                logger.info(f"Attendance record added for {enroll_no} on {date} at {time}")
                return True, "Attendance record added successfully"
                
        except ValueError as e:
            logger.error(f"Invalid data type for attendance:  {str(e)}", exc_info=True)
            return False, f"Invalid data format: {str(e)}"
        except Exception as e:
            logger.error(f"Error adding attendance:  {str(e)}", exc_info=True)
            return False, f"Error adding attendance: {str(e)}"
    
    @staticmethod
    def delete_by_index(index: int) -> Tuple[bool, str]:
        """
        Delete attendance record by index (ordered by date DESC, time DESC)
        
        Args:
            index: Index of record to delete
            
        Returns: 
            Tuple of (success:  bool, message: str)
        """
        try:
            if not isinstance(index, int) or index < 0:
                return False, "Invalid index"
            
            with get_db() as conn:
                cursor = conn.cursor()
                # Get all records ordered
                cursor.execute('SELECT id FROM attendance ORDER BY date DESC, time DESC')
                rows = cursor.fetchall()
                
                if index < len(rows):
                    record_id = rows[index]['id']
                    cursor.execute('DELETE FROM attendance WHERE id = ? ', (record_id,))
                    conn.commit()
                    logger.info(f"Attendance record {record_id} deleted successfully")
                    return True, "Attendance record deleted successfully"
                else:
                    return False, "Index out of range"
                    
        except Exception as e:
            logger.error(f"Error deleting attendance: {str(e)}", exc_info=True)
            return False, f"Error deleting attendance: {str(e)}"
    
    @staticmethod
    def export_filtered(filters: Optional[Dict[str, Any]] = None) -> pd.DataFrame:
        """
        Export filtered attendance records as DataFrame
        
        Args:
            filters: Dictionary with optional keys:  date_from, date_to, enroll_no
            
        Returns:
            pandas DataFrame with filtered records
        """
        try: 
            with get_db() as conn:
                query = '''
                    SELECT enroll_no, name, date, time, latitude, longitude, liveness_score 
                    FROM attendance 
                    WHERE 1=1
                '''
                params = []
                
                if filters:
                    if filters.get('date_from'):
                        query += ' AND date >= ?'
                        params.append(str(filters['date_from']).strip())
                    if filters.get('date_to'):
                        query += ' AND date <= ?'
                        params. append(str(filters['date_to']).strip())
                    if filters.get('enroll_no'):
                        query += ' AND enroll_no = ?'
                        params.append(str(filters['enroll_no']).strip())
                
                query += ' ORDER BY date DESC, time DESC'
                df = pd.read_sql_query(query, conn, params=params)
                logger.info(f"Exported {len(df)} attendance records")
                return df
                
        except Exception as e:
            logger. error(f"Error exporting attendance: {str(e)}", exc_info=True)
            return pd.DataFrame()


class FeedbackModel:
    """Model for feedback database operations"""
    
    @staticmethod
    def add(name: str, message: str) -> Tuple[bool, str]: 
        """
        Add feedback to database
        
        Args: 
            name: Name of person providing feedback
            message: Feedback message
            
        Returns: 
            Tuple of (success: bool, message: str)
        """
        try:
            name = str(name).strip()
            message = str(message).strip()
            
            if not name or not message:
                return False, "Name and message are required"
            
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO feedback (name, message) VALUES (?, ?)',
                    (name, message)
                )
                conn.commit()
                logger.info(f"Feedback added from {name}")
                return True, "Feedback submitted successfully"
                
        except Exception as e:
            logger.error(f"Error adding feedback: {str(e)}", exc_info=True)
            return False, f"Error adding feedback: {str(e)}"


class UserModel:
    """Model for user/admin database operations"""
    
    @staticmethod
    def get_all() -> List[Dict[str, Any]]:
        """
        Get all users
        
        Returns:
            List of user dictionaries
        """
        try: 
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT email, username, password_hash FROM users')
                rows = cursor. fetchall()
                
                return [{
                    'email': row['email'],
                    'username': row['username'],
                    'password_hash': row['password_hash']
                } for row in rows]
                
        except Exception as e:
            logger. error(f"Error fetching all users: {str(e)}", exc_info=True)
            return []
    
    @staticmethod
    def get_by_email(email: str) -> Optional[Dict[str, Any]]: 
        """
        Get user by email
        
        Args: 
            email: User email address
            
        Returns:
            User dictionary or None if not found
        """
        try:
            email = str(email).lower().strip()
            
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT email, username, password_hash FROM users WHERE email = ?',
                    (email,)
                )
                row = cursor.fetchone()
                
                if row:
                    return {
                        'email':  row['email'],
                        'username': row['username'],
                        'password_hash': row['password_hash']
                    }
                return None
                
        except Exception as e:
            logger.error(f"Error fetching user by email: {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def get_by_username(username: str) -> Optional[Dict[str, Any]]:
        """
        Get user by username
        
        Args:
            username: Username to search for
            
        Returns: 
            User dictionary or None if not found
        """
        try: 
            username = str(username).strip()
            
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT email, username, password_hash FROM users WHERE username = ?',
                    (username,)
                )
                row = cursor.fetchone()
                
                if row:
                    return {
                        'email': row['email'],
                        'username': row['username'],
                        'password_hash': row['password_hash']
                    }
                return None
                
        except Exception as e:
            logger.error(f"Error fetching user by username:  {str(e)}", exc_info=True)
            return None
    
    @staticmethod
    def add(email: str, username: str, password_hash: str) -> Tuple[bool, str]:
        """
        Add new user to database
        
        Args:
            email: User email address
            username: Username
            password_hash:  Hashed password
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            email = str(email).lower().strip()
            username = str(username).strip()
            password_hash = str(password_hash).strip()
            
            if not email or not username or not password_hash:
                return False, "Email, username, and password are required"
            
            with get_db() as conn:
                cursor = conn.cursor()
                
                # Check if email already exists
                cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
                if cursor. fetchone():
                    return False, "Email already registered"
                
                # Check if username already exists
                cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
                if cursor.fetchone():
                    return False, "Username already exists"
                
                cursor.execute(
                    'INSERT INTO users (email, username, password_hash) VALUES (?, ?, ?)',
                    (email, username, password_hash)
                )
                conn.commit()
                logger.info(f"User {username} registered successfully")
                return True, "User registered successfully"
                
        except Exception as e:
            logger.error(f"Error adding user: {str(e)}", exc_info=True)
            return False, f"Error adding user: {str(e)}"
    
    @staticmethod
    def update_password(email: str, new_password_hash: str) -> Tuple[bool, str]:
        """
        Update user password by email
        
        Args: 
            email: User email address
            new_password_hash: New hashed password
            
        Returns: 
            Tuple of (success:  bool, message: str)
        """
        try:
            email = str(email).lower().strip()
            new_password_hash = str(new_password_hash).strip()
            
            if not email or not new_password_hash:
                return False, "Email and password hash are required"
            
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'UPDATE users SET password_hash = ? WHERE email = ?',
                    (new_password_hash, email)
                )
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger. info(f"Password updated for user {email}")
                    return True, "Password updated successfully"
                else:
                    return False, "User not found"
                    
        except Exception as e:
            logger.error(f"Error updating password: {str(e)}", exc_info=True)
            return False, f"Error updating password:  {str(e)}"
    
    @staticmethod
    def update_password_by_username(username: str, new_password_hash: str) -> Tuple[bool, str]: 
        """
        Update user password by username
        
        Args: 
            username: Username
            new_password_hash: New hashed password
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            username = str(username).strip()
            new_password_hash = str(new_password_hash).strip()
            
            if not username or not new_password_hash:
                return False, "Username and password hash are required"
            
            with get_db() as conn:
                cursor = conn. cursor()
                cursor.execute(
                    'UPDATE users SET password_hash = ? WHERE username = ? ',
                    (new_password_hash, username)
                )
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger. info(f"Password updated for user {username}")
                    return True, "Password updated successfully"
                else:
                    return False, "User not found"
                    
        except Exception as e: 
            logger.error(f"Error updating password: {str(e)}", exc_info=True)
            return False, f"Error updating password: {str(e)}"
    
    @staticmethod
    def update_username(old_username: str, new_username: str) -> Tuple[bool, str]:
        """
        Update username
        
        Args:
            old_username: Current username
            new_username: New username
            
        Returns: 
            Tuple of (success: bool, message: str)
        """
        try:
            old_username = str(old_username).strip()
            new_username = str(new_username).strip()
            
            if not old_username or not new_username: 
                return False, "Both usernames are required"
            
            if old_username == new_username: 
                return False, "New username must be different from current username"
            
            with get_db() as conn:
                cursor = conn.cursor()
                
                # Check if new username already exists
                cursor.execute('SELECT username FROM users WHERE username = ?', (new_username,))
                if cursor.fetchone():
                    return False, "New username already exists"
                
                cursor.execute(
                    'UPDATE users SET username = ? WHERE username = ?',
                    (new_username, old_username)
                )
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"Username updated from {old_username} to {new_username}")
                    return True, "Username updated successfully"
                else: 
                    return False, "User not found"
                    
        except Exception as e:
            logger.error(f"Error updating username: {str(e)}", exc_info=True)
            return False, f"Error updating username:  {str(e)}"
