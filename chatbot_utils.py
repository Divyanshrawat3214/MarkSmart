"""
Chatbot utilities for admin student statistics summary
"""
import os
import logging
from datetime import datetime
from models import StudentModel, AttendanceModel
from database import get_db
import config

logger = logging.getLogger(__name__)

def get_student_by_enroll_or_name(query):
    """Get student by enrollment number or name"""
    query = query.strip()
    if not query:
        return None
    
    student = StudentModel.get_by_enroll(query)
    if student:
        return student
    
    all_students = StudentModel.get_all()
    for s in all_students:
        if s.get('name', '').lower() == query.lower():
            return s
        if query.lower() in s.get('name', '').lower():
            return s
    
    return None

def compute_student_statistics(enroll_no):
    """Compute attendance statistics for a student"""
    student = StudentModel.get_by_enroll(enroll_no)
    if not student:
        return None
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT date, time FROM attendance 
            WHERE enroll_no = ? 
            ORDER BY date ASC, time ASC
        ''', (str(enroll_no),))
        attendance_records = cursor.fetchall()
    
    if not attendance_records:
        return {
            'student': student,
            'total_days_present': 0,
            'total_days_absent': 0,
            'total_days_in_period': 0,
            'attendance_percentage': 0.0,
            'first_attendance_date': None,
            'last_attendance_date': None,
            'monthly_breakdown': {}
        }
    
    unique_dates = set()
    monthly_count = {}
    
    for record in attendance_records:
        date_str = record['date']
        unique_dates.add(date_str)
        
        try:
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            month_key = date_obj.strftime('%Y-%m')
            monthly_count[month_key] = monthly_count.get(month_key, 0) + 1
        except:
            pass
    
    first_date = min(unique_dates) if unique_dates else None
    last_date = max(unique_dates) if unique_dates else None
    
    first_record = attendance_records[0] if attendance_records else None
    last_record = attendance_records[-1] if attendance_records else None
    
    first_attendance_date = first_record['date'] if first_record else None
    last_attendance_date = last_record['date'] if last_record else None
    
    total_days_present = len(unique_dates)
    
    if first_date and last_date:
        try:
            start = datetime.strptime(first_date, '%Y-%m-%d')
            end = datetime.strptime(last_date, '%Y-%m-%d')
            total_days_in_period = (end - start).days + 1
            total_days_absent = max(0, total_days_in_period - total_days_present)
        except:
            total_days_in_period = total_days_present
            total_days_absent = 0
    else:
        total_days_in_period = total_days_present
        total_days_absent = 0
    
    attendance_percentage = (total_days_present / total_days_in_period * 100) if total_days_in_period > 0 else 0.0
    
    return {
        'student': student,
        'total_days_present': total_days_present,
        'total_days_absent': total_days_absent,
        'total_days_in_period': total_days_in_period,
        'attendance_percentage': round(attendance_percentage, 2),
        'first_attendance_date': first_attendance_date,
        'last_attendance_date': last_attendance_date,
        'monthly_breakdown': monthly_count
    }

def generate_gemini_summary(stats_data):
    """Generate natural language summary using Gemini API"""
    if not config.GEMINI_API_KEY:
        logger.error("GEMINI_API_KEY not configured")
        return "Error: AI summary service not available."
    
    try:
        import google.generativeai as genai
        genai.configure(api_key=config.GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-pro')
        
        student = stats_data['student']
        
        prompt = f"""You are an administrative assistant generating a professional student attendance summary.

Use ONLY the following data. Do NOT assume or invent any values.

Student Information:
- Name: {student.get('name', 'N/A')}
- Enrollment Number: {student.get('enroll_no', 'N/A')}
- Class: {student.get('class', 'N/A')}

Attendance Statistics:
- Total Days Present: {stats_data['total_days_present']}
- Total Days Absent: {stats_data['total_days_absent']}
- Total Days in Period: {stats_data['total_days_in_period']}
- Attendance Percentage: {stats_data['attendance_percentage']}%
- First Attendance Date: {stats_data['first_attendance_date'] or 'N/A'}
- Last Attendance Date: {stats_data['last_attendance_date'] or 'N/A'}
- Monthly Breakdown: {stats_data['monthly_breakdown']}

Generate a concise, professional administrative summary (2-3 sentences) that includes:
1. Student identification
2. Attendance percentage and total days present/absent
3. Brief observation about attendance pattern

Keep the tone professional and administrative. Use only the provided data."""
        
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        logger.error(f"Error generating Gemini summary: {str(e)}", exc_info=True)
        return "Error generating summary. Please check logs."

