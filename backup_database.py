"""
Backup script for MarkSmart SQLite database
Run this daily via cron (Linux) or Task Scheduler (Windows) for automated backups
"""
import os
import shutil
import datetime
import zipfile
import config

def backup_database():
    """Create backup of database and uploads (compressed zip file)"""
    backup_dir = os.path.join(config.BASE_DIR, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f'marksmart_backup_{timestamp}.zip'
    backup_path = os.path.join(backup_dir, backup_filename)
    
    db_path = os.path.join(config.DATA_DIR, 'marksmart.db')
    
    # Create zip file with database and uploads
    with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Add database if it exists
        if os.path.exists(db_path):
            zipf.write(db_path, 'marksmart.db')
        
        # Add uploads directory
        if os.path.exists(config.UPLOADS_DIR):
            for root, dirs, files in os.walk(config.UPLOADS_DIR):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, config.BASE_DIR)
                    zipf.write(file_path, arcname)
    
    # Keep only last 30 backups (optional cleanup)
    backups = sorted([f for f in os.listdir(backup_dir) if f.startswith('marksmart_backup_') and f.endswith('.zip')])
    if len(backups) > 30:
        for old_backup in backups[:-30]:
            os.remove(os.path.join(backup_dir, old_backup))
    
    print(f"Backup created: {backup_path}")
    return backup_path

if __name__ == '__main__':
    backup_database()

