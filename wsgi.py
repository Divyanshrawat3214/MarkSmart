"""
Production WSGI Entry Point for MarkSmart
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from app import app
import config

# Configure logging for production
if not app.debug:
    # Create logs directory if it doesn't exist
    log_dir = os.path.dirname(config.LOG_FILE)
    os.makedirs(log_dir, exist_ok=True)
    
    # Set up file logging with rotation
    file_handler = RotatingFileHandler(
        config.LOG_FILE,
        maxBytes=config.LOG_MAX_BYTES,
        backupCount=config.LOG_BACKUP_COUNT
    )
    file_handler.setLevel(getattr(logging, config.LOG_LEVEL))
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    app.logger.addHandler(file_handler)
    app.logger.setLevel(getattr(logging, config.LOG_LEVEL))
    app.logger.info('MarkSmart production server starting...')

# Export the application for WSGI servers
application = app

if __name__ == "__main__":
    # For testing the WSGI entry point
    app.run(host=config.HOST, port=config.PORT, debug=not config.IS_PRODUCTION)

