"""
Production WSGI Entry Point for MarkSmart
"""
import os
import logging
import sys
from logging.handlers import RotatingFileHandler
from app import app
import config

# Configure logging for production
if not app.debug:
    try:
        # Create logs directory if it doesn't exist
        log_dir = os.path.dirname(config.LOG_FILE)
        if log_dir and not os.path. exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Validate required config attributes
        required_config = ['LOG_FILE', 'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT', 'LOG_LEVEL']
        for attr in required_config:
            if not hasattr(config, attr):
                raise AttributeError(f"Missing required config attribute: {attr}")
        
        # Validate LOG_LEVEL
        log_level = config.LOG_LEVEL. upper()
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError(f"Invalid LOG_LEVEL: {config.LOG_LEVEL}")
        
        # Set up file logging with rotation
        file_handler = RotatingFileHandler(
            config.LOG_FILE,
            maxBytes=config.LOG_MAX_BYTES,
            backupCount=config.LOG_BACKUP_COUNT
        )
        file_handler.setLevel(getattr(logging, log_level))
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        app.logger.addHandler(file_handler)
        app.logger.setLevel(getattr(logging, log_level))
        app.logger.info('MarkSmart production server starting...')
        
    except (OSError, AttributeError, ValueError) as e:
        print(f"Failed to configure logging: {e}", file=sys.stderr)
        sys.exit(1)

# Export the application for WSGI servers
if app is None:
    raise RuntimeError("Failed to initialize Flask application")

application = app
