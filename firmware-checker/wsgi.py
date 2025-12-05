"""
Production WSGI entry point using Waitress server
Use this instead of Flask's built-in development server
"""
from waitress import serve
from app import app
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/waitress.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

if __name__ == '__main__':
    logger.info("Starting Firmware Checker application with Waitress...")
    logger.info("Server will listen on 0.0.0.0:5000")
    
    # Serve the Flask application with Waitress
    # - host: Listen on all interfaces
    # - port: 5000 (nginx will proxy to this)
    # - threads: Number of worker threads (adjust based on server capacity)
    # - channel_timeout: Time to wait for client request (seconds)
    # - cleanup_interval: How often to clean up inactive connections (seconds)
    serve(
        app,
        host='0.0.0.0',
        port=5000,
        threads=8,
        channel_timeout=120,
        cleanup_interval=30,
        connection_limit=1000,
        asyncore_use_poll=True
    )
