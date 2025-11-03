#!/usr/bin/env python3
"""
Production server launcher using Waitress WSGI server
"""

import os
from waitress import serve
from app import app, init_db, cleanup_orphaned_checks

def run_production_server():
    """Run the application with Waitress production server"""
    
    # Configuration from environment
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', '5000'))
    threads = int(os.environ.get('WAITRESS_THREADS', '4'))
    
    print("=" * 80)
    print("FIRMWARE CHECKER - PRODUCTION SERVER")
    print("=" * 80)
    print("Initializing database...")
    
    # Initialize database
    init_db()
    
    print("Database initialized successfully!")
    
    # Cleanup orphaned running checks on startup
    cleanup_orphaned_checks()
    
    print("")
    print(f"Starting Waitress WSGI server on {host}:{port}")
    print(f"Threads: {threads}")
    print(f"Access the application at: http://localhost:{port}")
    print("=" * 80)
    print("Production server is running...")
    print("Press Ctrl+C to stop")
    print("=" * 80)
    
    # Run with Waitress
    serve(
        app,
        host=host,
        port=port,
        threads=threads,
        url_scheme='http',
        channel_timeout=120,  # Longer timeout for firmware checks
        _quiet=False
    )

if __name__ == '__main__':
    run_production_server()
