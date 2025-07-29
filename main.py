#!/usr/bin/env python3
"""
Main entry point for deployment
"""
import os
from app import app

if __name__ == '__main__':
    # Use PORT environment variable for deployment compatibility
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)