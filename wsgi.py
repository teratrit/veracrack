"""
WSGI entry point for gunicorn deployment
"""
import os
from app import create_app

# Set deployment flag
os.environ['DEPLOYMENT'] = 'true'

app = create_app()

if __name__ == "__main__":
    app.run()