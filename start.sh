#!/bin/bash
# Startup script for deployment

# Install dependencies
pip install flask pycryptodome pykeepass psutil sqlalchemy psycopg2-binary gunicorn

# Start the application with gunicorn for production
if [ "$DEPLOYMENT" = "true" ]; then
    exec gunicorn --bind 0.0.0.0:$PORT --workers 4 --timeout 300 app:app
else
    # Development mode
    exec python app.py
fi