#!/usr/bin/env python3
"""
Unified Password Recovery Tool - Web Interface
Supports VeraCrypt drive headers and KeePass databases
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import json
import threading
import time
from datetime import datetime
import tempfile
import base64

from core.veracrypt_handler import VeraCryptHandler
from core.keepass_handler import KeePassHandler
from core.password_generator import PasswordGenerator
from core.session_manager import SessionManager
from core.utils import detect_file_type, format_time, setup_logging

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Global variables for session management
active_sessions = {}
session_lock = threading.Lock()

logger = setup_logging()

@app.route('/')
def index():
    """Main page with tool selection and upload interface"""
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    try:
        if 'file' not in request.files and 'hash_data' not in request.form:
            return jsonify({'error': 'No file or hash data provided'}), 400
        
        session_id = f"session_{int(time.time())}"
        temp_dir = tempfile.mkdtemp(prefix=f"recovery_{session_id}_")
        
        file_info = {}
        
        # Handle file upload
        if 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            file_path = os.path.join(temp_dir, file.filename)
            file.save(file_path)
            
            file_type = detect_file_type(file_path)
            file_info = {
                'type': file_type,
                'path': file_path,
                'name': file.filename,
                'size': os.path.getsize(file_path)
            }
        
        # Handle hash data input
        elif 'hash_data' in request.form and request.form['hash_data']:
            hash_data = request.form['hash_data']
            partition_data = request.form.get('partition_data', '')
            
            # Save hash data to temporary file
            hash_file = os.path.join(temp_dir, 'veracrypt_data.bin')
            try:
                # Try to decode as base64 first
                data = base64.b64decode(hash_data)
            except:
                # If not base64, treat as hex
                data = bytes.fromhex(hash_data.replace(' ', '').replace('\n', ''))
            
            with open(hash_file, 'wb') as f:
                f.write(data)
            
            file_info = {
                'type': 'veracrypt',
                'path': hash_file,
                'name': 'VeraCrypt Data',
                'size': len(data),
                'partition_data': partition_data
            }
        else:
            return jsonify({'error': 'No valid data provided'}), 400
        
        # Create session
        with session_lock:
            active_sessions[session_id] = {
                'id': session_id,
                'file_info': file_info,
                'temp_dir': temp_dir,
                'status': 'ready',
                'progress': 0,
                'attempts': 0,
                'start_time': None,
                'estimated_time': None,
                'found_password': None,
                'log_messages': []
            }
        
        return jsonify({
            'session_id': session_id,
            'file_info': file_info,
            'message': f'File analyzed. Type: {file_info["type"]}'
        })
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/start_recovery', methods=['POST'])
def start_recovery():
    """Start password recovery process"""
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        
        if session_id not in active_sessions:
            return jsonify({'error': 'Invalid session'}), 400
        
        session = active_sessions[session_id]
        
        if session['status'] == 'running':
            return jsonify({'error': 'Recovery already in progress'}), 400
        
        # Get recovery parameters
        password_hints = data.get('password_hints', [])
        dictionary_file = data.get('dictionary_file', '')
        max_length = data.get('max_length', 20)
        use_patterns = data.get('use_patterns', True)
        use_substitutions = data.get('use_substitutions', True)
        thread_count = data.get('thread_count', 4)
        
        # Update session
        session['status'] = 'running'
        session['start_time'] = datetime.now()
        session['progress'] = 0
        session['attempts'] = 0
        
        # Start recovery in background thread
        recovery_thread = threading.Thread(
            target=run_recovery,
            args=(session_id, password_hints, dictionary_file, max_length, 
                  use_patterns, use_substitutions, thread_count)
        )
        recovery_thread.daemon = True
        recovery_thread.start()
        
        return jsonify({'message': 'Recovery started', 'session_id': session_id})
        
    except Exception as e:
        logger.error(f"Start recovery error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/session_status/<session_id>')
def session_status(session_id):
    """Get current session status"""
    try:
        if session_id not in active_sessions:
            return jsonify({'error': 'Session not found'}), 404
        
        session = active_sessions[session_id]
        
        # Calculate elapsed time and ETA
        elapsed_time = None
        eta = None
        if session['start_time']:
            elapsed_time = (datetime.now() - session['start_time']).total_seconds()
            if session['progress'] > 0:
                total_time = elapsed_time / (session['progress'] / 100)
                eta = total_time - elapsed_time
        
        return jsonify({
            'session_id': session_id,
            'status': session['status'],
            'progress': session['progress'],
            'attempts': session['attempts'],
            'elapsed_time': elapsed_time,
            'eta': eta,
            'found_password': session['found_password'],
            'log_messages': session['log_messages'][-50:]  # Last 50 messages
        })
        
    except Exception as e:
        logger.error(f"Status error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stop_recovery/<session_id>', methods=['POST'])
def stop_recovery(session_id):
    """Stop recovery process"""
    try:
        if session_id not in active_sessions:
            return jsonify({'error': 'Session not found'}), 404
        
        session = active_sessions[session_id]
        session['status'] = 'stopped'
        
        return jsonify({'message': 'Recovery stopped'})
        
    except Exception as e:
        logger.error(f"Stop recovery error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def run_recovery(session_id, password_hints, dictionary_file, max_length, 
                use_patterns, use_substitutions, thread_count):
    """Run password recovery in background thread"""
    try:
        session = active_sessions[session_id]
        file_info = session['file_info']
        
        # Initialize password generator
        password_gen = PasswordGenerator(
            hints=password_hints,
            dictionary_file=dictionary_file,
            max_length=max_length,
            use_patterns=use_patterns,
            use_substitutions=use_substitutions
        )
        
        # Initialize appropriate handler
        if file_info['type'] == 'veracrypt':
            handler = VeraCryptHandler(file_info['path'])
            partition_data = file_info.get('partition_data', '')
            if partition_data:
                handler.set_partition_data(partition_data)
        elif file_info['type'] == 'keepass':
            handler = KeePassHandler(file_info['path'])
        else:
            session['status'] = 'error'
            session['log_messages'].append('Unsupported file type')
            return
        
        # Generate password list
        session['log_messages'].append('Generating password candidates...')
        passwords = list(password_gen.generate_passwords())
        total_passwords = len(passwords)
        
        session['log_messages'].append(f'Generated {total_passwords} password candidates')
        
        # Test passwords
        found = False
        for i, password in enumerate(passwords):
            if session['status'] != 'running':
                break
            
            session['attempts'] += 1
            session['progress'] = (i / total_passwords) * 100
            
            if i % 100 == 0:
                session['log_messages'].append(f'Tested {i}/{total_passwords} passwords...')
            
            try:
                if handler.test_password(password):
                    session['found_password'] = password
                    session['status'] = 'success'
                    session['log_messages'].append(f'SUCCESS! Password found: {password}')
                    found = True
                    break
            except Exception as e:
                if i % 1000 == 0:  # Log errors occasionally
                    session['log_messages'].append(f'Error testing password: {str(e)}')
        
        if not found and session['status'] == 'running':
            session['status'] = 'completed'
            session['log_messages'].append('Password recovery completed - no match found')
        
        session['progress'] = 100
        
    except Exception as e:
        logger.error(f"Recovery error: {str(e)}")
        session['status'] = 'error'
        session['log_messages'].append(f'Error: {str(e)}')

if __name__ == '__main__':
    print("Starting Unified Password Recovery Tool...")
    print("Access the web interface at: http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
