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
from core.bruteforce_generator import BruteForceGenerator, OptimizedCharsetAnalyzer, create_optimized_generator
try:
    from core.gpu_bruteforce import GPUBruteForcer, SmartBruteForcer, get_gpu_info, test_gpu_performance
    HAS_GPU_SUPPORT = True
except ImportError:
    HAS_GPU_SUPPORT = False

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
        
        # New brute force parameters
        use_brute_force = data.get('use_brute_force', False)
        brute_force_charset = data.get('brute_force_charset', '')
        brute_force_min_length = data.get('brute_force_min_length', 1)
        brute_force_max_length = data.get('brute_force_max_length', 20)
        use_gpu = data.get('use_gpu', False)
        
        # Update session
        session['status'] = 'running'
        session['start_time'] = datetime.now()
        session['progress'] = 0
        session['attempts'] = 0
        session['use_brute_force'] = use_brute_force
        session['use_gpu'] = use_gpu
        
        # Start recovery in background thread
        recovery_thread = threading.Thread(
            target=run_recovery,
            args=(session_id, password_hints, dictionary_file, max_length, 
                  use_patterns, use_substitutions, thread_count, use_brute_force,
                  brute_force_charset, brute_force_min_length, brute_force_max_length, use_gpu)
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
                use_patterns, use_substitutions, thread_count, use_brute_force=False,
                brute_force_charset='', brute_force_min_length=1, brute_force_max_length=20, use_gpu=False):
    """Run password recovery in background thread"""
    try:
        session = active_sessions[session_id]
        file_info = session['file_info']
        
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
        
        # Choose generation strategy based on parameters
        if use_brute_force:
            session['log_messages'].append('Using brute force mode...')
            session['log_messages'].append(f'Charset: {brute_force_charset or "default alphanumeric"}')
            session['log_messages'].append(f'Length range: {brute_force_min_length}-{brute_force_max_length}')
            
            # Initialize brute force generator
            charset_info = {
                'known_chars': brute_force_charset if brute_force_charset else None
            }
            
            bf_gen = create_optimized_generator(
                charset_info, 
                (brute_force_min_length, brute_force_max_length)
            )
            
            session['log_messages'].append(f'Total keyspace: {bf_gen.total_keyspace:,} passwords')
            
            if use_gpu and HAS_GPU_SUPPORT:
                session['log_messages'].append('Attempting GPU acceleration...')
                try:
                    smart_bf = SmartBruteForcer(handler, brute_force_charset)
                    gpu_bf = smart_bf.create_gpu_bruteforcer(
                        brute_force_charset or bf_gen.charset, 
                        brute_force_min_length, 
                        brute_force_max_length
                    )
                    
                    session['log_messages'].append('GPU initialization successful')
                    
                    # GPU brute force with progress tracking
                    def progress_callback(tested, rate, elapsed):
                        session['attempts'] = tested
                        progress = min((tested / bf_gen.total_keyspace) * 100, 99.9) if bf_gen.total_keyspace > 0 else 0
                        session['progress'] = progress
                        session['log_messages'].append(f'GPU: {tested:,} tested, {rate:.0f}/sec, {progress:.2f}%')
                    
                    import threading
                    stop_event = threading.Event()
                    
                    def check_stop():
                        while session['status'] == 'running':
                            time.sleep(1)
                        stop_event.set()
                    
                    stop_thread = threading.Thread(target=check_stop)
                    stop_thread.daemon = True
                    stop_thread.start()
                    
                    found_password = gpu_bf.run_brute_force(progress_callback, stop_event)
                    
                    if found_password:
                        session['found_password'] = found_password
                        session['status'] = 'success'
                        session['log_messages'].append(f'SUCCESS! Password found: {found_password}')
                        session['progress'] = 100
                        return
                        
                except Exception as e:
                    session['log_messages'].append(f'GPU acceleration failed: {str(e)}')
                    session['log_messages'].append('Falling back to CPU brute force...')
            
            # CPU brute force
            session['log_messages'].append('Running CPU brute force...')
            total_tested = 0
            found = False
            
            for length, batch in bf_gen.generate_incremental(batch_size=1000):
                if session['status'] != 'running':
                    break
                
                session['log_messages'].append(f'Testing length {length}...')
                
                for password in batch:
                    if session['status'] != 'running':
                        break
                    
                    total_tested += 1
                    session['attempts'] = total_tested
                    
                    try:
                        if handler.test_password(password):
                            session['found_password'] = password
                            session['status'] = 'success'
                            session['log_messages'].append(f'SUCCESS! Password found: {password}')
                            found = True
                            break
                    except Exception as e:
                        if total_tested % 10000 == 0:
                            session['log_messages'].append(f'Error testing password: {str(e)}')
                    
                    # Update progress
                    if total_tested % 10000 == 0:
                        progress = min((total_tested / bf_gen.total_keyspace) * 100, 99.9) if bf_gen.total_keyspace > 0 else 0
                        session['progress'] = progress
                        session['log_messages'].append(f'CPU: Length {length}, tested {total_tested:,}, {progress:.3f}%')
                
                if found:
                    break
            
            if not found and session['status'] == 'running':
                session['status'] = 'completed'
                session['log_messages'].append('Brute force completed - no match found')
        
        else:
            # Original hint-based password generation
            session['log_messages'].append('Using hint-based password generation...')
            
            password_gen = PasswordGenerator(
                hints=password_hints,
                dictionary_file=dictionary_file,
                max_length=max_length,
                use_patterns=use_patterns,
                use_substitutions=use_substitutions
            )
            
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
                session['progress'] = (i / total_passwords) * 100 if total_passwords > 0 else 0
                
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

# GPU and system info endpoints
@app.route('/api/gpu_info')
def gpu_info():
    """Get GPU information"""
    try:
        if HAS_GPU_SUPPORT:
            info = get_gpu_info()
        else:
            info = {'error': 'GPU support not available'}
        return jsonify(info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/gpu_benchmark')
def gpu_benchmark():
    """Run GPU performance benchmark"""
    try:
        if HAS_GPU_SUPPORT:
            result = test_gpu_performance()
        else:
            result = {'error': 'GPU support not available'}
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/estimate_time', methods=['POST'])
def estimate_time():
    """Estimate brute force time requirements"""
    try:
        data = request.get_json()
        charset = data.get('charset', '')
        min_length = data.get('min_length', 1)
        max_length = data.get('max_length', 20)
        
        if not charset:
            analyzer = OptimizedCharsetAnalyzer()
            _, charset = analyzer.suggest_charset()
        
        bf_gen = BruteForceGenerator(charset, min_length, max_length)
        
        # Estimate with different rates
        estimates = {}
        for rate_name, rate in [('cpu_single', 1000), ('cpu_multi', 5000), ('gpu_estimate', 50000)]:
            estimates[rate_name] = bf_gen.estimate_time(rate)
        
        return jsonify({
            'charset': charset,
            'charset_size': len(charset),
            'total_keyspace': bf_gen.total_keyspace,
            'estimates': estimates
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("Starting Unified Password Recovery Tool...")
    print("Access the web interface at: http://localhost:5000")
    
    if HAS_GPU_SUPPORT:
        print("GPU acceleration support: Available")
        try:
            gpu_info_result = get_gpu_info()
            if gpu_info_result.get('devices'):
                print(f"Detected {len(gpu_info_result['devices'])} GPU device(s)")
                for device in gpu_info_result['devices']:
                    print(f"  - {device['name']} ({device['type']})")
            else:
                print("No GPU devices detected")
        except Exception as e:
            print(f"GPU detection error: {str(e)}")
    else:
        print("GPU acceleration support: Not available (install pyopencl)")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
