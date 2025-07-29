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
from datetime import datetime, timedelta
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

# Database imports
from sqlalchemy import create_engine, func
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Base, RecoverySession, RecoveryLog, GPUPerformance, RecoveryStatus, FileType

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database setup
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    engine = create_engine(DATABASE_URL, echo=False)
    Base.metadata.create_all(engine)
    SessionLocal = scoped_session(sessionmaker(bind=engine))
    HAS_DATABASE = True
    logger = setup_logging()
    logger.info("Database connection established")
else:
    HAS_DATABASE = False
    logger = setup_logging()
    logger.warning("No database connection - using memory-only sessions")

# Global variables for session management
active_sessions = {}
session_lock = threading.Lock()

# Database helper functions
def save_session_to_db(session_data):
    """Save session to database"""
    if not HAS_DATABASE:
        return
    
    try:
        db_session = SessionLocal()
        
        # Convert session data to database model
        recovery_session = RecoverySession(
            session_id=session_data['session_id'],
            file_type=FileType.VERACRYPT if session_data['file_info']['type'] == 'veracrypt' else FileType.KEEPASS,
            file_path=session_data['file_info']['path'],
            file_size=session_data['file_info'].get('size', 0),
            partition_data=session_data['file_info'].get('partition_data'),
            use_brute_force=session_data.get('use_brute_force', False),
            brute_force_charset=session_data.get('brute_force_charset'),
            brute_force_min_length=session_data.get('brute_force_min_length', 1),
            brute_force_max_length=session_data.get('brute_force_max_length', 20),
            use_gpu=session_data.get('use_gpu', False),
            max_length=session_data.get('max_length', 20),
            use_patterns=session_data.get('use_patterns', True),
            use_substitutions=session_data.get('use_substitutions', True),
            thread_count=session_data.get('thread_count', 4),
            status=RecoveryStatus(session_data['status']),
            progress=session_data.get('progress', 0.0),
            attempts=session_data.get('attempts', 0),
            total_keyspace=str(session_data.get('total_keyspace', '0')),
            found_password=session_data.get('found_password'),
            started_at=session_data.get('start_time'),
            password_hints=session_data.get('password_hints', []),
            log_messages=session_data.get('log_messages', [])
        )
        
        # Check if session exists
        existing = db_session.query(RecoverySession).filter_by(session_id=session_data['session_id']).first()
        if existing:
            # Update existing session
            for key, value in {
                'status': RecoveryStatus(session_data['status']),
                'progress': session_data.get('progress', 0.0),
                'attempts': session_data.get('attempts', 0),
                'found_password': session_data.get('found_password'),
                'log_messages': session_data.get('log_messages', [])
            }.items():
                setattr(existing, key, value)
        else:
            db_session.add(recovery_session)
        
        db_session.commit()
        db_session.close()
    except Exception as e:
        logger.error(f"Database save error: {str(e)}")

def log_to_db(session_id, message, level='INFO', passwords_tested=None, test_rate=None, current_length=None):
    """Log message to database"""
    if not HAS_DATABASE:
        return
    
    try:
        db_session = SessionLocal()
        log_entry = RecoveryLog(
            session_id=session_id,
            level=level,
            message=message,
            passwords_tested=passwords_tested,
            test_rate=test_rate,
            current_length=current_length
        )
        db_session.add(log_entry)
        db_session.commit()
        db_session.close()
    except Exception as e:
        logger.error(f"Database log error: {str(e)}")

def save_gpu_benchmark(benchmark_data):
    """Save GPU benchmark to database"""
    if not HAS_DATABASE:
        return
    
    try:
        db_session = SessionLocal()
        gpu_perf = GPUPerformance(
            device_name=benchmark_data.get('device_name'),
            device_type=benchmark_data.get('device_type'),
            platform_name=benchmark_data.get('platform_name'),
            operations_per_second=benchmark_data.get('operations_per_second'),
            estimated_password_rate=benchmark_data.get('estimated_password_rate'),
            execution_time=benchmark_data.get('execution_time')
        )
        db_session.add(gpu_perf)
        db_session.commit()
        db_session.close()
    except Exception as e:
        logger.error(f"GPU benchmark save error: {str(e)}")

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
        session_data = {
            'session_id': session_id,
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
        
        with session_lock:
            active_sessions[session_id] = session_data
        
        # Save to database
        save_session_to_db(session_data)
        
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
        
        # Update session with parameters
        session.update({
            'status': 'running',
            'start_time': datetime.now(),
            'progress': 0,
            'attempts': 0,
            'use_brute_force': use_brute_force,
            'brute_force_charset': brute_force_charset,
            'brute_force_min_length': brute_force_min_length,
            'brute_force_max_length': brute_force_max_length,
            'use_gpu': use_gpu,
            'max_length': max_length,
            'use_patterns': use_patterns,
            'use_substitutions': use_substitutions,
            'thread_count': thread_count,
            'password_hints': password_hints
        })
        
        # Save updated session to database
        save_session_to_db(session)
        
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
            
            keyspace = bf_gen.total_keyspace
            session['log_messages'].append(f'Total keyspace: {keyspace:,} passwords')
            
            # Add more reasonable limits for VeraCrypt  
            if keyspace > 1e12:  # More than 1 trillion
                session['log_messages'].append('WARNING: Very large keyspace detected!')
                if session['file_info']['type'] == 'veracrypt':
                    # For VeraCrypt, limit to more reasonable ranges
                    if brute_force_max_length > 8:
                        brute_force_max_length = 8
                        session['brute_force_max_length'] = 8
                        session['log_messages'].append('Limiting VeraCrypt max length to 8 characters for practical recovery.')
                        # Recreate generator with reduced length
                        bf_gen = create_optimized_generator(
                            charset_info, 
                            (brute_force_min_length, brute_force_max_length)
                        )
                        session['log_messages'].append(f'Reduced keyspace: {bf_gen.total_keyspace:,} passwords')
                
                session['log_messages'].append('Consider reducing the length range or character set for faster results.')
            
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

# Database endpoints
@app.route('/api/sessions')
def get_sessions():
    """Get all recovery sessions from database"""
    try:
        if not HAS_DATABASE:
            return jsonify({'error': 'Database not available'}), 503
        
        db_session = SessionLocal()
        sessions = db_session.query(RecoverySession).order_by(RecoverySession.created_at.desc()).limit(50).all()
        db_session.close()
        
        return jsonify([session.to_dict() for session in sessions])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>')
def get_session_details(session_id):
    """Get detailed session information"""
    try:
        if not HAS_DATABASE:
            return jsonify({'error': 'Database not available'}), 503
        
        db_session = SessionLocal()
        session = db_session.query(RecoverySession).filter_by(session_id=session_id).first()
        
        if not session:
            db_session.close()
            return jsonify({'error': 'Session not found'}), 404
        
        # Get logs for this session
        logs = db_session.query(RecoveryLog).filter_by(session_id=session_id).order_by(RecoveryLog.timestamp.asc()).all()
        db_session.close()
        
        result = session.to_dict()
        result['logs'] = [log.to_dict() for log in logs]
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/sessions/<session_id>/logs')
def get_session_logs(session_id):
    """Get logs for a specific session"""
    try:
        if not HAS_DATABASE:
            return jsonify({'error': 'Database not available'}), 503
        
        db_session = SessionLocal()
        logs = db_session.query(RecoveryLog).filter_by(session_id=session_id).order_by(RecoveryLog.timestamp.asc()).all()
        db_session.close()
        
        return jsonify([log.to_dict() for log in logs])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/gpu_benchmarks')
def get_gpu_benchmarks():
    """Get GPU benchmark history"""
    try:
        if not HAS_DATABASE:
            return jsonify({'error': 'Database not available'}), 503
        
        db_session = SessionLocal()
        benchmarks = db_session.query(GPUPerformance).order_by(GPUPerformance.benchmark_date.desc()).limit(20).all()
        db_session.close()
        
        return jsonify([benchmark.to_dict() for benchmark in benchmarks])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def get_stats():
    """Get database statistics"""
    try:
        if not HAS_DATABASE:
            return jsonify({'error': 'Database not available'}), 503
        
        db_session = SessionLocal()
        
        # Get basic statistics
        total_sessions = db_session.query(RecoverySession).count()
        successful_sessions = db_session.query(RecoverySession).filter(RecoverySession.status == RecoveryStatus.SUCCESS).count()
        active_sessions_count = db_session.query(RecoverySession).filter(RecoverySession.status == RecoveryStatus.RUNNING).count()
        
        # Get recent activity
        recent_sessions = db_session.query(RecoverySession).filter(
            RecoverySession.created_at >= datetime.now() - timedelta(days=7)
        ).count()
        
        db_session.close()
        
        return jsonify({
            'total_sessions': total_sessions,
            'successful_sessions': successful_sessions,
            'success_rate': (successful_sessions / total_sessions * 100) if total_sessions > 0 else 0,
            'active_sessions': active_sessions_count,
            'recent_sessions': recent_sessions,
            'database_available': True
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download')
def download_package():
    """Create and download a complete package of the tool"""
    try:
        import zipfile
        import io
        
        # Create a zip file in memory
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add main files
            zip_file.write('app.py')
            zip_file.write('cli.py')
            zip_file.write('models.py')
            
            # Add core modules
            for root, dirs, files in os.walk('core'):
                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        zip_file.write(file_path)
            
            # Add templates and static files
            for root, dirs, files in os.walk('templates'):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_file.write(file_path)
            
            for root, dirs, files in os.walk('static'):
                for file in files:
                    file_path = os.path.join(root, file)
                    zip_file.write(file_path)
            
            # Add README
            readme_content = """# Unified Password Recovery Tool

## Installation

1. Install Python 3.7+
2. Install dependencies:
   ```bash
   pip install flask pycryptodome pykeepass psutil sqlalchemy psycopg2-binary pyopencl
   ```

## Usage

### Web Interface
```bash
python app.py
```
Access at http://localhost:5000

### Command Line
```bash
python cli.py --help
```

## Features

- VeraCrypt volume header recovery
- KeePass database password recovery  
- GPU-accelerated brute force (AMD/OpenCL)
- Pure brute force (no wordlist dependency)
- Session persistence with PostgreSQL
- Advanced progress tracking and logging

## Database Setup (Optional)

Set DATABASE_URL environment variable for session persistence:
```bash
export DATABASE_URL="postgresql://user:password@localhost/recovery_db"
```

## GPU Support

For AMD GPU acceleration:
1. Install OpenCL drivers for your GPU
2. Install PyOpenCL: `pip install pyopencl`
3. Enable GPU mode in the web interface

## Security Note

This tool is designed for legitimate password recovery of your own files.
Always ensure you have legal authorization before attempting password recovery.
"""
            zip_file.writestr('README.md', readme_content)
            
            # Add requirements file
            requirements_content = """flask>=2.0.0
pycryptodome>=3.15.0
pykeepass>=4.0.0
psutil>=5.8.0
sqlalchemy>=1.4.0
psycopg2-binary>=2.9.0
pyopencl>=2021.2.0
"""
            zip_file.writestr('requirements.txt', requirements_content)
        
        zip_buffer.seek(0)
        
        return send_file(
            io.BytesIO(zip_buffer.read()),
            mimetype='application/zip',
            as_attachment=True,
            download_name='password_recovery_tool.zip'
        )
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def create_app():
    """Application factory for deployment"""
    return app

if __name__ == '__main__':
    print("Starting Unified Password Recovery Tool...")
    
    # Use PORT environment variable for deployment compatibility
    port = int(os.environ.get('PORT', 5000))
    print(f"Access the web interface at: http://localhost:{port}")
    
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
    
    # Check if running in deployment mode
    is_deployment = os.environ.get('DEPLOYMENT', 'false').lower() == 'true'
    
    if is_deployment:
        # In deployment, use gunicorn
        print("Running in deployment mode with gunicorn")
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        # Development mode
        app.run(host='0.0.0.0', port=port, debug=False)
