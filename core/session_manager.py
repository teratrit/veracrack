"""
Session Manager for password recovery sessions
Handles session persistence, progress tracking, and recovery state
"""

import json
import os
import time
import threading
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SessionManager:
    """Manages password recovery sessions with persistence"""
    
    def __init__(self, session_dir=None):
        """Initialize session manager"""
        self.session_dir = session_dir or os.path.join(os.getcwd(), '.recovery_sessions')
        self.sessions = {}
        self.lock = threading.Lock()
        
        # Create session directory if it doesn't exist
        os.makedirs(self.session_dir, exist_ok=True)
        
        # Load existing sessions
        self._load_sessions()
    
    def create_session(self, session_id, file_info, options=None):
        """Create a new recovery session"""
        with self.lock:
            session = {
                'id': session_id,
                'created': datetime.now().isoformat(),
                'file_info': file_info,
                'options': options or {},
                'status': 'created',
                'progress': {
                    'current_password': 0,
                    'total_passwords': 0,
                    'percentage': 0.0,
                    'attempts_per_second': 0.0,
                    'elapsed_time': 0.0,
                    'estimated_time_remaining': None
                },
                'results': {
                    'found_password': None,
                    'successful': False,
                    'error_message': None
                },
                'log': [],
                'checkpoints': []
            }
            
            self.sessions[session_id] = session
            self._save_session(session_id)
            
            logger.info(f"Created session {session_id}")
            return session
    
    def update_session(self, session_id, updates):
        """Update session data"""
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                
                # Deep merge updates
                for key, value in updates.items():
                    if key in session and isinstance(session[key], dict) and isinstance(value, dict):
                        session[key].update(value)
                    else:
                        session[key] = value
                
                session['updated'] = datetime.now().isoformat()
                self._save_session(session_id)
                return session
            
        return None
    
    def get_session(self, session_id):
        """Get session data"""
        with self.lock:
            return self.sessions.get(session_id)
    
    def list_sessions(self):
        """List all sessions"""
        with self.lock:
            return list(self.sessions.values())
    
    def delete_session(self, session_id):
        """Delete a session"""
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                
                # Remove session file
                session_file = os.path.join(self.session_dir, f"{session_id}.json")
                if os.path.exists(session_file):
                    os.remove(session_file)
                
                logger.info(f"Deleted session {session_id}")
                return True
            
        return False
    
    def add_log_entry(self, session_id, message, level='info'):
        """Add log entry to session"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message
        }
        
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['log'].append(log_entry)
                
                # Keep only last 1000 log entries
                if len(self.sessions[session_id]['log']) > 1000:
                    self.sessions[session_id]['log'] = self.sessions[session_id]['log'][-1000:]
                
                # Save periodically (every 10 entries)
                if len(self.sessions[session_id]['log']) % 10 == 0:
                    self._save_session(session_id)
    
    def create_checkpoint(self, session_id, password_index, password):
        """Create a recovery checkpoint"""
        checkpoint = {
            'timestamp': datetime.now().isoformat(),
            'password_index': password_index,
            'last_password': password,
            'attempts': self.sessions[session_id]['progress'].get('current_password', 0)
        }
        
        with self.lock:
            if session_id in self.sessions:
                self.sessions[session_id]['checkpoints'].append(checkpoint)
                
                # Keep only last 10 checkpoints
                if len(self.sessions[session_id]['checkpoints']) > 10:
                    self.sessions[session_id]['checkpoints'] = self.sessions[session_id]['checkpoints'][-10:]
                
                self._save_session(session_id)
                logger.debug(f"Created checkpoint for session {session_id} at password {password_index}")
    
    def get_latest_checkpoint(self, session_id):
        """Get the latest checkpoint for resuming"""
        with self.lock:
            if session_id in self.sessions:
                checkpoints = self.sessions[session_id]['checkpoints']
                if checkpoints:
                    return checkpoints[-1]
        return None
    
    def update_progress(self, session_id, current_password, total_passwords, 
                       elapsed_time, attempts_per_second=None):
        """Update session progress"""
        percentage = (current_password / total_passwords * 100) if total_passwords > 0 else 0
        
        # Calculate ETA
        eta = None
        if attempts_per_second and attempts_per_second > 0:
            remaining_passwords = total_passwords - current_password
            eta = remaining_passwords / attempts_per_second
        
        progress_update = {
            'progress': {
                'current_password': current_password,
                'total_passwords': total_passwords,
                'percentage': percentage,
                'elapsed_time': elapsed_time,
                'attempts_per_second': attempts_per_second or 0,
                'estimated_time_remaining': eta
            }
        }
        
        return self.update_session(session_id, progress_update)
    
    def mark_success(self, session_id, password):
        """Mark session as successful"""
        updates = {
            'status': 'completed',
            'results': {
                'found_password': password,
                'successful': True,
                'completed_at': datetime.now().isoformat()
            }
        }
        
        self.add_log_entry(session_id, f"PASSWORD FOUND: {password}", 'success')
        return self.update_session(session_id, updates)
    
    def mark_failure(self, session_id, error_message=None):
        """Mark session as failed"""
        updates = {
            'status': 'failed',
            'results': {
                'successful': False,
                'error_message': error_message,
                'completed_at': datetime.now().isoformat()
            }
        }
        
        if error_message:
            self.add_log_entry(session_id, f"ERROR: {error_message}", 'error')
        
        return self.update_session(session_id, updates)
    
    def _save_session(self, session_id):
        """Save session to disk"""
        try:
            session_file = os.path.join(self.session_dir, f"{session_id}.json")
            with open(session_file, 'w') as f:
                json.dump(self.sessions[session_id], f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save session {session_id}: {str(e)}")
    
    def _load_sessions(self):
        """Load existing sessions from disk"""
        try:
            if not os.path.exists(self.session_dir):
                return
            
            for filename in os.listdir(self.session_dir):
                if filename.endswith('.json'):
                    session_id = filename[:-5]  # Remove .json extension
                    try:
                        session_file = os.path.join(self.session_dir, filename)
                        with open(session_file, 'r') as f:
                            session = json.load(f)
                        
                        self.sessions[session_id] = session
                        logger.debug(f"Loaded session {session_id}")
                        
                    except Exception as e:
                        logger.warning(f"Failed to load session {session_id}: {str(e)}")
            
            logger.info(f"Loaded {len(self.sessions)} existing sessions")
            
        except Exception as e:
            logger.error(f"Failed to load sessions: {str(e)}")
    
    def cleanup_old_sessions(self, max_age_days=30):
        """Clean up old sessions"""
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)
        
        with self.lock:
            to_delete = []
            for session_id, session in self.sessions.items():
                created_time = datetime.fromisoformat(session['created']).timestamp()
                if created_time < cutoff_time:
                    to_delete.append(session_id)
            
            for session_id in to_delete:
                self.delete_session(session_id)
            
            if to_delete:
                logger.info(f"Cleaned up {len(to_delete)} old sessions")
    
    def get_session_stats(self):
        """Get statistics about all sessions"""
        with self.lock:
            total_sessions = len(self.sessions)
            successful_sessions = sum(1 for s in self.sessions.values() 
                                    if s['results'].get('successful', False))
            active_sessions = sum(1 for s in self.sessions.values() 
                                if s['status'] in ['running', 'created'])
            
            return {
                'total_sessions': total_sessions,
                'successful_sessions': successful_sessions,
                'active_sessions': active_sessions,
                'success_rate': (successful_sessions / total_sessions * 100) if total_sessions > 0 else 0
            }
