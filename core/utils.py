"""
Utility functions for password recovery tool
"""

import os
import logging
import time
import hashlib
from typing import Optional

def setup_logging(level=logging.INFO, log_file=None):
    """Setup logging configuration"""
    
    # Create logs directory if it doesn't exist
    log_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Default log file
    if log_file is None:
        log_file = os.path.join(log_dir, f'recovery_{int(time.time())}.log')
    
    # Configure logging
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized - Level: {level}, File: {log_file}")
    
    return logger

def detect_file_type(file_path: str) -> str:
    """Detect the type of file for recovery"""
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    try:
        with open(file_path, 'rb') as f:
            header = f.read(32)
        
        # KeePass database signatures
        if header[:4] == b'\x03\xd9\xa2\x9a':
            return 'keepass'
        elif header[:4] == b'\x9a\xa2\xd9\x03':
            return 'keepass'
        
        # VeraCrypt/TrueCrypt signatures
        # Note: VeraCrypt headers are encrypted, so we look for file patterns
        file_ext = os.path.splitext(file_path)[1].lower()
        if file_ext in ['.tc', '.hc']:
            return 'veracrypt'
        
        # Check file size - VeraCrypt containers are typically large
        file_size = os.path.getsize(file_path)
        if file_size >= 1024 * 1024:  # 1MB or larger
            # Could be a VeraCrypt container
            return 'veracrypt'
        
        # For small files, check if it looks like hash data
        if file_size <= 1024:  # Small file, might be hash data
            return 'veracrypt'
        
        # Default to VeraCrypt for unknown files
        return 'veracrypt'
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error detecting file type: {str(e)}")
        return 'unknown'

def format_time(seconds: float) -> str:
    """Format time duration in human-readable format"""
    
    if seconds is None:
        return "Unknown"
    
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    else:
        days = seconds / 86400
        return f"{days:.1f} days"

def format_bytes(bytes_count: int) -> str:
    """Format byte count in human-readable format"""
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"

def calculate_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """Calculate hash of a file"""
    
    hash_func = getattr(hashlib, algorithm.lower())()
    
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error calculating hash: {str(e)}")
        return None

def validate_password(password: str, min_length: int = 1, max_length: int = 128) -> bool:
    """Validate password constraints"""
    
    if not isinstance(password, str):
        return False
    
    if len(password) < min_length or len(password) > max_length:
        return False
    
    # Additional validation can be added here
    return True

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem usage"""
    
    # Remove or replace unsafe characters
    unsafe_chars = '<>:"/\\|?*'
    for char in unsafe_chars:
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing whitespace and dots
    filename = filename.strip('. ')
    
    # Ensure filename is not empty
    if not filename:
        filename = 'unnamed_file'
    
    return filename

def estimate_crack_time(password_count: int, attempts_per_second: float) -> dict:
    """Estimate time to crack password based on position in password list"""
    
    if attempts_per_second <= 0:
        return {
            'min_time': None,
            'avg_time': None,
            'max_time': None
        }
    
    # Minimum time (password found immediately)
    min_time = 0
    
    # Average time (password found at halfway point)
    avg_time = (password_count / 2) / attempts_per_second
    
    # Maximum time (password is the last one tried)
    max_time = password_count / attempts_per_second
    
    return {
        'min_time': min_time,
        'avg_time': avg_time,
        'max_time': max_time,
        'min_time_formatted': format_time(min_time),
        'avg_time_formatted': format_time(avg_time),
        'max_time_formatted': format_time(max_time)
    }

def check_system_resources() -> dict:
    """Check available system resources"""
    
    import psutil
    
    try:
        memory = psutil.virtual_memory()
        cpu_count = psutil.cpu_count()
        cpu_percent = psutil.cpu_percent(interval=1)
        
        return {
            'memory_total': memory.total,
            'memory_available': memory.available,
            'memory_percent': memory.percent,
            'cpu_count': cpu_count,
            'cpu_percent': cpu_percent,
            'recommended_threads': min(cpu_count, 8)  # Cap at 8 threads
        }
        
    except ImportError:
        # psutil not available
        return {
            'memory_total': None,
            'memory_available': None,
            'memory_percent': None,
            'cpu_count': None,
            'cpu_percent': None,
            'recommended_threads': 4  # Default
        }
    except Exception as e:
        logging.getLogger(__name__).warning(f"Error checking system resources: {str(e)}")
        return {
            'memory_total': None,
            'memory_available': None,
            'memory_percent': None,
            'cpu_count': None,
            'cpu_percent': None,
            'recommended_threads': 4  # Default
        }

def create_temp_directory(prefix: str = 'recovery_') -> str:
    """Create a temporary directory for recovery operations"""
    
    import tempfile
    
    temp_dir = tempfile.mkdtemp(prefix=prefix)
    logging.getLogger(__name__).debug(f"Created temporary directory: {temp_dir}")
    
    return temp_dir

def cleanup_temp_directory(temp_dir: str) -> bool:
    """Clean up temporary directory"""
    
    import shutil
    
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logging.getLogger(__name__).debug(f"Cleaned up temporary directory: {temp_dir}")
            return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Error cleaning up temporary directory: {str(e)}")
    
    return False

class ProgressTracker:
    """Simple progress tracking utility"""
    
    def __init__(self, total_items: int, update_interval: int = 100):
        self.total_items = total_items
        self.update_interval = update_interval
        self.current_item = 0
        self.start_time = time.time()
        self.last_update = 0
        
    def update(self, current_item: int) -> dict:
        """Update progress and return statistics"""
        self.current_item = current_item
        current_time = time.time()
        
        # Only calculate stats at intervals
        if current_item - self.last_update >= self.update_interval or current_item >= self.total_items:
            self.last_update = current_item
            
            elapsed_time = current_time - self.start_time
            percentage = (current_item / self.total_items * 100) if self.total_items > 0 else 0
            
            # Calculate rate
            rate = current_item / elapsed_time if elapsed_time > 0 else 0
            
            # Calculate ETA
            remaining_items = self.total_items - current_item
            eta = remaining_items / rate if rate > 0 else None
            
            return {
                'current': current_item,
                'total': self.total_items,
                'percentage': percentage,
                'elapsed_time': elapsed_time,
                'rate': rate,
                'eta': eta
            }
        
        return None

def load_wordlist(file_path: str, max_words: int = 100000) -> list:
    """Load wordlist from file with limits"""
    
    words = []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= max_words:
                    break
                
                word = line.strip()
                if word and len(word) <= 50:  # Reasonable length limit
                    words.append(word)
        
        logging.getLogger(__name__).info(f"Loaded {len(words)} words from {file_path}")
        
    except Exception as e:
        logging.getLogger(__name__).error(f"Error loading wordlist: {str(e)}")
    
    return words
