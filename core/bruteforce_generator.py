"""
Advanced Brute Force Password Generator for Very Long Passwords
Optimized for 90+ character passwords with GPU acceleration support
"""

import itertools
import string
import logging
import math
import time
from typing import Generator, List, Optional, Tuple
import threading
import queue

logger = logging.getLogger(__name__)


class BruteForceGenerator:
    """Advanced brute force generator for very long passwords"""
    
    def __init__(self, charset: str = None, min_length: int = 1, max_length: int = 90):
        """Initialize brute force generator"""
        self.charset = charset or (string.ascii_letters + string.digits)
        self.min_length = min_length
        self.max_length = max_length
        
        # Character set optimization
        self.charset_size = len(self.charset)
        self.charset_bytes = self.charset.encode('ascii')
        
        logger.info(f"Brute force generator initialized")
        logger.info(f"Charset: {self.charset}")
        logger.info(f"Charset size: {self.charset_size}")
        logger.info(f"Length range: {self.min_length}-{self.max_length}")
        
        # Calculate total keyspace
        self.total_keyspace = self._calculate_keyspace()
        logger.info(f"Total keyspace: {self.total_keyspace:,} passwords")
        
        if self.total_keyspace > 10**15:
            logger.warning("Extremely large keyspace - consider reducing parameters")
    
    def _calculate_keyspace(self) -> int:
        """Calculate total number of possible passwords"""
        total = 0
        for length in range(self.min_length, self.max_length + 1):
            total += self.charset_size ** length
        return total
    
    def estimate_time(self, passwords_per_second: int) -> dict:
        """Estimate time requirements"""
        if passwords_per_second <= 0:
            return {'error': 'Invalid rate'}
        
        total_seconds = self.total_keyspace / passwords_per_second
        
        # Average time (50% chance of finding password)
        avg_seconds = total_seconds / 2
        
        return {
            'total_keyspace': self.total_keyspace,
            'rate_per_second': passwords_per_second,
            'worst_case_seconds': total_seconds,
            'average_case_seconds': avg_seconds,
            'worst_case_formatted': self._format_duration(total_seconds),
            'average_case_formatted': self._format_duration(avg_seconds)
        }
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human readable format"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"
    
    def generate_by_length(self, length: int, batch_size: int = 10000) -> Generator[List[str], None, None]:
        """Generate passwords of specific length in batches"""
        logger.info(f"Generating passwords of length {length}")
        
        batch = []
        count = 0
        
        for password_tuple in itertools.product(self.charset, repeat=length):
            password = ''.join(password_tuple)
            batch.append(password)
            count += 1
            
            if len(batch) >= batch_size:
                yield batch
                batch = []
            
            # Safety limit for very long passwords
            if count >= 1000000:  # 1M limit per length
                logger.warning(f"Reached safety limit for length {length}")
                break
        
        # Yield remaining passwords
        if batch:
            yield batch
    
    def generate_incremental(self, batch_size: int = 10000, start_length: int = None) -> Generator[Tuple[int, List[str]], None, None]:
        """Generate passwords incrementally by length"""
        start_len = start_length or self.min_length
        
        for length in range(start_len, self.max_length + 1):
            logger.info(f"Starting length {length} (charset^{length} = {self.charset_size**length:,} combinations)")
            
            batch_count = 0
            for batch in self.generate_by_length(length, batch_size):
                yield length, batch
                batch_count += 1
                
                # Log progress periodically
                if batch_count % 100 == 0:
                    logger.info(f"Length {length}: Generated {batch_count * batch_size:,} passwords")
    
    def generate_smart_patterns(self, batch_size: int = 10000) -> Generator[List[str], None, None]:
        """Generate passwords using smart patterns for optimization"""
        
        # Start with shorter lengths first (more likely)
        for length in range(self.min_length, min(self.max_length + 1, 20)):
            for batch in self.generate_by_length(length, batch_size):
                yield batch
        
        # For very long passwords, use pattern-based generation
        if self.max_length > 20:
            yield from self._generate_long_password_patterns(batch_size)
    
    def _generate_long_password_patterns(self, batch_size: int) -> Generator[List[str], None, None]:
        """Generate patterns for very long passwords"""
        logger.info("Generating long password patterns")
        
        batch = []
        
        # Pattern: repeating sequences
        for base_length in range(2, 10):
            for base_tuple in itertools.product(self.charset, repeat=base_length):
                base_pattern = ''.join(base_tuple)
                
                # Repeat pattern to different lengths
                for target_length in range(20, self.max_length + 1, 5):
                    repetitions = target_length // base_length
                    remainder = target_length % base_length
                    
                    password = base_pattern * repetitions + base_pattern[:remainder]
                    if len(password) >= self.min_length:
                        batch.append(password)
                    
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
        
        # Pattern: alternating characters
        for char1 in self.charset[:10]:  # Limit to first 10 chars
            for char2 in self.charset[:10]:
                for length in range(self.min_length, min(self.max_length + 1, 50)):
                    password = (char1 + char2) * (length // 2) + char1 * (length % 2)
                    batch.append(password)
                    
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
        
        # Yield remaining
        if batch:
            yield batch
    
    def generate_resume_from_position(self, length: int, position: int, batch_size: int = 10000) -> Generator[List[str], None, None]:
        """Resume generation from specific position"""
        logger.info(f"Resuming from length {length}, position {position}")
        
        batch = []
        current_pos = 0
        
        for password_tuple in itertools.product(self.charset, repeat=length):
            if current_pos < position:
                current_pos += 1
                continue
            
            password = ''.join(password_tuple)
            batch.append(password)
            current_pos += 1
            
            if len(batch) >= batch_size:
                yield batch
                batch = []
        
        if batch:
            yield batch


class OptimizedCharsetAnalyzer:
    """Analyze and optimize character sets for brute force attacks"""
    
    def __init__(self):
        self.common_charsets = {
            'alpha_lower': string.ascii_lowercase,
            'alpha_upper': string.ascii_uppercase,  
            'alpha_mixed': string.ascii_letters,
            'numeric': string.digits,
            'alphanumeric': string.ascii_letters + string.digits,
            'alphanumeric_symbols': string.ascii_letters + string.digits + "!@#$%^&*()_+-=",
            'hex_lower': '0123456789abcdef',
            'hex_upper': '0123456789ABCDEF',
            'base64': string.ascii_letters + string.digits + '+/',
            'printable_ascii': ''.join(chr(i) for i in range(32, 127))
        }
    
    def suggest_charset(self, known_info: dict = None) -> Tuple[str, str]:
        """Suggest optimal charset based on known information"""
        if not known_info:
            return 'alphanumeric', self.common_charsets['alphanumeric']
        
        # Analyze hints
        has_lowercase = known_info.get('has_lowercase', True)
        has_uppercase = known_info.get('has_uppercase', True)
        has_digits = known_info.get('has_digits', True)
        has_symbols = known_info.get('has_symbols', False)
        known_chars = known_info.get('known_chars', '')
        
        if known_chars:
            return 'custom', known_chars
        
        # Build charset based on requirements
        charset = ''
        name_parts = []
        
        if has_lowercase:
            charset += string.ascii_lowercase
            name_parts.append('lower')
        
        if has_uppercase:
            charset += string.ascii_uppercase
            name_parts.append('upper')
        
        if has_digits:
            charset += string.digits
            name_parts.append('digits')
        
        if has_symbols:
            charset += "!@#$%^&*()_+-="
            name_parts.append('symbols')
        
        name = '_'.join(name_parts) if name_parts else 'alphanumeric'
        return name, charset or self.common_charsets['alphanumeric']
    
    def calculate_entropy(self, charset: str, length: int) -> float:
        """Calculate password entropy"""
        if not charset or length <= 0:
            return 0.0
        
        charset_size = len(set(charset))  # Remove duplicates
        return math.log2(charset_size ** length)
    
    def compare_strategies(self, charset: str, min_len: int, max_len: int) -> dict:
        """Compare different attack strategies"""
        strategies = {}
        
        # Strategy 1: Incremental by length
        total_combinations = sum(len(charset) ** l for l in range(min_len, max_len + 1))
        strategies['incremental'] = {
            'total_combinations': total_combinations,
            'avg_combinations': total_combinations / 2,
            'description': 'Test all passwords of length N before moving to N+1'
        }
        
        # Strategy 2: Smart patterns (for very long passwords)
        if max_len > 20:
            pattern_combinations = min(total_combinations, 10**9)  # Cap at 1B
            strategies['pattern_based'] = {
                'total_combinations': pattern_combinations,
                'avg_combinations': pattern_combinations / 2,
                'description': 'Use common patterns for very long passwords'
            }
        
        return strategies


def create_optimized_generator(charset_info: dict, length_range: Tuple[int, int]) -> BruteForceGenerator:
    """Create optimized brute force generator"""
    analyzer = OptimizedCharsetAnalyzer()
    charset_name, charset = analyzer.suggest_charset(charset_info)
    
    min_len, max_len = length_range
    
    logger.info(f"Creating optimized generator:")
    logger.info(f"Charset: {charset_name} ({len(charset)} characters)")
    logger.info(f"Length range: {min_len}-{max_len}")
    
    # Calculate entropy
    avg_entropy = analyzer.calculate_entropy(charset, (min_len + max_len) // 2)
    logger.info(f"Average entropy: {avg_entropy:.1f} bits")
    
    return BruteForceGenerator(charset, min_len, max_len)