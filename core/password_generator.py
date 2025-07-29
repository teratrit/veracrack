"""
Password Generator for brute force and dictionary attacks
Generates password candidates based on hints, patterns, and common strategies
"""

import itertools
import string
import calendar
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class PasswordGenerator:
    """Generates password candidates for recovery attempts"""
    
    # Common character substitutions
    SUBSTITUTIONS = {
        'a': ['@', '4'],
        'e': ['3'],
        'i': ['1', '!'],
        'o': ['0'],
        's': ['$', '5'],
        't': ['7'],
        'l': ['1'],
        'g': ['9'],
        'b': ['6'],
        'A': ['@', '4'],
        'E': ['3'],
        'I': ['1', '!'],
        'O': ['0'],
        'S': ['$', '5'],
        'T': ['7'],
        'L': ['1'],
        'G': ['9'],
        'B': ['6']
    }
    
    # Common password patterns
    COMMON_PATTERNS = [
        'password', 'Password', 'PASSWORD',
        '123456', '12345678', '1234567890',
        'qwerty', 'QWERTY', 'admin', 'ADMIN',
        'letmein', 'welcome', 'WELCOME',
        'monkey', 'dragon', 'master', 'MASTER'
    ]
    
    # Common separators
    SEPARATORS = ['', '-', '_', '.', '!', '@', '#', '$', '%', '^', '&', '*']
    
    def __init__(self, hints=None, dictionary_file=None, max_length=20, 
                 use_patterns=True, use_substitutions=True):
        """Initialize password generator"""
        self.hints = hints or []
        self.dictionary_file = dictionary_file
        self.max_length = max_length
        self.use_patterns = use_patterns
        self.use_substitutions = use_substitutions
        
        self.dictionary_words = []
        if dictionary_file and dictionary_file.strip():
            self._load_dictionary()
        
        logger.info(f"Password generator initialized with {len(self.hints)} hints")
    
    def _load_dictionary(self):
        """Load dictionary words from file"""
        try:
            with open(self.dictionary_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.dictionary_words = [
                    line.strip() for line in f 
                    if line.strip() and len(line.strip()) <= self.max_length
                ]
            logger.info(f"Loaded {len(self.dictionary_words)} dictionary words")
        except Exception as e:
            logger.warning(f"Failed to load dictionary: {str(e)}")
    
    def generate_passwords(self):
        """Generate all password candidates"""
        generated = set()
        
        # 1. Direct hints
        for hint in self.hints:
            yield from self._yield_if_new(generated, [hint])
        
        # 2. Common patterns
        if self.use_patterns:
            yield from self._yield_if_new(generated, self.COMMON_PATTERNS)
        
        # 3. Dictionary words
        yield from self._yield_if_new(generated, self.dictionary_words)
        
        # 4. Hint variations
        yield from self._generate_hint_variations(generated)
        
        # 5. Date-based passwords
        yield from self._generate_date_passwords(generated)
        
        # 6. Number combinations with hints
        yield from self._generate_number_combinations(generated)
        
        # 7. Character substitutions
        if self.use_substitutions:
            yield from self._generate_substitution_passwords(generated)
        
        # 8. Complex combinations
        yield from self._generate_complex_combinations(generated)
    
    def _yield_if_new(self, generated, passwords):
        """Yield password if not already generated and within length limit"""
        for password in passwords:
            if password and len(password) <= self.max_length and password not in generated:
                generated.add(password)
                yield password
    
    def _generate_hint_variations(self, generated):
        """Generate variations of hints"""
        for hint in self.hints:
            if not hint:
                continue
            
            # Case variations
            variations = [
                hint.lower(),
                hint.upper(),
                hint.capitalize(),
                hint.title()
            ]
            
            yield from self._yield_if_new(generated, variations)
            
            # Add numbers to end
            for num in range(100):
                for sep in ['', '!', '@', '#']:
                    candidate = f"{hint}{sep}{num}"
                    if len(candidate) <= self.max_length:
                        yield from self._yield_if_new(generated, [candidate])
            
            # Add years
            current_year = datetime.now().year
            for year in range(current_year - 50, current_year + 5):
                for sep in self.SEPARATORS[:6]:  # Use fewer separators
                    candidates = [f"{hint}{sep}{year}", f"{year}{sep}{hint}"]
                    yield from self._yield_if_new(generated, candidates)
    
    def _generate_date_passwords(self, generated):
        """Generate date-based passwords"""
        current_year = datetime.now().year
        
        # Years
        for year in range(current_year - 30, current_year + 2):
            yield from self._yield_if_new(generated, [str(year)])
        
        # Birth years with common names
        common_names = ['john', 'mary', 'mike', 'sarah', 'david', 'lisa']
        for name in common_names:
            for year in range(1950, 2005):
                candidates = [f"{name}{year}", f"{name}_{year}", f"{year}{name}"]
                yield from self._yield_if_new(generated, candidates)
        
        # Dates in various formats
        for year in range(current_year - 10, current_year + 1):
            for month in range(1, 13):
                for day in [1, 15, 25]:  # Common days
                    if day <= calendar.monthrange(year, month)[1]:
                        date_formats = [
                            f"{day:02d}{month:02d}{year}",
                            f"{month:02d}{day:02d}{year}",
                            f"{year}{month:02d}{day:02d}",
                            f"{day}/{month}/{year}",
                            f"{month}/{day}/{year}"
                        ]
                        yield from self._yield_if_new(generated, date_formats)
    
    def _generate_number_combinations(self, generated):
        """Generate number-based passwords"""
        # Simple number sequences
        number_patterns = [
            '123456', '12345678', '1234567890',
            '000000', '111111', '222222', '999999',
            '123123', '456456', '789789',
            '112233', '121212', '131313'
        ]
        
        yield from self._yield_if_new(generated, number_patterns)
        
        # Phone number patterns (common area codes)
        area_codes = ['555', '123', '000', '911']
        for area in area_codes:
            for i in range(1000, 10000, 1111):  # Simple patterns
                phone = f"{area}{i:04d}"
                if len(phone) <= self.max_length:
                    yield from self._yield_if_new(generated, [phone])
    
    def _generate_substitution_passwords(self, generated):
        """Generate passwords with character substitutions"""
        base_words = self.hints + self.COMMON_PATTERNS + ['password', 'admin', 'welcome']
        
        for word in base_words:
            if not word or len(word) > self.max_length - 2:
                continue
            
            # Single substitutions
            for i, char in enumerate(word):
                if char.lower() in self.SUBSTITUTIONS:
                    for sub_char in self.SUBSTITUTIONS[char.lower()]:
                        new_word = word[:i] + sub_char + word[i+1:]
                        yield from self._yield_if_new(generated, [new_word])
            
            # Multiple substitutions (limit to prevent explosion)
            if len(word) <= 8:  # Only for shorter words
                substituted = self._apply_all_substitutions(word)
                yield from self._yield_if_new(generated, [substituted])
    
    def _apply_all_substitutions(self, word):
        """Apply all possible substitutions to a word"""
        result = word
        for char, subs in self.SUBSTITUTIONS.items():
            if char in result:
                result = result.replace(char, subs[0])  # Use first substitution
        return result
    
    def _generate_complex_combinations(self, generated):
        """Generate complex combinations of hints"""
        if len(self.hints) < 2:
            return
        
        # Combine pairs of hints
        for i, hint1 in enumerate(self.hints):
            for j, hint2 in enumerate(self.hints):
                if i != j and hint1 and hint2:
                    for sep in self.SEPARATORS[:4]:  # Limit separators
                        combinations = [
                            f"{hint1}{sep}{hint2}",
                            f"{hint2}{sep}{hint1}",
                            f"{hint1.upper()}{sep}{hint2.lower()}",
                            f"{hint1.lower()}{sep}{hint2.upper()}"
                        ]
                        yield from self._yield_if_new(generated, combinations)
        
        # Combine hints with years
        current_year = datetime.now().year
        for hint in self.hints[:5]:  # Limit to first 5 hints
            if not hint:
                continue
            for year in range(current_year - 20, current_year + 1, 5):  # Every 5 years
                for sep in ['', '_', '-']:
                    combinations = [
                        f"{hint}{sep}{year}",
                        f"{year}{sep}{hint}",
                        f"{hint}{sep}{str(year)[2:]}",  # 2-digit year
                        f"{str(year)[2:]}{sep}{hint}"
                    ]
                    yield from self._yield_if_new(generated, combinations)
    
    def estimate_password_count(self):
        """Estimate total number of passwords to be generated"""
        # This is a rough estimate
        base_count = len(self.hints) + len(self.COMMON_PATTERNS) + len(self.dictionary_words)
        
        # Hint variations
        variation_multiplier = 20  # Average variations per hint
        
        # Date passwords
        date_count = 1000  # Rough estimate
        
        # Substitutions
        substitution_multiplier = 5 if self.use_substitutions else 1
        
        # Complex combinations
        combination_count = len(self.hints) * len(self.hints) * 10
        
        total = (base_count * variation_multiplier * substitution_multiplier) + date_count + combination_count
        
        return min(total, 1000000)  # Cap at 1M for sanity
