"""
VeraCrypt Handler for password recovery
Handles VeraCrypt volume header parsing and password testing
"""

import os
import struct
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, RIPEMD160, SHA256
try:
    from Crypto.Hash import Whirlpool
    HAS_WHIRLPOOL = True
except ImportError:
    HAS_WHIRLPOOL = False
import logging

logger = logging.getLogger(__name__)

class VeraCryptHandler:
    """Handler for VeraCrypt volume password recovery"""
    
    # VeraCrypt constants
    VERACRYPT_MAGIC = b'VERA'
    HEADER_SIZE = 512
    SALT_SIZE = 64
    MASTER_KEY_SIZE = 32
    
    # Supported encryption algorithms
    ENCRYPTION_ALGORITHMS = {
        'AES': 1,
        'SERPENT': 2, 
        'TWOFISH': 3,
        'CAMELLIA': 4,
        'KUZNYECHIK': 5
    }
    
    # Hash algorithms for key derivation
    HASH_ALGORITHMS = {
        'SHA512': (SHA512, 1000000),
        'SHA256': (SHA256, 200000), 
        'RIPEMD160': (RIPEMD160, 655331)
    }
    
    # Add Whirlpool if available
    if HAS_WHIRLPOOL:
        HASH_ALGORITHMS['WHIRLPOOL'] = (Whirlpool, 1000000)
    
    def __init__(self, file_path):
        """Initialize VeraCrypt handler with volume file"""
        self.file_path = file_path
        self.header_data = None
        self.partition_data = None
        self.volume_header = None
        self.salt = None
        self.encrypted_header = None
        
        self._load_volume_data()
    
    def _load_volume_data(self):
        """Load and parse VeraCrypt volume header"""
        try:
            with open(self.file_path, 'rb') as f:
                self.header_data = f.read(self.HEADER_SIZE)
            
            if len(self.header_data) < self.HEADER_SIZE:
                raise ValueError(f"File too small: {len(self.header_data)} bytes, need at least {self.HEADER_SIZE}")
            
            # Extract salt (first 64 bytes)
            self.salt = self.header_data[:self.SALT_SIZE]
            
            # Extract encrypted header (remaining bytes)
            self.encrypted_header = self.header_data[self.SALT_SIZE:]
            
            logger.info(f"Loaded VeraCrypt data: {len(self.header_data)} bytes")
            logger.info(f"Salt: {self.salt[:16].hex()}... (showing first 16 bytes)")
            
        except Exception as e:
            logger.error(f"Failed to load VeraCrypt volume: {str(e)}")
            raise
    
    def set_partition_data(self, partition_data):
        """Set additional partition data if available"""
        try:
            if isinstance(partition_data, str):
                # Try to decode as hex
                try:
                    partition_data = bytes.fromhex(partition_data.replace(' ', '').replace('\n', ''))
                except ValueError:
                    # Try base64
                    import base64
                    partition_data = base64.b64decode(partition_data)
            
            self.partition_data = partition_data
            logger.info(f"Set partition data: {len(partition_data)} bytes")
            
        except Exception as e:
            logger.warning(f"Failed to set partition data: {str(e)}")
    
    def test_password(self, password):
        """Test if password can decrypt the VeraCrypt volume"""
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Try different hash algorithms
        for hash_name, (hash_func, iterations) in self.HASH_ALGORITHMS.items():
            try:
                if self._test_password_with_hash(password, hash_func, iterations):
                    logger.info(f"Password found with {hash_name} hash!")
                    return True
            except Exception as e:
                logger.debug(f"Error testing with {hash_name}: {str(e)}")
                continue
        
        return False
    
    def _test_password_with_hash(self, password, hash_func, iterations):
        """Test password with specific hash algorithm"""
        try:
            # Derive key using PBKDF2
            if hash_func == SHA512:
                key = PBKDF2(
                    password, 
                    self.salt, 
                    dkLen=64,  # 64 bytes for header key + secondary key
                    count=iterations,
                    prf=lambda p, s: hmac.new(p, s, SHA512).digest()
                )
            elif hash_func == SHA256:
                key = PBKDF2(
                    password,
                    self.salt,
                    dkLen=64,
                    count=iterations,
                    prf=lambda p, s: hmac.new(p, s, SHA256).digest()
                )
            elif hash_func == RIPEMD160:
                key = PBKDF2(
                    password,
                    self.salt,
                    dkLen=64,
                    count=iterations,
                    prf=lambda p, s: hmac.new(p, s, RIPEMD160).digest()
                )
            else:
                # For other hash functions, use standard PBKDF2
                key = PBKDF2(password, self.salt, dkLen=64, count=iterations)
            
            # Split key into header key and secondary key
            header_key = key[:32]
            secondary_key = key[32:64]
            
            # Try to decrypt header with AES
            cipher = AES.new(header_key, AES.MODE_XTS, secondary_key)
            decrypted = cipher.decrypt(self.encrypted_header)
            
            # Verify header magic
            if decrypted[:4] == self.VERACRYPT_MAGIC:
                return True
            
            # Also check for TrueCrypt magic if VeraCrypt magic fails
            if decrypted[:4] == b'TRUE':
                return True
            
            # Check for other potential header indicators
            if self._verify_header_structure(decrypted):
                return True
            
        except Exception as e:
            logger.debug(f"Decryption failed: {str(e)}")
            
        return False
    
    def _verify_header_structure(self, decrypted_header):
        """Verify if decrypted header has valid structure"""
        try:
            # Check if we have enough data
            if len(decrypted_header) < 64:
                return False
            
            # Check for reasonable version numbers (typically 1-10)
            version = struct.unpack('<I', decrypted_header[4:8])[0]
            if version > 0 and version < 100:
                # Check for reasonable minimum version
                min_version = struct.unpack('<I', decrypted_header[8:12])[0]
                if min_version > 0 and min_version <= version:
                    # Check CRC (bytes 8-12 should be reasonable)
                    crc = struct.unpack('<I', decrypted_header[12:16])[0]
                    if crc != 0:  # CRC should not be zero
                        logger.debug(f"Potential valid header: version={version}, min_version={min_version}")
                        return True
            
            # Check for null bytes in reasonable positions
            # A valid header should not be all zeros or all 0xFF
            if not (all(b == 0 for b in decrypted_header[:32]) or 
                   all(b == 0xFF for b in decrypted_header[:32])):
                # Look for entropy - valid headers have mixed byte values
                unique_bytes = len(set(decrypted_header[:64]))
                if unique_bytes > 10:  # Good entropy indicator
                    logger.debug(f"Good entropy in header: {unique_bytes} unique bytes")
                    return True
            
        except Exception as e:
            logger.debug(f"Header verification error: {str(e)}")
        
        return False
    
    def get_volume_info(self):
        """Get information about the volume"""
        return {
            'type': 'VeraCrypt',
            'header_size': len(self.header_data) if self.header_data else 0,
            'salt_size': len(self.salt) if self.salt else 0,
            'has_partition_data': self.partition_data is not None,
            'supported_algorithms': list(self.HASH_ALGORITHMS.keys())
        }
