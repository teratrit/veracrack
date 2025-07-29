"""
KeePass Handler for password recovery
Handles KeePass database (.kdbx) password testing
"""

import os
import logging
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

logger = logging.getLogger(__name__)

class KeePassHandler:
    """Handler for KeePass database password recovery"""
    
    def __init__(self, file_path):
        """Initialize KeePass handler with database file"""
        self.file_path = file_path
        self.database_info = None
        self._analyze_database()
    
    def _analyze_database(self):
        """Analyze KeePass database file"""
        try:
            if not os.path.exists(self.file_path):
                raise FileNotFoundError(f"KeePass file not found: {self.file_path}")
            
            # Get file size and basic info
            file_size = os.path.getsize(self.file_path)
            
            # Read header to get version info
            with open(self.file_path, 'rb') as f:
                header = f.read(32)
            
            self.database_info = {
                'file_size': file_size,
                'header': header.hex()[:64],  # First 32 bytes as hex
            }
            
            # Check if it's a valid KDBX file
            if header[:4] == b'\x03\xd9\xa2\x9a':
                self.database_info['version'] = '2.x'
                self.database_info['format'] = 'KDBX'
            elif header[:4] == b'\x9a\xa2\xd9\x03':
                self.database_info['version'] = '1.x/2.x'
                self.database_info['format'] = 'KDBX'
            else:
                logger.warning("File may not be a valid KeePass database")
                self.database_info['format'] = 'Unknown'
            
            logger.info(f"Loaded KeePass database: {file_size} bytes, format: {self.database_info.get('format', 'Unknown')}")
            
        except Exception as e:
            logger.error(f"Failed to analyze KeePass database: {str(e)}")
            raise
    
    def test_password(self, password):
        """Test if password can open the KeePass database"""
        try:
            # Attempt to open the database with the password
            kp = PyKeePass(self.file_path, password=password)
            
            # If we get here, the password worked
            logger.info(f"Successfully opened KeePass database with password")
            
            # Get some basic info about the database
            try:
                num_entries = len(kp.entries)
                num_groups = len(kp.groups)
                logger.info(f"Database contains {num_entries} entries in {num_groups} groups")
            except:
                pass
            
            return True
            
        except CredentialsError:
            # Wrong password - this is expected for most attempts
            return False
        except Exception as e:
            # Other errors (file corruption, etc.)
            logger.debug(f"Error testing password: {str(e)}")
            return False
    
    def test_password_with_keyfile(self, password, keyfile_path):
        """Test password with a keyfile"""
        try:
            if not os.path.exists(keyfile_path):
                logger.warning(f"Keyfile not found: {keyfile_path}")
                return False
            
            kp = PyKeePass(self.file_path, password=password, keyfile=keyfile_path)
            logger.info(f"Successfully opened KeePass database with password and keyfile")
            return True
            
        except CredentialsError:
            return False
        except Exception as e:
            logger.debug(f"Error testing password with keyfile: {str(e)}")
            return False
    
    def get_database_info(self):
        """Get information about the KeePass database"""
        info = {
            'type': 'KeePass',
            'file_path': self.file_path,
            'file_exists': os.path.exists(self.file_path)
        }
        
        if self.database_info:
            info.update(self.database_info)
        
        return info
    
    def extract_metadata(self):
        """Extract metadata that might help with password recovery"""
        metadata = {
            'creation_hints': [],
            'file_info': {}
        }
        
        try:
            # File system metadata
            stat = os.stat(self.file_path)
            metadata['file_info'] = {
                'size': stat.st_size,
                'created': stat.st_ctime,
                'modified': stat.st_mtime,
                'accessed': stat.st_atime
            }
            
            # Try to extract any hints from the filename
            filename = os.path.basename(self.file_path)
            if filename:
                # Remove extension
                name_part = os.path.splitext(filename)[0]
                
                # Look for common patterns
                if any(char.isdigit() for char in name_part):
                    metadata['creation_hints'].append(f"Filename contains numbers: {name_part}")
                
                if '_' in name_part or '-' in name_part:
                    parts = name_part.replace('-', '_').split('_')
                    metadata['creation_hints'].extend([f"Filename part: {part}" for part in parts if len(part) > 2])
            
        except Exception as e:
            logger.debug(f"Error extracting metadata: {str(e)}")
        
        return metadata
