# Unified Password Recovery Tool

## Overview

The Unified Password Recovery Tool is a Python-based application that supports password recovery for VeraCrypt encrypted volumes and KeePass databases. The application provides both a web interface (Flask) and command-line interface, featuring brute force and dictionary-based password cracking capabilities with session management and progress tracking.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Web Interface**: Flask-based web application with Bootstrap 5 UI
- **Templates**: Jinja2 templating with responsive design
- **Static Assets**: CSS styling with custom themes and Font Awesome icons
- **Client-Side**: JavaScript for file uploads, progress tracking, and real-time updates

### Backend Architecture
- **Core Framework**: Flask web framework for HTTP handling
- **Modular Design**: Separate handlers for different file types (VeraCrypt, KeePass)
- **Session Management**: Thread-safe session persistence with JSON storage
- **CLI Interface**: Independent command-line tool sharing core functionality

### Key Components
1. **VeraCrypt Handler** (`core/veracrypt_handler.py`)
   - Volume header parsing and analysis
   - Multiple encryption algorithm support (AES, Serpent, Twofish, Camellia, Kuznyechik)
   - Hash algorithm support (SHA512, SHA256, RIPEMD160, Whirlpool)
   - PBKDF2 key derivation for password testing

2. **KeePass Handler** (`core/keepass_handler.py`)
   - KDBX database format support
   - PyKeePass integration for password verification
   - Database version detection and analysis

3. **Password Generator** (`core/password_generator.py`)
   - Dictionary-based password generation
   - Brute force character combinations
   - Common password patterns and substitutions
   - Date-based and personal information patterns

4. **Session Manager** (`core/session_manager.py`)
   - Thread-safe session persistence
   - Progress tracking and statistics
   - Resume capability for interrupted sessions
   - JSON-based session storage

## Data Flow

1. **File Upload/Analysis**
   - User uploads encrypted file or provides hash data
   - System detects file type (VeraCrypt/KeePass)
   - File headers are analyzed for encryption parameters

2. **Password Generation**
   - Generator creates password candidates based on:
     - Dictionary words and common patterns
     - User-provided hints and personal information
     - Brute force character combinations
     - Character substitutions and transformations

3. **Password Testing**
   - Each candidate is tested against the target
   - VeraCrypt: Key derivation and header decryption attempt
   - KeePass: Database unlock attempt using PyKeePass
   - Progress tracking and session updates

4. **Result Handling**
   - Successful passwords are stored and reported
   - Session state is persisted for recovery resumption
   - Results are displayed via web interface or CLI

## External Dependencies

### Core Libraries
- **Flask**: Web framework for HTTP handling and routing
- **PyKeePass**: KeePass database manipulation and password testing
- **PyCrypto/PyCryptodome**: Cryptographic operations for VeraCrypt
- **Threading**: Concurrent password testing and session management

### Frontend Dependencies
- **Bootstrap 5**: Responsive UI framework
- **Font Awesome**: Icon library
- **JavaScript**: Client-side interactivity and AJAX requests

### System Dependencies
- **Python 3.7+**: Core runtime environment
- **Temporary File System**: Session and file storage
- **Logging System**: Application logging and debugging

## Deployment Strategy

### Development Setup
- **Local Development**: Flask development server with debug mode
- **File Storage**: Temporary directories for uploaded files and sessions
- **Session Persistence**: Local JSON files in `.recovery_sessions` directory

### Production Considerations
- **WSGI Server**: Gunicorn or uWSGI for production deployment
- **Reverse Proxy**: Nginx for static file serving and SSL termination
- **Security**: File upload validation and temporary file cleanup
- **Resource Management**: Memory and CPU limits for password testing operations

### Key Architectural Decisions

1. **Modular Handler Design**
   - **Problem**: Supporting multiple encryption formats with different requirements
   - **Solution**: Separate handler classes for each format (VeraCrypt, KeePass)
   - **Benefits**: Extensible design, format-specific optimizations, clear separation of concerns

2. **Session Management**
   - **Problem**: Long-running password recovery operations need persistence
   - **Solution**: JSON-based session storage with thread-safe operations
   - **Benefits**: Resume capability, progress tracking, multi-session support

3. **Dual Interface Approach**
   - **Problem**: Different user preferences for web vs command-line interfaces
   - **Solution**: Shared core functionality with separate Flask and CLI frontends
   - **Benefits**: Flexibility, automation capabilities, user choice

4. **Generator-Based Password Creation**
   - **Problem**: Memory-efficient handling of large password spaces
   - **Solution**: Generator patterns for on-demand password creation
   - **Benefits**: Low memory footprint, scalable to large dictionaries

5. **Temporary File Management**
   - **Problem**: Secure handling of sensitive uploaded files
   - **Solution**: Temporary directories with automatic cleanup
   - **Benefits**: Security, disk space management, session isolation