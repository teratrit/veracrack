#!/usr/bin/env python3
"""
Command Line Interface for Unified Password Recovery Tool
"""

import argparse
import sys
import os
import time
import threading
import signal
from datetime import datetime

from core.veracrypt_handler import VeraCryptHandler
from core.keepass_handler import KeePassHandler
from core.password_generator import PasswordGenerator
from core.session_manager import SessionManager
from core.utils import detect_file_type, format_time, setup_logging, ProgressTracker

class PasswordRecoveryCLI:
    """Command line interface for password recovery"""
    
    def __init__(self):
        self.running = True
        self.session_manager = SessionManager()
        self.logger = setup_logging()
        
        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        print("\n\n[!] Interrupt received. Stopping recovery...")
        self.running = False
    
    def run(self):
        """Main CLI entry point"""
        parser = self._create_parser()
        args = parser.parse_args()
        
        if args.command == 'recover':
            return self._run_recovery(args)
        elif args.command == 'sessions':
            return self._manage_sessions(args)
        elif args.command == 'info':
            return self._show_info(args)
        else:
            parser.print_help()
            return 1
    
    def _create_parser(self):
        """Create command line argument parser"""
        parser = argparse.ArgumentParser(
            description='Unified Password Recovery Tool for VeraCrypt and KeePass',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Recover VeraCrypt password with hints
  python cli.py recover --file encrypted.tc --hints john 1990 password --max-length 20
  
  # Recover KeePass password with dictionary
  python cli.py recover --file database.kdbx --dictionary passwords.txt --threads 8
  
  # Resume a previous session
  python cli.py recover --resume session_12345
  
  # List all sessions
  python cli.py sessions --list
  
  # Show file information
  python cli.py info --file encrypted.tc
            """
        )
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Recovery command
        recover_parser = subparsers.add_parser('recover', help='Start password recovery')
        recover_parser.add_argument('--file', '-f', help='Target file (VeraCrypt container or KeePass database)')
        recover_parser.add_argument('--hash-data', help='VeraCrypt hash data (hex or base64)')
        recover_parser.add_argument('--partition-data', help='VeraCrypt partition data (optional)')
        recover_parser.add_argument('--hints', nargs='*', help='Password hints (names, dates, words)')
        recover_parser.add_argument('--dictionary', help='Dictionary file path')
        recover_parser.add_argument('--max-length', type=int, default=20, help='Maximum password length')
        recover_parser.add_argument('--threads', type=int, default=4, help='Number of threads')
        recover_parser.add_argument('--no-patterns', action='store_true', help='Disable common patterns')
        recover_parser.add_argument('--no-substitutions', action='store_true', help='Disable character substitutions')
        recover_parser.add_argument('--resume', help='Resume session ID')
        recover_parser.add_argument('--output', help='Output file for results')
        
        # Session management
        session_parser = subparsers.add_parser('sessions', help='Manage recovery sessions')
        session_parser.add_argument('--list', action='store_true', help='List all sessions')
        session_parser.add_argument('--delete', help='Delete session by ID')
        session_parser.add_argument('--cleanup', action='store_true', help='Clean up old sessions')
        session_parser.add_argument('--stats', action='store_true', help='Show session statistics')
        
        # Info command
        info_parser = subparsers.add_parser('info', help='Show file information')
        info_parser.add_argument('--file', '-f', required=True, help='File to analyze')
        
        return parser
    
    def _run_recovery(self, args):
        """Run password recovery"""
        try:
            # Validate arguments
            if not args.resume and not args.file and not args.hash_data:
                print("Error: Must specify --file, --hash-data, or --resume")
                return 1
            
            # Resume existing session
            if args.resume:
                return self._resume_session(args.resume)
            
            # Create new session
            session_id = f"cli_session_{int(time.time())}"
            
            # Prepare file info
            file_info = {}
            if args.file:
                if not os.path.exists(args.file):
                    print(f"Error: File not found: {args.file}")
                    return 1
                
                file_type = detect_file_type(args.file)
                file_info = {
                    'type': file_type,
                    'path': args.file,
                    'name': os.path.basename(args.file),
                    'size': os.path.getsize(args.file)
                }
            elif args.hash_data:
                # Handle hash data
                temp_file = f"/tmp/veracrypt_data_{session_id}.bin"
                try:
                    import base64
                    data = base64.b64decode(args.hash_data)
                except:
                    data = bytes.fromhex(args.hash_data.replace(' ', '').replace('\n', ''))
                
                with open(temp_file, 'wb') as f:
                    f.write(data)
                
                file_info = {
                    'type': 'veracrypt',
                    'path': temp_file,
                    'name': 'VeraCrypt Hash Data',
                    'size': len(data),
                    'partition_data': args.partition_data or ''
                }
            
            # Create session
            options = {
                'hints': args.hints or [],
                'dictionary': args.dictionary,
                'max_length': args.max_length,
                'threads': args.threads,
                'use_patterns': not args.no_patterns,
                'use_substitutions': not args.no_substitutions
            }
            
            session = self.session_manager.create_session(session_id, file_info, options)
            
            print(f"[+] Created recovery session: {session_id}")
            print(f"[+] Target: {file_info['name']} ({file_info['type'].upper()})")
            print(f"[+] Size: {file_info['size']} bytes")
            
            # Start recovery
            return self._execute_recovery(session_id, file_info, options, args.output)
            
        except Exception as e:
            print(f"Error: {str(e)}")
            return 1
    
    def _execute_recovery(self, session_id, file_info, options, output_file):
        """Execute the password recovery process"""
        try:
            # Initialize handler
            if file_info['type'] == 'veracrypt':
                handler = VeraCryptHandler(file_info['path'])
                if 'partition_data' in file_info and file_info['partition_data']:
                    handler.set_partition_data(file_info['partition_data'])
            elif file_info['type'] == 'keepass':
                handler = KeePassHandler(file_info['path'])
            else:
                print(f"Error: Unsupported file type: {file_info['type']}")
                return 1
            
            # Initialize password generator
            password_gen = PasswordGenerator(
                hints=options['hints'],
                dictionary_file=options['dictionary'],
                max_length=options['max_length'],
                use_patterns=options['use_patterns'],
                use_substitutions=options['use_substitutions']
            )
            
            # Generate password list
            print("[+] Generating password candidates...")
            passwords = list(password_gen.generate_passwords())
            total_passwords = len(passwords)
            
            print(f"[+] Generated {total_passwords:,} password candidates")
            
            if total_passwords == 0:
                print("[-] No passwords to test. Please provide hints or a dictionary.")
                return 1
            
            # Estimate time
            estimated_rate = 1000  # passwords per second (rough estimate)
            estimated_time = total_passwords / estimated_rate
            print(f"[+] Estimated time: {format_time(estimated_time)} (at {estimated_rate} passwords/sec)")
            
            # Update session
            self.session_manager.update_session(session_id, {
                'status': 'running',
                'progress': {'total_passwords': total_passwords}
            })
            
            # Start recovery
            start_time = time.time()
            progress_tracker = ProgressTracker(total_passwords, update_interval=1000)
            
            print("\n[+] Starting password recovery...")
            print("    Press Ctrl+C to stop\n")
            
            for i, password in enumerate(passwords):
                if not self.running:
                    print("\n[!] Recovery stopped by user")
                    break
                
                try:
                    if handler.test_password(password):
                        elapsed_time = time.time() - start_time
                        print(f"\n[SUCCESS] Password found: {password}")
                        print(f"[+] Time taken: {format_time(elapsed_time)}")
                        print(f"[+] Passwords tested: {i+1:,}")
                        
                        # Update session
                        self.session_manager.mark_success(session_id, password)
                        
                        # Save result to file
                        if output_file:
                            self._save_result(output_file, password, session_id, elapsed_time, i+1)
                        
                        return 0  # Success
                    
                    # Update progress
                    if i % 1000 == 0:
                        elapsed_time = time.time() - start_time
                        rate = i / elapsed_time if elapsed_time > 0 else 0
                        eta = (total_passwords - i) / rate if rate > 0 else None
                        
                        print(f"\r[+] Progress: {i:,}/{total_passwords:,} ({i/total_passwords*100:.1f}%) "
                              f"Rate: {rate:.0f}/sec ETA: {format_time(eta) if eta else 'Unknown'}", end='', flush=True)
                        
                        # Update session
                        self.session_manager.update_progress(session_id, i, total_passwords, elapsed_time, rate)
                        
                        # Create checkpoint
                        if i % 10000 == 0:
                            self.session_manager.create_checkpoint(session_id, i, password)
                
                except Exception as e:
                    if i % 10000 == 0:  # Log errors occasionally
                        self.logger.warning(f"Error testing password at index {i}: {str(e)}")
            
            # Recovery completed without finding password
            elapsed_time = time.time() - start_time
            print(f"\n[-] Password not found")
            print(f"[+] Time taken: {format_time(elapsed_time)}")
            print(f"[+] Passwords tested: {min(i+1, total_passwords):,}")
            
            # Update session
            self.session_manager.update_session(session_id, {'status': 'completed'})
            
            return 2  # Not found
            
        except Exception as e:
            print(f"\nError during recovery: {str(e)}")
            self.session_manager.mark_failure(session_id, str(e))
            return 1
    
    def _resume_session(self, session_id):
        """Resume a previous recovery session"""
        session = self.session_manager.get_session(session_id)
        if not session:
            print(f"Error: Session {session_id} not found")
            return 1
        
        print(f"[+] Resuming session: {session_id}")
        
        # Get latest checkpoint
        checkpoint = self.session_manager.get_latest_checkpoint(session_id)
        if checkpoint:
            print(f"[+] Resuming from checkpoint: password index {checkpoint['password_index']}")
        
        # Continue with recovery
        return self._execute_recovery(session_id, session['file_info'], session['options'], None)
    
    def _manage_sessions(self, args):
        """Manage recovery sessions"""
        if args.list:
            sessions = self.session_manager.list_sessions()
            if not sessions:
                print("No sessions found")
                return 0
            
            print(f"{'ID':<20} {'Type':<10} {'Status':<12} {'Created':<20} {'Progress':<10}")
            print("-" * 80)
            
            for session in sessions:
                progress = session.get('progress', {})
                percentage = progress.get('percentage', 0)
                
                print(f"{session['id']:<20} "
                      f"{session['file_info']['type']:<10} "
                      f"{session['status']:<12} "
                      f"{session['created'][:19]:<20} "
                      f"{percentage:.1f}%")
        
        elif args.delete:
            if self.session_manager.delete_session(args.delete):
                print(f"Deleted session: {args.delete}")
            else:
                print(f"Session not found: {args.delete}")
                return 1
        
        elif args.cleanup:
            self.session_manager.cleanup_old_sessions()
            print("Cleaned up old sessions")
        
        elif args.stats:
            stats = self.session_manager.get_session_stats()
            print(f"Total sessions: {stats['total_sessions']}")
            print(f"Successful sessions: {stats['successful_sessions']}")
            print(f"Active sessions: {stats['active_sessions']}")
            print(f"Success rate: {stats['success_rate']:.1f}%")
        
        return 0
    
    def _show_info(self, args):
        """Show file information"""
        try:
            if not os.path.exists(args.file):
                print(f"Error: File not found: {args.file}")
                return 1
            
            file_type = detect_file_type(args.file)
            file_size = os.path.getsize(args.file)
            
            print(f"File: {args.file}")
            print(f"Type: {file_type.upper()}")
            print(f"Size: {file_size:,} bytes")
            
            if file_type == 'veracrypt':
                handler = VeraCryptHandler(args.file)
                info = handler.get_volume_info()
                print(f"Header size: {info['header_size']} bytes")
                print(f"Salt size: {info['salt_size']} bytes")
                print(f"Supported algorithms: {', '.join(info['supported_algorithms'])}")
            
            elif file_type == 'keepass':
                handler = KeePassHandler(args.file)
                info = handler.get_database_info()
                if 'version' in info:
                    print(f"Version: {info['version']}")
                if 'format' in info:
                    print(f"Format: {info['format']}")
            
            return 0
            
        except Exception as e:
            print(f"Error: {str(e)}")
            return 1
    
    def _save_result(self, output_file, password, session_id, elapsed_time, attempts):
        """Save recovery result to file"""
        try:
            result = {
                'password': password,
                'session_id': session_id,
                'timestamp': datetime.now().isoformat(),
                'elapsed_time_seconds': elapsed_time,
                'elapsed_time_formatted': format_time(elapsed_time),
                'attempts': attempts
            }
            
            import json
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            
            print(f"[+] Result saved to: {output_file}")
            
        except Exception as e:
            print(f"Warning: Failed to save result to {output_file}: {str(e)}")

def main():
    """Main entry point"""
    cli = PasswordRecoveryCLI()
    return cli.run()

if __name__ == '__main__':
    sys.exit(main())
