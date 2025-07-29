"""
Database models for password recovery session management
"""
from datetime import datetime
from enum import Enum
import json
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import JSON

Base = declarative_base()


class RecoveryStatus(Enum):
    """Recovery session status"""
    READY = "ready"
    PENDING = "pending"
    RUNNING = "running" 
    SUCCESS = "success"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"


class FileType(Enum):
    """Supported file types"""
    VERACRYPT = "veracrypt"
    KEEPASS = "keepass"


class RecoverySession(Base):
    """Password recovery session"""
    __tablename__ = 'recovery_sessions'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(50), unique=True, nullable=False, index=True)
    
    # File information
    file_type = Column(SQLEnum(FileType), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer)
    partition_data = Column(Text)  # For VeraCrypt
    
    # Recovery parameters
    use_brute_force = Column(Boolean, default=False)
    brute_force_charset = Column(String(500))
    brute_force_min_length = Column(Integer, default=1)
    brute_force_max_length = Column(Integer, default=20)
    use_gpu = Column(Boolean, default=False)
    max_length = Column(Integer, default=20)
    use_patterns = Column(Boolean, default=True)
    use_substitutions = Column(Boolean, default=True)
    thread_count = Column(Integer, default=4)
    
    # Recovery state
    status = Column(SQLEnum(RecoveryStatus), default=RecoveryStatus.READY)
    progress = Column(Float, default=0.0)
    attempts = Column(Integer, default=0)
    total_keyspace = Column(String(50))  # Store as string for very large numbers
    
    # Results
    found_password = Column(String(500))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    
    # Additional data
    password_hints = Column(JSON)
    log_messages = Column(JSON, default=list)
    error_message = Column(Text)
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'file_type': self.file_type.value if self.file_type else None,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'partition_data': self.partition_data,
            'use_brute_force': self.use_brute_force,
            'brute_force_charset': self.brute_force_charset,
            'brute_force_min_length': self.brute_force_min_length,
            'brute_force_max_length': self.brute_force_max_length,
            'use_gpu': self.use_gpu,
            'max_length': self.max_length,
            'use_patterns': self.use_patterns,
            'use_substitutions': self.use_substitutions,
            'thread_count': self.thread_count,
            'status': self.status.value if self.status else None,
            'progress': self.progress,
            'attempts': self.attempts,
            'total_keyspace': self.total_keyspace,
            'found_password': self.found_password,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'password_hints': self.password_hints,
            'log_messages': self.log_messages or [],
            'error_message': self.error_message
        }


class RecoveryLog(Base):
    """Detailed recovery log entries"""
    __tablename__ = 'recovery_logs'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(50), nullable=False, index=True)
    
    # Log entry details
    timestamp = Column(DateTime, default=datetime.utcnow)
    level = Column(String(20), default='INFO')  # DEBUG, INFO, WARNING, ERROR
    message = Column(Text, nullable=False)
    
    # Performance metrics
    passwords_tested = Column(Integer)
    test_rate = Column(Float)  # passwords per second
    current_length = Column(Integer)
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'level': self.level,
            'message': self.message,
            'passwords_tested': self.passwords_tested,
            'test_rate': self.test_rate,
            'current_length': self.current_length
        }


class GPUPerformance(Base):
    """GPU performance benchmarks"""
    __tablename__ = 'gpu_performance'
    
    id = Column(Integer, primary_key=True)
    
    # Device information
    device_name = Column(String(200))
    device_type = Column(String(50))
    platform_name = Column(String(200))
    global_mem_size = Column(String(50))
    max_work_group_size = Column(Integer)
    max_compute_units = Column(Integer)
    
    # Performance metrics
    benchmark_date = Column(DateTime, default=datetime.utcnow)
    operations_per_second = Column(Float)
    estimated_password_rate = Column(Integer)
    execution_time = Column(Float)
    
    # Test parameters
    test_size = Column(Integer)
    test_type = Column(String(100), default='vector_addition')
    
    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'device_name': self.device_name,
            'device_type': self.device_type,
            'platform_name': self.platform_name,
            'global_mem_size': self.global_mem_size,
            'max_work_group_size': self.max_work_group_size,
            'max_compute_units': self.max_compute_units,
            'benchmark_date': self.benchmark_date.isoformat() if self.benchmark_date else None,
            'operations_per_second': self.operations_per_second,
            'estimated_password_rate': self.estimated_password_rate,
            'execution_time': self.execution_time,
            'test_size': self.test_size,
            'test_type': self.test_type
        }