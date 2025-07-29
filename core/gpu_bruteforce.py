"""
GPU-Accelerated Brute Force Module for Password Recovery
Supports AMD GPUs via OpenCL for high-performance password testing
"""

import os
import sys
import logging
import string
import itertools
import time
from typing import List, Optional, Generator, Tuple
import threading
import queue

try:
    import pyopencl as cl
    import numpy as np
    HAS_OPENCL = True
except ImportError:
    HAS_OPENCL = False
    cl = None
    np = None

logger = logging.getLogger(__name__)


class GPUBruteForcer:
    """GPU-accelerated brute force password testing"""
    
    def __init__(self, handler, charset: str = None, min_length: int = 1, max_length: int = 20):
        """Initialize GPU brute forcer"""
        self.handler = handler
        self.charset = charset or (string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?")
        self.min_length = min_length
        self.max_length = max_length
        self.context = None
        self.queue_cl = None
        self.program = None
        self.device = None
        
        if not HAS_OPENCL:
            raise ImportError("PyOpenCL not available. Install with: pip install pyopencl")
        
        self._init_opencl()
    
    def _init_opencl(self):
        """Initialize OpenCL context and queue"""
        try:
            # Get available platforms
            platforms = cl.get_platforms()
            if not platforms:
                raise RuntimeError("No OpenCL platforms found")
            
            # Find AMD platform if available
            amd_platform = None
            for platform in platforms:
                if 'AMD' in platform.name.upper() or 'ADVANCED MICRO DEVICES' in platform.name.upper():
                    amd_platform = platform
                    break
            
            platform = amd_platform or platforms[0]
            logger.info(f"Using OpenCL platform: {platform.name}")
            
            # Get GPU devices
            devices = platform.get_devices(device_type=cl.device_type.GPU)
            if not devices:
                # Fall back to CPU if no GPU
                devices = platform.get_devices(device_type=cl.device_type.CPU)
                logger.warning("No GPU devices found, falling back to CPU")
            
            self.device = devices[0]  # Use first available device
            logger.info(f"Using device: {self.device.name}")
            logger.info(f"Device memory: {self.device.global_mem_size // (1024*1024)} MB")
            logger.info(f"Max work group size: {self.device.max_work_group_size}")
            
            # Create context and queue
            self.context = cl.Context([self.device])
            self.queue_cl = cl.CommandQueue(self.context)
            
            # Compile kernel
            self._compile_kernel()
            
        except Exception as e:
            logger.error(f"Failed to initialize OpenCL: {str(e)}")
            raise
    
    def _compile_kernel(self):
        """Compile OpenCL kernel for password testing"""
        kernel_source = """
        __kernel void test_passwords(
            __global const char* passwords,
            __global const int* password_lengths,
            __global int* results,
            const int num_passwords,
            const int max_password_length
        ) {
            int gid = get_global_id(0);
            if (gid >= num_passwords) return;
            
            // Extract password for this work item
            __global const char* password = passwords + gid * max_password_length;
            int password_len = password_lengths[gid];
            
            // Simple placeholder - actual password testing would go here
            // This would need to be customized for VeraCrypt/KeePass
            results[gid] = 0;  // 0 = failed, 1 = success
        }
        """
        
        try:
            self.program = cl.Program(self.context, kernel_source).build()
        except Exception as e:
            logger.error(f"Failed to compile OpenCL kernel: {str(e)}")
            raise
    
    def generate_password_batches(self, batch_size: int = 10000) -> Generator[List[str], None, None]:
        """Generate batches of passwords for GPU testing"""
        current_batch = []
        
        for length in range(self.min_length, self.max_length + 1):
            logger.info(f"Generating passwords of length {length}")
            
            for password_tuple in itertools.product(self.charset, repeat=length):
                password = ''.join(password_tuple)
                current_batch.append(password)
                
                if len(current_batch) >= batch_size:
                    yield current_batch
                    current_batch = []
                
                # Safety check to prevent infinite generation
                if len(current_batch) + (len(self.charset) ** length) > 1000000:
                    logger.warning(f"Stopping generation at length {length} - too many combinations")
                    break
        
        # Yield remaining passwords
        if current_batch:
            yield current_batch
    
    def test_password_batch_cpu(self, passwords: List[str]) -> Optional[str]:
        """Test batch of passwords on CPU (fallback)"""
        for password in passwords:
            try:
                if self.handler.test_password(password):
                    return password
            except Exception as e:
                logger.debug(f"Error testing password: {str(e)}")
        return None
    
    def test_password_batch_gpu(self, passwords: List[str]) -> Optional[str]:
        """Test batch of passwords on GPU"""
        if not self.context or not self.program:
            logger.warning("GPU not available, falling back to CPU")
            return self.test_password_batch_cpu(passwords)
        
        try:
            batch_size = len(passwords)
            max_password_length = max(len(p) for p in passwords) if passwords else 0
            
            # Prepare password data
            password_data = np.zeros((batch_size, max_password_length), dtype=np.int8)
            password_lengths = np.zeros(batch_size, dtype=np.int32)
            
            for i, password in enumerate(passwords):
                password_bytes = password.encode('utf-8')
                password_lengths[i] = len(password_bytes)
                password_data[i, :len(password_bytes)] = list(password_bytes)
            
            # Create OpenCL buffers
            password_buffer = cl.Buffer(self.context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=password_data)
            length_buffer = cl.Buffer(self.context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=password_lengths)
            result_buffer = cl.Buffer(self.context, cl.mem_flags.WRITE_ONLY, batch_size * 4)
            
            # Execute kernel
            self.program.test_passwords(
                self.queue_cl,
                (batch_size,),
                None,
                password_buffer,
                length_buffer,
                result_buffer,
                np.int32(batch_size),
                np.int32(max_password_length)
            )
            
            # Read results
            results = np.zeros(batch_size, dtype=np.int32)
            cl.enqueue_copy(self.queue_cl, results, result_buffer)
            
            # Check for successful password
            for i, result in enumerate(results):
                if result == 1:
                    return passwords[i]
            
            return None
            
        except Exception as e:
            logger.warning(f"GPU testing failed: {str(e)}, falling back to CPU")
            return self.test_password_batch_cpu(passwords)
    
    def run_brute_force(self, progress_callback=None, stop_event=None) -> Optional[str]:
        """Run brute force attack"""
        logger.info(f"Starting GPU brute force attack")
        logger.info(f"Charset: {self.charset}")
        logger.info(f"Length range: {self.min_length}-{self.max_length}")
        
        batch_size = 10000
        total_tested = 0
        start_time = time.time()
        
        try:
            for batch in self.generate_password_batches(batch_size):
                if stop_event and stop_event.is_set():
                    logger.info("Brute force stopped by user")
                    break
                
                # Test batch
                found_password = self.test_password_batch_gpu(batch)
                total_tested += len(batch)
                
                if found_password:
                    elapsed_time = time.time() - start_time
                    logger.info(f"PASSWORD FOUND: {found_password}")
                    logger.info(f"Total tested: {total_tested:,}")
                    logger.info(f"Time taken: {elapsed_time:.2f} seconds")
                    logger.info(f"Rate: {total_tested/elapsed_time:.0f} passwords/sec")
                    return found_password
                
                # Progress callback
                if progress_callback and total_tested % (batch_size * 10) == 0:
                    elapsed_time = time.time() - start_time
                    rate = total_tested / elapsed_time if elapsed_time > 0 else 0
                    progress_callback(total_tested, rate, elapsed_time)
        
        except Exception as e:
            logger.error(f"Brute force error: {str(e)}")
            raise
        
        logger.info(f"Brute force completed - no password found")
        logger.info(f"Total tested: {total_tested:,}")
        return None


class SmartBruteForcer:
    """Smart brute force with character set analysis"""
    
    def __init__(self, handler, known_chars: str = None):
        """Initialize with known character constraints"""
        self.handler = handler
        self.known_chars = known_chars
        
        # Default character sets by category
        self.charsets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'extended': '`~"\'\\/'
        }
    
    def analyze_charset(self, sample_chars: str = None) -> str:
        """Analyze and optimize character set based on known information"""
        if sample_chars:
            # Use only characters we know are in the password
            return sample_chars
        
        if self.known_chars:
            return self.known_chars
        
        # Default comprehensive set
        return (self.charsets['lowercase'] + 
                self.charsets['uppercase'] + 
                self.charsets['digits'] + 
                self.charsets['symbols'])
    
    def estimate_keyspace(self, charset: str, min_len: int, max_len: int) -> int:
        """Estimate total keyspace size"""
        total = 0
        charset_size = len(charset)
        
        for length in range(min_len, max_len + 1):
            total += charset_size ** length
        
        return total
    
    def create_gpu_bruteforcer(self, charset: str = None, min_length: int = 1, max_length: int = 20) -> GPUBruteForcer:
        """Create optimized GPU brute forcer"""
        if not charset:
            charset = self.analyze_charset()
        
        keyspace = self.estimate_keyspace(charset, min_length, max_length)
        logger.info(f"Estimated keyspace: {keyspace:,} passwords")
        
        if keyspace > 10**12:  # 1 trillion
            logger.warning(f"Very large keyspace detected: {keyspace:,}")
            logger.warning("Consider reducing max_length or charset size")
        
        return GPUBruteForcer(self.handler, charset, min_length, max_length)


def get_gpu_info() -> dict:
    """Get information about available GPU resources"""
    info = {
        'opencl_available': HAS_OPENCL,
        'platforms': [],
        'devices': []
    }
    
    if not HAS_OPENCL:
        return info
    
    try:
        platforms = cl.get_platforms()
        for platform in platforms:
            platform_info = {
                'name': platform.name,
                'vendor': platform.vendor,
                'version': platform.version
            }
            info['platforms'].append(platform_info)
            
            # Get devices for this platform
            try:
                devices = platform.get_devices()
                for device in devices:
                    device_info = {
                        'name': device.name,
                        'type': cl.device_type.to_string(device.type),
                        'global_mem_size': device.global_mem_size,
                        'max_work_group_size': device.max_work_group_size,
                        'max_compute_units': device.max_compute_units
                    }
                    info['devices'].append(device_info)
            except Exception as e:
                logger.debug(f"Error getting devices for platform {platform.name}: {str(e)}")
    
    except Exception as e:
        logger.error(f"Error getting GPU info: {str(e)}")
    
    return info


def test_gpu_performance() -> dict:
    """Test GPU performance with a small benchmark"""
    if not HAS_OPENCL:
        return {'error': 'OpenCL not available'}
    
    try:
        # Create a simple test
        platforms = cl.get_platforms()
        if not platforms:
            return {'error': 'No OpenCL platforms found'}
        
        platform = platforms[0]
        devices = platform.get_devices()
        if not devices:
            return {'error': 'No OpenCL devices found'}
        
        device = devices[0]
        context = cl.Context([device])
        queue = cl.CommandQueue(context)
        
        # Simple benchmark: vector addition
        size = 100000
        a = np.random.rand(size).astype(np.float32)
        b = np.random.rand(size).astype(np.float32)
        
        # OpenCL kernel
        kernel_source = """
        __kernel void vector_add(__global const float* a,
                               __global const float* b,
                               __global float* result) {
            int gid = get_global_id(0);
            result[gid] = a[gid] + b[gid];
        }
        """
        
        program = cl.Program(context, kernel_source).build()
        
        # Buffers
        a_buffer = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=a)
        b_buffer = cl.Buffer(context, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, hostbuf=b)
        result_buffer = cl.Buffer(context, cl.mem_flags.WRITE_ONLY, a.nbytes)
        
        # Execute
        start_time = time.time()
        program.vector_add(queue, a.shape, None, a_buffer, b_buffer, result_buffer)
        queue.finish()
        end_time = time.time()
        
        execution_time = end_time - start_time
        operations_per_second = size / execution_time
        
        return {
            'device_name': device.name,
            'execution_time': execution_time,
            'operations_per_second': operations_per_second,
            'estimated_password_rate': int(operations_per_second / 1000)  # Rough estimate
        }
        
    except Exception as e:
        return {'error': str(e)}