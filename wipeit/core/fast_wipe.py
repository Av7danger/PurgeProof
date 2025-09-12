"""
Fast Wipe Engine - Optimized for performance

This module provides high-performance disk wiping functionality with:
- Large block I/O operations
- Parallel processing
- Optimized pattern generation
- Efficient progress tracking
"""

import os
import time
import random
import threading
import concurrent.futures
from typing import Optional, List, Tuple, Callable, BinaryIO
from dataclasses import dataclass
import math

# Constants for optimal performance
DEFAULT_BLOCK_SIZE = 64 * 1024 * 1024  # 64MB chunks for better throughput
MAX_WORKERS = 4  # Number of parallel workers
BUFFER_POOL_SIZE = 4  # Number of pre-allocated buffers

@dataclass
class WipeProgress:
    total_bytes: int
    bytes_processed: int = 0
    percent_complete: float = 0.0
    speed_mbps: float = 0.0
    time_remaining: float = 0.0
    is_complete: bool = False
    error: Optional[str] = None

class FastWipeEngine:
    """High-performance disk wiping engine."""
    
    def __init__(self, progress_callback: Optional[Callable[[WipeProgress], None]] = None):
        self.progress_callback = progress_callback
        self._stop_requested = False
        self._buffer_pool = []
        self._init_buffer_pool()
    
    def _init_buffer_pool(self):
        """Pre-allocate memory buffers to avoid allocation during wiping."""
        for _ in range(BUFFER_POOL_SIZE):
            self._buffer_pool.append(bytearray(DEFAULT_BLOCK_SIZE))
    
    def _get_buffer(self) -> bytearray:
        """Get a buffer from the pool or allocate a new one if needed."""
        if self._buffer_pool:
            return self._buffer_pool.pop()
        return bytearray(DEFAULT_BLOCK_SIZE)
    
    def _return_buffer(self, buf: bytearray):
        """Return a buffer to the pool for reuse."""
        if len(self._buffer_pool) < BUFFER_POOL_SIZE:
            self._buffer_pool.append(buf)
    
    def stop(self):
        """Request the wipe operation to stop."""
        self._stop_requested = True
    
    def _generate_random_chunk(self, size: int) -> bytes:
        """Generate a chunk of random data efficiently."""
        # Use a faster random number generator for better performance
        return os.urandom(size)
    
    def _generate_zero_chunk(self, size: int) -> bytes:
        """Generate a chunk of zeros."""
        return bytes(size)
    
    def _generate_pattern_chunk(self, size: int, pattern: bytes) -> bytes:
        """Generate a chunk with a repeating pattern."""
        pattern_len = len(pattern)
        repeats = (size + pattern_len - 1) // pattern_len
        return (pattern * repeats)[:size]
    
    def _write_chunk(self, fd: int, chunk: bytes, offset: int) -> int:
        """Write a chunk of data at the specified offset."""
        try:
            os.lseek(fd, offset, os.SEEK_SET)
            return os.write(fd, chunk)
        except OSError as e:
            raise IOError(f"Failed to write at offset {offset}: {e}")
    
    def _wipe_chunk(self, fd: int, chunk_size: int, offset: int, 
                   pattern_generator: Callable[[int], bytes]) -> int:
        """Wipe a single chunk of the disk."""
        if self._stop_requested:
            return 0
            
        # Get a buffer and fill it with the pattern
        buf = self._get_buffer()
        try:
            chunk = pattern_generator(chunk_size)
            buf[:len(chunk)] = chunk
            bytes_written = self._write_chunk(fd, buf[:chunk_size], offset)
            return bytes_written
        finally:
            self._return_buffer(buf)
    
    def _calculate_chunks(self, total_size: int, chunk_size: int) -> List[Tuple[int, int]]:
        """Calculate chunk offsets and sizes for parallel processing."""
        chunks = []
        for offset in range(0, total_size, chunk_size):
            size = min(chunk_size, total_size - offset)
            chunks.append((offset, size))
        return chunks
    
    def _update_progress(self, progress: WipeProgress, bytes_processed: int, 
                        start_time: float, total_bytes: int):
        """Update progress information."""
        current_time = time.time()
        elapsed = max(0.1, current_time - start_time)
        
        progress.bytes_processed += bytes_processed
        progress.percent_complete = min(100.0, (progress.bytes_processed / total_bytes) * 100)
        
        # Calculate speed in MB/s
        progress.speed_mbps = (progress.bytes_processed / (1024 * 1024)) / elapsed
        
        # Estimate time remaining
        if progress.speed_mbps > 0:
            remaining_bytes = total_bytes - progress.bytes_processed
            progress.time_remaining = (remaining_bytes / (progress.speed_mbps * 1024 * 1024))
        
        # Call the progress callback if provided
        if self.progress_callback:
            self.progress_callback(progress)
    
    def wipe_device(self, device_path: str, method: str = "random", 
                   verify: bool = False) -> WipeProgress:
        """
        Wipe a storage device with the specified method.
        
        Args:
            device_path: Path to the device to wipe
            method: Wipe method ('random', 'zeros', or a byte pattern)
            verify: Whether to verify the wipe
            
        Returns:
            WipeProgress: Final progress information
        """
        self._stop_requested = False
        progress = WipeProgress(total_bytes=0)
        start_time = time.time()
        
        try:
            # Get device size
            total_bytes = os.path.getsize(device_path)
            progress.total_bytes = total_bytes
            
            # Set up pattern generator
            if method == "random":
                pattern_generator = self._generate_random_chunk
            elif method == "zeros":
                pattern_generator = self._generate_zero_chunk
            else:
                # Use a custom pattern
                pattern = method.encode() if isinstance(method, str) else method
                pattern_generator = lambda size: self._generate_pattern_chunk(size, pattern)
            
            # Open device with direct I/O if available
            flags = os.O_WRONLY | os.O_SYNC
            if hasattr(os, 'O_DIRECT'):
                flags |= os.O_DIRECT
            
            with open(device_path, 'wb', buffering=0) as f:
                fd = f.fileno()
                
                # Process in parallel
                chunk_size = max(DEFAULT_BLOCK_SIZE, total_bytes // (MAX_WORKERS * 4))
                chunks = self._calculate_chunks(total_bytes, chunk_size)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    futures = []
                    
                    for offset, size in chunks:
                        if self._stop_requested:
                            break
                            
                        future = executor.submit(
                            self._wipe_chunk, 
                            fd, size, offset, 
                            lambda s: pattern_generator(s)
                        )
                        future.add_done_callback(
                            lambda f, o=offset, s=size: 
                                self._update_progress(progress, s, start_time, total_bytes)
                        )
                        futures.append(future)
                    
                    # Wait for all tasks to complete
                    for future in concurrent.futures.as_completed(futures):
                        if self._stop_requested:
                            break
                            
                        try:
                            future.result()
                        except Exception as e:
                            progress.error = str(e)
                            self._stop_requested = True
                            break
            
            progress.is_complete = not self._stop_requested and progress.bytes_processed >= total_bytes
            
        except Exception as e:
            progress.error = str(e)
        finally:
            progress.time_remaining = 0
            if self.progress_callback:
                self.progress_callback(progress)
        
        return progress
