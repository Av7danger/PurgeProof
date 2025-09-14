"""
Real-time Performance Monitoring for PurgeProof Operations.

This module provides actual real-time measurement of performance metrics during
sanitization operations, replacing estimated values with precise measurements.
"""

import time
import threading
import logging
import psutil
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import deque
import statistics

logger = logging.getLogger(__name__)

@dataclass
class PerformanceSnapshot:
    """Single point-in-time performance measurement."""
    timestamp: float
    bytes_processed: int
    operation_time_seconds: float
    throughput_mbps: float
    cpu_usage_percent: float
    memory_usage_mb: float
    disk_io_read_mbps: float
    disk_io_write_mbps: float
    operation_phase: str  # "scanning", "sanitizing", "verifying"

@dataclass 
class PerformanceMetrics:
    """Comprehensive performance metrics for an operation."""
    operation_id: str
    device_path: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_bytes: int = 0
    bytes_processed: int = 0
    
    # Real-time metrics
    current_throughput_mbps: float = 0.0
    average_throughput_mbps: float = 0.0
    peak_throughput_mbps: float = 0.0
    
    # System resource usage
    cpu_usage_avg: float = 0.0
    cpu_usage_peak: float = 0.0
    memory_usage_avg_mb: float = 0.0
    memory_usage_peak_mb: float = 0.0
    
    # I/O metrics
    disk_io_read_total_mb: float = 0.0
    disk_io_write_total_mb: float = 0.0
    disk_io_avg_latency_ms: float = 0.0
    
    # Efficiency metrics
    efficiency_score: float = 0.0  # 0-100, based on resource utilization
    estimated_time_remaining: float = 0.0  # seconds
    
    # Historical data (last N snapshots)
    snapshots: List[PerformanceSnapshot] = field(default_factory=list)
    
    def get_progress_percentage(self) -> float:
        """Get current progress as percentage."""
        if self.total_bytes == 0:
            return 0.0
        return min(100.0, (self.bytes_processed / self.total_bytes) * 100.0)
    
    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        end_time = self.end_time or datetime.now(timezone.utc)
        return (end_time - self.start_time).total_seconds()
    
    def update_estimates(self):
        """Update calculated metrics based on current data."""
        if len(self.snapshots) < 2:
            return
            
        # Calculate average throughput from recent snapshots
        recent_snapshots = self.snapshots[-10:]  # Last 10 measurements
        if recent_snapshots:
            throughputs = [s.throughput_mbps for s in recent_snapshots if s.throughput_mbps > 0]
            if throughputs:
                self.current_throughput_mbps = throughputs[-1]
                self.average_throughput_mbps = statistics.mean(throughputs)
                self.peak_throughput_mbps = max(self.peak_throughput_mbps, max(throughputs))
        
        # Calculate resource usage averages
        cpu_values = [s.cpu_usage_percent for s in recent_snapshots]
        memory_values = [s.memory_usage_mb for s in recent_snapshots]
        
        if cpu_values:
            self.cpu_usage_avg = statistics.mean(cpu_values)
            self.cpu_usage_peak = max(self.cpu_usage_peak, max(cpu_values))
            
        if memory_values:
            self.memory_usage_avg_mb = statistics.mean(memory_values)
            self.memory_usage_peak_mb = max(self.memory_usage_peak_mb, max(memory_values))
        
        # Estimate time remaining
        if self.current_throughput_mbps > 0 and self.total_bytes > self.bytes_processed:
            remaining_bytes = self.total_bytes - self.bytes_processed
            remaining_mb = remaining_bytes / (1024 * 1024)
            self.estimated_time_remaining = remaining_mb / self.current_throughput_mbps * 60  # minutes to seconds
        
        # Calculate efficiency score (0-100)
        # Based on CPU utilization, memory efficiency, and I/O throughput
        cpu_efficiency = min(100, self.cpu_usage_avg * 2)  # Prefer higher CPU usage for intensive ops
        memory_efficiency = 100 - min(100, self.memory_usage_avg_mb / 1024 * 10)  # Penalize excessive memory
        io_efficiency = min(100, self.current_throughput_mbps / 100 * 100)  # Based on expected max ~100 MB/s
        
        self.efficiency_score = (cpu_efficiency + memory_efficiency + io_efficiency) / 3

class RealTimePerformanceMonitor:
    """Real-time performance monitoring engine."""
    
    def __init__(self, sampling_interval: float = 1.0, max_snapshots: int = 1000):
        """Initialize performance monitor.
        
        Args:
            sampling_interval: Time between measurements in seconds
            max_snapshots: Maximum number of snapshots to keep per operation
        """
        self.sampling_interval = sampling_interval
        self.max_snapshots = max_snapshots
        
        # Active monitoring
        self._active_operations: Dict[str, PerformanceMetrics] = {}
        self._monitoring_threads: Dict[str, threading.Thread] = {}
        self._stop_flags: Dict[str, threading.Event] = {}
        
        # System baseline
        self._baseline_cpu = 0.0
        self._baseline_memory = 0.0
        self._baseline_disk_io = {}
        
        # Callbacks for progress updates
        self._progress_callbacks: Dict[str, List[Callable]] = {}
        
        self._establish_baseline()
    
    def _establish_baseline(self):
        """Establish system performance baseline."""
        try:
            # Sample system for 3 seconds to get baseline
            cpu_samples = []
            memory_samples = []
            
            for _ in range(3):
                cpu_samples.append(psutil.cpu_percent(interval=1))
                memory_samples.append(psutil.virtual_memory().used / (1024 * 1024))
            
            self._baseline_cpu = statistics.mean(cpu_samples)
            self._baseline_memory = statistics.mean(memory_samples)
            
            # Get baseline disk I/O
            self._baseline_disk_io = dict(psutil.disk_io_counters(perdisk=True))
            
            logger.info(f"Performance baseline established: CPU {self._baseline_cpu:.1f}%, "
                       f"Memory {self._baseline_memory:.1f}MB")
                       
        except Exception as e:
            logger.warning(f"Failed to establish performance baseline: {e}")
            self._baseline_cpu = 5.0  # Default fallback
            self._baseline_memory = 100.0
    
    def start_monitoring(self, operation_id: str, device_path: str, 
                        total_bytes: int, progress_callback: Optional[Callable] = None) -> PerformanceMetrics:
        """Start monitoring a new operation.
        
        Args:
            operation_id: Unique identifier for the operation
            device_path: Path to device being operated on
            total_bytes: Total bytes to process
            progress_callback: Optional callback for progress updates
            
        Returns:
            PerformanceMetrics object for this operation
        """
        if operation_id in self._active_operations:
            logger.warning(f"Operation {operation_id} already being monitored")
            return self._active_operations[operation_id]
        
        # Create metrics object
        metrics = PerformanceMetrics(
            operation_id=operation_id,
            device_path=device_path,
            start_time=datetime.now(timezone.utc),
            total_bytes=total_bytes
        )
        
        self._active_operations[operation_id] = metrics
        
        # Set up progress callback
        if progress_callback:
            if operation_id not in self._progress_callbacks:
                self._progress_callbacks[operation_id] = []
            self._progress_callbacks[operation_id].append(progress_callback)
        
        # Start monitoring thread
        stop_flag = threading.Event()
        self._stop_flags[operation_id] = stop_flag
        
        monitor_thread = threading.Thread(
            target=self._monitor_operation,
            args=(operation_id, stop_flag),
            daemon=True
        )
        monitor_thread.start()
        self._monitoring_threads[operation_id] = monitor_thread
        
        logger.info(f"Started performance monitoring for operation {operation_id}")
        return metrics
    
    def update_progress(self, operation_id: str, bytes_processed: int, 
                       operation_phase: str = "sanitizing"):
        """Update progress for an operation.
        
        Args:
            operation_id: Operation identifier
            bytes_processed: Bytes processed so far
            operation_phase: Current phase of operation
        """
        if operation_id not in self._active_operations:
            logger.warning(f"No monitoring active for operation {operation_id}")
            return
        
        metrics = self._active_operations[operation_id]
        metrics.bytes_processed = bytes_processed
        
        # Store current phase for next snapshot
        if hasattr(self, '_current_phases'):
            self._current_phases[operation_id] = operation_phase
        else:
            self._current_phases = {operation_id: operation_phase}
    
    def stop_monitoring(self, operation_id: str) -> Optional[PerformanceMetrics]:
        """Stop monitoring an operation and get final metrics.
        
        Args:
            operation_id: Operation identifier
            
        Returns:
            Final PerformanceMetrics or None if not found
        """
        if operation_id not in self._active_operations:
            logger.warning(f"No monitoring active for operation {operation_id}")
            return None
        
        # Signal stop
        if operation_id in self._stop_flags:
            self._stop_flags[operation_id].set()
        
        # Wait for thread to finish
        if operation_id in self._monitoring_threads:
            thread = self._monitoring_threads[operation_id]
            thread.join(timeout=5.0)
            if thread.is_alive():
                logger.warning(f"Monitoring thread for {operation_id} did not stop gracefully")
        
        # Finalize metrics
        metrics = self._active_operations[operation_id]
        metrics.end_time = datetime.now(timezone.utc)
        metrics.update_estimates()
        
        # Cleanup
        self._cleanup_operation(operation_id)
        
        logger.info(f"Stopped performance monitoring for operation {operation_id}")
        return metrics
    
    def get_current_metrics(self, operation_id: str) -> Optional[PerformanceMetrics]:
        """Get current metrics for an active operation."""
        return self._active_operations.get(operation_id)
    
    def _monitor_operation(self, operation_id: str, stop_flag: threading.Event):
        """Background monitoring thread for an operation."""
        metrics = self._active_operations[operation_id]
        last_bytes = 0
        last_time = time.time()
        
        # Initial disk I/O counters
        try:
            initial_io = psutil.disk_io_counters(perdisk=True)
            device_name = self._get_device_name(metrics.device_path)
            device_io_start = initial_io.get(device_name) if device_name else None
        except Exception:
            device_io_start = None
        
        while not stop_flag.wait(self.sampling_interval):
            try:
                current_time = time.time()
                
                # Get current phase
                current_phase = getattr(self, '_current_phases', {}).get(operation_id, "processing")
                
                # Calculate throughput
                bytes_diff = metrics.bytes_processed - last_bytes
                time_diff = current_time - last_time
                
                throughput_mbps = 0.0
                if time_diff > 0:
                    throughput_mbps = (bytes_diff / (1024 * 1024)) / time_diff
                
                # Get system metrics
                cpu_usage = psutil.cpu_percent(interval=None)
                memory_info = psutil.virtual_memory()
                memory_usage_mb = memory_info.used / (1024 * 1024)
                
                # Get disk I/O metrics
                disk_io_read_mbps = 0.0
                disk_io_write_mbps = 0.0
                
                try:
                    current_io = psutil.disk_io_counters(perdisk=True)
                    device_name = self._get_device_name(metrics.device_path)
                    
                    if device_name and device_name in current_io and device_io_start:
                        current_device_io = current_io[device_name]
                        read_bytes_diff = current_device_io.read_bytes - device_io_start.read_bytes
                        write_bytes_diff = current_device_io.write_bytes - device_io_start.write_bytes
                        
                        elapsed = current_time - last_time
                        if elapsed > 0:
                            disk_io_read_mbps = (read_bytes_diff / (1024 * 1024)) / elapsed
                            disk_io_write_mbps = (write_bytes_diff / (1024 * 1024)) / elapsed
                            
                except Exception as e:
                    logger.debug(f"Failed to get disk I/O metrics: {e}")
                
                # Create snapshot
                snapshot = PerformanceSnapshot(
                    timestamp=current_time,
                    bytes_processed=metrics.bytes_processed,
                    operation_time_seconds=current_time - metrics.start_time.timestamp(),
                    throughput_mbps=throughput_mbps,
                    cpu_usage_percent=cpu_usage - self._baseline_cpu,
                    memory_usage_mb=memory_usage_mb - self._baseline_memory,
                    disk_io_read_mbps=disk_io_read_mbps,
                    disk_io_write_mbps=disk_io_write_mbps,
                    operation_phase=current_phase
                )
                
                # Add to metrics
                metrics.snapshots.append(snapshot)
                
                # Limit snapshot history
                if len(metrics.snapshots) > self.max_snapshots:
                    metrics.snapshots = metrics.snapshots[-self.max_snapshots:]
                
                # Update calculated metrics
                metrics.update_estimates()
                
                # Call progress callbacks
                if operation_id in self._progress_callbacks:
                    for callback in self._progress_callbacks[operation_id]:
                        try:
                            callback(metrics)
                        except Exception as e:
                            logger.warning(f"Progress callback failed: {e}")
                
                # Update for next iteration
                last_bytes = metrics.bytes_processed
                last_time = current_time
                
            except Exception as e:
                logger.error(f"Error in performance monitoring for {operation_id}: {e}")
    
    def _get_device_name(self, device_path: str) -> Optional[str]:
        """Extract device name from path for I/O monitoring."""
        import re
        
        # Windows: Extract drive letter (C:, D:, etc)
        if device_path.startswith(('\\\\', '/')):
            # Network paths or Unix paths
            return None
        
        # Try to extract device identifier
        if ':' in device_path:
            # Windows drive letter
            drive = device_path.split(':')[0].upper()
            return f"{drive}:"
        
        # Unix-style paths
        match = re.search(r'/dev/([a-zA-Z0-9]+)', device_path)
        if match:
            return match.group(1)
        
        return None
    
    def _cleanup_operation(self, operation_id: str):
        """Clean up resources for a finished operation."""
        self._active_operations.pop(operation_id, None)
        self._monitoring_threads.pop(operation_id, None)
        self._stop_flags.pop(operation_id, None)
        self._progress_callbacks.pop(operation_id, None)
        
        if hasattr(self, '_current_phases'):
            self._current_phases.pop(operation_id, None)
    
    def get_system_performance_summary(self) -> Dict[str, Any]:
        """Get current system performance summary."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk_io = psutil.disk_io_counters()
            
            return {
                'cpu_usage_percent': cpu_percent,
                'memory_total_gb': memory.total / (1024**3),
                'memory_used_gb': memory.used / (1024**3),
                'memory_available_gb': memory.available / (1024**3),
                'memory_usage_percent': memory.percent,
                'disk_read_mb': disk_io.read_bytes / (1024**2) if disk_io else 0,
                'disk_write_mb': disk_io.write_bytes / (1024**2) if disk_io else 0,
                'active_operations': len(self._active_operations),
                'baseline_cpu': self._baseline_cpu,
                'baseline_memory_mb': self._baseline_memory
            }
        except Exception as e:
            logger.error(f"Failed to get system performance summary: {e}")
            return {}

# Global monitor instance
_performance_monitor: Optional[RealTimePerformanceMonitor] = None

def get_performance_monitor() -> RealTimePerformanceMonitor:
    """Get the global performance monitor instance."""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = RealTimePerformanceMonitor()
    return _performance_monitor

def start_operation_monitoring(operation_id: str, device_path: str, 
                             total_bytes: int, progress_callback: Optional[Callable] = None) -> PerformanceMetrics:
    """Start monitoring a sanitization operation."""
    return get_performance_monitor().start_monitoring(operation_id, device_path, total_bytes, progress_callback)

def update_operation_progress(operation_id: str, bytes_processed: int, phase: str = "sanitizing"):
    """Update progress for a monitored operation."""
    get_performance_monitor().update_progress(operation_id, bytes_processed, phase)

def stop_operation_monitoring(operation_id: str) -> Optional[PerformanceMetrics]:
    """Stop monitoring and get final metrics."""
    return get_performance_monitor().stop_monitoring(operation_id)

def get_operation_metrics(operation_id: str) -> Optional[PerformanceMetrics]:
    """Get current metrics for an operation."""
    return get_performance_monitor().get_current_metrics(operation_id)

def get_system_summary() -> Dict[str, Any]:
    """Get system performance summary."""
    return get_performance_monitor().get_system_performance_summary()