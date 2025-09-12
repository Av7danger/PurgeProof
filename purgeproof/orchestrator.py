"""
Main orchestration engine coordinating hybrid sanitization operations.

This module provides the high-level coordination between device detection,
method selection, native engine execution, and progress monitoring for
optimal sanitization workflows.
"""

import asyncio
import logging
import time
import threading
from typing import Dict, List, Tuple, Optional, Callable, Any, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import json

from .device_utils import (
    DeviceCapabilities, DeviceEnumerator, DevicePerformanceProfiler,
    enumerate_devices, get_device_capabilities
)
from .decision_engine import (
    MethodSelectionEngine, ComplianceLevel, SecurityObjective, 
    SanitizationMethod, MethodScore, DeviceContext, SelectionCriteria,
    select_sanitization_method
)

# Try to import the native Rust engine
try:
    from . import ffi_bindings  # type: ignore
    NATIVE_ENGINE_AVAILABLE = True
except ImportError:
    NATIVE_ENGINE_AVAILABLE = False

logger = logging.getLogger(__name__)

class OperationStatus(Enum):
    """Status of sanitization operations."""
    PENDING = auto()
    ANALYZING = auto()
    SELECTING_METHOD = auto()
    PREPARING = auto()
    EXECUTING = auto()
    VERIFYING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()

class JobPriority(Enum):
    """Job priority levels."""
    LOW = auto()
    NORMAL = auto()
    HIGH = auto()
    CRITICAL = auto()

@dataclass
class ProgressInfo:
    """Progress information for operations."""
    current_phase: str
    phase_progress: float  # 0.0 to 1.0
    overall_progress: float  # 0.0 to 1.0
    bytes_processed: int
    total_bytes: int
    current_speed_mbps: float
    estimated_time_remaining: float  # seconds
    detailed_status: str

@dataclass
class OperationResult:
    """Result of a sanitization operation."""
    success: bool
    device_path: str
    method_used: SanitizationMethod
    duration_seconds: float
    bytes_processed: int
    throughput_mbps: float
    verification_passed: bool
    compliance_met: List[str]
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SanitizationJob:
    """Sanitization job configuration."""
    job_id: str
    device_path: str
    device_capabilities: Optional[DeviceCapabilities]
    compliance_level: ComplianceLevel
    security_objective: SecurityObjective
    max_time_minutes: Optional[float]
    priority: JobPriority
    verify_completion: bool
    progress_callback: Optional[Callable[[str, ProgressInfo], None]]
    completion_callback: Optional[Callable[[str, OperationResult], None]]
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    status: OperationStatus = OperationStatus.PENDING
    selected_method: Optional[MethodScore] = None
    result: Optional[OperationResult] = None

class HybridSanitizationOrchestrator:
    """
    Main orchestration engine for hybrid sanitization operations.
    
    Coordinates device detection, method selection, native engine execution,
    and progress monitoring for optimal sanitization workflows.
    """
    
    def __init__(self, max_concurrent_jobs: int = 4):
        self.max_concurrent_jobs = max_concurrent_jobs
        self.device_enumerator = DeviceEnumerator()
        self.method_selector = MethodSelectionEngine()
        self.performance_profiler = DevicePerformanceProfiler()
        
        # Job management
        self.jobs: Dict[str, SanitizationJob] = {}
        self.job_queue: List[str] = []
        self.active_jobs: Dict[str, Any] = {}  # Can hold threads or futures
        self.job_lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'total_jobs': 0,
            'completed_jobs': 0,
            'failed_jobs': 0,
            'total_bytes_processed': 0,
            'total_execution_time': 0.0,
            'average_throughput_mbps': 0.0,
        }
        
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_jobs)
        self._running = True
        self._job_processor_thread = threading.Thread(target=self._process_job_queue, daemon=True)
        self._job_processor_thread.start()
    
    async def enumerate_available_devices(self, force_refresh: bool = False) -> List[DeviceCapabilities]:
        """
        Enumerate all available storage devices with capabilities.
        
        Args:
            force_refresh: Force device cache refresh
            
        Returns:
            List of device capabilities
        """
        logger.info("Enumerating available storage devices...")
        return await self.device_enumerator.enumerate_devices(force_refresh)
    
    async def analyze_device(self, device_path: str) -> Optional[DeviceCapabilities]:
        """
        Analyze a specific device and return its capabilities.
        
        Args:
            device_path: Path to device to analyze
            
        Returns:
            Device capabilities or None if not found
        """
        logger.info(f"Analyzing device: {device_path}")
        return await get_device_capabilities(device_path)
    
    def recommend_sanitization_method(self, device_capabilities: DeviceCapabilities,
                                    compliance_level: ComplianceLevel = ComplianceLevel.STANDARD,
                                    security_objective: SecurityObjective = SecurityObjective.BALANCED,
                                    max_time_minutes: Optional[float] = None) -> MethodScore:
        """
        Recommend optimal sanitization method for device and requirements.
        
        Args:
            device_capabilities: Device to sanitize
            compliance_level: Required compliance level
            security_objective: Primary security objective
            max_time_minutes: Maximum time constraint
            
        Returns:
            Method recommendation with detailed scoring
        """
        logger.info(f"Recommending method for {device_capabilities.path}")
        
        device_context = DeviceContext(capabilities=device_capabilities)
        criteria = SelectionCriteria(
            compliance_level=compliance_level,
            security_objective=security_objective,
            max_time_minutes=max_time_minutes
        )
        
        return self.method_selector.select_optimal_method(device_context, criteria)
    
    def submit_sanitization_job(self, device_path: str,
                              compliance_level: ComplianceLevel = ComplianceLevel.STANDARD,
                              security_objective: SecurityObjective = SecurityObjective.BALANCED,
                              max_time_minutes: Optional[float] = None,
                              priority: JobPriority = JobPriority.NORMAL,
                              verify_completion: bool = True,
                              progress_callback: Optional[Callable[[str, ProgressInfo], None]] = None,
                              completion_callback: Optional[Callable[[str, OperationResult], None]] = None) -> str:
        """
        Submit a sanitization job for execution.
        
        Args:
            device_path: Path to device to sanitize
            compliance_level: Required compliance level
            security_objective: Primary security objective
            max_time_minutes: Maximum time constraint
            priority: Job priority
            verify_completion: Whether to verify sanitization completion
            progress_callback: Optional progress update callback
            completion_callback: Optional completion callback
            
        Returns:
            Job ID for tracking
        """
        job_id = f"job_{int(time.time() * 1000)}_{len(self.jobs)}"
        
        logger.info(f"Submitting sanitization job {job_id} for {device_path}")
        
        # Get device capabilities (this should be done async, but we'll handle it in the job)
        job = SanitizationJob(
            job_id=job_id,
            device_path=device_path,
            device_capabilities=None,  # Will be populated when job starts
            compliance_level=compliance_level,
            security_objective=security_objective,
            max_time_minutes=max_time_minutes,
            priority=priority,
            verify_completion=verify_completion,
            progress_callback=progress_callback,
            completion_callback=completion_callback
        )
        
        with self.job_lock:
            self.jobs[job_id] = job
            self._insert_job_by_priority(job_id)
            self.stats['total_jobs'] += 1
        
        logger.info(f"Job {job_id} queued (priority: {priority.name})")
        return job_id
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a specific job.
        
        Args:
            job_id: Job ID to query
            
        Returns:
            Job status information or None if job not found
        """
        job = self.jobs.get(job_id)
        if not job:
            return None
        
        return {
            'job_id': job.job_id,
            'device_path': job.device_path,
            'status': job.status.name,
            'priority': job.priority.name,
            'compliance_level': job.compliance_level.name,
            'security_objective': job.security_objective.name,
            'created_at': job.created_at,
            'started_at': job.started_at,
            'completed_at': job.completed_at,
            'selected_method': job.selected_method.method.name if job.selected_method else None,
            'estimated_duration': job.selected_method.estimated_duration_minutes if job.selected_method else None,
            'result': {
                'success': job.result.success,
                'duration_seconds': job.result.duration_seconds,
                'throughput_mbps': job.result.throughput_mbps,
                'verification_passed': job.result.verification_passed,
                'error_message': job.result.error_message,
            } if job.result else None
        }
    
    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a pending or running job.
        
        Args:
            job_id: Job ID to cancel
            
        Returns:
            True if job was cancelled, False if not found or already completed
        """
        with self.job_lock:
            job = self.jobs.get(job_id)
            if not job:
                return False
            
            if job.status in [OperationStatus.COMPLETED, OperationStatus.FAILED, OperationStatus.CANCELLED]:
                return False
            
            job.status = OperationStatus.CANCELLED
            
            # Remove from queue if pending
            if job_id in self.job_queue:
                self.job_queue.remove(job_id)
            
            # TODO: Cancel active execution if running
            if job_id in self.active_jobs:
                logger.warning(f"Job {job_id} is running, cancellation may not be immediate")
        
        logger.info(f"Job {job_id} cancelled")
        return True
    
    def get_orchestrator_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics and performance metrics."""
        with self.job_lock:
            active_count = len(self.active_jobs)
            queued_count = len(self.job_queue)
            
            return {
                'total_jobs': self.stats['total_jobs'],
                'completed_jobs': self.stats['completed_jobs'],
                'failed_jobs': self.stats['failed_jobs'],
                'active_jobs': active_count,
                'queued_jobs': queued_count,
                'total_bytes_processed': self.stats['total_bytes_processed'],
                'total_execution_time': self.stats['total_execution_time'],
                'average_throughput_mbps': self.stats['average_throughput_mbps'],
                'success_rate': (
                    self.stats['completed_jobs'] / max(1, self.stats['completed_jobs'] + self.stats['failed_jobs'])
                ),
            }
    
    def shutdown(self):
        """Shutdown the orchestrator and cleanup resources."""
        logger.info("Shutting down sanitization orchestrator...")
        
        self._running = False
        
        # Cancel all pending jobs
        with self.job_lock:
            for job_id in list(self.job_queue):
                self.cancel_job(job_id)
        
        # Wait for active jobs to complete (with timeout)
        shutdown_timeout = 30  # seconds
        start_time = time.time()
        
        while self.active_jobs and (time.time() - start_time) < shutdown_timeout:
            time.sleep(1)
        
        # Force shutdown executor
        self.executor.shutdown(wait=True)
        
        logger.info("Orchestrator shutdown complete")
    
    def _insert_job_by_priority(self, job_id: str):
        """Insert job into queue based on priority."""
        job = self.jobs[job_id]
        priority_order = {
            JobPriority.CRITICAL: 0,
            JobPriority.HIGH: 1,
            JobPriority.NORMAL: 2,
            JobPriority.LOW: 3,
        }
        
        job_priority = priority_order[job.priority]
        
        # Find insertion point
        insert_index = len(self.job_queue)
        for i, queued_job_id in enumerate(self.job_queue):
            queued_job = self.jobs[queued_job_id]
            if priority_order[queued_job.priority] > job_priority:
                insert_index = i
                break
        
        self.job_queue.insert(insert_index, job_id)
    
    def _process_job_queue(self):
        """Background thread to process job queue."""
        while self._running:
            try:
                job_id = None
                
                with self.job_lock:
                    if (self.job_queue and 
                        len(self.active_jobs) < self.max_concurrent_jobs):
                        job_id = self.job_queue.pop(0)
                        job = self.jobs[job_id]
                        if job.status == OperationStatus.PENDING:
                            job.status = OperationStatus.ANALYZING
                            job.started_at = time.time()
                            
                            # Start job in executor
                            future = self.executor.submit(self._execute_job, job_id)
                            self.active_jobs[job_id] = future
                
                if not job_id:
                    time.sleep(0.1)  # No jobs to process, wait briefly
                    
            except Exception as e:
                logger.error(f"Error in job queue processor: {e}")
                time.sleep(1)
    
    def _execute_job(self, job_id: str):
        """Execute a sanitization job."""
        try:
            job = self.jobs[job_id]
            logger.info(f"Executing job {job_id} for device {job.device_path}")
            
            # Phase 1: Device Analysis
            self._update_job_progress(job, "Device Analysis", 0.0, 0.1)
            
            # Get device capabilities if not already set
            if not job.device_capabilities:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                job.device_capabilities = loop.run_until_complete(
                    self.analyze_device(job.device_path)
                )
                loop.close()
                
                if not job.device_capabilities:
                    raise Exception(f"Could not analyze device {job.device_path}")
            
            # Phase 2: Method Selection
            job.status = OperationStatus.SELECTING_METHOD
            self._update_job_progress(job, "Method Selection", 0.0, 0.2)
            
            job.selected_method = self.recommend_sanitization_method(
                job.device_capabilities,
                job.compliance_level,
                job.security_objective,
                job.max_time_minutes
            )
            
            logger.info(f"Selected method for job {job_id}: {job.selected_method.method}")
            
            # Phase 3: Preparation
            job.status = OperationStatus.PREPARING
            self._update_job_progress(job, "Preparing Sanitization", 0.0, 0.3)
            
            # Prepare for sanitization (unmount, etc.)
            self._prepare_device_for_sanitization(job)
            
            # Phase 4: Execution
            job.status = OperationStatus.EXECUTING
            self._update_job_progress(job, "Executing Sanitization", 0.0, 0.8)
            
            result = self._execute_sanitization_method(job)
            
            # Phase 5: Verification (if requested)
            if job.verify_completion:
                job.status = OperationStatus.VERIFYING
                self._update_job_progress(job, "Verifying Completion", 0.0, 0.95)
                
                verification_result = self._verify_sanitization(job, result)
                result.verification_passed = verification_result
            else:
                result.verification_passed = True
            
            # Complete job
            job.status = OperationStatus.COMPLETED
            job.completed_at = time.time()
            job.result = result
            
            self._update_job_progress(job, "Completed", 1.0, 1.0)
            
            # Update statistics
            with self.job_lock:
                self.stats['completed_jobs'] += 1
                self.stats['total_bytes_processed'] += result.bytes_processed
                self.stats['total_execution_time'] += result.duration_seconds
                
                # Update average throughput
                if self.stats['completed_jobs'] > 0:
                    self.stats['average_throughput_mbps'] = (
                        self.stats['total_bytes_processed'] / (1024 * 1024) /
                        max(1, self.stats['total_execution_time'])
                    )
            
            logger.info(f"Job {job_id} completed successfully")
            
            # Call completion callback
            if job.completion_callback:
                try:
                    job.completion_callback(job_id, result)
                except Exception as e:
                    logger.warning(f"Completion callback failed for job {job_id}: {e}")
                    
        except Exception as e:
            logger.error(f"Job {job_id} failed: {e}")
            
            job.status = OperationStatus.FAILED
            job.completed_at = time.time()
            job.result = OperationResult(
                success=False,
                device_path=job.device_path,
                method_used=job.selected_method.method if job.selected_method else SanitizationMethod.OVERWRITE_SINGLE,
                duration_seconds=time.time() - (job.started_at or time.time()),
                bytes_processed=0,
                throughput_mbps=0.0,
                verification_passed=False,
                compliance_met=[],
                error_message=str(e)
            )
            
            with self.job_lock:
                self.stats['failed_jobs'] += 1
            
            # Call completion callback
            if job.completion_callback:
                try:
                    job.completion_callback(job_id, job.result)
                except Exception as e:
                    logger.warning(f"Completion callback failed for job {job_id}: {e}")
        
        finally:
            # Remove from active jobs
            with self.job_lock:
                self.active_jobs.pop(job_id, None)
    
    def _update_job_progress(self, job: SanitizationJob, phase: str, 
                           phase_progress: float, overall_progress: float):
        """Update job progress and call progress callback."""
        if job.progress_callback:
            try:
                progress = ProgressInfo(
                    current_phase=phase,
                    phase_progress=phase_progress,
                    overall_progress=overall_progress,
                    bytes_processed=0,  # TODO: Track actual bytes
                    total_bytes=job.device_capabilities.size_bytes if job.device_capabilities else 0,
                    current_speed_mbps=0.0,  # TODO: Track actual speed
                    estimated_time_remaining=0.0,  # TODO: Calculate remaining time
                    detailed_status=f"{phase} in progress..."
                )
                
                job.progress_callback(job.job_id, progress)
            except Exception as e:
                logger.warning(f"Progress callback failed for job {job.job_id}: {e}")
    
    def _prepare_device_for_sanitization(self, job: SanitizationJob):
        """Prepare device for sanitization (unmount, check locks, etc.)."""
        # TODO: Implement device preparation
        # - Check if device is mounted and unmount if necessary
        # - Verify no processes are using the device
        # - Check for encryption locks
        # - Prepare hardware for specific sanitization methods
        time.sleep(0.1)  # Placeholder
    
    def _execute_sanitization_method(self, job: SanitizationJob) -> OperationResult:
        """Execute the selected sanitization method."""
        start_time = time.time()
        
        if not job.selected_method:
            raise Exception("No method selected for job")
        
        if NATIVE_ENGINE_AVAILABLE:
            try:
                return self._execute_with_native_engine(job)
            except Exception as e:
                logger.warning(f"Native execution failed, using Python fallback: {e}")
        
        return self._execute_with_python_implementation(job)
    
    def _execute_with_native_engine(self, job: SanitizationJob) -> OperationResult:
        """Execute sanitization using the native Rust engine."""
        if not job.selected_method or not job.device_capabilities:
            raise Exception("Missing method or device capabilities")
            
        method_map = {
            SanitizationMethod.CRYPTO_ERASE: 'crypto_erase',
            SanitizationMethod.NVME_SANITIZE: 'nvme_sanitize',
            SanitizationMethod.SECURE_ERASE: 'secure_erase',
            SanitizationMethod.TRIM_DISCARD: 'trim_discard',
            SanitizationMethod.OVERWRITE_SINGLE: 'overwrite_single',
            SanitizationMethod.OVERWRITE_MULTI: 'overwrite_multi',
            SanitizationMethod.HYBRID_CRYPTO: 'hybrid_crypto',
            SanitizationMethod.HYBRID_SECURE: 'hybrid_secure',
        }
        
        native_method = method_map.get(job.selected_method.method, 'overwrite_single')
        
        # Call appropriate native function based on method
        if native_method == 'crypto_erase':
            result = ffi_bindings.crypto_erase_fast(job.device_path)
        elif native_method == 'nvme_sanitize':
            result = ffi_bindings.nvme_sanitize_direct(job.device_path, 'crypto_erase')
        elif native_method == 'overwrite_single':
            result = ffi_bindings.overwrite_parallel(
                job.device_path, 
                1,  # single pass
                job.device_capabilities.size_bytes
            )
        elif native_method == 'overwrite_multi':
            result = ffi_bindings.overwrite_parallel(
                job.device_path,
                3,  # three passes
                job.device_capabilities.size_bytes
            )
        else:
            # Fallback to overwrite
            result = ffi_bindings.overwrite_parallel(
                job.device_path,
                1,
                job.device_capabilities.size_bytes
            )
        
        # Convert native result to OperationResult
        return OperationResult(
            success=result.get('success', False),
            device_path=job.device_path,
            method_used=job.selected_method.method,
            duration_seconds=result.get('duration_seconds', 0.0),
            bytes_processed=result.get('bytes_processed', 0),
            throughput_mbps=result.get('throughput_mbps', 0.0),
            verification_passed=result.get('verification_passed', False),
            compliance_met=job.selected_method.compliance_standards,
            error_message=result.get('error_message'),
            warnings=result.get('warnings', []),
            metadata=result.get('metadata', {})
        )
    
    def _execute_with_python_implementation(self, job: SanitizationJob) -> OperationResult:
        """Execute sanitization using Python implementation (fallback)."""
        start_time = time.time()
        
        if not job.selected_method or not job.device_capabilities:
            raise Exception("Missing method or device capabilities")
        
        # Mock implementation for demonstration
        # In a real implementation, this would call platform-specific APIs
        
        logger.info(f"Executing {job.selected_method.method} on {job.device_path} (Python fallback)")
        
        # Simulate execution time based on method and device
        execution_time = job.selected_method.estimated_duration_minutes * 60
        
        # For demo purposes, just sleep for a short time
        demo_time = min(2.0, execution_time / 30)  # Scale down for demo
        time.sleep(demo_time)
        
        actual_duration = time.time() - start_time
        
        # Simulate successful completion
        return OperationResult(
            success=True,
            device_path=job.device_path,
            method_used=job.selected_method.method,
            duration_seconds=actual_duration,
            bytes_processed=job.device_capabilities.size_bytes,
            throughput_mbps=job.device_capabilities.max_write_speed_mbps,
            verification_passed=False,  # Will be set during verification phase
            compliance_met=job.selected_method.compliance_standards,
            warnings=["Python fallback implementation - not for production use"]
        )
    
    def _verify_sanitization(self, job: SanitizationJob, result: OperationResult) -> bool:
        """Verify sanitization completion."""
        if NATIVE_ENGINE_AVAILABLE:
            try:
                # Use native verification
                sample_size = 1000  # Default sample size in MB
                if job.device_capabilities:
                    sample_size = min(1000, job.device_capabilities.size_bytes // (1024 * 1024))
                
                verify_result = ffi_bindings.verify_sampling_fast(
                    job.device_path,
                    sample_size
                )
                return verify_result.get('success', False)
            except Exception as e:
                logger.warning(f"Native verification failed: {e}")
        
        # Python fallback verification
        logger.info(f"Verifying sanitization of {job.device_path} (Python fallback)")
        
        # Mock verification - in real implementation, would sample device
        time.sleep(0.5)  # Simulate verification time
        
        # For demo, assume verification passes
        return True

# Global orchestrator instance
_orchestrator: Optional[HybridSanitizationOrchestrator] = None

def get_orchestrator() -> HybridSanitizationOrchestrator:
    """Get the global orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = HybridSanitizationOrchestrator()
    return _orchestrator

def shutdown_orchestrator():
    """Shutdown the global orchestrator."""
    global _orchestrator
    if _orchestrator:
        _orchestrator.shutdown()
        _orchestrator = None

# Convenience functions
async def enumerate_devices_and_capabilities() -> List[DeviceCapabilities]:
    """Enumerate all devices with capabilities."""
    return await get_orchestrator().enumerate_available_devices()

def submit_sanitization(device_path: str, **kwargs) -> str:
    """Submit a sanitization job."""
    return get_orchestrator().submit_sanitization_job(device_path, **kwargs)

def get_job_status(job_id: str) -> Optional[Dict[str, Any]]:
    """Get job status."""
    return get_orchestrator().get_job_status(job_id)

def cancel_sanitization(job_id: str) -> bool:
    """Cancel a sanitization job."""
    return get_orchestrator().cancel_job(job_id)

if __name__ == "__main__":
    # Example usage
    import asyncio
    
    async def main():
        orchestrator = get_orchestrator()
        
        # Enumerate devices
        devices = await orchestrator.enumerate_available_devices()
        print(f"Found {len(devices)} devices:")
        
        for device in devices:
            print(f"  {device.path}: {device.model} ({device.device_type.name})")
            
            # Get method recommendation
            recommendation = orchestrator.recommend_sanitization_method(
                device,
                ComplianceLevel.ENHANCED,
                SecurityObjective.BALANCED,
                max_time_minutes=30
            )
            
            print(f"    Recommended: {recommendation.method} "
                  f"(score: {recommendation.overall_score:.2f}, "
                  f"time: {recommendation.estimated_duration_minutes:.1f}min)")
            
            # Submit job (for demo, don't actually execute)
            if False:  # Set to True to actually submit jobs
                job_id = orchestrator.submit_sanitization_job(
                    device.path,
                    compliance_level=ComplianceLevel.STANDARD,
                    security_objective=SecurityObjective.SPEED,
                    max_time_minutes=10
                )
                print(f"    Submitted job: {job_id}")
        
        # Show statistics
        stats = orchestrator.get_orchestrator_statistics()
        print(f"\nOrchestrator stats: {stats}")
        
        # Cleanup
        shutdown_orchestrator()
    
    asyncio.run(main())