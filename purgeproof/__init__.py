"""
PurgeProof: Enterprise-grade hybrid data sanitization solution.

This package provides a comprehensive data sanitization solution combining
high-performance native Rust engine with intelligent Python orchestration
for optimal security, compliance, and performance.

Main Components:
- device_utils: Device enumeration and capability detection
- decision_engine: Intelligent method selection algorithms  
- orchestrator: Main coordination and job management
- ffi_bindings: Native Rust engine integration

Key Features:
- Hybrid architecture (Rust + Python)
- Intelligent method selection
- NIST SP 800-88 compliance
- Parallel processing
- Hardware acceleration
- Real-time progress monitoring
"""

import logging
from typing import List, Dict, Optional, Any

# Import DeviceCapabilities first for type annotations
from .device_utils import DeviceCapabilities as _DeviceCapabilities

# Core modules
from .device_utils import (
    DeviceType, EncryptionType, InterfaceType,
    DeviceEnumerator, DevicePerformanceProfiler,
    enumerate_devices, get_device_capabilities, get_optimal_chunk_size
)

from .decision_engine import (
    ComplianceLevel, SecurityObjective, SanitizationMethod, MethodScore,
    DeviceContext, SelectionCriteria, MethodSelectionEngine,
    select_sanitization_method
)

from .orchestrator import (
    OperationStatus, JobPriority, ProgressInfo, OperationResult,
    SanitizationJob, HybridSanitizationOrchestrator,
    get_orchestrator, shutdown_orchestrator,
    enumerate_devices_and_capabilities, submit_sanitization,
    get_job_status, cancel_sanitization
)

# FFI bindings (optional, with graceful fallback)
try:
    from . import ffi_bindings
    NATIVE_ENGINE_AVAILABLE = ffi_bindings.is_native_engine_available()
except ImportError:
    ffi_bindings = None
    NATIVE_ENGINE_AVAILABLE = False

# Package metadata
__version__ = "2.1.0"
__author__ = "PurgeProof Development Team"
__description__ = "Enterprise-grade hybrid data sanitization solution"

# Setup logging
logger = logging.getLogger(__name__)

def configure_logging(level: str = "INFO", format_string: Optional[str] = None):
    """
    Configure logging for the PurgeProof package.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_string: Custom format string for log messages
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=format_string,
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    logger.info(f"PurgeProof v{__version__} logging configured (level: {level})")

def get_version_info() -> Dict[str, Any]:
    """Get detailed version and capability information."""
    return {
        'version': __version__,
        'description': __description__,
        'native_engine_available': NATIVE_ENGINE_AVAILABLE,
        'ffi_bindings_loaded': ffi_bindings is not None,
        'capabilities': {
            'device_enumeration': True,
            'method_selection': True,
            'job_orchestration': True,
            'native_acceleration': NATIVE_ENGINE_AVAILABLE,
            'crypto_erase': NATIVE_ENGINE_AVAILABLE,
            'nvme_sanitize': NATIVE_ENGINE_AVAILABLE,
            'parallel_overwrite': True,
            'sampling_verification': NATIVE_ENGINE_AVAILABLE,
            'compliance_validation': True,
        },
        'supported_platforms': ['Windows', 'Linux', 'macOS'],
        'supported_methods': [method.name for method in SanitizationMethod],
        'compliance_levels': [level.name for level in ComplianceLevel],
    }

def quick_device_scan() -> List[_DeviceCapabilities]:
    """
    Perform a quick scan of available storage devices.
    
    Returns:
        List of device capabilities
    """
    import asyncio
    
    async def _scan():
        return await enumerate_devices()
    
    return asyncio.run(_scan())

def recommend_method(device_path: str, 
                    compliance: str = "STANDARD",
                    objective: str = "BALANCED",
                    max_time_minutes: Optional[float] = None) -> MethodScore:
    """
    Get method recommendation for a device.
    
    Args:
        device_path: Path to device
        compliance: Compliance level name
        objective: Security objective name  
        max_time_minutes: Maximum time constraint
        
    Returns:
        Method recommendation with scoring
    """
    import asyncio
    
    async def _recommend():
        device_caps = await get_device_capabilities(device_path)
        if not device_caps:
            raise ValueError(f"Device not found: {device_path}")
        
        return select_sanitization_method(
            device_caps,
            ComplianceLevel[compliance.upper()],
            SecurityObjective[objective.upper()],
            max_time_minutes
        )
    
    return asyncio.run(_recommend())

def sanitize_device(device_path: str,
                   compliance: str = "STANDARD", 
                   objective: str = "BALANCED",
                   max_time_minutes: Optional[float] = None,
                   priority: str = "NORMAL",
                   verify: bool = True,
                   progress_callback: Optional[Any] = None,
                   completion_callback: Optional[Any] = None) -> str:
    """
    Submit a device for sanitization.
    
    Args:
        device_path: Path to device to sanitize
        compliance: Compliance level (BASIC, STANDARD, ENHANCED, CLASSIFIED, TOP_SECRET)
        objective: Security objective (SPEED, SECURITY, COMPLIANCE, BALANCED)
        max_time_minutes: Maximum time constraint
        priority: Job priority (LOW, NORMAL, HIGH, CRITICAL)
        verify: Whether to verify completion
        progress_callback: Optional progress callback
        completion_callback: Optional completion callback
        
    Returns:
        Job ID for tracking
    """
    return submit_sanitization(
        device_path,
        compliance_level=ComplianceLevel[compliance.upper()],
        security_objective=SecurityObjective[objective.upper()],
        max_time_minutes=max_time_minutes,
        priority=JobPriority[priority.upper()],
        verify_completion=verify,
        progress_callback=progress_callback,
        completion_callback=completion_callback
    )

def get_orchestrator_stats() -> Dict[str, Any]:
    """Get orchestrator statistics."""
    return get_orchestrator().get_orchestrator_statistics()

def list_active_jobs() -> List[Dict[str, Any]]:
    """List all active jobs."""
    orchestrator = get_orchestrator()
    jobs = []
    
    for job_id in orchestrator.jobs:
        job_status = orchestrator.get_job_status(job_id)
        if job_status and job_status['status'] not in ['COMPLETED', 'FAILED', 'CANCELLED']:
            jobs.append(job_status)
    
    return jobs

def cleanup():
    """Cleanup resources and shutdown orchestrator."""
    logger.info("Cleaning up PurgeProof resources...")
    shutdown_orchestrator()
    logger.info("Cleanup complete")

# Convenience aliases
DeviceCapabilities = _DeviceCapabilities
SanitizationMethod = SanitizationMethod
ComplianceLevel = ComplianceLevel
SecurityObjective = SecurityObjective

# Main interface functions
scan_devices = quick_device_scan
get_recommendation = recommend_method
sanitize = sanitize_device
get_stats = get_orchestrator_stats
list_jobs = list_active_jobs

# Package initialization
logger.info(f"PurgeProof v{__version__} initialized")
if NATIVE_ENGINE_AVAILABLE:
    logger.info("Native Rust engine available - optimal performance enabled")
else:
    logger.warning("Native Rust engine not available - using Python fallback implementations")

__all__ = [
    # Core classes
    'DeviceCapabilities', 'DeviceType', 'EncryptionType', 'InterfaceType',
    'ComplianceLevel', 'SecurityObjective', 'SanitizationMethod', 'MethodScore',
    'OperationStatus', 'JobPriority', 'ProgressInfo', 'OperationResult',
    'DeviceContext', 'SelectionCriteria', 'SanitizationJob',
    
    # Main engines
    'DeviceEnumerator', 'DevicePerformanceProfiler', 'MethodSelectionEngine',
    'HybridSanitizationOrchestrator',
    
    # Core functions
    'enumerate_devices', 'get_device_capabilities', 'select_sanitization_method',
    'submit_sanitization', 'get_job_status', 'cancel_sanitization',
    'get_orchestrator', 'shutdown_orchestrator',
    
    # Convenience functions
    'quick_device_scan', 'recommend_method', 'sanitize_device',
    'get_orchestrator_stats', 'list_active_jobs', 'cleanup',
    
    # Aliases
    'scan_devices', 'get_recommendation', 'sanitize', 'get_stats', 'list_jobs',
    
    # Utilities
    'configure_logging', 'get_version_info',
    
    # Constants
    'NATIVE_ENGINE_AVAILABLE', '__version__',
]