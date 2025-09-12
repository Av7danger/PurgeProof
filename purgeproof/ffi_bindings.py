"""
FFI bindings for the native Rust sanitization engine.

This module provides Python bindings to the high-performance Rust engine
for optimal sanitization operations with native speed and hardware access.
"""

import logging
import ctypes
import platform
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import json

logger = logging.getLogger(__name__)

# Try to load the native Rust library
_native_lib = None
_lib_loaded = False

def _load_native_library():
    """Load the native Rust library."""
    global _native_lib, _lib_loaded
    
    if _lib_loaded:
        return _native_lib
    
    try:
        # Determine library name based on platform
        if platform.system() == "Windows":
            lib_name = "purgeproof_engine.dll"
        elif platform.system() == "Darwin":
            lib_name = "libpurgeproof_engine.dylib"
        else:
            lib_name = "libpurgeproof_engine.so"
        
        # Try to find the library in various locations
        search_paths = [
            Path(__file__).parent / "native" / lib_name,
            Path(__file__).parent.parent / "target" / "release" / lib_name,
            Path(__file__).parent.parent / "target" / "debug" / lib_name,
            Path(lib_name),  # Current directory
        ]
        
        for lib_path in search_paths:
            if lib_path.exists():
                logger.info(f"Loading native library from: {lib_path}")
                _native_lib = ctypes.CDLL(str(lib_path))
                break
        else:
            logger.warning("Native Rust library not found in any search path")
            _native_lib = None
        
    except Exception as e:
        logger.warning(f"Failed to load native Rust library: {e}")
        _native_lib = None
    
    _lib_loaded = True
    return _native_lib

def _setup_function_signatures():
    """Setup function signatures for the native library."""
    lib = _load_native_library()
    if not lib:
        return
    
    try:
        # Define C structures that match Rust FFI
        class PurgeProofResult(ctypes.Structure):
            _fields_ = [
                ("success", ctypes.c_bool),
                ("duration_seconds", ctypes.c_double),
                ("bytes_processed", ctypes.c_uint64),
                ("throughput_mbps", ctypes.c_double),
                ("verification_passed", ctypes.c_bool),
                ("error_message", ctypes.c_char_p),
                ("method_used", ctypes.c_char_p),
            ]
        
        class PurgeProofDeviceInfo(ctypes.Structure):
            _fields_ = [
                ("path", ctypes.c_char_p),
                ("size_bytes", ctypes.c_uint64),
                ("sector_size", ctypes.c_uint32),
                ("model", ctypes.c_char_p),
                ("serial", ctypes.c_char_p),
                ("supports_crypto_erase", ctypes.c_bool),
                ("supports_secure_erase", ctypes.c_bool),
                ("supports_nvme_sanitize", ctypes.c_bool),
                ("supports_trim", ctypes.c_bool),
                ("is_encrypted", ctypes.c_bool),
                ("max_write_speed_mbps", ctypes.c_double),
            ]
        
        # Set up function signatures
        
        # Crypto erase function
        lib.crypto_erase_fast.argtypes = [ctypes.c_char_p]
        lib.crypto_erase_fast.restype = PurgeProofResult
        
        # NVMe sanitize function
        lib.nvme_sanitize_direct.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.nvme_sanitize_direct.restype = PurgeProofResult
        
        # Parallel overwrite function
        lib.overwrite_parallel.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint64]
        lib.overwrite_parallel.restype = PurgeProofResult
        
        # Device capabilities function
        lib.get_device_capabilities.argtypes = [ctypes.c_char_p]
        lib.get_device_capabilities.restype = PurgeProofDeviceInfo
        
        # Verification function
        lib.verify_sampling_fast.argtypes = [ctypes.c_char_p, ctypes.c_uint64]
        lib.verify_sampling_fast.restype = PurgeProofResult
        
        # Method selection function
        lib.select_optimal_method.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        lib.select_optimal_method.restype = ctypes.c_char_p
        
        # Device enumeration function
        lib.enumerate_storage_devices.argtypes = []
        lib.enumerate_storage_devices.restype = ctypes.c_char_p
        
        # TRIM/discard function
        lib.trim_discard_ranges.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64]
        lib.trim_discard_ranges.restype = PurgeProofResult
        
        # Free string function (for memory management)
        lib.free_string.argtypes = [ctypes.c_char_p]
        lib.free_string.restype = None
        
        logger.info("Native library function signatures configured")
        
    except Exception as e:
        logger.error(f"Failed to setup function signatures: {e}")

# Setup function signatures on import
_setup_function_signatures()

def is_native_engine_available() -> bool:
    """Check if the native Rust engine is available."""
    return _load_native_library() is not None

def crypto_erase_fast(device_path: str) -> Dict[str, Any]:
    """
    Perform cryptographic erase using native engine.
    
    Args:
        device_path: Path to device to erase
        
    Returns:
        Operation result dictionary
    """
    lib = _load_native_library()
    if not lib:
        raise RuntimeError("Native library not available")
    
    try:
        logger.info(f"Performing crypto erase on {device_path}")
        
        # Call native function
        result = lib.crypto_erase_fast(device_path.encode('utf-8'))
        
        # Convert result to dictionary
        return {
            'success': result.success,
            'duration_seconds': result.duration_seconds,
            'bytes_processed': result.bytes_processed,
            'throughput_mbps': result.throughput_mbps,
            'verification_passed': result.verification_passed,
            'error_message': result.error_message.decode('utf-8') if result.error_message else None,
            'method_used': result.method_used.decode('utf-8') if result.method_used else 'crypto_erase',
        }
        
    except Exception as e:
        logger.error(f"Crypto erase failed: {e}")
        return {
            'success': False,
            'duration_seconds': 0.0,
            'bytes_processed': 0,
            'throughput_mbps': 0.0,
            'verification_passed': False,
            'error_message': str(e),
            'method_used': 'crypto_erase',
        }

def nvme_sanitize_direct(device_path: str, action: str = "crypto_erase") -> Dict[str, Any]:
    """
    Perform NVMe sanitize using native engine.
    
    Args:
        device_path: Path to NVMe device
        action: Sanitize action ('crypto_erase', 'block_erase', 'overwrite')
        
    Returns:
        Operation result dictionary
    """
    lib = _load_native_library()
    if not lib:
        raise RuntimeError("Native library not available")
    
    try:
        logger.info(f"Performing NVMe sanitize ({action}) on {device_path}")
        
        # Call native function
        result = lib.nvme_sanitize_direct(
            device_path.encode('utf-8'),
            action.encode('utf-8')
        )
        
        # Convert result to dictionary
        return {
            'success': result.success,
            'duration_seconds': result.duration_seconds,
            'bytes_processed': result.bytes_processed,
            'throughput_mbps': result.throughput_mbps,
            'verification_passed': result.verification_passed,
            'error_message': result.error_message.decode('utf-8') if result.error_message else None,
            'method_used': result.method_used.decode('utf-8') if result.method_used else f'nvme_sanitize_{action}',
        }
        
    except Exception as e:
        logger.error(f"NVMe sanitize failed: {e}")
        return {
            'success': False,
            'duration_seconds': 0.0,
            'bytes_processed': 0,
            'throughput_mbps': 0.0,
            'verification_passed': False,
            'error_message': str(e),
            'method_used': f'nvme_sanitize_{action}',
        }

def overwrite_parallel(device_path: str, passes: int, total_size: int) -> Dict[str, Any]:
    """
    Perform parallel overwrite using native engine.
    
    Args:
        device_path: Path to device to overwrite
        passes: Number of overwrite passes
        total_size: Total size in bytes
        
    Returns:
        Operation result dictionary
    """
    lib = _load_native_library()
    if not lib:
        raise RuntimeError("Native library not available")
    
    try:
        logger.info(f"Performing {passes}-pass overwrite on {device_path}")
        
        # Call native function
        result = lib.overwrite_parallel(
            device_path.encode('utf-8'),
            passes,
            total_size
        )
        
        # Convert result to dictionary
        return {
            'success': result.success,
            'duration_seconds': result.duration_seconds,
            'bytes_processed': result.bytes_processed,
            'throughput_mbps': result.throughput_mbps,
            'verification_passed': result.verification_passed,
            'error_message': result.error_message.decode('utf-8') if result.error_message else None,
            'method_used': result.method_used.decode('utf-8') if result.method_used else f'overwrite_{passes}_pass',
        }
        
    except Exception as e:
        logger.error(f"Parallel overwrite failed: {e}")
        return {
            'success': False,
            'duration_seconds': 0.0,
            'bytes_processed': 0,
            'throughput_mbps': 0.0,
            'verification_passed': False,
            'error_message': str(e),
            'method_used': f'overwrite_{passes}_pass',
        }

def get_device_capabilities(device_path: str) -> Dict[str, Any]:
    """
    Get device capabilities using native engine.
    
    Args:
        device_path: Path to device to analyze
        
    Returns:
        Device capabilities dictionary
    """
    lib = _load_native_library()
    if not lib:
        raise RuntimeError("Native library not available")
    
    try:
        logger.debug(f"Getting device capabilities for {device_path}")
        
        # Call native function
        result = lib.get_device_capabilities(device_path.encode('utf-8'))
        
        # Convert result to dictionary
        return {
            'path': result.path.decode('utf-8') if result.path else device_path,
            'size_bytes': result.size_bytes,
            'sector_size': result.sector_size,
            'model': result.model.decode('utf-8') if result.model else 'Unknown',
            'serial': result.serial.decode('utf-8') if result.serial else 'Unknown',
            'supports_crypto_erase': result.supports_crypto_erase,
            'supports_secure_erase': result.supports_secure_erase,
            'supports_nvme_sanitize': result.supports_nvme_sanitize,
            'supports_trim': result.supports_trim,
            'is_encrypted': result.is_encrypted,
            'max_write_speed_mbps': result.max_write_speed_mbps,
        }
        
    except Exception as e:
        logger.error(f"Get device capabilities failed: {e}")
        return {
            'path': device_path,
            'size_bytes': 0,
            'sector_size': 512,
            'model': 'Unknown',
            'serial': 'Unknown',
            'supports_crypto_erase': False,
            'supports_secure_erase': False,
            'supports_nvme_sanitize': False,
            'supports_trim': False,
            'is_encrypted': False,
            'max_write_speed_mbps': 100.0,
        }

def verify_sampling_fast(device_path: str, sample_size_mb: int) -> Dict[str, Any]:
    """
    Perform fast sampling verification using native engine.
    
    Args:
        device_path: Path to device to verify
        sample_size_mb: Sample size in megabytes
        
    Returns:
        Verification result dictionary
    """
    lib = _load_native_library()
    if not lib:
        raise RuntimeError("Native library not available")
    
    try:
        logger.info(f"Performing sampling verification on {device_path} ({sample_size_mb} MB)")
        
        # Call native function
        result = lib.verify_sampling_fast(
            device_path.encode('utf-8'),
            sample_size_mb * 1024 * 1024  # Convert to bytes
        )
        
        # Convert result to dictionary
        return {
            'success': result.success,
            'duration_seconds': result.duration_seconds,
            'bytes_processed': result.bytes_processed,
            'throughput_mbps': result.throughput_mbps,
            'verification_passed': result.verification_passed,
            'error_message': result.error_message.decode('utf-8') if result.error_message else None,
            'method_used': result.method_used.decode('utf-8') if result.method_used else 'sampling_verification',
        }
        
    except Exception as e:
        logger.error(f"Sampling verification failed: {e}")
        return {
            'success': False,
            'duration_seconds': 0.0,
            'bytes_processed': 0,
            'throughput_mbps': 0.0,
            'verification_passed': False,
            'error_message': str(e),
            'method_used': 'sampling_verification',
        }

def select_optimal_method(device_dict: Dict[str, Any], criteria_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Select optimal sanitization method using native engine.
    
    Args:
        device_dict: Device information dictionary
        criteria_dict: Selection criteria dictionary
        
    Returns:
        Method selection result dictionary
    """
    lib = _load_native_library()
    if not lib:
        raise RuntimeError("Native library not available")
    
    try:
        logger.debug("Selecting optimal method using native engine")
        
        # Convert dictionaries to JSON strings
        device_json = json.dumps(device_dict).encode('utf-8')
        criteria_json = json.dumps(criteria_dict).encode('utf-8')
        
        # Call native function
        result_json_ptr = lib.select_optimal_method(device_json, criteria_json)
        
        if not result_json_ptr:
            raise Exception("Native method selection returned null")
        
        # Convert result from JSON
        result_json_value = ctypes.c_char_p(result_json_ptr).value
        if not result_json_value:
            raise Exception("Native method selection returned empty result")
        
        result_json = result_json_value.decode('utf-8')
        result = json.loads(result_json)
        
        # Free the native string
        lib.free_string(result_json_ptr)
        
        return result
        
    except Exception as e:
        logger.error(f"Method selection failed: {e}")
        return {
            'method': 'OVERWRITE_SINGLE',
            'overall_score': 0.5,
            'time_score': 0.5,
            'security_score': 0.5,
            'compliance_score': 0.5,
            'compatibility_score': 0.5,
            'estimated_duration_minutes': 60.0,
            'security_level': 'medium',
            'compliance_standards': [],
            'risk_factors': ['Native selection failed'],
            'optimization_notes': ['Using fallback method'],
        }

def enumerate_storage_devices() -> List[Dict[str, Any]]:
    """
    Enumerate storage devices using native engine.
    
    Returns:
        List of device information dictionaries
    """
    lib = _load_native_library()
    if not lib:
        raise RuntimeError("Native library not available")
    
    try:
        logger.debug("Enumerating storage devices using native engine")
        
        # Call native function
        result_json_ptr = lib.enumerate_storage_devices()
        
        if not result_json_ptr:
            raise Exception("Native device enumeration returned null")
        
        # Convert result from JSON
        result_json_value = ctypes.c_char_p(result_json_ptr).value
        if not result_json_value:
            raise Exception("Native device enumeration returned empty result")
        
        result_json = result_json_value.decode('utf-8')
        result = json.loads(result_json)
        
        # Free the native string
        lib.free_string(result_json_ptr)
        
        return result
        
    except Exception as e:
        logger.error(f"Device enumeration failed: {e}")
        return []

def trim_discard_ranges(device_path: str, start_offset: int, length: int) -> Dict[str, Any]:
    """
    Perform TRIM/discard operation using native engine.
    
    Args:
        device_path: Path to device
        start_offset: Starting offset in bytes
        length: Length in bytes
        
    Returns:
        Operation result dictionary
    """
    lib = _load_native_library()
    if not lib:
        raise RuntimeError("Native library not available")
    
    try:
        logger.info(f"Performing TRIM/discard on {device_path} (offset: {start_offset}, length: {length})")
        
        # Call native function
        result = lib.trim_discard_ranges(
            device_path.encode('utf-8'),
            start_offset,
            length
        )
        
        # Convert result to dictionary
        return {
            'success': result.success,
            'duration_seconds': result.duration_seconds,
            'bytes_processed': result.bytes_processed,
            'throughput_mbps': result.throughput_mbps,
            'verification_passed': result.verification_passed,
            'error_message': result.error_message.decode('utf-8') if result.error_message else None,
            'method_used': result.method_used.decode('utf-8') if result.method_used else 'trim_discard',
        }
        
    except Exception as e:
        logger.error(f"TRIM/discard failed: {e}")
        return {
            'success': False,
            'duration_seconds': 0.0,
            'bytes_processed': 0,
            'throughput_mbps': 0.0,
            'verification_passed': False,
            'error_message': str(e),
            'method_used': 'trim_discard',
        }

# Convenience functions that handle fallbacks gracefully

def safe_crypto_erase(device_path: str) -> Dict[str, Any]:
    """Safe crypto erase with fallback."""
    try:
        if is_native_engine_available():
            return crypto_erase_fast(device_path)
    except Exception as e:
        logger.warning(f"Native crypto erase failed: {e}")
    
    # Fallback - return mock result
    return {
        'success': False,
        'duration_seconds': 0.0,
        'bytes_processed': 0,
        'throughput_mbps': 0.0,
        'verification_passed': False,
        'error_message': 'Native engine not available',
        'method_used': 'crypto_erase_fallback',
    }

def safe_device_capabilities(device_path: str) -> Dict[str, Any]:
    """Safe device capabilities with fallback."""
    try:
        if is_native_engine_available():
            return get_device_capabilities(device_path)
    except Exception as e:
        logger.warning(f"Native device capabilities failed: {e}")
    
    # Fallback - return basic capabilities
    return {
        'path': device_path,
        'size_bytes': 1024 * 1024 * 1024,  # 1GB default
        'sector_size': 512,
        'model': 'Unknown Device',
        'serial': 'Unknown',
        'supports_crypto_erase': False,
        'supports_secure_erase': False,
        'supports_nvme_sanitize': False,
        'supports_trim': False,
        'is_encrypted': False,
        'max_write_speed_mbps': 100.0,
    }

def get_native_engine_info() -> Dict[str, Any]:
    """Get information about the native engine."""
    return {
        'available': is_native_engine_available(),
        'library_path': str(_load_native_library()) if _load_native_library() else None,
        'platform': platform.system(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
    }

if __name__ == "__main__":
    # Test the FFI bindings
    print("PurgeProof Native Engine FFI Bindings")
    print("=" * 40)
    
    info = get_native_engine_info()
    print(f"Native engine available: {info['available']}")
    print(f"Platform: {info['platform']} ({info['architecture']})")
    print(f"Python version: {info['python_version']}")
    
    if info['available']:
        print(f"Library path: {info['library_path']}")
        
        # Test device enumeration
        try:
            devices = enumerate_storage_devices()
            print(f"\nFound {len(devices)} devices:")
            for device in devices[:3]:  # Show first 3
                print(f"  {device.get('path', 'Unknown')}: {device.get('model', 'Unknown')}")
        except Exception as e:
            print(f"Device enumeration test failed: {e}")
    else:
        print("Native library not found - FFI bindings will use fallback implementations")