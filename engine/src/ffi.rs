/// FFI (Foreign Function Interface) bindings for C/C++ integration
/// This module provides a C-compatible API for the Rust engine
/// 
/// Usage example:
/// ```c
/// #include "purgeproof_engine.h"
/// 
/// PurgeProofResult result = purgeproof_crypto_erase("/dev/sdb");
/// if (result.success) {
///     printf("Sanitization completed in %.2f seconds\n", result.duration_seconds);
/// }
/// ```

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_double, c_ulong};
use crate::{OperationResult, DeviceCapabilities, SanitizationMethod};

/// C-compatible result structure
#[repr(C)]
pub struct PurgeProofResult {
    pub success: c_int,
    pub duration_seconds: c_double,
    pub bytes_processed: c_ulong,
    pub throughput_mbps: c_double,
    pub verification_passed: c_int,
    pub error_code: c_int,
}

/// C-compatible device capabilities structure
#[repr(C)]
pub struct PurgeProofDeviceInfo {
    pub supports_crypto_erase: c_int,
    pub supports_secure_erase: c_int,
    pub supports_nvme_sanitize: c_int,
    pub supports_trim: c_int,
    pub is_encrypted: c_int,
    pub size_bytes: c_ulong,
    pub sector_size: c_int,
    pub max_write_speed_mbps: c_double,
}

/// Convert Rust OperationResult to C-compatible structure
impl From<OperationResult> for PurgeProofResult {
    fn from(result: OperationResult) -> Self {
        PurgeProofResult {
            success: if result.success { 1 } else { 0 },
            duration_seconds: result.duration_seconds,
            bytes_processed: result.bytes_processed as c_ulong,
            throughput_mbps: result.throughput_mbps,
            verification_passed: if result.verification_passed { 1 } else { 0 },
            error_code: 0, // TODO: Add proper error codes
        }
    }
}

/// Convert Rust DeviceCapabilities to C-compatible structure
impl From<DeviceCapabilities> for PurgeProofDeviceInfo {
    fn from(caps: DeviceCapabilities) -> Self {
        PurgeProofDeviceInfo {
            supports_crypto_erase: if caps.supports_crypto_erase { 1 } else { 0 },
            supports_secure_erase: if caps.supports_secure_erase { 1 } else { 0 },
            supports_nvme_sanitize: if caps.supports_nvme_sanitize { 1 } else { 0 },
            supports_trim: if caps.supports_trim { 1 } else { 0 },
            is_encrypted: if caps.is_encrypted { 1 } else { 0 },
            size_bytes: caps.size_bytes as c_ulong,
            sector_size: caps.sector_size as c_int,
            max_write_speed_mbps: caps.max_write_speed_mbps,
        }
    }
}

/// Initialize the PurgeProof engine
/// Must be called before any other FFI functions
#[no_mangle]
pub extern "C" fn purgeproof_init() -> c_int {
    // Initialize logging
    env_logger::init();
    
    // TODO: Initialize hardware detection subsystems
    // TODO: Load vendor-specific drivers/SDKs
    // TODO: Verify system permissions
    
    1 // Success
}

/// Cleanup and shutdown the PurgeProof engine
#[no_mangle]
pub extern "C" fn purgeproof_cleanup() -> c_int {
    // TODO: Cleanup any persistent resources
    // TODO: Flush logs
    // TODO: Release hardware handles
    
    1 // Success
}

/// List all detected storage devices
/// Returns the number of devices found, fills the devices array
#[no_mangle]
pub extern "C" fn purgeproof_list_devices(devices: *mut *mut c_char, max_devices: c_int) -> c_int {
    if devices.is_null() || max_devices <= 0 {
        return -1;
    }
    
    // TODO: Implement actual device enumeration
    // For now, return mock data
    unsafe {
        let mock_device = CString::new("/dev/sdb").unwrap();
        *devices = mock_device.into_raw();
    }
    
    1 // Number of devices found
}

/// Get detailed information about a specific device
#[no_mangle]
pub extern "C" fn purgeproof_get_device_info(device_path: *const c_char, info: *mut PurgeProofDeviceInfo) -> c_int {
    if device_path.is_null() || info.is_null() {
        return -1;
    }
    
    let device_path_str = unsafe {
        match CStr::from_ptr(device_path).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    match crate::device::get_device_capabilities_enhanced(device_path_str) {
        Ok(caps) => {
            unsafe {
                *info = caps.into();
            }
            1 // Success
        }
        Err(_) => -1, // Error
    }
}

/// Perform crypto erase operation
#[no_mangle]
pub extern "C" fn purgeproof_crypto_erase(device_path: *const c_char, result: *mut PurgeProofResult) -> c_int {
    if device_path.is_null() || result.is_null() {
        return -1;
    }
    
    let device_path_str = unsafe {
        match CStr::from_ptr(device_path).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    match crate::crypto_erase::destroy_encryption_key(device_path_str) {
        Ok(op_result) => {
            unsafe {
                *result = op_result.into();
            }
            1 // Success
        }
        Err(_) => -1, // Error
    }
}

/// Perform firmware secure erase operation
#[no_mangle]
pub extern "C" fn purgeproof_firmware_secure_erase(device_path: *const c_char, result: *mut PurgeProofResult) -> c_int {
    if device_path.is_null() || result.is_null() {
        return -1;
    }
    
    let device_path_str = unsafe {
        match CStr::from_ptr(device_path).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    match crate::device::nvme_sanitize_enhanced(device_path_str, "crypto_erase") {
        Ok(op_result) => {
            unsafe {
                *result = op_result.into();
            }
            1 // Success
        }
        Err(_) => -1, // Error
    }
}

/// Perform TRIM/discard operation on ranges
#[no_mangle]
pub extern "C" fn purgeproof_trim_all(device_path: *const c_char, result: *mut PurgeProofResult) -> c_int {
    if device_path.is_null() || result.is_null() {
        return -1;
    }
    
    let device_path_str = unsafe {
        match CStr::from_ptr(device_path).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    match crate::trim_support::trim_device(device_path_str, None) {
        Ok(op_result) => {
            unsafe {
                *result = op_result.into();
            }
            1 // Success
        }
        Err(_) => -1, // Error
    }
}

/// Perform single-pass overwrite operation
#[no_mangle]
pub extern "C" fn purgeproof_overwrite_single(device_path: *const c_char, pattern: *const c_char, result: *mut PurgeProofResult) -> c_int {
    if device_path.is_null() || result.is_null() {
        return -1;
    }
    
    let device_path_str = unsafe {
        match CStr::from_ptr(device_path).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    let pattern_bytes = if pattern.is_null() {
        None
    } else {
        unsafe {
            CStr::from_ptr(pattern).to_str().ok().map(|s| s.as_bytes().to_vec())
        }
    };
    
    match crate::overwrite::parallel_overwrite_with_progress(device_path_str, 1, pattern_bytes, None) {
        Ok(op_result) => {
            unsafe {
                *result = op_result.into();
            }
            1 // Success
        }
        Err(_) => -1, // Error
    }
}

/// Perform multi-pass overwrite operation
#[no_mangle]
pub extern "C" fn purgeproof_overwrite_multi(device_path: *const c_char, passes: c_int, result: *mut PurgeProofResult) -> c_int {
    if device_path.is_null() || result.is_null() || passes <= 0 {
        return -1;
    }
    
    let device_path_str = unsafe {
        match CStr::from_ptr(device_path).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    match crate::overwrite::parallel_overwrite_with_progress(device_path_str, passes as u32, None, None) {
        Ok(op_result) => {
            unsafe {
                *result = op_result.into();
            }
            1 // Success
        }
        Err(_) => -1, // Error
    }
}

/// Verify blocks with sampling
#[no_mangle]
pub extern "C" fn purgeproof_verify_blocks(device_path: *const c_char, sample_rate: c_double, seed: c_ulong, result: *mut PurgeProofResult) -> c_int {
    if device_path.is_null() || result.is_null() || sample_rate < 0.0 || sample_rate > 1.0 {
        return -1;
    }
    
    let device_path_str = unsafe {
        match CStr::from_ptr(device_path).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    let deterministic_seed = if seed == 0 { None } else { Some(seed as u64) };
    
    match crate::verification::verify_random_sampling_seeded(device_path_str, sample_rate as f32, deterministic_seed) {
        Ok(op_result) => {
            unsafe {
                *result = op_result.into();
            }
            1 // Success
        }
        Err(_) => -1, // Error
    }
}

/// Select optimal sanitization method for device and compliance requirements
#[no_mangle]
pub extern "C" fn purgeproof_select_optimal_method(device_path: *const c_char, compliance_level: *const c_char) -> c_int {
    if device_path.is_null() || compliance_level.is_null() {
        return -1;
    }
    
    let device_path_str = unsafe {
        match CStr::from_ptr(device_path).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    let compliance_str = unsafe {
        match CStr::from_ptr(compliance_level).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    match crate::smart_selection::select_best_method(device_path_str, compliance_str) {
        Ok(method) => {
            // Return method as integer constant
            match method {
                SanitizationMethod::CryptoErase => 1,
                SanitizationMethod::SecureErase => 2,
                SanitizationMethod::NvmeSanitize => 3,
                SanitizationMethod::TrimDiscard => 4,
                SanitizationMethod::SinglePassOverwrite => 5,
                SanitizationMethod::MultiPassOverwrite { .. } => 6,
                SanitizationMethod::CryptoWrap { .. } => 7,
            }
        }
        Err(_) => -1, // Error
    }
}

/// Get engine version information
#[no_mangle]
pub extern "C" fn purgeproof_get_version() -> *const c_char {
    static VERSION: &str = env!("CARGO_PKG_VERSION");
    VERSION.as_ptr() as *const c_char
}

/// Free a string allocated by the engine
#[no_mangle]
pub extern "C" fn purgeproof_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;
    
    #[test]
    fn test_ffi_init_cleanup() {
        assert_eq!(purgeproof_init(), 1);
        assert_eq!(purgeproof_cleanup(), 1);
    }
    
    #[test]
    fn test_ffi_version() {
        let version_ptr = purgeproof_get_version();
        assert!(!version_ptr.is_null());
    }
    
    #[test]
    fn test_ffi_null_safety() {
        let mut result = PurgeProofResult {
            success: 0,
            duration_seconds: 0.0,
            bytes_processed: 0,
            throughput_mbps: 0.0,
            verification_passed: 0,
            error_code: 0,
        };
        
        // Test null device path
        assert_eq!(purgeproof_crypto_erase(ptr::null(), &mut result), -1);
        
        // Test null result pointer
        let device_path = CString::new("/dev/null").unwrap();
        assert_eq!(purgeproof_crypto_erase(device_path.as_ptr(), ptr::null_mut()), -1);
    }
}