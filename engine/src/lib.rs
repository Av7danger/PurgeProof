use pyo3::prelude::*;
use std::path::Path;
use std::fs::OpenOptions;
use std::io::{self, Write, Seek, SeekFrom};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

mod crypto_erase;
mod overwrite;
mod verification;
mod device;
mod ffi;
mod smart_selection;
mod parallel;
mod trim_support;

use crypto_erase::*;
use overwrite::*;
use verification::*;
use device::*;
pub use ffi::*; // Expose FFI functions for C bindings

/// Operation result structure for consistent error handling
#[derive(Debug, Serialize, Deserialize)]
pub struct OperationResult {
    pub success: bool,
    pub method_used: String,
    pub duration_seconds: f64,
    pub bytes_processed: u64,
    pub throughput_mbps: f64,
    pub verification_passed: bool,
    pub error_message: Option<String>,
}

/// Device capabilities structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCapabilities {
    pub supports_crypto_erase: bool,
    pub supports_secure_erase: bool,
    pub supports_nvme_sanitize: bool,
    pub supports_trim: bool,
    pub is_encrypted: bool,
    pub encryption_type: Option<String>,
    pub size_bytes: u64,
    pub sector_size: u32,
    pub model: String,
    pub serial: String,
    pub interface_type: String,
    pub firmware_version: String,
    pub max_write_speed_mbps: f64,
}

/// Sanitization method enum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SanitizationMethod {
    CryptoErase,
    SecureErase,
    NvmeSanitize,
    TrimDiscard,
    SinglePassOverwrite,
    MultiPassOverwrite { passes: u32 },
    CryptoWrap { quick_overwrite: bool },
}

/// Fast crypto erase implementation with enhanced error handling
#[pyfunction]
fn crypto_erase_fast(device_path: &str) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match crypto_erase::destroy_encryption_key(device_path) {
            Ok(result) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("success", result.success)?;
                dict.set_item("method_used", result.method_used)?;
                dict.set_item("duration_seconds", result.duration_seconds)?;
                dict.set_item("bytes_processed", result.bytes_processed)?;
                dict.set_item("throughput_mbps", result.throughput_mbps)?;
                Ok(dict.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("success", false)?;
                dict.set_item("error_message", format!("Crypto erase failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// Smart method selection based on device capabilities
#[pyfunction]
fn select_optimal_method(device_path: &str, compliance_level: &str) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match smart_selection::select_best_method(device_path, compliance_level) {
            Ok(method) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("method", serde_json::to_string(&method).unwrap_or_default())?;
                dict.set_item("estimated_time_seconds", smart_selection::estimate_time(&method, device_path).unwrap_or(0.0))?;
                Ok(dict.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("error", format!("Method selection failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// Optimized multi-threaded overwrite with progress tracking
#[pyfunction]
fn overwrite_parallel(device_path: &str, passes: u32, pattern: Option<Vec<u8>>, progress_callback: Option<PyObject>) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let callback = progress_callback.map(|cb| {
            move |progress: f64| {
                Python::with_gil(|py| {
                    let _ = cb.call1(py, (progress,));
                });
            }
        });
        
        match overwrite::parallel_overwrite_with_progress(device_path, passes, pattern, callback) {
            Ok(result) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("success", result.success)?;
                dict.set_item("method_used", result.method_used)?;
                dict.set_item("duration_seconds", result.duration_seconds)?;
                dict.set_item("throughput_mbps", result.throughput_mbps)?;
                Ok(dict.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("success", false)?;
                dict.set_item("error_message", format!("Parallel overwrite failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// Direct NVMe sanitize command with enhanced status monitoring
#[pyfunction]
fn nvme_sanitize_direct(device_path: &str, sanitize_action: Option<&str>) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        let action = sanitize_action.unwrap_or("crypto_erase");
        match device::nvme_sanitize_enhanced(device_path, action) {
            Ok(result) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("success", result.success)?;
                dict.set_item("method_used", result.method_used)?;
                dict.set_item("duration_seconds", result.duration_seconds)?;
                Ok(dict.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("success", false)?;
                dict.set_item("error_message", format!("NVMe sanitize failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// TRIM/Discard support for SSDs
#[pyfunction]
fn trim_discard_ranges(device_path: &str, ranges: Option<Vec<(u64, u64)>>) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match trim_support::trim_device(device_path, ranges) {
            Ok(result) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("success", result.success)?;
                dict.set_item("ranges_trimmed", result.bytes_processed / 4096)?; // Approximate ranges
                dict.set_item("duration_seconds", result.duration_seconds)?;
                Ok(dict.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("success", false)?;
                dict.set_item("error_message", format!("TRIM operation failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// Fast verification with configurable sampling
#[pyfunction] 
fn verify_sampling_fast(device_path: &str, sample_rate: f32, deterministic_seed: Option<u64>) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match verification::verify_random_sampling_seeded(device_path, sample_rate, deterministic_seed) {
            Ok(result) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("verification_passed", result.verification_passed)?;
                dict.set_item("samples_checked", result.bytes_processed / 4096)?; // Approximate samples
                dict.set_item("duration_seconds", result.duration_seconds)?;
                dict.set_item("confidence_level", (sample_rate * 100.0) as u32)?;
                Ok(dict.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("verification_passed", false)?;
                dict.set_item("error_message", format!("Verification failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// Get comprehensive device information and capabilities
#[pyfunction]
fn get_device_info(device_path: &str) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match device::get_device_capabilities_enhanced(device_path) {
            Ok(info) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("supports_crypto_erase", info.supports_crypto_erase)?;
                dict.set_item("supports_secure_erase", info.supports_secure_erase)?;
                dict.set_item("supports_nvme_sanitize", info.supports_nvme_sanitize)?;
                dict.set_item("supports_trim", info.supports_trim)?;
                dict.set_item("is_encrypted", info.is_encrypted)?;
                dict.set_item("encryption_type", info.encryption_type)?;
                dict.set_item("size_bytes", info.size_bytes)?;
                dict.set_item("sector_size", info.sector_size)?;
                dict.set_item("model", info.model)?;
                dict.set_item("serial", info.serial)?;
                dict.set_item("interface_type", info.interface_type)?;
                dict.set_item("firmware_version", info.firmware_version)?;
                dict.set_item("max_write_speed_mbps", info.max_write_speed_mbps)?;
                Ok(dict.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("error", format!("Device info failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// List all detected storage devices
#[pyfunction]
fn list_devices() -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match device::enumerate_storage_devices() {
            Ok(devices) => {
                let list = pyo3::types::PyList::empty(py);
                for device in devices {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("path", device.0)?;
                    dict.set_item("info", serde_json::to_string(&device.1).unwrap_or_default())?;
                    list.append(dict)?;
                }
                Ok(list.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("error", format!("Device enumeration failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// Parallel processing of multiple devices
#[pyfunction]
fn parallel_sanitize_devices(device_configs: Vec<(String, String)>, max_concurrent: Option<usize>) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match parallel::sanitize_multiple_devices(device_configs, max_concurrent.unwrap_or(4)) {
            Ok(results) => {
                let list = pyo3::types::PyList::empty(py);
                for result in results {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("device_path", result.0)?;
                    dict.set_item("result", serde_json::to_string(&result.1).unwrap_or_default())?;
                    list.append(dict)?;
                }
                Ok(list.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("error", format!("Parallel sanitization failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// Performance benchmark function with detailed metrics
#[pyfunction]
fn benchmark_write_speed(device_path: &str, test_size_mb: u64, test_pattern: Option<&str>) -> PyResult<PyObject> {
    Python::with_gil(|py| {
        match overwrite::benchmark_device_enhanced(device_path, test_size_mb, test_pattern) {
            Ok(metrics) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("sequential_write_mbps", metrics.sequential_write_mbps)?;
                dict.set_item("random_write_mbps", metrics.random_write_mbps)?;
                dict.set_item("iops", metrics.iops)?;
                dict.set_item("latency_ms", metrics.latency_ms)?;
                dict.set_item("cpu_usage_percent", metrics.cpu_usage_percent)?;
                Ok(dict.into())
            }
            Err(e) => {
                let dict = pyo3::types::PyDict::new(py);
                dict.set_item("error", format!("Benchmark failed: {}", e))?;
                Ok(dict.into())
            }
        }
    })
}

/// Python module definition with comprehensive FFI surface
#[pymodule]
fn purgeproof_engine(_py: Python, m: &PyModule) -> PyResult<()> {
    // Core sanitization functions
    m.add_function(wrap_pyfunction!(crypto_erase_fast, m)?)?;
    m.add_function(wrap_pyfunction!(select_optimal_method, m)?)?;
    m.add_function(wrap_pyfunction!(overwrite_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(nvme_sanitize_direct, m)?)?;
    m.add_function(wrap_pyfunction!(trim_discard_ranges, m)?)?;
    
    // Verification functions
    m.add_function(wrap_pyfunction!(verify_sampling_fast, m)?)?;
    
    // Device management
    m.add_function(wrap_pyfunction!(get_device_info, m)?)?;
    m.add_function(wrap_pyfunction!(list_devices, m)?)?;
    
    // Parallel processing
    m.add_function(wrap_pyfunction!(parallel_sanitize_devices, m)?)?;
    
    // Performance and benchmarking
    m.add_function(wrap_pyfunction!(benchmark_write_speed, m)?)?;
    
    // Add version and capability info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__build_features__", env!("CARGO_CFG_TARGET_FEATURE"))?;
    
    Ok(())
}