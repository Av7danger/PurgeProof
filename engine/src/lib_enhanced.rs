use pyo3::prelude::*;

// Core modules with peak optimization
mod crypto_erase;
mod crypto_erase_enhanced;
mod overwrite;
mod device;
mod verification;
mod utils;

// Re-export main functions for Python
use crypto_erase_enhanced::{crypto_erase_device, check_crypto_erase_support, get_crypto_capabilities};
use overwrite::{parallel_overwrite_file, benchmark_overwrite_performance, get_optimal_overwrite_settings};
use device::{enumerate_storage_devices, get_device_optimal_chunk_size};
use verification::{verify_file_pattern, calculate_file_checksum, verify_file_checksum};
use utils::{get_system_info, get_optimal_chunk_size, is_ssd_path};

/// PurgeProof Rust Acceleration Engine
/// High-performance cryptographic and overwrite operations with hardware acceleration
#[pymodule]
fn purgeproof_engine(py: Python, m: &PyModule) -> PyResult<()> {
    // Module metadata
    m.add("__version__", "1.0.0")?;
    m.add("__author__", "PurgeProof Development Team")?;
    m.add("__description__", "Hardware-accelerated secure data sanitization engine")?;

    // Cryptographic erase functions
    m.add_function(wrap_pyfunction!(crypto_erase_device, m)?)?;
    m.add_function(wrap_pyfunction!(check_crypto_erase_support, m)?)?;
    m.add_function(wrap_pyfunction!(get_crypto_capabilities, m)?)?;

    // High-performance overwrite functions
    m.add_function(wrap_pyfunction!(parallel_overwrite_file, m)?)?;
    m.add_function(wrap_pyfunction!(benchmark_overwrite_performance, m)?)?;
    m.add_function(wrap_pyfunction!(get_optimal_overwrite_settings, m)?)?;

    // Device management functions
    m.add_function(wrap_pyfunction!(enumerate_storage_devices, m)?)?;
    m.add_function(wrap_pyfunction!(get_device_optimal_chunk_size, m)?)?;

    // Verification functions
    m.add_function(wrap_pyfunction!(verify_file_pattern, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_file_checksum, m)?)?;
    m.add_function(wrap_pyfunction!(verify_file_checksum, m)?)?;

    // Utility functions
    m.add_function(wrap_pyfunction!(get_system_info, m)?)?;
    m.add_function(wrap_pyfunction!(get_optimal_chunk_size, m)?)?;
    m.add_function(wrap_pyfunction!(is_ssd_path, m)?)?;

    // Performance optimization functions
    m.add_function(wrap_pyfunction!(get_performance_profile, m)?)?;
    m.add_function(wrap_pyfunction!(benchmark_system_capabilities, m)?)?;

    // Legacy compatibility functions
    m.add_function(wrap_pyfunction!(crypto_erase_fast, m)?)?;
    m.add_function(wrap_pyfunction!(overwrite_parallel, m)?)?;
    m.add_function(wrap_pyfunction!(verify_sampling_fast, m)?)?;

    Ok(())
}

/// Get comprehensive performance profile for optimization
#[pyfunction]
fn get_performance_profile() -> PyResult<std::collections::HashMap<String, String>> {
    let mut profile = std::collections::HashMap::new();
    
    // CPU capabilities
    profile.insert("cpu_cores".to_string(), num_cpus::get().to_string());
    profile.insert("cpu_features".to_string(), get_cpu_features());
    
    // Memory information
    profile.insert("available_memory".to_string(), utils::platform::get_available_memory().to_string());
    profile.insert("page_size".to_string(), utils::platform::get_page_size().to_string());
    
    // Hardware acceleration
    #[cfg(target_arch = "x86_64")]
    {
        profile.insert("aes_ni".to_string(), is_x86_feature_detected!("aes").to_string());
        profile.insert("avx2".to_string(), is_x86_feature_detected!("avx2").to_string());
        profile.insert("sse4_2".to_string(), is_x86_feature_detected!("sse4.2").to_string());
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        profile.insert("aes_ni".to_string(), "false".to_string());
        profile.insert("avx2".to_string(), "false".to_string());
        profile.insert("sse4_2".to_string(), "false".to_string());
    }
    
    // Platform information
    profile.insert("platform".to_string(), std::env::consts::OS.to_string());
    profile.insert("architecture".to_string(), std::env::consts::ARCH.to_string());
    profile.insert("is_virtual_machine".to_string(), utils::platform::is_virtual_machine().to_string());
    
    Ok(profile)
}

/// Benchmark system capabilities for optimal configuration
#[pyfunction]
fn benchmark_system_capabilities() -> PyResult<std::collections::HashMap<String, f64>> {
    let mut benchmarks = std::collections::HashMap::new();
    
    // Memory bandwidth test
    let memory_bandwidth = benchmark_memory_bandwidth();
    benchmarks.insert("memory_bandwidth_gbps".to_string(), memory_bandwidth);
    
    // CPU performance test
    let cpu_performance = benchmark_cpu_performance();
    benchmarks.insert("cpu_performance_mhz".to_string(), cpu_performance);
    
    // SIMD performance test
    let simd_performance = benchmark_simd_performance();
    benchmarks.insert("simd_speedup_factor".to_string(), simd_performance);
    
    // Encryption performance test
    let encryption_performance = benchmark_encryption_performance();
    benchmarks.insert("aes_encryption_mbps".to_string(), encryption_performance);
    
    Ok(benchmarks)
}

fn get_cpu_features() -> String {
    let mut features = Vec::new();
    
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("aes") { features.push("AES-NI"); }
        if is_x86_feature_detected!("avx2") { features.push("AVX2"); }
        if is_x86_feature_detected!("avx") { features.push("AVX"); }
        if is_x86_feature_detected!("sse4.2") { features.push("SSE4.2"); }
        if is_x86_feature_detected!("sse4.1") { features.push("SSE4.1"); }
        if is_x86_feature_detected!("ssse3") { features.push("SSSE3"); }
        if is_x86_feature_detected!("sse3") { features.push("SSE3"); }
        if is_x86_feature_detected!("sse2") { features.push("SSE2"); }
    }
    
    if features.is_empty() {
        "None".to_string()
    } else {
        features.join(", ")
    }
}

fn benchmark_memory_bandwidth() -> f64 {
    const TEST_SIZE: usize = 64 * 1024 * 1024; // 64MB
    const ITERATIONS: usize = 10;
    
    let mut total_time = 0.0;
    let test_data = vec![0u8; TEST_SIZE];
    
    for _ in 0..ITERATIONS {
        let start = std::time::Instant::now();
        
        // Memory copy benchmark
        let mut dest = vec![0u8; TEST_SIZE];
        dest.copy_from_slice(&test_data);
        
        // Ensure the compiler doesn't optimize away
        std::hint::black_box(&dest);
        
        total_time += start.elapsed().as_secs_f64();
    }
    
    let avg_time = total_time / ITERATIONS as f64;
    let bytes_per_second = (TEST_SIZE as f64) / avg_time;
    bytes_per_second / (1024.0 * 1024.0 * 1024.0) // Convert to GB/s
}

fn benchmark_cpu_performance() -> f64 {
    const ITERATIONS: u64 = 10_000_000;
    
    let start = std::time::Instant::now();
    
    let mut result = 0u64;
    for i in 0..ITERATIONS {
        result = result.wrapping_add(i.wrapping_mul(i));
    }
    
    // Ensure calculation isn't optimized away
    std::hint::black_box(result);
    
    let duration = start.elapsed().as_secs_f64();
    (ITERATIONS as f64) / duration / 1_000_000.0 // Millions of operations per second
}

fn benchmark_simd_performance() -> f64 {
    const TEST_SIZE: usize = 1024 * 1024; // 1MB
    let data = vec![0xAAu8; TEST_SIZE];
    
    // Scalar benchmark
    let start_scalar = std::time::Instant::now();
    let scalar_result = scalar_sum(&data);
    let scalar_time = start_scalar.elapsed().as_secs_f64();
    
    // SIMD benchmark
    let start_simd = std::time::Instant::now();
    let simd_result = simd_sum(&data);
    let simd_time = start_simd.elapsed().as_secs_f64();
    
    // Ensure results match and aren't optimized away
    assert_eq!(scalar_result, simd_result);
    std::hint::black_box((scalar_result, simd_result));
    
    if simd_time > 0.0 {
        scalar_time / simd_time
    } else {
        1.0
    }
}

fn scalar_sum(data: &[u8]) -> u64 {
    data.iter().map(|&x| x as u64).sum()
}

#[cfg(target_arch = "x86_64")]
fn simd_sum(data: &[u8]) -> u64 {
    if is_x86_feature_detected!("avx2") {
        unsafe { simd_sum_avx2(data) }
    } else {
        scalar_sum(data)
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn simd_sum(data: &[u8]) -> u64 {
    scalar_sum(data)
}

#[cfg(target_arch = "x86_64")]
unsafe fn simd_sum_avx2(data: &[u8]) -> u64 {
    use std::arch::x86_64::*;
    
    let mut sum = _mm256_setzero_si256();
    let chunks = data.chunks_exact(32);
    let remainder = chunks.remainder();
    
    for chunk in chunks {
        let bytes = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
        let words = _mm256_unpacklo_epi8(bytes, _mm256_setzero_si256());
        sum = _mm256_add_epi16(sum, words);
    }
    
    // Extract and sum the partial results
    let mut result = [0u16; 16];
    _mm256_storeu_si256(result.as_mut_ptr() as *mut __m256i, sum);
    
    let partial_sum: u64 = result.iter().map(|&x| x as u64).sum();
    let remainder_sum: u64 = remainder.iter().map(|&x| x as u64).sum();
    
    partial_sum + remainder_sum
}

fn benchmark_encryption_performance() -> f64 {
    use aes::Aes256;
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    
    const TEST_SIZE: usize = 16 * 1024 * 1024; // 16MB
    const BLOCK_SIZE: usize = 16; // AES block size
    
    let key = [0u8; 32];
    let cipher = Aes256::new(GenericArray::from_slice(&key));
    let data = vec![0xAAu8; TEST_SIZE];
    
    let start = std::time::Instant::now();
    
    let blocks = data.chunks_exact(BLOCK_SIZE);
    for chunk in blocks {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        std::hint::black_box(&block);
    }
    
    let duration = start.elapsed().as_secs_f64();
    (TEST_SIZE as f64) / (1024.0 * 1024.0) / duration // MB/s
}

// Legacy compatibility functions
#[pyfunction]
fn crypto_erase_fast(device_path: String) -> PyResult<bool> {
    match crypto_erase::destroy_encryption_key(&device_path) {
        Ok(_) => Ok(true),
        Err(e) => {
            eprintln!("Crypto erase failed: {}", e);
            Ok(false)
        }
    }
}

#[pyfunction]
fn overwrite_parallel(device_path: String, passes: u32, pattern: Option<Vec<u8>>) -> PyResult<bool> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(async {
        overwrite::OverwriteEngine::new()
            .parallel_overwrite(&device_path, passes, Some(vec![pattern.unwrap_or_else(|| vec![0x00])]), None)
            .await
    }) {
        Ok(_) => Ok(true),
        Err(e) => {
            eprintln!("Parallel overwrite failed: {}", e);
            Ok(false)
        }
    }
}

#[pyfunction]
fn verify_sampling_fast(device_path: String, sample_rate: f32) -> PyResult<bool> {
    // Simplified verification using new verification engine
    let engine = verification::VerificationEngine::new();
    match engine.verify_pattern(std::path::Path::new(&device_path), &[0x00]) {
        Ok(result) => Ok(result.is_verified),
        Err(e) => {
            eprintln!("Verification failed: {}", e);
            Ok(false)
        }
    }
}