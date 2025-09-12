use pyo3::prelude::*;
use std::path::Path;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use sha2::{Sha256, Digest};
use blake3;
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Verification result structure
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub is_verified: bool,
    pub total_bytes: u64,
    pub verified_bytes: u64,
    pub error_message: Option<String>,
    pub checksum: Option<String>,
    pub verification_time: f64,
    pub throughput_mbps: f64,
}

/// High-performance verification engine with SIMD optimization
pub struct VerificationEngine {
    chunk_size: usize,
    thread_count: usize,
    use_simd: bool,
}

impl VerificationEngine {
    pub fn new() -> Self {
        Self {
            chunk_size: 1024 * 1024 * 2, // 2MB default
            thread_count: num_cpus::get(),
            use_simd: is_x86_feature_detected!("avx2"),
        }
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn with_thread_count(mut self, count: usize) -> Self {
        self.thread_count = count;
        self
    }

    /// Ultra-fast pattern verification using SIMD when available
    pub fn verify_pattern(&self, file_path: &Path, expected_pattern: &[u8]) -> PyResult<VerificationResult> {
        let start_time = std::time::Instant::now();
        
        let mut file = File::open(file_path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to open file: {}", e)))?;

        let file_size = file.seek(SeekFrom::End(0))
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to get file size: {}", e)))?;
        
        file.seek(SeekFrom::Start(0))
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to seek to start: {}", e)))?;

        let total_bytes = Arc::new(AtomicU64::new(0));
        let verified_bytes = Arc::new(AtomicU64::new(0));
        
        // Determine optimal chunk size based on file size and available memory
        let optimal_chunk_size = self.calculate_optimal_chunk_size(file_size);
        
        let chunks_per_thread = std::cmp::max(1, (file_size as usize) / (optimal_chunk_size * self.thread_count));
        let mut verification_passed = true;
        let mut error_message = None;

        // Parallel verification using rayon
        let chunk_size = optimal_chunk_size;
        let pattern_len = expected_pattern.len();
        
        // For large files, use memory-mapped I/O for better performance
        if file_size > 100 * 1024 * 1024 { // 100MB threshold
            match self.verify_pattern_mmap(file_path, expected_pattern, &total_bytes, &verified_bytes) {
                Ok(passed) => verification_passed = passed,
                Err(e) => {
                    verification_passed = false;
                    error_message = Some(format!("Memory-mapped verification failed: {}", e));
                }
            }
        } else {
            // Traditional chunked reading for smaller files
            match self.verify_pattern_chunked(&mut file, expected_pattern, chunk_size, &total_bytes, &verified_bytes) {
                Ok(passed) => verification_passed = passed,
                Err(e) => {
                    verification_passed = false;
                    error_message = Some(format!("Chunked verification failed: {}", e));
                }
            }
        }

        let verification_time = start_time.elapsed().as_secs_f64();
        let total_verified = verified_bytes.load(Ordering::Relaxed);
        let throughput_mbps = if verification_time > 0.0 {
            (total_verified as f64 / (1024.0 * 1024.0)) / verification_time
        } else {
            0.0
        };

        Ok(VerificationResult {
            is_verified: verification_passed,
            total_bytes: file_size,
            verified_bytes: total_verified,
            error_message,
            checksum: None,
            verification_time,
            throughput_mbps,
        })
    }

    /// Memory-mapped pattern verification for large files
    fn verify_pattern_mmap(
        &self,
        file_path: &Path,
        expected_pattern: &[u8],
        total_bytes: &Arc<AtomicU64>,
        verified_bytes: &Arc<AtomicU64>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        use memmap2::MmapOptions;
        
        let file = File::open(file_path)?;
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        
        let pattern_len = expected_pattern.len();
        let file_len = mmap.len();
        
        total_bytes.store(file_len as u64, Ordering::Relaxed);

        // Parallel verification using chunks
        let chunk_size = self.chunk_size;
        let chunks: Vec<_> = mmap.chunks(chunk_size).collect();
        
        let verification_results: Vec<bool> = chunks
            .par_iter()
            .map(|chunk| {
                let bytes_processed = chunk.len() as u64;
                verified_bytes.fetch_add(bytes_processed, Ordering::Relaxed);
                
                if self.use_simd {
                    self.verify_chunk_simd(chunk, expected_pattern)
                } else {
                    self.verify_chunk_scalar(chunk, expected_pattern)
                }
            })
            .collect();

        Ok(verification_results.iter().all(|&x| x))
    }

    /// Traditional chunked verification
    fn verify_pattern_chunked(
        &self,
        file: &mut File,
        expected_pattern: &[u8],
        chunk_size: usize,
        total_bytes: &Arc<AtomicU64>,
        verified_bytes: &Arc<AtomicU64>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; chunk_size];
        let pattern_len = expected_pattern.len();
        
        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }

            total_bytes.fetch_add(bytes_read as u64, Ordering::Relaxed);
            
            let chunk = &buffer[..bytes_read];
            let is_valid = if self.use_simd {
                self.verify_chunk_simd(chunk, expected_pattern)
            } else {
                self.verify_chunk_scalar(chunk, expected_pattern)
            };

            if !is_valid {
                return Ok(false);
            }

            verified_bytes.fetch_add(bytes_read as u64, Ordering::Relaxed);
        }

        Ok(true)
    }

    /// SIMD-accelerated pattern verification
    #[cfg(target_arch = "x86_64")]
    fn verify_chunk_simd(&self, chunk: &[u8], expected_pattern: &[u8]) -> bool {
        if !is_x86_feature_detected!("avx2") {
            return self.verify_chunk_scalar(chunk, expected_pattern);
        }

        use std::arch::x86_64::*;
        
        unsafe {
            let pattern_len = expected_pattern.len();
            if pattern_len == 1 {
                // Single-byte pattern optimization
                let pattern_byte = expected_pattern[0];
                let pattern_vec = _mm256_set1_epi8(pattern_byte as i8);
                
                let chunks_256 = chunk.chunks_exact(32);
                let remainder = chunks_256.remainder();
                
                for chunk_32 in chunks_256 {
                    let data = _mm256_loadu_si256(chunk_32.as_ptr() as *const __m256i);
                    let cmp = _mm256_cmpeq_epi8(data, pattern_vec);
                    let mask = _mm256_movemask_epi8(cmp);
                    
                    if mask != -1 {
                        return false;
                    }
                }
                
                // Handle remainder with scalar code
                return remainder.iter().all(|&b| b == pattern_byte);
            } else {
                // Multi-byte pattern - fall back to scalar for now
                return self.verify_chunk_scalar(chunk, expected_pattern);
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn verify_chunk_simd(&self, chunk: &[u8], expected_pattern: &[u8]) -> bool {
        self.verify_chunk_scalar(chunk, expected_pattern)
    }

    /// Scalar pattern verification
    fn verify_chunk_scalar(&self, chunk: &[u8], expected_pattern: &[u8]) -> bool {
        let pattern_len = expected_pattern.len();
        
        if pattern_len == 1 {
            // Optimized single-byte pattern check
            let pattern_byte = expected_pattern[0];
            chunk.iter().all(|&b| b == pattern_byte)
        } else {
            // Multi-byte pattern verification
            chunk.chunks_exact(pattern_len)
                .all(|chunk_pattern| chunk_pattern == expected_pattern)
        }
    }

    /// Calculate optimal chunk size based on file size and system memory
    fn calculate_optimal_chunk_size(&self, file_size: u64) -> usize {
        // Get available system memory
        let available_memory = self.get_available_memory();
        
        // Use up to 25% of available memory for I/O buffers
        let max_buffer_size = available_memory / 4;
        
        // Calculate optimal chunk size based on file size
        let base_chunk_size = if file_size < 100 * 1024 * 1024 {
            // Small files: 1MB chunks
            1024 * 1024
        } else if file_size < 1024 * 1024 * 1024 {
            // Medium files: 4MB chunks
            4 * 1024 * 1024
        } else {
            // Large files: 16MB chunks
            16 * 1024 * 1024
        };

        // Ensure we don't exceed memory limits
        std::cmp::min(base_chunk_size, max_buffer_size)
    }

    /// Get available system memory
    fn get_available_memory(&self) -> usize {
        #[cfg(target_os = "linux")]
        {
            if let Ok(mem_info) = std::fs::read_to_string("/proc/meminfo") {
                for line in mem_info.lines() {
                    if line.starts_with("MemAvailable:") {
                        if let Some(mem_kb) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = mem_kb.parse::<usize>() {
                                return kb * 1024; // Convert to bytes
                            }
                        }
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            use winapi::um::sysinfoapi::{GetPhysicallyInstalledSystemMemory, GlobalMemoryStatusEx, MEMORYSTATUSEX};
            use std::mem;
            
            unsafe {
                let mut mem_status: MEMORYSTATUSEX = mem::zeroed();
                mem_status.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
                
                if GlobalMemoryStatusEx(&mut mem_status) != 0 {
                    return mem_status.ullAvailPhys as usize;
                }
            }
        }
        
        // Default fallback: 8GB
        8 * 1024 * 1024 * 1024
    }

    /// High-performance checksum calculation
    pub fn calculate_checksum(&self, file_path: &Path, algorithm: &str) -> PyResult<String> {
        let start_time = std::time::Instant::now();
        
        match algorithm.to_lowercase().as_str() {
            "sha256" => self.calculate_sha256(file_path),
            "blake3" => self.calculate_blake3(file_path),
            "xxhash" => self.calculate_xxhash(file_path),
            _ => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>("Unsupported checksum algorithm")),
        }
    }

    fn calculate_sha256(&self, file_path: &Path) -> PyResult<String> {
        let mut file = File::open(file_path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to open file: {}", e)))?;

        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            let bytes_read = file.read(&mut buffer)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to read file: {}", e)))?;
            
            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    fn calculate_blake3(&self, file_path: &Path) -> PyResult<String> {
        let mut file = File::open(file_path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to open file: {}", e)))?;

        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            let bytes_read = file.read(&mut buffer)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to read file: {}", e)))?;
            
            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize().to_hex().to_string())
    }

    fn calculate_xxhash(&self, file_path: &Path) -> PyResult<String> {
        use twox_hash::XxHash64;
        use std::hash::Hasher;
        
        let mut file = File::open(file_path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to open file: {}", e)))?;

        let mut hasher = XxHash64::with_seed(0);
        let mut buffer = vec![0u8; self.chunk_size];

        loop {
            let bytes_read = file.read(&mut buffer)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to read file: {}", e)))?;
            
            if bytes_read == 0 {
                break;
            }

            hasher.write(&buffer[..bytes_read]);
        }

        Ok(format!("{:016x}", hasher.finish()))
    }

    /// Verify file integrity against known checksum
    pub fn verify_checksum(&self, file_path: &Path, expected_checksum: &str, algorithm: &str) -> PyResult<VerificationResult> {
        let start_time = std::time::Instant::now();
        
        let calculated_checksum = self.calculate_checksum(file_path, algorithm)?;
        let is_verified = calculated_checksum.eq_ignore_ascii_case(expected_checksum);
        
        let file_size = std::fs::metadata(file_path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("Failed to get file metadata: {}", e)))?
            .len();

        let verification_time = start_time.elapsed().as_secs_f64();
        let throughput_mbps = if verification_time > 0.0 {
            (file_size as f64 / (1024.0 * 1024.0)) / verification_time
        } else {
            0.0
        };

        Ok(VerificationResult {
            is_verified,
            total_bytes: file_size,
            verified_bytes: if is_verified { file_size } else { 0 },
            error_message: if is_verified { None } else { Some("Checksum mismatch".to_string()) },
            checksum: Some(calculated_checksum),
            verification_time,
            throughput_mbps,
        })
    }
}

/// Python exports for verification
#[pyfunction]
pub fn verify_file_pattern(file_path: String, pattern_bytes: Vec<u8>) -> PyResult<std::collections::HashMap<String, String>> {
    let engine = VerificationEngine::new();
    let result = engine.verify_pattern(Path::new(&file_path), &pattern_bytes)?;
    
    let mut result_map = std::collections::HashMap::new();
    result_map.insert("is_verified".to_string(), result.is_verified.to_string());
    result_map.insert("total_bytes".to_string(), result.total_bytes.to_string());
    result_map.insert("verified_bytes".to_string(), result.verified_bytes.to_string());
    result_map.insert("verification_time".to_string(), format!("{:.3}", result.verification_time));
    result_map.insert("throughput_mbps".to_string(), format!("{:.2}", result.throughput_mbps));
    
    if let Some(error) = result.error_message {
        result_map.insert("error_message".to_string(), error);
    }
    
    Ok(result_map)
}

#[pyfunction]
pub fn calculate_file_checksum(file_path: String, algorithm: String) -> PyResult<String> {
    let engine = VerificationEngine::new();
    engine.calculate_checksum(Path::new(&file_path), &algorithm)
}

#[pyfunction]
pub fn verify_file_checksum(file_path: String, expected_checksum: String, algorithm: String) -> PyResult<std::collections::HashMap<String, String>> {
    let engine = VerificationEngine::new();
    let result = engine.verify_checksum(Path::new(&file_path), &expected_checksum, &algorithm)?;
    
    let mut result_map = std::collections::HashMap::new();
    result_map.insert("is_verified".to_string(), result.is_verified.to_string());
    result_map.insert("total_bytes".to_string(), result.total_bytes.to_string());
    result_map.insert("verification_time".to_string(), format!("{:.3}", result.verification_time));
    result_map.insert("throughput_mbps".to_string(), format!("{:.2}", result.throughput_mbps));
    
    if let Some(checksum) = result.checksum {
        result_map.insert("calculated_checksum".to_string(), checksum);
    }
    
    if let Some(error) = result.error_message {
        result_map.insert("error_message".to_string(), error);
    }
    
    Ok(result_map)
}