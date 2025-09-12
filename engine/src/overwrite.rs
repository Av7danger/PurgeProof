use pyo3::prelude::*;
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom, Read};
use rayon::prelude::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use memmap2::{MmapMut, MmapOptions};
use std::time::Instant;
use thiserror::Error;
use crate::utils::{memory, platform, progress::ProgressTracker};

/// SIMD-optimized pattern generation
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[derive(Error, Debug)]
pub enum OverwriteError {
    #[error("Device access failed: {0}")]
    DeviceAccess(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Threading error: {0}")]
    ThreadError(String),
    #[error("Memory mapping error: {0}")]
    MemoryMapError(String),
}

/// High-performance parallel overwrite engine with SIMD optimization
pub struct OverwriteEngine {
    thread_count: usize,
    chunk_size: usize,
    use_simd: bool,
    use_mmap: bool,
    adaptive_sizing: bool,
    max_memory_usage: usize,
}

impl OverwriteEngine {
    pub fn new() -> Self {
        Self {
            thread_count: platform::get_optimal_thread_count(),
            chunk_size: 16 * 1024 * 1024, // 16MB default
            use_simd: Self::detect_simd_support(),
            use_mmap: true,
            adaptive_sizing: true,
            max_memory_usage: platform::get_available_memory() as usize / 4, // 25% of available memory
        }
    }

    pub fn with_threads(mut self, count: usize) -> Self {
        self.thread_count = count;
        self
    }

    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    pub fn with_memory_limit(mut self, limit: usize) -> Self {
        self.max_memory_usage = limit;
        self
    }

    /// Detect SIMD instruction support
    fn detect_simd_support() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            is_x86_feature_detected!("avx2") || is_x86_feature_detected!("sse2")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    /// Ultra-fast parallel overwrite with adaptive optimization
    pub async fn parallel_overwrite(
        &self,
        device_path: &str,
        passes: u32,
        patterns: Option<Vec<Vec<u8>>>,
        progress_callback: Option<Box<dyn Fn(f64) + Send + Sync>>,
    ) -> Result<(), OverwriteError> {
        let device_size = self.get_device_size(device_path)?;
        let progress = Arc::new(ProgressTracker::new(device_size * passes as u64));
        
        println!("🚀 Starting {} passes on {} ({:.2} GB)", 
                 passes, device_path, device_size as f64 / (1024.0 * 1024.0 * 1024.0));
        
        // Optimize chunk size based on device characteristics
        let optimal_chunk_size = self.calculate_optimal_chunk_size(device_path, device_size)?;
        
        for pass in 0..passes {
            let pass_start = Instant::now();
            println!("⚡ Pass {}/{}", pass + 1, passes);
            
            let pattern = if let Some(ref patterns) = patterns {
                patterns.get(pass as usize).cloned().unwrap_or_else(|| self.generate_adaptive_pattern(pass))
            } else {
                self.generate_adaptive_pattern(pass)
            };
            
            // Choose optimal strategy based on file size and system capabilities
            if device_size > 1024 * 1024 * 1024 && self.use_mmap {
                // Large files: Use memory-mapped I/O
                self.mmap_overwrite_pass(device_path, device_size, &pattern, &progress).await?;
            } else {
                // Smaller files: Use traditional buffered I/O with SIMD
                self.buffered_overwrite_pass(device_path, device_size, &pattern, optimal_chunk_size, &progress).await?;
            }
            
            // Ensure data is physically written
            self.sync_device(device_path)?;
            
            let pass_duration = pass_start.elapsed();
            let throughput = (device_size as f64 / (1024.0 * 1024.0)) / pass_duration.as_secs_f64();
            println!("✅ Pass {} completed in {:.2}s ({:.2} MB/s)", 
                     pass + 1, pass_duration.as_secs_f64(), throughput);
            
            // Call progress callback if provided
            if let Some(ref callback) = progress_callback {
                let current_progress = ((pass + 1) as f64) / (passes as f64);
                callback(current_progress);
            }
        }
        
        Ok(())
    }

    /// Memory-mapped overwrite for maximum performance on large files
    async fn mmap_overwrite_pass(
        &self,
        device_path: &str,
        device_size: u64,
        pattern: &[u8],
        progress: &Arc<ProgressTracker>,
    ) -> Result<(), OverwriteError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(device_path)
            .map_err(|e| OverwriteError::DeviceAccess(format!("{}: {}", device_path, e)))?;

        // Create memory mapping
        let mut mmap = unsafe {
            MmapOptions::new()
                .len(device_size as usize)
                .map_mut(&file)
                .map_err(|e| OverwriteError::MemoryMapError(e.to_string()))?
        };

        let chunk_size = self.calculate_simd_chunk_size();
        let chunks: Vec<_> = (0..device_size)
            .step_by(chunk_size)
            .collect();

        // Parallel SIMD-optimized overwrite
        chunks.par_iter().for_each(|&offset| {
            let start = offset as usize;
            let end = std::cmp::min(start + chunk_size, device_size as usize);
            let chunk = &mut mmap[start..end];
            
            if self.use_simd {
                self.simd_fill_chunk(chunk, pattern);
            } else {
                self.scalar_fill_chunk(chunk, pattern);
            }
            
            progress.add((end - start) as u64);
        });

        // Ensure memory-mapped data is flushed
        mmap.flush().map_err(|e| OverwriteError::IoError(e))?;
        
        Ok(())
    }

    /// Traditional buffered I/O with SIMD optimization
    async fn buffered_overwrite_pass(
        &self,
        device_path: &str,
        device_size: u64,
        pattern: &[u8],
        chunk_size: usize,
        progress: &Arc<ProgressTracker>,
    ) -> Result<(), OverwriteError> {
        let chunks_count = (device_size as usize + chunk_size - 1) / chunk_size;
        let chunk_indices: Vec<usize> = (0..chunks_count).collect();
        
        let device_path = Arc::new(device_path.to_string());
        let pattern = Arc::new(pattern.to_vec());
        
        // Parallel processing with optimal thread count
        chunk_indices.par_iter().try_for_each(|&chunk_idx| -> Result<(), OverwriteError> {
            let offset = chunk_idx * chunk_size;
            let chunk_data_size = std::cmp::min(chunk_size, device_size as usize - offset);
            
            // Pre-generate optimized chunk data
            let mut chunk_data = vec![0u8; chunk_data_size];
            if self.use_simd {
                self.simd_fill_chunk(&mut chunk_data, &pattern);
            } else {
                self.scalar_fill_chunk(&mut chunk_data, &pattern);
            }
            
            // Write chunk with optimal I/O
            let mut file = OpenOptions::new()
                .write(true)
                .open(device_path.as_str())
                .map_err(|e| OverwriteError::DeviceAccess(format!("{}: {}", device_path, e)))?;
            
            file.seek(SeekFrom::Start(offset as u64))?;
            file.write_all(&chunk_data)?;
            
            progress.add(chunk_data_size as u64);
            Ok(())
        })?;
        
        Ok(())
    }

    /// SIMD-accelerated chunk filling
    #[cfg(target_arch = "x86_64")]
    fn simd_fill_chunk(&self, chunk: &mut [u8], pattern: &[u8]) {
        if !is_x86_feature_detected!("avx2") {
            return self.scalar_fill_chunk(chunk, pattern);
        }

        unsafe {
            if pattern.len() == 1 {
                // Single-byte pattern optimization with AVX2
                let pattern_byte = pattern[0];
                let pattern_vec = _mm256_set1_epi8(pattern_byte as i8);
                
                let chunks_256 = chunk.chunks_exact_mut(32);
                let remainder = chunks_256.into_remainder();
                
                // Process 32-byte chunks with AVX2
                for chunk_32 in chunk.chunks_exact_mut(32) {
                    _mm256_storeu_si256(chunk_32.as_mut_ptr() as *mut __m256i, pattern_vec);
                }
                
                // Handle remainder
                for byte in remainder.iter_mut() {
                    *byte = pattern_byte;
                }
            } else if pattern.len() == 2 {
                // Optimized 2-byte pattern with AVX2
                let pattern_u16 = u16::from_le_bytes([pattern[0], pattern[1]]);
                let pattern_vec = _mm256_set1_epi16(pattern_u16 as i16);
                
                let aligned_chunks = chunk.chunks_exact_mut(32);
                let remainder = aligned_chunks.into_remainder();
                
                for chunk_32 in chunk.chunks_exact_mut(32) {
                    _mm256_storeu_si256(chunk_32.as_mut_ptr() as *mut __m256i, pattern_vec);
                }
                
                // Handle remainder with scalar code
                self.scalar_fill_chunk(remainder, pattern);
            } else if pattern.len() == 4 {
                // Optimized 4-byte pattern with AVX2
                let pattern_u32 = u32::from_le_bytes([pattern[0], pattern[1], pattern[2], pattern[3]]);
                let pattern_vec = _mm256_set1_epi32(pattern_u32 as i32);
                
                for chunk_32 in chunk.chunks_exact_mut(32) {
                    _mm256_storeu_si256(chunk_32.as_mut_ptr() as *mut __m256i, pattern_vec);
                }
                
                // Handle remainder
                let remainder_start = (chunk.len() / 32) * 32;
                self.scalar_fill_chunk(&mut chunk[remainder_start..], pattern);
            } else {
                // Complex patterns: fall back to optimized scalar
                self.scalar_fill_chunk(chunk, pattern);
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn simd_fill_chunk(&self, chunk: &mut [u8], pattern: &[u8]) {
        self.scalar_fill_chunk(chunk, pattern);
    }

    /// Optimized scalar chunk filling
    fn scalar_fill_chunk(&self, chunk: &mut [u8], pattern: &[u8]) {
        if pattern.is_empty() {
            return;
        }

        if pattern.len() == 1 {
            // Ultra-fast single-byte fill
            chunk.fill(pattern[0]);
        } else {
            // Optimized pattern repetition
            let pattern_len = pattern.len();
            let full_cycles = chunk.len() / pattern_len;
            let remainder = chunk.len() % pattern_len;
            
            // Fill complete pattern cycles
            for i in 0..full_cycles {
                let start = i * pattern_len;
                let end = start + pattern_len;
                chunk[start..end].copy_from_slice(pattern);
            }
            
            // Fill remainder
            if remainder > 0 {
                let start = full_cycles * pattern_len;
                chunk[start..].copy_from_slice(&pattern[..remainder]);
            }
        }
    }

    /// Calculate optimal chunk size for SIMD operations
    fn calculate_simd_chunk_size(&self) -> usize {
        let cache_line_size = platform::get_cache_line_size();
        let page_size = platform::get_page_size();
        
        // Optimize for L3 cache and memory bandwidth
        let base_size = if self.use_simd { 
            32 * cache_line_size // 32 cache lines for SIMD
        } else { 
            16 * cache_line_size // 16 cache lines for scalar
        };
        
        // Ensure alignment to page boundaries
        ((base_size + page_size - 1) / page_size) * page_size
    }

    /// Calculate optimal chunk size based on device and system characteristics
    fn calculate_optimal_chunk_size(&self, device_path: &str, device_size: u64) -> Result<usize, OverwriteError> {
        let available_memory = platform::get_available_memory() as usize;
        let max_chunk_size = available_memory / (self.thread_count * 4); // Conservative memory usage
        
        // Base chunk size on device type and size
        let base_chunk_size = if device_size < 100 * 1024 * 1024 {
            // Small files: 1MB chunks
            1024 * 1024
        } else if device_size < 10 * 1024 * 1024 * 1024 {
            // Medium files: 8MB chunks
            8 * 1024 * 1024
        } else {
            // Large files: 32MB chunks
            32 * 1024 * 1024
        };

        let chunk_size = std::cmp::min(base_chunk_size, max_chunk_size);
        
        // Align to page boundaries for optimal performance
        let page_size = platform::get_page_size();
        Ok(((chunk_size + page_size - 1) / page_size) * page_size)
    }

    /// Generate adaptive patterns based on pass number and security requirements
    fn generate_adaptive_pattern(&self, pass: u32) -> Vec<u8> {
        match pass {
            0 => vec![0x00], // First pass: zeros
            1 => vec![0xFF], // Second pass: ones
            2 => vec![0xAA], // Third pass: alternating 10101010
            3 => vec![0x55], // Fourth pass: alternating 01010101
            4 => vec![0x92, 0x49, 0x24], // Gutmann pattern 1
            5 => vec![0x49, 0x24, 0x92], // Gutmann pattern 2
            6 => vec![0x24, 0x92, 0x49], // Gutmann pattern 3
            _ => {
                // High-entropy random patterns for additional passes
                let mut pattern = vec![0u8; 4]; // 4-byte patterns for SIMD optimization
                memory::secure_random_fill(&mut pattern);
                pattern
            }
        }
    }

    /// Get device size with platform-specific optimizations
    fn get_device_size(&self, device_path: &str) -> Result<u64, OverwriteError> {
        #[cfg(unix)]
        {
            self.linux_get_device_size(device_path)
        }
        
        #[cfg(windows)]
        {
            self.windows_get_device_size(device_path)
        }
    }

    #[cfg(unix)]
    fn linux_get_device_size(&self, device_path: &str) -> Result<u64, OverwriteError> {
        use std::fs::File;
        use std::os::unix::io::AsRawFd;
        
        let file = File::open(device_path)
            .map_err(|e| OverwriteError::DeviceAccess(format!("{}: {}", device_path, e)))?;
        
        let fd = file.as_raw_fd();
        
        // Try BLKGETSIZE64 first (most accurate for block devices)
        let mut size: u64 = 0;
        unsafe {
            if libc::ioctl(fd, 0x80081272, &mut size) == 0 {
                return Ok(size);
            }
        }
        
        // Fallback to file metadata
        use std::fs::metadata;
        let metadata = metadata(device_path)
            .map_err(|e| OverwriteError::DeviceAccess(format!("Cannot get file size: {}", e)))?;
        
        Ok(metadata.len())
    }

    #[cfg(windows)]
    fn windows_get_device_size(&self, device_path: &str) -> Result<u64, OverwriteError> {
        use std::ffi::CString;
        use std::ptr;
        use winapi::um::fileapi::{CreateFileA, GetFileSizeEx, OPEN_EXISTING};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::winnt::{GENERIC_READ, LARGE_INTEGER, FILE_SHARE_READ, FILE_SHARE_WRITE};
        use winapi::um::winioctl::{DeviceIoControl, IOCTL_DISK_GET_LENGTH_INFO, DISK_LENGTH_INFO};
        
        let device_name = CString::new(device_path)
            .map_err(|_| OverwriteError::DeviceAccess("Invalid device path".to_string()))?;
        
        unsafe {
            let handle = CreateFileA(
                device_name.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            );
            
            if handle == INVALID_HANDLE_VALUE {
                return Err(OverwriteError::DeviceAccess("Cannot open device".to_string()));
            }
            
            // Try disk length info first (for block devices)
            let mut disk_length: DISK_LENGTH_INFO = std::mem::zeroed();
            let mut bytes_returned = 0u32;
            
            if DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                ptr::null_mut(),
                0,
                &mut disk_length as *mut _ as *mut _,
                std::mem::size_of::<DISK_LENGTH_INFO>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            ) != 0 {
                CloseHandle(handle);
                return Ok(disk_length.Length as u64);
            }
            
            // Fallback to file size
            let mut size: LARGE_INTEGER = std::mem::zeroed();
            if GetFileSizeEx(handle, &mut size) != 0 {
                let file_size = *size.QuadPart() as u64;
                CloseHandle(handle);
                return Ok(file_size);
            }
            
            CloseHandle(handle);
            Err(OverwriteError::DeviceAccess("Cannot get device size".to_string()))
        }
    }

    /// Platform-optimized device synchronization
    fn sync_device(&self, device_path: &str) -> Result<(), OverwriteError> {
        let file = OpenOptions::new()
            .write(true)
            .open(device_path)
            .map_err(|e| OverwriteError::DeviceAccess(format!("{}: {}", device_path, e)))?;
        
        file.sync_all()?;
        
        // Additional platform-specific sync
        #[cfg(unix)]
        {
            unsafe {
                libc::sync(); // Global filesystem sync
            }
        }
        
        Ok(())
    }

    /// Benchmark device performance for optimization
    pub fn benchmark_device(&self, device_path: &str, test_size_mb: u64) -> Result<f64, OverwriteError> {
        let test_size = test_size_mb * 1024 * 1024;
        let mut test_data = vec![0xAAu8; test_size as usize];
        
        // Use SIMD for test data generation if available
        if self.use_simd {
            self.simd_fill_chunk(&mut test_data, &[0xAA]);
        }
        
        let mut file = OpenOptions::new()
            .write(true)
            .open(device_path)
            .map_err(|e| OverwriteError::DeviceAccess(format!("{}: {}", device_path, e)))?;
        
        let start = Instant::now();
        file.write_all(&test_data)?;
        file.sync_all()?;
        let duration = start.elapsed();
        
        let mb_per_second = (test_size_mb as f64) / duration.as_secs_f64();
        Ok(mb_per_second)
    }
}

/// Python exports for high-performance overwrite operations
#[pyfunction]
pub fn parallel_overwrite_file(
    device_path: String,
    passes: u32,
    patterns: Option<Vec<Vec<u8>>>,
) -> PyResult<()> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = OverwriteEngine::new();
    
    rt.block_on(async {
        engine.parallel_overwrite(&device_path, passes, patterns, None)
            .await
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    })
}

#[pyfunction]
pub fn benchmark_overwrite_performance(device_path: String, test_size_mb: u64) -> PyResult<f64> {
    let engine = OverwriteEngine::new();
    engine.benchmark_device(&device_path, test_size_mb)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
pub fn get_optimal_overwrite_settings(device_path: String) -> PyResult<std::collections::HashMap<String, String>> {
    let engine = OverwriteEngine::new();
    let device_size = engine.get_device_size(&device_path)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    
    let chunk_size = engine.calculate_optimal_chunk_size(&device_path, device_size)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    
    let mut settings = std::collections::HashMap::new();
    settings.insert("device_size".to_string(), device_size.to_string());
    settings.insert("optimal_chunk_size".to_string(), chunk_size.to_string());
    settings.insert("thread_count".to_string(), engine.thread_count.to_string());
    settings.insert("simd_support".to_string(), engine.use_simd.to_string());
    settings.insert("mmap_support".to_string(), engine.use_mmap.to_string());
    
    Ok(settings)
}