use pyo3::prelude::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

/// Utility functions and shared components for the PurgeProof engine

/// Memory utilities for secure operations
pub mod memory {
    use std::ptr;
    
    /// Securely zero memory using volatile operations
    pub fn secure_zero(data: &mut [u8]) {
        unsafe {
            ptr::write_volatile(data.as_mut_ptr(), 0);
            for byte in data.iter_mut() {
                ptr::write_volatile(byte, 0);
            }
        }
    }
    
    /// Securely fill memory with random data
    pub fn secure_random_fill(data: &mut [u8]) {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(data);
        
        // Ensure the write is not optimized away
        unsafe {
            ptr::write_volatile(data.as_mut_ptr(), data[0]);
        }
    }
    
    /// Check if memory region contains only zeros
    pub fn is_zero_filled(data: &[u8]) -> bool {
        data.iter().all(|&b| b == 0)
    }
    
    /// Check if memory region contains specific pattern
    pub fn is_pattern_filled(data: &[u8], pattern: &[u8]) -> bool {
        if pattern.len() == 1 {
            data.iter().all(|&b| b == pattern[0])
        } else {
            data.chunks_exact(pattern.len()).all(|chunk| chunk == pattern)
        }
    }
}

/// Performance monitoring and metrics
pub mod metrics {
    use super::*;
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PerformanceMetrics {
        pub operation: String,
        pub start_time: Instant,
        pub duration: Duration,
        pub bytes_processed: u64,
        pub throughput_mbps: f64,
        pub cpu_usage: f64,
        pub memory_usage: u64,
        pub thread_count: usize,
    }
    
    impl PerformanceMetrics {
        pub fn new(operation: &str) -> Self {
            Self {
                operation: operation.to_string(),
                start_time: Instant::now(),
                duration: Duration::default(),
                bytes_processed: 0,
                throughput_mbps: 0.0,
                cpu_usage: 0.0,
                memory_usage: 0,
                thread_count: 1,
            }
        }
        
        pub fn finish(&mut self) {
            self.duration = self.start_time.elapsed();
            if self.duration.as_secs_f64() > 0.0 {
                self.throughput_mbps = (self.bytes_processed as f64 / (1024.0 * 1024.0)) / self.duration.as_secs_f64();
            }
        }
        
        pub fn add_bytes(&mut self, bytes: u64) {
            self.bytes_processed += bytes;
        }
        
        pub fn set_thread_count(&mut self, count: usize) {
            self.thread_count = count;
        }
    }
    
    /// Global metrics collector
    pub struct MetricsCollector {
        metrics: Arc<std::sync::Mutex<Vec<PerformanceMetrics>>>,
    }
    
    impl MetricsCollector {
        pub fn new() -> Self {
            Self {
                metrics: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }
        
        pub fn record(&self, metric: PerformanceMetrics) {
            if let Ok(mut metrics) = self.metrics.lock() {
                metrics.push(metric);
            }
        }
        
        pub fn get_metrics(&self) -> Vec<PerformanceMetrics> {
            self.metrics.lock().unwrap_or_else(|_| std::sync::MutexGuard::new(Vec::new())).clone()
        }
        
        pub fn clear(&self) {
            if let Ok(mut metrics) = self.metrics.lock() {
                metrics.clear();
            }
        }
    }
}

/// Platform-specific utilities
pub mod platform {
    use super::*;
    
    /// Get optimal thread count for current system
    pub fn get_optimal_thread_count() -> usize {
        let cpu_count = num_cpus::get();
        
        // For I/O bound operations, use more threads than CPU cores
        // For CPU bound operations, use CPU core count
        std::cmp::max(1, cpu_count)
    }
    
    /// Get system page size
    pub fn get_page_size() -> usize {
        #[cfg(unix)]
        {
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
        }
        
        #[cfg(windows)]
        {
            use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
            use std::mem;
            
            unsafe {
                let mut sys_info: SYSTEM_INFO = mem::zeroed();
                GetSystemInfo(&mut sys_info);
                sys_info.dwPageSize as usize
            }
        }
        
        #[cfg(not(any(unix, windows)))]
        {
            4096 // Default page size
        }
    }
    
    /// Get available system memory
    pub fn get_available_memory() -> u64 {
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemAvailable:") {
                        if let Some(mem_kb) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = mem_kb.parse::<u64>() {
                                return kb * 1024; // Convert to bytes
                            }
                        }
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
            use std::mem;
            
            unsafe {
                let mut mem_status: MEMORYSTATUSEX = mem::zeroed();
                mem_status.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;
                
                if GlobalMemoryStatusEx(&mut mem_status) != 0 {
                    return mem_status.ullAvailPhys;
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            use std::process::Command;
            
            if let Ok(output) = Command::new("vm_stat").output() {
                if let Ok(vm_stat) = String::from_utf8(output.stdout) {
                    // Parse vm_stat output to get available memory
                    // This is a simplified implementation
                    return 8 * 1024 * 1024 * 1024; // 8GB default
                }
            }
        }
        
        // Default fallback
        8 * 1024 * 1024 * 1024 // 8GB
    }
    
    /// Get CPU cache line size
    pub fn get_cache_line_size() -> usize {
        // Most modern CPUs have 64-byte cache lines
        64
    }
    
    /// Check if running in virtual machine
    pub fn is_virtual_machine() -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(dmi) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
                let dmi_lower = dmi.to_lowercase();
                return dmi_lower.contains("virtual") || 
                       dmi_lower.contains("vmware") || 
                       dmi_lower.contains("virtualbox") ||
                       dmi_lower.contains("qemu");
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
            use std::mem;
            
            // This is a simplified check - in practice, you'd want more comprehensive detection
            unsafe {
                let mut sys_info: SYSTEM_INFO = mem::zeroed();
                GetSystemInfo(&mut sys_info);
                // Virtual machines often have specific processor architectures
                return sys_info.dwNumberOfProcessors > 64; // Unlikely in most VMs
            }
        }
        
        false
    }
}

/// Cryptographic utilities
pub mod crypto {
    use super::*;
    use rand::RngCore;
    
    /// Generate cryptographically secure random bytes
    pub fn generate_secure_random(size: usize) -> Vec<u8> {
        let mut data = vec![0u8; size];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut data);
        data
    }
    
    /// Generate DOD 5220.22-M patterns
    pub fn generate_dod_patterns() -> Vec<Vec<u8>> {
        vec![
            vec![0x00], // Pass 1: All zeros
            vec![0xFF], // Pass 2: All ones
            generate_secure_random(1), // Pass 3: Random
        ]
    }
    
    /// Generate NIST SP 800-88 patterns
    pub fn generate_nist_patterns() -> Vec<Vec<u8>> {
        vec![
            vec![0x00], // Single pass with zeros (for SSDs)
            generate_secure_random(1), // Alternative: random pattern
        ]
    }
    
    /// Generate Gutmann patterns (35 passes)
    pub fn generate_gutmann_patterns() -> Vec<Vec<u8>> {
        let mut patterns = Vec::new();
        
        // First 4 passes: random
        for _ in 0..4 {
            patterns.push(generate_secure_random(1));
        }
        
        // 27 specific patterns designed for older magnetic media
        let specific_patterns = [
            0x55, 0xAA, 0x92, 0x49, 0x24, 0x00, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF, 0x92, 0x49, 0x24, 0x6D, 0xB6, 0xDB,
        ];
        
        for pattern in specific_patterns.iter() {
            patterns.push(vec![*pattern]);
        }
        
        // Final 4 passes: random
        for _ in 0..4 {
            patterns.push(generate_secure_random(1));
        }
        
        patterns
    }
    
    /// Derive key from password using PBKDF2
    pub fn derive_key_from_password(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;
        
        let mut key = vec![0u8; 32]; // 256-bit key
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
        key
    }
}

/// File system utilities
pub mod filesystem {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::fs;
    
    /// Get file system type for a path
    pub fn get_filesystem_type(path: &Path) -> String {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::mem;
            
            if let Ok(path_cstr) = CString::new(path.to_string_lossy().as_bytes()) {
                unsafe {
                    let mut statfs: libc::statfs = mem::zeroed();
                    if libc::statfs(path_cstr.as_ptr(), &mut statfs) == 0 {
                        match statfs.f_type as u32 {
                            0xEF53 => return "ext2/ext3/ext4".to_string(),
                            0x58465342 => return "xfs".to_string(),
                            0x9123683E => return "btrfs".to_string(),
                            0x01021994 => return "tmpfs".to_string(),
                            _ => return "unknown".to_string(),
                        }
                    }
                }
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            use std::ffi::OsString;
            use std::os::windows::ffi::OsStringExt;
            use winapi::um::fileapi::GetVolumeInformationW;
            use winapi::um::errhandlingapi::GetLastError;
            
            let root = if let Some(root) = path.ancestors().last() {
                root.to_path_buf()
            } else {
                return "unknown".to_string();
            };
            
            let root_wide: Vec<u16> = OsString::from(root.as_os_str())
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            
            let mut fs_name = vec![0u16; 256];
            
            unsafe {
                if GetVolumeInformationW(
                    root_wide.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    fs_name.as_mut_ptr(),
                    fs_name.len() as u32,
                ) != 0 {
                    let fs_name_str = String::from_utf16_lossy(&fs_name);
                    return fs_name_str.trim_end_matches('\0').to_string();
                }
            }
        }
        
        "unknown".to_string()
    }
    
    /// Get optimal I/O block size for a file system
    pub fn get_optimal_block_size(path: &Path) -> usize {
        #[cfg(unix)]
        {
            if let Ok(metadata) = fs::metadata(path) {
                use std::os::unix::fs::MetadataExt;
                let blksize = metadata.blksize() as usize;
                if blksize > 0 {
                    return blksize;
                }
            }
        }
        
        // Default to 64KB for most modern systems
        64 * 1024
    }
    
    /// Check if path is on an SSD
    pub fn is_ssd(path: &Path) -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Some(device) = get_device_from_path(path) {
                let rotational_path = format!("/sys/block/{}/queue/rotational", device);
                if let Ok(content) = std::fs::read_to_string(rotational_path) {
                    return content.trim() == "0";
                }
            }
        }
        
        // Default assumption for modern systems
        true
    }
    
    #[cfg(target_os = "linux")]
    fn get_device_from_path(path: &Path) -> Option<String> {
        // This is a simplified implementation
        // In practice, you'd need to resolve the actual block device
        None
    }
    
    /// Sync file system to ensure data is written
    pub fn sync_filesystem() {
        #[cfg(unix)]
        {
            unsafe {
                libc::sync();
            }
        }
        
        #[cfg(windows)]
        {
            // Windows doesn't have a direct equivalent to sync()
            // FlushFileBuffers would be used for specific files
        }
    }
}

/// Progress tracking utilities
pub mod progress {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    
    #[derive(Clone)]
    pub struct ProgressTracker {
        total: Arc<AtomicU64>,
        current: Arc<AtomicU64>,
        start_time: Instant,
    }
    
    impl ProgressTracker {
        pub fn new(total: u64) -> Self {
            Self {
                total: Arc::new(AtomicU64::new(total)),
                current: Arc::new(AtomicU64::new(0)),
                start_time: Instant::now(),
            }
        }
        
        pub fn add(&self, amount: u64) {
            self.current.fetch_add(amount, Ordering::Relaxed);
        }
        
        pub fn set(&self, value: u64) {
            self.current.store(value, Ordering::Relaxed);
        }
        
        pub fn get_progress(&self) -> f64 {
            let total = self.total.load(Ordering::Relaxed);
            let current = self.current.load(Ordering::Relaxed);
            
            if total == 0 {
                0.0
            } else {
                (current as f64) / (total as f64)
            }
        }
        
        pub fn get_eta(&self) -> Option<Duration> {
            let progress = self.get_progress();
            if progress <= 0.0 {
                return None;
            }
            
            let elapsed = self.start_time.elapsed();
            let total_time = elapsed.as_secs_f64() / progress;
            let remaining_time = total_time - elapsed.as_secs_f64();
            
            if remaining_time > 0.0 {
                Some(Duration::from_secs_f64(remaining_time))
            } else {
                None
            }
        }
        
        pub fn get_speed(&self) -> f64 {
            let elapsed = self.start_time.elapsed().as_secs_f64();
            let current = self.current.load(Ordering::Relaxed) as f64;
            
            if elapsed > 0.0 {
                current / elapsed
            } else {
                0.0
            }
        }
    }
}

/// Python exports for utilities
#[pyfunction]
pub fn get_system_info() -> PyResult<std::collections::HashMap<String, String>> {
    let mut info = std::collections::HashMap::new();
    
    info.insert("cpu_count".to_string(), num_cpus::get().to_string());
    info.insert("page_size".to_string(), platform::get_page_size().to_string());
    info.insert("available_memory".to_string(), platform::get_available_memory().to_string());
    info.insert("cache_line_size".to_string(), platform::get_cache_line_size().to_string());
    info.insert("is_virtual_machine".to_string(), platform::is_virtual_machine().to_string());
    
    Ok(info)
}

#[pyfunction]
pub fn get_optimal_chunk_size(file_path: String) -> PyResult<usize> {
    let path = Path::new(&file_path);
    Ok(filesystem::get_optimal_block_size(path))
}

#[pyfunction]
pub fn is_ssd_path(file_path: String) -> PyResult<bool> {
    let path = Path::new(&file_path);
    Ok(filesystem::is_ssd(path))
}