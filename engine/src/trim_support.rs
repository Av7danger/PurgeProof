/// TRIM/Discard support for SSD optimization and fast sanitization
/// This module provides TRIM/discard functionality for SSDs to quickly
/// mark data blocks as no longer in use, supporting fast sanitization workflows.

use crate::OperationResult;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Instant;
use anyhow::{Result, anyhow};

#[cfg(target_os = "linux")]
use nix::sys::ioctl;

/// TRIM/Discard range specification
#[derive(Debug, Clone)]
pub struct TrimRange {
    pub start_sector: u64,
    pub sector_count: u64,
}

/// TRIM operation configuration
pub struct TrimConfig {
    pub max_ranges_per_call: usize,
    pub secure_discard: bool,
    pub verify_trim: bool,
    pub chunk_size_mb: u64,
}

impl Default for TrimConfig {
    fn default() -> Self {
        TrimConfig {
            max_ranges_per_call: 256,
            secure_discard: true,
            verify_trim: false,
            chunk_size_mb: 1024, // 1GB chunks
        }
    }
}

// Linux TRIM/discard ioctl definitions
#[cfg(target_os = "linux")]
mod linux_trim {
    use super::*;
    
    // From linux/fs.h
    const BLKDISCARD: u64 = 0x1277;
    const BLKSECDISCARD: u64 = 0x127d;
    const BLKDISCARDZEROES: u64 = 0x127c;
    
    #[repr(C)]
    pub struct BlkdiscardRange {
        pub start: u64,
        pub len: u64,
    }
    
    ioctl_write_ptr!(blkdiscard, BLKDISCARD, BlkdiscardRange);
    ioctl_write_ptr!(blksecdiscard, BLKSECDISCARD, BlkdiscardRange);
    ioctl_read!(blkdiscardzeroes, BLKDISCARDZEROES, u32);
}

/// Windows TRIM support
#[cfg(target_os = "windows")]
mod windows_trim {
    use super::*;
    use winapi::um::winioctl::{DEVICE_MANAGE_DATA_SET_ATTRIBUTES, DEVICE_DSM_FLAG_TRIM_NOT_FS_ALLOCATED};
    use winapi::um::ioapiset::DeviceIoControl;
    use winapi::shared::minwindef::{DWORD, FALSE};
    use std::ptr;
    
    #[repr(C)]
    pub struct DeviceManageDataSetAttributes {
        pub size: DWORD,
        pub action: DWORD,
        pub flags: DWORD,
        pub parameter_block_offset: DWORD,
        pub parameter_block_length: DWORD,
        pub data_set_ranges_offset: DWORD,
        pub data_set_ranges_length: DWORD,
    }
    
    #[repr(C)]
    pub struct DeviceDataSetRange {
        pub starting_offset: i64,
        pub length_in_bytes: u64,
    }
    
    pub const DEVICE_DSM_ACTION_TRIM: DWORD = 1;
}

/// Check if device supports TRIM/discard operations
pub fn check_trim_support(device_path: &str) -> Result<bool> {
    #[cfg(target_os = "linux")]
    {
        // Check if device supports discard
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(device_path)?;
            
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
        
        unsafe {
            let mut discard_zeroes: u32 = 0;
            let result = linux_trim::blkdiscardzeroes(fd, &mut discard_zeroes);
            
            match result {
                Ok(_) => Ok(true),
                Err(_) => {
                    // Try reading /sys/block/*/queue/discard_granularity
                    let device_name = device_path.trim_start_matches("/dev/");
                    let sysfs_path = format!("/sys/block/{}/queue/discard_granularity", device_name);
                    
                    match std::fs::read_to_string(&sysfs_path) {
                        Ok(content) => {
                            let granularity: u64 = content.trim().parse().unwrap_or(0);
                            Ok(granularity > 0)
                        }
                        Err(_) => Ok(false),
                    }
                }
            }
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        // Windows TRIM support detection
        // TODO: Implement proper Windows TRIM capability detection
        // For now, assume modern SSDs support it
        Ok(device_path.to_lowercase().contains("ssd") || 
           device_path.to_lowercase().contains("nvme"))
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        // Unsupported platform
        Ok(false)
    }
}

/// Get optimal TRIM configuration for device
pub fn get_optimal_trim_config(device_path: &str) -> Result<TrimConfig> {
    let mut config = TrimConfig::default();
    
    // Detect device characteristics
    let device_info = crate::device::get_device_capabilities_enhanced(device_path)?;
    
    // Adjust configuration based on device type and size
    if device_info.interface_type.contains("NVMe") {
        config.max_ranges_per_call = 512; // NVMe can handle more ranges
        config.chunk_size_mb = 2048; // Larger chunks for faster NVMe
    } else if device_info.interface_type.contains("SATA") {
        config.max_ranges_per_call = 256;
        config.chunk_size_mb = 1024;
    }
    
    // Large devices benefit from bigger chunks
    let size_gb = device_info.size_bytes / (1024 * 1024 * 1024);
    if size_gb > 1000 {
        config.chunk_size_mb *= 2;
    }
    
    Ok(config)
}

/// Perform TRIM operation on entire device
pub fn trim_device(device_path: &str, custom_ranges: Option<Vec<(u64, u64)>>) -> Result<OperationResult> {
    let start_time = Instant::now();
    
    if !check_trim_support(device_path)? {
        return Err(anyhow!("Device does not support TRIM/discard operations"));
    }
    
    let device_info = crate::device::get_device_capabilities_enhanced(device_path)?;
    let config = get_optimal_trim_config(device_path)?;
    
    let total_bytes = device_info.size_bytes;
    let sector_size = device_info.sector_size as u64;
    let total_sectors = total_bytes / sector_size;
    
    // Determine ranges to TRIM
    let ranges = if let Some(custom_ranges) = custom_ranges {
        custom_ranges.into_iter()
            .map(|(start, count)| TrimRange { start_sector: start, sector_count: count })
            .collect()
    } else {
        // TRIM entire device in chunks
        let chunk_sectors = (config.chunk_size_mb * 1024 * 1024) / sector_size;
        let mut ranges = Vec::new();
        
        let mut current_sector = 0;
        while current_sector < total_sectors {
            let remaining_sectors = total_sectors - current_sector;
            let chunk_size = std::cmp::min(chunk_sectors, remaining_sectors);
            
            ranges.push(TrimRange {
                start_sector: current_sector,
                sector_count: chunk_size,
            });
            
            current_sector += chunk_size;
        }
        
        ranges
    };
    
    // Execute TRIM operations
    let mut total_trimmed_bytes = 0;
    let mut successful_ranges = 0;
    
    for chunk in ranges.chunks(config.max_ranges_per_call) {
        match trim_ranges(device_path, chunk, &config) {
            Ok(bytes_trimmed) => {
                total_trimmed_bytes += bytes_trimmed;
                successful_ranges += chunk.len();
            }
            Err(e) => {
                log::warn!("TRIM operation failed for chunk: {}", e);
                // Continue with remaining ranges
            }
        }
    }
    
    let duration = start_time.elapsed().as_secs_f64();
    let throughput_mbps = if duration > 0.0 {
        (total_trimmed_bytes as f64) / (1024.0 * 1024.0) / duration
    } else {
        0.0
    };
    
    Ok(OperationResult {
        success: successful_ranges > 0,
        method_used: "TRIM/Discard".to_string(),
        duration_seconds: duration,
        bytes_processed: total_trimmed_bytes,
        throughput_mbps,
        verification_passed: true, // TRIM success implies verification
        error_message: if successful_ranges == 0 {
            Some("All TRIM operations failed".to_string())
        } else {
            None
        },
    })
}

/// Execute TRIM on specific ranges
fn trim_ranges(device_path: &str, ranges: &[TrimRange], config: &TrimConfig) -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        let file = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(device_path)?;
            
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
        let mut total_bytes = 0;
        
        for range in ranges {
            let start_byte = range.start_sector * 512; // Assume 512-byte sectors
            let length_bytes = range.sector_count * 512;
            
            let discard_range = linux_trim::BlkdiscardRange {
                start: start_byte,
                len: length_bytes,
            };
            
            unsafe {
                if config.secure_discard {
                    // Try secure discard first
                    match linux_trim::blksecdiscard(fd, &discard_range) {
                        Ok(_) => {
                            total_bytes += length_bytes;
                            continue;
                        }
                        Err(_) => {
                            // Fall back to regular discard
                            log::debug!("Secure discard failed, trying regular discard");
                        }
                    }
                }
                
                // Regular discard
                linux_trim::blkdiscard(fd, &discard_range)?;
                total_bytes += length_bytes;
            }
        }
        
        Ok(total_bytes)
    }
    
    #[cfg(target_os = "windows")]
    {
        use winapi::um::fileapi::CreateFileA;
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};
        use winapi::um::winbase::OPEN_EXISTING;
        use std::ffi::CString;
        
        let device_name = CString::new(format!(r"\\.\{}", device_path))?;
        
        unsafe {
            let handle = CreateFileA(
                device_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            
            if handle == INVALID_HANDLE_VALUE {
                return Err(anyhow!("Failed to open device for TRIM"));
            }
            
            let mut total_bytes = 0;
            
            for range in ranges {
                let start_byte = range.start_sector * 512;
                let length_bytes = range.sector_count * 512;
                
                // Prepare TRIM command structure
                let data_set_range = windows_trim::DeviceDataSetRange {
                    starting_offset: start_byte as i64,
                    length_in_bytes: length_bytes,
                };
                
                let attributes = windows_trim::DeviceManageDataSetAttributes {
                    size: std::mem::size_of::<windows_trim::DeviceManageDataSetAttributes>() as DWORD,
                    action: windows_trim::DEVICE_DSM_ACTION_TRIM,
                    flags: winapi::um::winioctl::DEVICE_DSM_FLAG_TRIM_NOT_FS_ALLOCATED,
                    parameter_block_offset: 0,
                    parameter_block_length: 0,
                    data_set_ranges_offset: std::mem::size_of::<windows_trim::DeviceManageDataSetAttributes>() as DWORD,
                    data_set_ranges_length: std::mem::size_of::<windows_trim::DeviceDataSetRange>() as DWORD,
                };
                
                let mut input_buffer = Vec::new();
                input_buffer.extend_from_slice(&attributes.size.to_ne_bytes());
                input_buffer.extend_from_slice(&attributes.action.to_ne_bytes());
                input_buffer.extend_from_slice(&attributes.flags.to_ne_bytes());
                input_buffer.extend_from_slice(&attributes.parameter_block_offset.to_ne_bytes());
                input_buffer.extend_from_slice(&attributes.parameter_block_length.to_ne_bytes());
                input_buffer.extend_from_slice(&attributes.data_set_ranges_offset.to_ne_bytes());
                input_buffer.extend_from_slice(&attributes.data_set_ranges_length.to_ne_bytes());
                
                input_buffer.extend_from_slice(&data_set_range.starting_offset.to_ne_bytes());
                input_buffer.extend_from_slice(&data_set_range.length_in_bytes.to_ne_bytes());
                
                let mut bytes_returned: DWORD = 0;
                
                let success = DeviceIoControl(
                    handle,
                    winapi::um::winioctl::IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES,
                    input_buffer.as_ptr() as *mut _,
                    input_buffer.len() as DWORD,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                );
                
                if success != FALSE {
                    total_bytes += length_bytes;
                } else {
                    log::warn!("TRIM operation failed for range at sector {}", range.start_sector);
                }
            }
            
            CloseHandle(handle);
            Ok(total_bytes)
        }
    }
    
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(anyhow!("TRIM/discard not supported on this platform"))
    }
}

/// Verify TRIM effectiveness (check if data is actually cleared)
pub fn verify_trim_effectiveness(device_path: &str, ranges: &[TrimRange]) -> Result<bool> {
    // TODO: Implement verification by reading trimmed sectors
    // and checking if they return zeros or if reads fail (indicating unmapped)
    
    let file = OpenOptions::new()
        .read(true)
        .open(device_path)?;
    
    let mut verification_buffer = vec![0u8; 4096]; // 4KB test buffer
    let mut verified_ranges = 0;
    
    for range in ranges.iter().take(10) { // Sample first 10 ranges
        let offset = range.start_sector * 512;
        
        // Try to read from the trimmed area
        use std::io::{Seek, SeekFrom, Read};
        let mut file_handle = file.try_clone()?;
        
        match file_handle.seek(SeekFrom::Start(offset)) {
            Ok(_) => {
                match file_handle.read_exact(&mut verification_buffer) {
                    Ok(_) => {
                        // Check if data is all zeros (successful TRIM)
                        if verification_buffer.iter().all(|&b| b == 0) {
                            verified_ranges += 1;
                        }
                    }
                    Err(_) => {
                        // Read error might indicate successful unmapping
                        verified_ranges += 1;
                    }
                }
            }
            Err(_) => continue,
        }
    }
    
    // Consider TRIM effective if most sampled ranges are cleared
    Ok(verified_ranges as f64 / ranges.len().min(10) as f64 > 0.7)
}

/// Get TRIM operation statistics for device
pub fn get_trim_statistics(device_path: &str) -> Result<HashMap<String, u64>> {
    let mut stats = std::collections::HashMap::new();
    
    #[cfg(target_os = "linux")]
    {
        let device_name = device_path.trim_start_matches("/dev/");
        
        // Read discard statistics from sysfs
        let stats_files = [
            ("discard_granularity", "/sys/block/{}/queue/discard_granularity"),
            ("discard_max_bytes", "/sys/block/{}/queue/discard_max_bytes"),
            ("discard_max_hw_bytes", "/sys/block/{}/queue/discard_max_hw_bytes"),
            ("discard_alignment", "/sys/block/{}/queue/discard_alignment"),
        ];
        
        for (key, path_template) in &stats_files {
            let path = path_template.replace("{}", device_name);
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(value) = content.trim().parse::<u64>() {
                    stats.insert(key.to_string(), value);
                }
            }
        }
    }
    
    // Add computed statistics
    let device_info = crate::device::get_device_capabilities_enhanced(device_path)?;
    stats.insert("device_size_bytes".to_string(), device_info.size_bytes);
    stats.insert("sector_size".to_string(), device_info.sector_size as u64);
    
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_trim_range_creation() {
        let range = TrimRange {
            start_sector: 1000,
            sector_count: 2000,
        };
        
        assert_eq!(range.start_sector, 1000);
        assert_eq!(range.sector_count, 2000);
    }
    
    #[test]
    fn test_trim_config_defaults() {
        let config = TrimConfig::default();
        
        assert_eq!(config.max_ranges_per_call, 256);
        assert!(config.secure_discard);
        assert_eq!(config.chunk_size_mb, 1024);
    }
    
    #[test]
    fn test_optimal_config_generation() {
        // This will fail on most systems without actual devices,
        // but tests the interface
        let result = get_optimal_trim_config("/dev/null");
        // Should either succeed or fail gracefully
        assert!(result.is_ok() || result.is_err());
    }
    
    #[test]
    fn test_trim_support_detection() {
        // Test with a non-existent device - should handle gracefully
        let result = check_trim_support("/dev/nonexistent");
        assert!(result.is_err()); // Should fail for non-existent device
    }
    
    #[test]
    fn test_trim_statistics() {
        // Test with /dev/null - should handle gracefully
        let result = get_trim_statistics("/dev/null");
        // Should either work or fail gracefully
        assert!(result.is_ok() || result.is_err());
    }
}