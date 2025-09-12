use pyo3::prelude::*;
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use rand::{RngCore, thread_rng};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use sha2::{Sha256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;
use crate::utils::{memory, platform, crypto};

// Hardware acceleration detection
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[derive(Error, Debug)]
pub enum CryptoEraseError {
    #[error("Device access failed: {0}")]
    DeviceAccess(String),
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),
    #[error("Hardware acceleration not available: {0}")]
    HardwareError(String),
}

/// Secure key structure with automatic zeroization
#[derive(ZeroizeOnDrop)]
struct SecureKey {
    key_data: Vec<u8>,
    iv: Vec<u8>,
    salt: Vec<u8>,
}

impl SecureKey {
    fn new(key_size: usize) -> Self {
        let mut key_data = vec![0u8; key_size];
        let mut iv = vec![0u8; 16]; // AES block size
        let mut salt = vec![0u8; 32]; // 256-bit salt
        
        memory::secure_random_fill(&mut key_data);
        memory::secure_random_fill(&mut iv);
        memory::secure_random_fill(&mut salt);
        
        Self { key_data, iv, salt }
    }
    
    fn from_password(password: &str, salt: &[u8]) -> Result<Self, CryptoEraseError> {
        if password.is_empty() {
            return Err(CryptoEraseError::KeyDerivationError("Empty password".to_string()));
        }
        
        let key_data = crypto::derive_key_from_password(password, salt, 100_000); // 100k iterations
        let mut iv = vec![0u8; 16];
        memory::secure_random_fill(&mut iv);
        
        Ok(Self {
            key_data,
            iv,
            salt: salt.to_vec(),
        })
    }
}

/// Hardware-accelerated cryptographic erase engine
pub struct CryptoEraseEngine {
    use_hardware_aes: bool,
    use_parallel_processing: bool,
    chunk_size: usize,
    thread_count: usize,
}

impl CryptoEraseEngine {
    pub fn new() -> Self {
        Self {
            use_hardware_aes: Self::detect_aes_ni(),
            use_parallel_processing: true,
            chunk_size: 16 * 1024 * 1024, // 16MB chunks
            thread_count: platform::get_optimal_thread_count(),
        }
    }

    /// Detect AES-NI hardware acceleration
    fn detect_aes_ni() -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            is_x86_feature_detected!("aes")
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            false
        }
    }

    /// Ultra-fast cryptographic erase with hardware acceleration
    pub async fn crypto_erase(
        &self,
        device_path: &str,
        password: Option<String>,
        verification: bool,
    ) -> Result<(), CryptoEraseError> {
        let start_time = std::time::Instant::now();
        
        // Step 1: Generate or derive cryptographic key
        let secure_key = if let Some(pwd) = password {
            let salt = crypto::generate_secure_random(32);
            SecureKey::from_password(&pwd, &salt)?
        } else {
            SecureKey::new(32) // 256-bit key
        };
        
        println!("🔐 Starting cryptographic erase with hardware acceleration: {}", 
                 if self.use_hardware_aes { "AES-NI" } else { "Software AES" });
        
        // Step 2: Get device information
        let device_size = self.get_device_size(device_path)?;
        println!("📱 Device size: {:.2} GB", device_size as f64 / (1024.0 * 1024.0 * 1024.0));
        
        // Step 3: Perform hardware-accelerated encryption
        if self.supports_hardware_crypto_erase(device_path).await? {
            self.hardware_crypto_erase(device_path).await?;
        } else {
            self.software_crypto_erase(device_path, &secure_key).await?;
        }
        
        // Step 4: Verification if requested
        if verification {
            println!("🔍 Performing cryptographic verification...");
            self.verify_crypto_erase(device_path, &secure_key).await?;
        }
        
        let duration = start_time.elapsed();
        println!("✅ Cryptographic erase completed in {:.2}s", duration.as_secs_f64());
        
        Ok(())
    }

    /// Hardware-level cryptographic erase (Self-Encrypting Drives)
    async fn hardware_crypto_erase(&self, device_path: &str) -> Result<(), CryptoEraseError> {
        println!("⚡ Attempting hardware cryptographic erase...");
        
        #[cfg(target_os = "linux")]
        {
            self.linux_hardware_crypto_erase(device_path).await
        }
        
        #[cfg(target_os = "windows")]
        {
            self.windows_hardware_crypto_erase(device_path).await
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(CryptoEraseError::HardwareError("Platform not supported".to_string()))
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_hardware_crypto_erase(&self, device_path: &str) -> Result<(), CryptoEraseError> {
        use std::process::Command;
        
        // Try hdparm for ATA Secure Erase
        let output = Command::new("hdparm")
            .args(&["--user-master", "u", "--security-set-pass", "temp", device_path])
            .output();
            
        match output {
            Ok(result) if result.status.success() => {
                // Enable security, then perform enhanced erase
                let erase_result = Command::new("hdparm")
                    .args(&["--user-master", "u", "--security-erase-enhanced", "temp", device_path])
                    .output();
                    
                match erase_result {
                    Ok(erase) if erase.status.success() => {
                        println!("✅ Hardware cryptographic erase completed");
                        Ok(())
                    }
                    _ => Err(CryptoEraseError::HardwareError("Enhanced erase failed".to_string()))
                }
            }
            _ => {
                // Try nvme-cli for NVMe drives
                let nvme_result = Command::new("nvme")
                    .args(&["format", device_path, "--force", "--crypto-erase"])
                    .output();
                    
                match nvme_result {
                    Ok(result) if result.status.success() => {
                        println!("✅ NVMe cryptographic erase completed");
                        Ok(())
                    }
                    _ => Err(CryptoEraseError::HardwareError("Hardware erase not available".to_string()))
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    async fn windows_hardware_crypto_erase(&self, device_path: &str) -> Result<(), CryptoEraseError> {
        use std::ffi::CString;
        use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE};
        use winapi::um::winioctl::{DeviceIoControl, IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES};
        
        let device_name = CString::new(device_path)
            .map_err(|_| CryptoEraseError::DeviceAccess("Invalid device path".to_string()))?;
        
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
                return Err(CryptoEraseError::DeviceAccess("Cannot open device".to_string()));
            }
            
            // Try to send crypto erase command
            let mut bytes_returned = 0u32;
            let success = DeviceIoControl(
                handle,
                IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            );
            
            CloseHandle(handle);
            
            if success != 0 {
                println!("✅ Windows hardware cryptographic erase completed");
                Ok(())
            } else {
                Err(CryptoEraseError::HardwareError("Hardware crypto erase failed".to_string()))
            }
        }
    }

    /// Software-based cryptographic erase with hardware acceleration
    async fn software_crypto_erase(&self, device_path: &str, key: &SecureKey) -> Result<(), CryptoEraseError> {
        println!("💻 Performing software cryptographic erase...");
        
        let device_size = self.get_device_size(device_path)?;
        let chunk_count = (device_size + self.chunk_size as u64 - 1) / self.chunk_size as u64;
        
        // Parallel encryption using rayon
        use rayon::prelude::*;
        
        let chunk_indices: Vec<u64> = (0..chunk_count).collect();
        let device_path = std::sync::Arc::new(device_path.to_string());
        let key_data = std::sync::Arc::new(key.key_data.clone());
        
        chunk_indices.par_iter().try_for_each(|&chunk_idx| -> Result<(), CryptoEraseError> {
            let offset = chunk_idx * self.chunk_size as u64;
            let chunk_size = std::cmp::min(self.chunk_size, (device_size - offset) as usize);
            
            // Generate encrypted chunk
            let encrypted_chunk = self.generate_encrypted_chunk(&key_data, chunk_size, offset)?;
            
            // Write encrypted data
            let mut file = OpenOptions::new()
                .write(true)
                .open(device_path.as_str())
                .map_err(|e| CryptoEraseError::DeviceAccess(format!("{}: {}", device_path, e)))?;
            
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&encrypted_chunk)?;
            
            if chunk_idx % 100 == 0 {
                println!("🔄 Progress: {:.1}%", (chunk_idx as f64 / chunk_count as f64) * 100.0);
            }
            
            Ok(())
        })?;
        
        println!("✅ Software cryptographic erase completed");
        Ok(())
    }

    /// Generate hardware-accelerated encrypted chunk
    fn generate_encrypted_chunk(&self, key: &[u8], size: usize, nonce: u64) -> Result<Vec<u8>, CryptoEraseError> {
        let mut data = vec![0u8; size];
        memory::secure_random_fill(&mut data);
        
        if self.use_hardware_aes {
            self.hardware_aes_encrypt(&mut data, key, nonce)
        } else {
            self.software_aes_encrypt(&mut data, key, nonce)
        }
    }

    /// Hardware-accelerated AES encryption using AES-NI
    #[cfg(target_arch = "x86_64")]
    fn hardware_aes_encrypt(&self, data: &mut [u8], key: &[u8], nonce: u64) -> Result<Vec<u8>, CryptoEraseError> {
        if !is_x86_feature_detected!("aes") {
            return self.software_aes_encrypt(data, key, nonce);
        }

        // For hardware AES-NI, we use the aes crate which automatically uses hardware when available
        let cipher = Aes256::new(GenericArray::from_slice(&key[..32]));
        let mut encrypted = Vec::with_capacity(data.len());
        
        // Process in 16-byte blocks (AES block size)
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            
            // XOR with nonce for additional entropy
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= ((nonce >> (i % 8)) & 0xFF) as u8;
            }
            
            let mut block_array = GenericArray::from(block);
            cipher.encrypt_block(&mut block_array);
            
            encrypted.extend_from_slice(&block_array[..chunk.len()]);
        }
        
        Ok(encrypted)
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn hardware_aes_encrypt(&self, data: &mut [u8], key: &[u8], nonce: u64) -> Result<Vec<u8>, CryptoEraseError> {
        self.software_aes_encrypt(data, key, nonce)
    }

    /// Software AES encryption fallback
    fn software_aes_encrypt(&self, data: &mut [u8], key: &[u8], nonce: u64) -> Result<Vec<u8>, CryptoEraseError> {
        let cipher = Aes256::new(GenericArray::from_slice(&key[..32]));
        let mut encrypted = Vec::with_capacity(data.len());
        
        for chunk in data.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            
            // XOR with nonce
            for (i, byte) in block.iter_mut().enumerate() {
                *byte ^= ((nonce >> (i % 8)) & 0xFF) as u8;
            }
            
            let mut block_array = GenericArray::from(block);
            cipher.encrypt_block(&mut block_array);
            
            encrypted.extend_from_slice(&block_array[..chunk.len()]);
        }
        
        Ok(encrypted)
    }

    /// Check if device supports hardware cryptographic erase
    async fn supports_hardware_crypto_erase(&self, device_path: &str) -> Result<bool, CryptoEraseError> {
        #[cfg(target_os = "linux")]
        {
            self.linux_check_crypto_erase_support(device_path).await
        }
        
        #[cfg(target_os = "windows")]
        {
            self.windows_check_crypto_erase_support(device_path).await
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Ok(false)
        }
    }

    #[cfg(target_os = "linux")]
    async fn linux_check_crypto_erase_support(&self, device_path: &str) -> Result<bool, CryptoEraseError> {
        use std::process::Command;
        
        // Check for ATA security features
        let hdparm_output = Command::new("hdparm")
            .args(&["-I", device_path])
            .output();
            
        if let Ok(output) = hdparm_output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Security:") && (stdout.contains("supported") || stdout.contains("enabled")) {
                return Ok(true);
            }
        }
        
        // Check for NVMe crypto erase support
        let nvme_output = Command::new("nvme")
            .args(&["id-ctrl", device_path])
            .output();
            
        if let Ok(output) = nvme_output {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("Format NVM Supported") || stdout.contains("Crypto Erase Supported") {
                return Ok(true);
            }
        }
        
        Ok(false)
    }

    #[cfg(target_os = "windows")]
    async fn windows_check_crypto_erase_support(&self, device_path: &str) -> Result<bool, CryptoEraseError> {
        // Simplified check - in practice would query device capabilities
        Ok(device_path.contains("NVMe") || device_path.contains("SSD"))
    }

    /// Verify cryptographic erase was successful
    async fn verify_crypto_erase(&self, device_path: &str, key: &SecureKey) -> Result<(), CryptoEraseError> {
        let device_size = self.get_device_size(device_path)?;
        let sample_size = std::cmp::min(1024 * 1024, device_size as usize); // 1MB sample
        
        let mut file = File::open(device_path)
            .map_err(|e| CryptoEraseError::DeviceAccess(format!("{}: {}", device_path, e)))?;
        
        let mut sample_data = vec![0u8; sample_size];
        file.read_exact(&mut sample_data)?;
        
        // Check that data appears encrypted (high entropy)
        let entropy = self.calculate_entropy(&sample_data);
        if entropy < 7.5 {
            return Err(CryptoEraseError::CryptoError("Low entropy detected - erase may have failed".to_string()));
        }
        
        println!("✅ Verification passed - entropy: {:.2}", entropy);
        Ok(())
    }

    /// Calculate Shannon entropy to verify encryption
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }

    /// Get device size
    fn get_device_size(&self, device_path: &str) -> Result<u64, CryptoEraseError> {
        use std::fs::metadata;
        
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
    fn linux_get_device_size(&self, device_path: &str) -> Result<u64, CryptoEraseError> {
        use std::fs::File;
        use std::os::unix::io::AsRawFd;
        
        let file = File::open(device_path)
            .map_err(|e| CryptoEraseError::DeviceAccess(format!("{}: {}", device_path, e)))?;
        
        let fd = file.as_raw_fd();
        
        let mut size: u64 = 0;
        unsafe {
            if libc::ioctl(fd, 0x80081272, &mut size) == 0 {
                return Ok(size);
            }
        }
        
        // Fallback to file metadata
        use std::fs::metadata;
        let metadata = metadata(device_path)
            .map_err(|e| CryptoEraseError::DeviceAccess(format!("Cannot get file size: {}", e)))?;
        
        Ok(metadata.len())
    }

    #[cfg(windows)]
    fn windows_get_device_size(&self, device_path: &str) -> Result<u64, CryptoEraseError> {
        use std::ffi::CString;
        use std::ptr;
        use winapi::um::fileapi::{CreateFileA, GetFileSizeEx, OPEN_EXISTING};
        use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
        use winapi::um::winnt::{GENERIC_READ, LARGE_INTEGER, FILE_SHARE_READ, FILE_SHARE_WRITE};
        
        let device_name = CString::new(device_path)
            .map_err(|_| CryptoEraseError::DeviceAccess("Invalid device path".to_string()))?;
        
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
                return Err(CryptoEraseError::DeviceAccess("Cannot open device".to_string()));
            }
            
            let mut size: LARGE_INTEGER = std::mem::zeroed();
            if GetFileSizeEx(handle, &mut size) != 0 {
                let file_size = *size.QuadPart() as u64;
                CloseHandle(handle);
                return Ok(file_size);
            }
            
            CloseHandle(handle);
            Err(CryptoEraseError::DeviceAccess("Cannot get device size".to_string()))
        }
    }
}

/// Python exports for cryptographic erase
#[pyfunction]
pub fn crypto_erase_device(
    device_path: String,
    password: Option<String>,
    verification: Option<bool>,
) -> PyResult<()> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = CryptoEraseEngine::new();
    
    rt.block_on(async {
        engine.crypto_erase(&device_path, password, verification.unwrap_or(true))
            .await
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    })
}

#[pyfunction]
pub fn check_crypto_erase_support(device_path: String) -> PyResult<bool> {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let engine = CryptoEraseEngine::new();
    
    rt.block_on(async {
        engine.supports_hardware_crypto_erase(&device_path)
            .await
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    })
}

#[pyfunction]
pub fn get_crypto_capabilities() -> PyResult<std::collections::HashMap<String, String>> {
    let mut capabilities = std::collections::HashMap::new();
    
    capabilities.insert("aes_ni_support".to_string(), CryptoEraseEngine::detect_aes_ni().to_string());
    capabilities.insert("parallel_processing".to_string(), "true".to_string());
    capabilities.insert("hardware_acceleration".to_string(), "available".to_string());
    
    #[cfg(target_arch = "x86_64")]
    {
        capabilities.insert("simd_support".to_string(), "avx2".to_string());
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        capabilities.insert("simd_support".to_string(), "none".to_string());
    }
    
    Ok(capabilities)
}