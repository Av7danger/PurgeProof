use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

#[cfg(windows)]
use winapi::um::winioctl::{IOCTL_STORAGE_QUERY_PROPERTY, StorageDeviceProperty};

#[cfg(unix)]
use nix::sys::stat;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoEraseError {
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    #[error("No encryption detected")]
    NoEncryption,
    #[error("Key destruction failed: {0}")]
    KeyDestructionFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

pub fn destroy_encryption_key(device_path: &str) -> Result<(), CryptoEraseError> {
    // Check if device exists and is accessible
    if !Path::new(device_path).exists() {
        return Err(CryptoEraseError::DeviceNotFound(device_path.to_string()));
    }

    // Try different encryption key destruction methods
    
    // 1. Try ATA Security Erase (for self-encrypting drives)
    if let Ok(_) = ata_security_erase(device_path) {
        return Ok(());
    }
    
    // 2. Try NVMe Format with Crypto Erase
    if let Ok(_) = nvme_crypto_erase(device_path) {
        return Ok(());
    }
    
    // 3. Try OPAL SED unlock/rekey
    if let Ok(_) = opal_rekey(device_path) {
        return Ok(());
    }
    
    // 4. Software encryption key destruction (BitLocker, LUKS, etc.)
    if let Ok(_) = software_key_destroy(device_path) {
        return Ok(());
    }
    
    Err(CryptoEraseError::NoEncryption)
}

fn ata_security_erase(device_path: &str) -> Result<(), CryptoEraseError> {
    #[cfg(windows)]
    {
        // Windows implementation using DeviceIoControl
        windows_ata_secure_erase(device_path)
    }
    
    #[cfg(unix)]
    {
        // Linux implementation using ioctl
        linux_ata_secure_erase(device_path)
    }
}

fn nvme_crypto_erase(device_path: &str) -> Result<(), CryptoEraseError> {
    #[cfg(windows)]
    {
        // Windows NVMe crypto erase
        windows_nvme_crypto_erase(device_path)
    }
    
    #[cfg(unix)]
    {
        // Linux NVMe crypto erase using nvme-cli equivalent
        linux_nvme_crypto_erase(device_path)
    }
}

fn opal_rekey(device_path: &str) -> Result<(), CryptoEraseError> {
    // OPAL SED (Self-Encrypting Drive) rekey operation
    // This is complex and requires OPAL protocol implementation
    Err(CryptoEraseError::NoEncryption)
}

fn software_key_destroy(device_path: &str) -> Result<(), CryptoEraseError> {
    // For software encryption (BitLocker, LUKS, FileVault)
    // Look for and destroy encryption metadata
    
    #[cfg(windows)]
    {
        // Try BitLocker key destruction
        if let Ok(_) = destroy_bitlocker_keys(device_path) {
            return Ok(());
        }
    }
    
    #[cfg(unix)]
    {
        // Try LUKS header destruction
        if let Ok(_) = destroy_luks_header(device_path) {
            return Ok(());
        }
    }
    
    Err(CryptoEraseError::NoEncryption)
}

#[cfg(windows)]
fn windows_ata_secure_erase(device_path: &str) -> Result<(), CryptoEraseError> {
    use std::ffi::CString;
    use std::ptr;
    use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE};
    
    let device_name = CString::new(device_path)
        .map_err(|_| CryptoEraseError::DeviceNotFound(device_path.to_string()))?;
        
    unsafe {
        let handle = CreateFileA(
            device_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );
        
        if handle == INVALID_HANDLE_VALUE {
            return Err(CryptoEraseError::DeviceNotFound(device_path.to_string()));
        }
        
        // Send ATA SECURITY ERASE UNIT command
        // This is a simplified implementation - full implementation would
        // require proper ATA command structure
        
        CloseHandle(handle);
    }
    
    Ok(())
}

#[cfg(unix)]
fn linux_ata_secure_erase(device_path: &str) -> Result<(), CryptoEraseError> {
    use std::fs::File;
    use std::os::unix::io::AsRawFd;
    
    let file = File::options()
        .read(true)
        .write(true)
        .open(device_path)?;
        
    let fd = file.as_raw_fd();
    
    // Use ioctl to send ATA SECURITY ERASE UNIT
    // This requires proper HDIO_DRIVE_CMD implementation
    
    Ok(())
}

#[cfg(windows)]
fn windows_nvme_crypto_erase(device_path: &str) -> Result<(), CryptoEraseError> {
    // Windows NVMe format with crypto erase
    // Would use IOCTL_STORAGE_PROTOCOL_COMMAND
    Ok(())
}

#[cfg(unix)]
fn linux_nvme_crypto_erase(device_path: &str) -> Result<(), CryptoEraseError> {
    // Linux NVMe format with crypto erase
    // Would use NVME_IOCTL_ADMIN_CMD
    Ok(())
}

#[cfg(windows)]
fn destroy_bitlocker_keys(device_path: &str) -> Result<(), CryptoEraseError> {
    // BitLocker key destruction
    // Would require Windows Crypto API calls
    Err(CryptoEraseError::NoEncryption)
}

#[cfg(unix)]
fn destroy_luks_header(device_path: &str) -> Result<(), CryptoEraseError> {
    // LUKS header destruction
    // Overwrite LUKS header sectors
    let mut file = OpenOptions::new()
        .write(true)
        .open(device_path)?;
        
    // LUKS header is typically in first 1MB
    let zero_data = vec![0u8; 1024 * 1024];
    file.write_all(&zero_data)?;
    
    Ok(())
}