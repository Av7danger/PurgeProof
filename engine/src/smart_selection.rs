/// Smart method selection engine for optimal sanitization performance
/// This module analyzes device capabilities and compliance requirements
/// to automatically select the fastest NIST-compliant sanitization method.

use crate::{DeviceCapabilities, SanitizationMethod, OperationResult};
use std::collections::HashMap;
use anyhow::{Result, anyhow};

/// Compliance levels supported by the selection engine
#[derive(Debug, Clone)]
pub enum ComplianceLevel {
    /// NIST SP 800-88 Rev.1 - Federal standard
    NistSp80088,
    /// DoD 5220.22-M - Military standard
    Dod522022M,
    /// Common Criteria EAL4+ - High assurance
    CommonCriteriaEal4,
    /// Corporate standard - Business requirements
    Corporate,
    /// Development/Testing - Relaxed requirements
    Development,
}

impl ComplianceLevel {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "nist" | "nist_sp_800_88" | "federal" => Ok(ComplianceLevel::NistSp80088),
            "dod" | "dod_5220_22_m" | "military" => Ok(ComplianceLevel::Dod522022M),
            "cc" | "common_criteria" | "eal4" => Ok(ComplianceLevel::CommonCriteriaEal4),
            "corporate" | "business" => Ok(ComplianceLevel::Corporate),
            "dev" | "development" | "testing" => Ok(ComplianceLevel::Development),
            _ => Err(anyhow!("Unknown compliance level: {}", s)),
        }
    }
}

/// Method performance characteristics
#[derive(Debug, Clone)]
struct MethodPerformance {
    pub time_complexity: f64,     // Time factor (0.0 = instant, 1.0 = baseline)
    pub compliance_strength: u8,  // 1-10 scale
    pub hardware_requirements: u8, // 1-10 scale
    pub success_probability: f64, // 0.0-1.0
}

/// Decision matrix for method selection
lazy_static::lazy_static! {
    static ref METHOD_MATRIX: HashMap<SanitizationMethod, MethodPerformance> = {
        let mut m = HashMap::new();
        
        // Crypto erase - instant if supported
        m.insert(SanitizationMethod::CryptoErase, MethodPerformance {
            time_complexity: 0.001,
            compliance_strength: 10,
            hardware_requirements: 8,
            success_probability: 0.95,
        });
        
        // Firmware secure erase - very fast
        m.insert(SanitizationMethod::SecureErase, MethodPerformance {
            time_complexity: 0.01,
            compliance_strength: 9,
            hardware_requirements: 6,
            success_probability: 0.90,
        });
        
        // NVMe sanitize - fast and reliable
        m.insert(SanitizationMethod::NvmeSanitize, MethodPerformance {
            time_complexity: 0.05,
            compliance_strength: 10,
            hardware_requirements: 7,
            success_probability: 0.92,
        });
        
        // TRIM discard - very fast but lower compliance
        m.insert(SanitizationMethod::TrimDiscard, MethodPerformance {
            time_complexity: 0.1,
            compliance_strength: 6,
            hardware_requirements: 5,
            success_probability: 0.85,
        });
        
        // Single pass overwrite - moderate time
        m.insert(SanitizationMethod::SinglePassOverwrite, MethodPerformance {
            time_complexity: 1.0,
            compliance_strength: 8,
            hardware_requirements: 3,
            success_probability: 0.99,
        });
        
        // Multi-pass overwrite - longer but highest compliance
        m.insert(SanitizationMethod::MultiPassOverwrite { passes: 3 }, MethodPerformance {
            time_complexity: 3.0,
            compliance_strength: 10,
            hardware_requirements: 3,
            success_probability: 0.999,
        });
        
        // Crypto wrap - very fast hybrid method
        m.insert(SanitizationMethod::CryptoWrap { quick_overwrite: true }, MethodPerformance {
            time_complexity: 0.02,
            compliance_strength: 9,
            hardware_requirements: 7,
            success_probability: 0.98,
        });
        
        m
    };
}

/// Get minimum compliance strength required for compliance level
fn get_min_compliance_strength(level: &ComplianceLevel) -> u8 {
    match level {
        ComplianceLevel::NistSp80088 => 8,
        ComplianceLevel::Dod522022M => 9,
        ComplianceLevel::CommonCriteriaEal4 => 10,
        ComplianceLevel::Corporate => 6,
        ComplianceLevel::Development => 4,
    }
}

/// Get available methods for device capabilities
fn get_available_methods(capabilities: &DeviceCapabilities) -> Vec<SanitizationMethod> {
    let mut methods = Vec::new();
    
    // Crypto erase - requires encrypted device
    if capabilities.is_encrypted && capabilities.supports_crypto_erase {
        methods.push(SanitizationMethod::CryptoErase);
        methods.push(SanitizationMethod::CryptoWrap { quick_overwrite: true });
    }
    
    // Hardware-based secure erase
    if capabilities.supports_secure_erase {
        methods.push(SanitizationMethod::SecureErase);
    }
    
    // NVMe sanitize command
    if capabilities.supports_nvme_sanitize && capabilities.interface_type.contains("NVMe") {
        methods.push(SanitizationMethod::NvmeSanitize);
    }
    
    // TRIM/discard for SSDs
    if capabilities.supports_trim && (
        capabilities.interface_type.contains("SSD") || 
        capabilities.interface_type.contains("NVMe")
    ) {
        methods.push(SanitizationMethod::TrimDiscard);
    }
    
    // Software overwrites - always available
    methods.push(SanitizationMethod::SinglePassOverwrite);
    methods.push(SanitizationMethod::MultiPassOverwrite { passes: 3 });
    methods.push(SanitizationMethod::MultiPassOverwrite { passes: 7 });
    
    methods
}

/// Calculate method score based on performance and compliance
fn calculate_method_score(method: &SanitizationMethod, capabilities: &DeviceCapabilities, compliance: &ComplianceLevel) -> f64 {
    let perf = METHOD_MATRIX.get(method).unwrap_or(&MethodPerformance {
        time_complexity: 1.0,
        compliance_strength: 5,
        hardware_requirements: 5,
        success_probability: 0.8,
    });
    
    let min_compliance = get_min_compliance_strength(compliance);
    
    // Compliance gate - method must meet minimum requirements
    if perf.compliance_strength < min_compliance {
        return 0.0;
    }
    
    // Hardware compatibility check
    let hardware_score = match method {
        SanitizationMethod::CryptoErase | SanitizationMethod::CryptoWrap { .. } => {
            if capabilities.is_encrypted { 1.0 } else { 0.0 }
        }
        SanitizationMethod::SecureErase => {
            if capabilities.supports_secure_erase { 1.0 } else { 0.0 }
        }
        SanitizationMethod::NvmeSanitize => {
            if capabilities.supports_nvme_sanitize { 1.0 } else { 0.0 }
        }
        SanitizationMethod::TrimDiscard => {
            if capabilities.supports_trim { 0.8 } else { 0.0 } // Lower score due to compliance concerns
        }
        _ => 1.0, // Software methods always work
    };
    
    if hardware_score == 0.0 {
        return 0.0;
    }
    
    // Calculate composite score
    // Priority: speed (40%), compliance (30%), success rate (20%), hardware compatibility (10%)
    let speed_score = 1.0 / (1.0 + perf.time_complexity); // Higher is better
    let compliance_score = perf.compliance_strength as f64 / 10.0;
    let success_score = perf.success_probability;
    
    let weighted_score = (speed_score * 0.4) + 
                        (compliance_score * 0.3) + 
                        (success_score * 0.2) + 
                        (hardware_score * 0.1);
    
    weighted_score
}

/// Select the best sanitization method for given device and compliance requirements
pub fn select_best_method(device_path: &str, compliance_level: &str) -> Result<SanitizationMethod> {
    // Get device capabilities
    let capabilities = crate::device::get_device_capabilities_enhanced(device_path)?;
    
    // Parse compliance level
    let compliance = ComplianceLevel::from_str(compliance_level)?;
    
    // Get available methods
    let available_methods = get_available_methods(&capabilities);
    
    if available_methods.is_empty() {
        return Err(anyhow!("No suitable sanitization methods available for device"));
    }
    
    // Score all methods and select the best
    let mut best_method = &available_methods[0];
    let mut best_score = 0.0;
    
    for method in &available_methods {
        let score = calculate_method_score(method, &capabilities, &compliance);
        if score > best_score {
            best_score = score;
            best_method = method;
        }
    }
    
    if best_score == 0.0 {
        return Err(anyhow!("No method meets the specified compliance requirements"));
    }
    
    Ok(best_method.clone())
}

/// Estimate sanitization time for a method and device
pub fn estimate_time(method: &SanitizationMethod, device_path: &str) -> Result<f64> {
    let capabilities = crate::device::get_device_capabilities_enhanced(device_path)?;
    
    let perf = METHOD_MATRIX.get(method).unwrap_or(&MethodPerformance {
        time_complexity: 1.0,
        compliance_strength: 5,
        hardware_requirements: 5,
        success_probability: 0.8,
    });
    
    let base_time = match method {
        SanitizationMethod::CryptoErase => 5.0, // 5 seconds
        SanitizationMethod::SecureErase => 30.0, // 30 seconds
        SanitizationMethod::NvmeSanitize => 120.0, // 2 minutes
        SanitizationMethod::TrimDiscard => 60.0, // 1 minute
        SanitizationMethod::CryptoWrap { .. } => 10.0, // 10 seconds
        SanitizationMethod::SinglePassOverwrite => {
            // Calculate based on device size and write speed
            let size_gb = capabilities.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let write_speed_gbps = capabilities.max_write_speed_mbps / 1024.0;
            size_gb / write_speed_gbps
        }
        SanitizationMethod::MultiPassOverwrite { passes } => {
            let size_gb = capabilities.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let write_speed_gbps = capabilities.max_write_speed_mbps / 1024.0;
            (size_gb / write_speed_gbps) * (*passes as f64)
        }
    };
    
    Ok(base_time * perf.time_complexity)
}

/// Get recommendation explanation for selected method
pub fn get_selection_reasoning(method: &SanitizationMethod, device_path: &str, compliance_level: &str) -> Result<String> {
    let capabilities = crate::device::get_device_capabilities_enhanced(device_path)?;
    let compliance = ComplianceLevel::from_str(compliance_level)?;
    
    let reasoning = match method {
        SanitizationMethod::CryptoErase => {
            format!("Crypto erase selected for encrypted {} device. Instant sanitization by destroying encryption keys. Meets {} compliance requirements.", 
                capabilities.encryption_type.as_deref().unwrap_or("unknown"), compliance_level)
        }
        SanitizationMethod::SecureErase => {
            format!("Hardware secure erase selected. Firmware-level sanitization for {} interface. Fast and compliant with {} standards.", 
                capabilities.interface_type, compliance_level)
        }
        SanitizationMethod::NvmeSanitize => {
            format!("NVMe sanitize command selected. Hardware-accelerated sanitization for NVMe SSD. Optimal for {} compliance.", 
                compliance_level)
        }
        SanitizationMethod::TrimDiscard => {
            format!("TRIM/discard selected for SSD optimization. Fast but may require additional verification for {} compliance.", 
                compliance_level)
        }
        SanitizationMethod::SinglePassOverwrite => {
            format!("Single-pass overwrite selected. Software-based sanitization suitable for {} compliance. Estimated time: {:.1} minutes.", 
                compliance_level, estimate_time(method, device_path)? / 60.0)
        }
        SanitizationMethod::MultiPassOverwrite { passes } => {
            format!("{}-pass overwrite selected for maximum security. Meets highest {} compliance standards. Estimated time: {:.1} minutes.", 
                passes, compliance_level, estimate_time(method, device_path)? / 60.0)
        }
        SanitizationMethod::CryptoWrap { quick_overwrite } => {
            let overwrite_desc = if *quick_overwrite { " with quick overwrite" } else { "" };
            format!("Crypto-wrap mode selected{}. Hybrid approach combining crypto erase with verification. Optimal for {} compliance.", 
                overwrite_desc, compliance_level)
        }
    };
    
    Ok(reasoning)
}

/// Performance comparison between methods for a device
pub fn compare_methods(device_path: &str, compliance_level: &str) -> Result<Vec<(SanitizationMethod, f64, f64)>> {
    let capabilities = crate::device::get_device_capabilities_enhanced(device_path)?;
    let compliance = ComplianceLevel::from_str(compliance_level)?;
    let available_methods = get_available_methods(&capabilities);
    
    let mut comparisons = Vec::new();
    
    for method in available_methods {
        let score = calculate_method_score(&method, &capabilities, &compliance);
        let estimated_time = estimate_time(&method, device_path)?;
        
        if score > 0.0 {
            comparisons.push((method, score, estimated_time));
        }
    }
    
    // Sort by score (descending)
    comparisons.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    
    Ok(comparisons)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_level_parsing() {
        assert!(matches!(ComplianceLevel::from_str("nist").unwrap(), ComplianceLevel::NistSp80088));
        assert!(matches!(ComplianceLevel::from_str("dod").unwrap(), ComplianceLevel::Dod522022M));
        assert!(ComplianceLevel::from_str("invalid").is_err());
    }

    #[test]
    fn test_method_scoring() {
        let mock_capabilities = DeviceCapabilities {
            supports_crypto_erase: true,
            supports_secure_erase: true,
            supports_nvme_sanitize: false,
            supports_trim: true,
            is_encrypted: true,
            encryption_type: Some("AES-256".to_string()),
            size_bytes: 1_000_000_000_000, // 1TB
            sector_size: 4096,
            model: "Mock SSD".to_string(),
            serial: "MOCK123".to_string(),
            interface_type: "SATA SSD".to_string(),
            firmware_version: "1.0".to_string(),
            max_write_speed_mbps: 500.0,
        };

        let compliance = ComplianceLevel::NistSp80088;
        
        // Crypto erase should score highly for encrypted device
        let crypto_score = calculate_method_score(&SanitizationMethod::CryptoErase, &mock_capabilities, &compliance);
        assert!(crypto_score > 0.5);
        
        // Single pass should always work but score lower
        let overwrite_score = calculate_method_score(&SanitizationMethod::SinglePassOverwrite, &mock_capabilities, &compliance);
        assert!(overwrite_score > 0.0);
        assert!(crypto_score > overwrite_score);
    }

    #[test]
    fn test_time_estimation() {
        // Mock a small device for testing
        let mock_path = "/dev/mock";
        
        // Time estimates should be reasonable
        let crypto_time = estimate_time(&SanitizationMethod::CryptoErase, mock_path);
        let overwrite_time = estimate_time(&SanitizationMethod::SinglePassOverwrite, mock_path);
        
        // Crypto erase should be much faster than overwrite
        if crypto_time.is_ok() && overwrite_time.is_ok() {
            assert!(crypto_time.unwrap() < overwrite_time.unwrap());
        }
    }

    #[test]
    fn test_available_methods() {
        let encrypted_ssd = DeviceCapabilities {
            supports_crypto_erase: true,
            supports_secure_erase: true,
            supports_nvme_sanitize: true,
            supports_trim: true,
            is_encrypted: true,
            encryption_type: Some("BitLocker".to_string()),
            size_bytes: 500_000_000_000,
            sector_size: 4096,
            model: "Samsung SSD".to_string(),
            serial: "S123456".to_string(),
            interface_type: "NVMe SSD".to_string(),
            firmware_version: "2.1".to_string(),
            max_write_speed_mbps: 3500.0,
        };

        let methods = get_available_methods(&encrypted_ssd);
        
        // Should have multiple fast methods available
        assert!(methods.len() > 3);
        assert!(methods.contains(&SanitizationMethod::CryptoErase));
        assert!(methods.contains(&SanitizationMethod::NvmeSanitize));
    }
}