"""
PurgeProof Configuration Management System
YAML-based configuration with validation and enterprise policy management

This module provides comprehensive configuration management for PurgeProof,
including wipe method priorities, verification settings, and compliance policies.
"""

import yaml
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import copy
import logging
from datetime import datetime


class WipeMethod(Enum):
    """Available sanitization methods"""
    CRYPTO_ERASE = "crypto_erase"
    SECURE_ERASE = "secure_erase"
    NVMe_SANITIZE = "nvme_sanitize"
    OVERWRITE_SINGLE = "overwrite_single"
    OVERWRITE_MULTI = "overwrite_multi"
    OVERWRITE_RANDOM = "overwrite_random"
    OVERWRITE_CUSTOM = "overwrite_custom"


class ComplianceLevel(Enum):
    """Security classification levels"""
    UNCLASSIFIED = "unclassified"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class DeviceType(Enum):
    """Device type categories"""
    SSD = "ssd"
    HDD = "hdd"
    USB = "usb"
    NVME = "nvme"
    OPTICAL = "optical"
    TAPE = "tape"
    MOBILE = "mobile"


@dataclass
class WipeMethodConfig:
    """Configuration for a specific wipe method"""
    method: WipeMethod
    enabled: bool = True
    priority: int = 5  # 1-10, higher = preferred
    nist_category: str = "Clear"  # Clear, Purge, Destroy
    compliance_levels: List[ComplianceLevel] = field(default_factory=lambda: [ComplianceLevel.CONFIDENTIAL])
    supported_devices: List[DeviceType] = field(default_factory=lambda: [DeviceType.SSD, DeviceType.HDD])
    passes: int = 1
    patterns: List[str] = field(default_factory=list)
    verification_required: bool = True
    verification_sampling_rate: float = 0.1  # 10% default
    timeout_minutes: int = 60
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationConfig:
    """Verification settings"""
    enabled: bool = True
    default_method: str = "pattern_verification"
    sampling_rate: float = 0.1  # 10% default sampling
    confidence_threshold: float = 0.95  # 95% confidence required
    entropy_threshold: float = 1.0  # Maximum entropy for successful wipe
    hash_algorithm: str = "sha256"
    real_time_monitoring: bool = True
    performance_benchmarking: bool = True


@dataclass
class CertificateConfig:
    """Certificate generation settings"""
    enabled: bool = True
    format: str = "both"  # json, pdf, both
    auto_generate: bool = True
    signing_enabled: bool = True
    private_key_path: Optional[str] = None
    public_key_path: Optional[str] = None
    key_size: int = 2048
    signature_algorithm: str = "RSA-PSS-SHA256"
    organization: str = "PurgeProof Enterprise"
    include_qr_code: bool = True
    pdf_template: str = "default"


@dataclass
class AuditConfig:
    """Audit logging configuration"""
    enabled: bool = True
    log_directory: str = "logs"
    log_filename: str = "purgeproof_audit.log"
    hash_chain_enabled: bool = True
    real_time_verification: bool = True
    max_log_size_mb: int = 100
    max_log_files: int = 10
    retention_days: int = 365
    compress_old_logs: bool = True
    export_formats: List[str] = field(default_factory=lambda: ["json", "csv"])
    syslog_enabled: bool = False
    syslog_server: Optional[str] = None


@dataclass
class SecurityConfig:
    """Security and access control settings"""
    require_authentication: bool = True
    operator_id_required: bool = True
    session_timeout_minutes: int = 60
    encryption_at_rest: bool = True
    encryption_algorithm: str = "AES-256-GCM"
    key_derivation: str = "PBKDF2"
    secure_delete_temp_files: bool = True
    memory_protection: bool = True
    privilege_escalation_required: bool = True


@dataclass
class PerformanceConfig:
    """Performance optimization settings"""
    rust_acceleration: bool = True
    simd_optimization: bool = True
    hardware_crypto: bool = True
    parallel_processing: bool = True
    max_threads: Optional[int] = None  # Auto-detect if None
    chunk_size_mb: int = 16
    memory_limit_mb: Optional[int] = None  # Auto-detect if None
    adaptive_optimization: bool = True
    benchmark_on_startup: bool = False


@dataclass
class EnterpriseConfig:
    """Enterprise deployment settings"""
    organization_name: str = "PurgeProof Enterprise"
    deployment_id: str = "default"
    central_management: bool = False
    central_server_url: Optional[str] = None
    api_key: Optional[str] = None
    bulk_operations: bool = True
    scheduled_operations: bool = False
    remote_monitoring: bool = False
    compliance_reporting: bool = True
    asset_tracking: bool = True


@dataclass
class GUIConfig:
    """GUI application settings"""
    enabled: bool = True
    theme: str = "default"  # default, dark, light
    auto_detect_devices: bool = True
    show_advanced_options: bool = False
    confirmation_dialogs: bool = True
    progress_notifications: bool = True
    sound_notifications: bool = False
    window_size: str = "1024x768"
    remember_settings: bool = True


@dataclass
class PurgeProofConfig:
    """Main configuration container"""
    version: str = "2.0"
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Core configuration sections
    wipe_methods: Dict[str, WipeMethodConfig] = field(default_factory=dict)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    certificates: CertificateConfig = field(default_factory=CertificateConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    enterprise: EnterpriseConfig = field(default_factory=EnterpriseConfig)
    gui: GUIConfig = field(default_factory=GUIConfig)
    
    # Custom settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)


class ConfigValidator:
    """Validates configuration settings"""
    
    @staticmethod
    def validate_config(config: PurgeProofConfig) -> Dict[str, List[str]]:
        """Validate complete configuration and return errors"""
        errors = {
            'wipe_methods': [],
            'verification': [],
            'certificates': [],
            'audit': [],
            'security': [],
            'performance': [],
            'enterprise': [],
            'gui': [],
            'general': []
        }
        
        # Validate wipe methods
        errors['wipe_methods'].extend(ConfigValidator._validate_wipe_methods(config.wipe_methods))
        
        # Validate verification settings
        errors['verification'].extend(ConfigValidator._validate_verification(config.verification))
        
        # Validate certificate settings
        errors['certificates'].extend(ConfigValidator._validate_certificates(config.certificates))
        
        # Validate audit settings
        errors['audit'].extend(ConfigValidator._validate_audit(config.audit))
        
        # Validate security settings
        errors['security'].extend(ConfigValidator._validate_security(config.security))
        
        # Validate performance settings
        errors['performance'].extend(ConfigValidator._validate_performance(config.performance))
        
        # Remove empty error lists
        return {k: v for k, v in errors.items() if v}
    
    @staticmethod
    def _validate_wipe_methods(methods: Dict[str, WipeMethodConfig]) -> List[str]:
        """Validate wipe method configurations"""
        errors = []
        
        if not methods:
            errors.append("No wipe methods configured")
            return errors
        
        for method_name, method_config in methods.items():
            # Validate priority range
            if not 1 <= method_config.priority <= 10:
                errors.append(f"{method_name}: Priority must be between 1-10")
            
            # Validate passes
            if method_config.passes < 1:
                errors.append(f"{method_name}: Passes must be at least 1")
            
            # Validate timeout
            if method_config.timeout_minutes < 1:
                errors.append(f"{method_name}: Timeout must be at least 1 minute")
            
            # Validate sampling rate
            if not 0.0 <= method_config.verification_sampling_rate <= 1.0:
                errors.append(f"{method_name}: Sampling rate must be between 0.0-1.0")
        
        return errors
    
    @staticmethod
    def _validate_verification(verification: VerificationConfig) -> List[str]:
        """Validate verification configuration"""
        errors = []
        
        if not 0.0 <= verification.sampling_rate <= 1.0:
            errors.append("Sampling rate must be between 0.0-1.0")
        
        if not 0.0 <= verification.confidence_threshold <= 1.0:
            errors.append("Confidence threshold must be between 0.0-1.0")
        
        if verification.entropy_threshold < 0.0:
            errors.append("Entropy threshold cannot be negative")
        
        valid_hash_algorithms = ["sha256", "sha512", "blake2b", "blake3"]
        if verification.hash_algorithm not in valid_hash_algorithms:
            errors.append(f"Invalid hash algorithm. Must be one of: {valid_hash_algorithms}")
        
        return errors
    
    @staticmethod
    def _validate_certificates(certificates: CertificateConfig) -> List[str]:
        """Validate certificate configuration"""
        errors = []
        
        valid_formats = ["json", "pdf", "both"]
        if certificates.format not in valid_formats:
            errors.append(f"Invalid certificate format. Must be one of: {valid_formats}")
        
        if certificates.signing_enabled:
            if certificates.private_key_path and not Path(certificates.private_key_path).exists():
                errors.append(f"Private key file not found: {certificates.private_key_path}")
            
            if certificates.public_key_path and not Path(certificates.public_key_path).exists():
                errors.append(f"Public key file not found: {certificates.public_key_path}")
            
            if certificates.key_size not in [1024, 2048, 4096]:
                errors.append("Key size must be 1024, 2048, or 4096 bits")
        
        return errors
    
    @staticmethod
    def _validate_audit(audit: AuditConfig) -> List[str]:
        """Validate audit configuration"""
        errors = []
        
        if audit.max_log_size_mb < 1:
            errors.append("Max log size must be at least 1 MB")
        
        if audit.max_log_files < 1:
            errors.append("Max log files must be at least 1")
        
        if audit.retention_days < 1:
            errors.append("Retention days must be at least 1")
        
        valid_export_formats = ["json", "csv", "html", "xml"]
        for format_type in audit.export_formats:
            if format_type not in valid_export_formats:
                errors.append(f"Invalid export format: {format_type}")
        
        return errors
    
    @staticmethod
    def _validate_security(security: SecurityConfig) -> List[str]:
        """Validate security configuration"""
        errors = []
        
        if security.session_timeout_minutes < 1:
            errors.append("Session timeout must be at least 1 minute")
        
        valid_encryption = ["AES-256-GCM", "AES-256-CBC", "ChaCha20-Poly1305"]
        if security.encryption_algorithm not in valid_encryption:
            errors.append(f"Invalid encryption algorithm. Must be one of: {valid_encryption}")
        
        valid_kdf = ["PBKDF2", "Argon2", "scrypt"]
        if security.key_derivation not in valid_kdf:
            errors.append(f"Invalid key derivation. Must be one of: {valid_kdf}")
        
        return errors
    
    @staticmethod
    def _validate_performance(performance: PerformanceConfig) -> List[str]:
        """Validate performance configuration"""
        errors = []
        
        if performance.chunk_size_mb < 1:
            errors.append("Chunk size must be at least 1 MB")
        
        if performance.max_threads is not None and performance.max_threads < 1:
            errors.append("Max threads must be at least 1")
        
        if performance.memory_limit_mb is not None and performance.memory_limit_mb < 64:
            errors.append("Memory limit must be at least 64 MB")
        
        return errors


class ConfigManager:
    """Main configuration management class"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path) if config_path else Path("config") / "default.yaml"
        self.config: PurgeProofConfig = PurgeProofConfig()
        self.validator = ConfigValidator()
        
        # Ensure config directory exists
        self.config_path.parent.mkdir(exist_ok=True)
        
        # Load or create default configuration
        if self.config_path.exists():
            self.load_config()
        else:
            self._create_default_config()
            self.save_config()
    
    def _create_default_config(self):
        """Create default configuration with all standard wipe methods"""
        self.config = PurgeProofConfig()
        
        # Configure default wipe methods
        self.config.wipe_methods = {
            "crypto_erase": WipeMethodConfig(
                method=WipeMethod.CRYPTO_ERASE,
                priority=10,
                nist_category="Purge",
                compliance_levels=[ComplianceLevel.SECRET, ComplianceLevel.TOP_SECRET],
                supported_devices=[DeviceType.SSD, DeviceType.NVME],
                passes=1,
                patterns=["AES-256 Key Destruction"],
                verification_sampling_rate=1.0,
                timeout_minutes=10,
                parameters={"hardware_acceleration": True}
            ),
            "secure_erase": WipeMethodConfig(
                method=WipeMethod.SECURE_ERASE,
                priority=9,
                nist_category="Purge",
                compliance_levels=[ComplianceLevel.SECRET],
                supported_devices=[DeviceType.SSD, DeviceType.HDD],
                passes=1,
                patterns=["ATA Secure Erase"],
                verification_sampling_rate=0.5,
                timeout_minutes=120,
                parameters={"enhanced_erase": True}
            ),
            "nvme_sanitize": WipeMethodConfig(
                method=WipeMethod.NVMe_SANITIZE,
                priority=9,
                nist_category="Purge",
                compliance_levels=[ComplianceLevel.SECRET],
                supported_devices=[DeviceType.NVME],
                passes=1,
                patterns=["NVMe Sanitize"],
                verification_sampling_rate=0.5,
                timeout_minutes=60,
                parameters={"sanitize_operation": "crypto_erase"}
            ),
            "overwrite_multi": WipeMethodConfig(
                method=WipeMethod.OVERWRITE_MULTI,
                priority=7,
                nist_category="Clear",
                compliance_levels=[ComplianceLevel.CONFIDENTIAL, ComplianceLevel.SECRET],
                supported_devices=[DeviceType.SSD, DeviceType.HDD, DeviceType.USB],
                passes=3,
                patterns=["0x00", "0xFF", "Random"],
                verification_sampling_rate=0.1,
                timeout_minutes=480,
                parameters={"parallel_processing": True, "simd_optimization": True}
            ),
            "overwrite_single": WipeMethodConfig(
                method=WipeMethod.OVERWRITE_SINGLE,
                priority=5,
                nist_category="Clear",
                compliance_levels=[ComplianceLevel.UNCLASSIFIED, ComplianceLevel.CONFIDENTIAL],
                supported_devices=[DeviceType.SSD, DeviceType.HDD, DeviceType.USB, DeviceType.OPTICAL],
                passes=1,
                patterns=["0x00"],
                verification_sampling_rate=0.05,
                timeout_minutes=240,
                parameters={"parallel_processing": True}
            ),
            "overwrite_random": WipeMethodConfig(
                method=WipeMethod.OVERWRITE_RANDOM,
                priority=6,
                nist_category="Clear",
                compliance_levels=[ComplianceLevel.CONFIDENTIAL],
                supported_devices=[DeviceType.SSD, DeviceType.HDD, DeviceType.USB],
                passes=1,
                patterns=["Random"],
                verification_sampling_rate=0.1,
                timeout_minutes=360,
                parameters={"cryptographic_random": True, "parallel_processing": True}
            )
        }
    
    def load_config(self) -> bool:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                config_dict = yaml.safe_load(f)
            
            self.config = self._dict_to_config(config_dict)
            return True
            
        except Exception as e:
            logging.error(f"Failed to load config from {self.config_path}: {e}")
            return False
    
    def save_config(self) -> bool:
        """Save configuration to YAML file"""
        try:
            # Update timestamp
            self.config.last_updated = datetime.now().isoformat()
            
            # Convert to dictionary
            config_dict = self._config_to_dict(self.config)
            
            # Save to YAML
            with open(self.config_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False, indent=2)
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to save config to {self.config_path}: {e}")
            return False
    
    def _config_to_dict(self, config: PurgeProofConfig) -> Dict[str, Any]:
        """Convert config object to dictionary for YAML serialization"""
        result = {}
        
        # Basic fields
        result['version'] = config.version
        result['last_updated'] = config.last_updated
        
        # Wipe methods
        result['wipe_methods'] = {}
        for name, method_config in config.wipe_methods.items():
            result['wipe_methods'][name] = {
                'method': method_config.method.value,
                'enabled': method_config.enabled,
                'priority': method_config.priority,
                'nist_category': method_config.nist_category,
                'compliance_levels': [level.value for level in method_config.compliance_levels],
                'supported_devices': [device.value for device in method_config.supported_devices],
                'passes': method_config.passes,
                'patterns': method_config.patterns,
                'verification_required': method_config.verification_required,
                'verification_sampling_rate': method_config.verification_sampling_rate,
                'timeout_minutes': method_config.timeout_minutes,
                'parameters': method_config.parameters
            }
        
        # Other sections
        result['verification'] = asdict(config.verification)
        result['certificates'] = asdict(config.certificates)
        result['audit'] = asdict(config.audit)
        result['security'] = asdict(config.security)
        result['performance'] = asdict(config.performance)
        result['enterprise'] = asdict(config.enterprise)
        result['gui'] = asdict(config.gui)
        result['custom_settings'] = config.custom_settings
        
        return result
    
    def _dict_to_config(self, config_dict: Dict[str, Any]) -> PurgeProofConfig:
        """Convert dictionary to config object"""
        config = PurgeProofConfig()
        
        # Basic fields
        config.version = config_dict.get('version', '2.0')
        config.last_updated = config_dict.get('last_updated', datetime.now().isoformat())
        
        # Wipe methods
        wipe_methods_dict = config_dict.get('wipe_methods', {})
        for name, method_dict in wipe_methods_dict.items():
            config.wipe_methods[name] = WipeMethodConfig(
                method=WipeMethod(method_dict['method']),
                enabled=method_dict.get('enabled', True),
                priority=method_dict.get('priority', 5),
                nist_category=method_dict.get('nist_category', 'Clear'),
                compliance_levels=[ComplianceLevel(level) for level in method_dict.get('compliance_levels', ['confidential'])],
                supported_devices=[DeviceType(device) for device in method_dict.get('supported_devices', ['ssd', 'hdd'])],
                passes=method_dict.get('passes', 1),
                patterns=method_dict.get('patterns', []),
                verification_required=method_dict.get('verification_required', True),
                verification_sampling_rate=method_dict.get('verification_sampling_rate', 0.1),
                timeout_minutes=method_dict.get('timeout_minutes', 60),
                parameters=method_dict.get('parameters', {})
            )
        
        # Other sections
        if 'verification' in config_dict:
            config.verification = VerificationConfig(**config_dict['verification'])
        
        if 'certificates' in config_dict:
            config.certificates = CertificateConfig(**config_dict['certificates'])
        
        if 'audit' in config_dict:
            config.audit = AuditConfig(**config_dict['audit'])
        
        if 'security' in config_dict:
            config.security = SecurityConfig(**config_dict['security'])
        
        if 'performance' in config_dict:
            config.performance = PerformanceConfig(**config_dict['performance'])
        
        if 'enterprise' in config_dict:
            config.enterprise = EnterpriseConfig(**config_dict['enterprise'])
        
        if 'gui' in config_dict:
            config.gui = GUIConfig(**config_dict['gui'])
        
        config.custom_settings = config_dict.get('custom_settings', {})
        
        return config
    
    def validate_config(self) -> Dict[str, List[str]]:
        """Validate current configuration"""
        return self.validator.validate_config(self.config)
    
    def get_wipe_method_priority(self, device_type: DeviceType, compliance_level: ComplianceLevel) -> List[str]:
        """Get prioritized list of wipe methods for device type and compliance level"""
        compatible_methods = []
        
        for name, method_config in self.config.wipe_methods.items():
            if (method_config.enabled and 
                device_type in method_config.supported_devices and
                compliance_level in method_config.compliance_levels):
                
                compatible_methods.append((name, method_config.priority))
        
        # Sort by priority (highest first)
        compatible_methods.sort(key=lambda x: x[1], reverse=True)
        
        return [name for name, _ in compatible_methods]
    
    def get_method_config(self, method_name: str) -> Optional[WipeMethodConfig]:
        """Get configuration for a specific wipe method"""
        return self.config.wipe_methods.get(method_name)
    
    def update_method_config(self, method_name: str, updates: Dict[str, Any]) -> bool:
        """Update configuration for a specific wipe method"""
        if method_name not in self.config.wipe_methods:
            return False
        
        method_config = self.config.wipe_methods[method_name]
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(method_config, key):
                setattr(method_config, key, value)
        
        return True
    
    def add_custom_setting(self, key: str, value: Any):
        """Add or update a custom setting"""
        self.config.custom_settings[key] = value
    
    def get_custom_setting(self, key: str, default: Any = None) -> Any:
        """Get a custom setting value"""
        return self.config.custom_settings.get(key, default)
    
    def export_config(self, output_path: str, format: str = 'yaml'):
        """Export configuration in various formats"""
        config_dict = self._config_to_dict(self.config)
        
        if format.lower() == 'yaml':
            with open(output_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False, indent=2)
        
        elif format.lower() == 'json':
            with open(output_path, 'w') as f:
                json.dump(config_dict, f, indent=2)
        
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def import_config(self, input_path: str) -> bool:
        """Import configuration from file"""
        try:
            path = Path(input_path)
            
            if path.suffix.lower() in ['.yaml', '.yml']:
                with open(path, 'r') as f:
                    config_dict = yaml.safe_load(f)
            
            elif path.suffix.lower() == '.json':
                with open(path, 'r') as f:
                    config_dict = json.load(f)
            
            else:
                raise ValueError(f"Unsupported config file format: {path.suffix}")
            
            self.config = self._dict_to_config(config_dict)
            return True
            
        except Exception as e:
            logging.error(f"Failed to import config from {input_path}: {e}")
            return False
    
    def reset_to_defaults(self):
        """Reset configuration to defaults"""
        self._create_default_config()
    
    def create_backup(self, backup_path: Optional[str] = None) -> str:
        """Create a backup of current configuration"""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = f"config_backup_{timestamp}.yaml"
        
        self.export_config(backup_path, 'yaml')
        return backup_path


# Convenience functions
def load_config(config_path: Optional[str] = None) -> ConfigManager:
    """Load configuration manager"""
    return ConfigManager(config_path)


def get_default_config() -> PurgeProofConfig:
    """Get default configuration"""
    manager = ConfigManager()
    manager._create_default_config()
    return manager.config


def validate_config_file(config_path: str) -> Dict[str, List[str]]:
    """Validate a configuration file"""
    manager = ConfigManager(config_path)
    return manager.validate_config()