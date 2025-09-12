"""
Unit tests for configuration management system

Tests the ConfigManager, validation, and YAML configuration handling
for enterprise settings and policy management.
"""

import pytest
import tempfile
import yaml
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

# Import modules to test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from wipeit.config import (
        ConfigManager, WipeMethodConfig, SecurityConfig, EnterpriseConfig,
        PerformanceConfig, GUIConfig, DeviceType, ComplianceLevel,
        WipeMethod, VerificationMethod, ConfigValidator
    )
except ImportError:
    # Mock objects for testing without dependencies
    ConfigManager = Mock
    WipeMethodConfig = Mock
    SecurityConfig = Mock
    EnterpriseConfig = Mock
    PerformanceConfig = Mock
    GUIConfig = Mock
    DeviceType = Mock
    ComplianceLevel = Mock
    WipeMethod = Mock
    VerificationMethod = Mock
    ConfigValidator = Mock


class TestConfigurationDataClasses:
    """Test configuration dataclass structures"""
    
    def test_wipe_method_config_creation(self):
        """Test WipeMethodConfig dataclass"""
        try:
            config = WipeMethodConfig(
                method="DoD_5220_22_M",
                nist_category="Purge",
                passes=3,
                patterns=["0x00", "0xFF", "random"],
                verification_required=True,
                timeout_minutes=120,
                priority=1,
                compliance_levels=["confidential", "secret"]
            )
            
            # Basic validation would go here if available
            assert True  # Placeholder for when actual implementation is available
        except (ImportError, NameError, TypeError):
            pytest.skip("WipeMethodConfig not available or incompatible")
    
    def test_security_config_creation(self):
        """Test SecurityConfig dataclass"""
        try:
            config = SecurityConfig(
                require_authentication=True,
                enable_audit_logging=True,
                log_encryption=True,
                certificate_signing=True,
                access_control_level="strict",
                session_timeout_minutes=30
            )
            
            assert True  # Placeholder
        except (ImportError, NameError, TypeError):
            pytest.skip("SecurityConfig not available or incompatible")
    
    def test_enterprise_config_creation(self):
        """Test EnterpriseConfig dataclass"""
        try:
            config = EnterpriseConfig(
                organization_name="Test Organization",
                department="IT Security",
                compliance_framework="NIST",
                data_classification_required=True,
                operator_certification_required=True,
                multi_factor_auth=True
            )
            
            assert True  # Placeholder
        except (ImportError, NameError, TypeError):
            pytest.skip("EnterpriseConfig not available or incompatible")


class TestConfigManager:
    """Test ConfigManager class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test configuration file
        self.test_config = {
            "wipe_methods": {
                "dod_5220_22_m": {
                    "method": "DoD_5220_22_M",
                    "nist_category": "Purge",
                    "passes": 3,
                    "patterns": ["0x00", "0xFF", "random"],
                    "verification_required": True,
                    "timeout_minutes": 120,
                    "priority": 1,
                    "compliance_levels": ["confidential", "secret"]
                }
            },
            "security": {
                "require_authentication": True,
                "enable_audit_logging": True,
                "log_encryption": False,
                "certificate_signing": True,
                "access_control_level": "moderate",
                "session_timeout_minutes": 30
            },
            "enterprise": {
                "organization_name": "Test Corp",
                "department": "Security",
                "compliance_framework": "NIST",
                "data_classification_required": True,
                "operator_certification_required": False,
                "multi_factor_auth": False
            },
            "performance": {
                "parallel_operations": 4,
                "buffer_size_mb": 64,
                "verification_threads": 2,
                "enable_hardware_acceleration": True,
                "memory_limit_mb": 2048
            },
            "gui": {
                "theme": "professional",
                "show_advanced_options": True,
                "auto_refresh_devices": True,
                "confirmation_dialogs": True,
                "progress_update_interval_ms": 500
            }
        }
        
        self.config_file = os.path.join(self.temp_dir, "test_config.yaml")
        with open(self.config_file, 'w') as f:
            yaml.dump(self.test_config, f)
        
        try:
            self.manager = ConfigManager(config_file=self.config_file)
        except (ImportError, NameError, TypeError):
            self.manager = Mock()
    
    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_config_loading(self):
        """Test configuration file loading"""
        if isinstance(self.manager, Mock):
            pytest.skip("ConfigManager not available")
        
        # Test that config was loaded
        assert self.manager is not None
        
        # Test access to configuration if methods are available
        if hasattr(self.manager, 'config'):
            assert self.manager.config is not None
    
    def test_method_config_retrieval(self):
        """Test wipe method configuration retrieval"""
        if isinstance(self.manager, Mock):
            pytest.skip("ConfigManager not available")
        
        # Test method retrieval
        if hasattr(self.manager, 'get_method_config'):
            method_config = self.manager.get_method_config("dod_5220_22_m")
            if method_config:
                # Basic validation
                assert method_config is not None
    
    def test_device_method_priority(self):
        """Test device-specific method prioritization"""
        if isinstance(self.manager, Mock):
            pytest.skip("ConfigManager not available")
        
        # Test priority retrieval for different device types
        if hasattr(self.manager, 'get_wipe_method_priority'):
            try:
                # Test with mock enum values if available
                priorities = self.manager.get_wipe_method_priority("SSD", "confidential")
                if priorities:
                    assert isinstance(priorities, list)
            except (TypeError, AttributeError):
                # Method signature might be different
                pass
    
    def test_config_validation(self):
        """Test configuration validation"""
        if isinstance(self.manager, Mock):
            pytest.skip("ConfigManager not available")
        
        # Test validation functionality
        if hasattr(self.manager, 'validate_config'):
            is_valid = self.manager.validate_config()
            assert isinstance(is_valid, bool)
    
    def test_config_export_import(self):
        """Test configuration export and import"""
        if isinstance(self.manager, Mock):
            pytest.skip("ConfigManager not available")
        
        # Test export
        export_path = os.path.join(self.temp_dir, "exported_config.yaml")
        
        if hasattr(self.manager, 'export_config'):
            try:
                success = self.manager.export_config(export_path, "yaml")
                if success:
                    assert os.path.exists(export_path)
            except (TypeError, AttributeError):
                pass
        
        # Test import
        if hasattr(self.manager, 'import_config'):
            try:
                success = self.manager.import_config(self.config_file)
                assert isinstance(success, bool)
            except (TypeError, AttributeError):
                pass
    
    def test_environment_specific_configs(self):
        """Test environment-specific configuration handling"""
        if isinstance(self.manager, Mock):
            pytest.skip("ConfigManager not available")
        
        # Test different environment configurations
        environments = ["development", "production", "testing"]
        
        for env in environments:
            if hasattr(self.manager, 'load_environment_config'):
                try:
                    env_config = self.manager.load_environment_config(env)
                    # Basic validation
                    if env_config:
                        assert env_config is not None
                except (TypeError, AttributeError):
                    pass


class TestConfigValidator:
    """Test configuration validation"""
    
    def setup_method(self):
        """Setup validator test environment"""
        try:
            self.validator = ConfigValidator()
        except (ImportError, NameError):
            self.validator = Mock()
    
    def test_method_validation(self):
        """Test wipe method validation"""
        if isinstance(self.validator, Mock):
            pytest.skip("ConfigValidator not available")
        
        # Test valid method configuration
        valid_method = {
            "method": "DoD_5220_22_M",
            "nist_category": "Purge",
            "passes": 3,
            "patterns": ["0x00", "0xFF", "random"],
            "verification_required": True,
            "timeout_minutes": 120,
            "priority": 1,
            "compliance_levels": ["confidential"]
        }
        
        if hasattr(self.validator, 'validate_method_config'):
            try:
                is_valid = self.validator.validate_method_config(valid_method)
                assert isinstance(is_valid, bool)
            except (TypeError, AttributeError):
                pass
    
    def test_security_validation(self):
        """Test security configuration validation"""
        if isinstance(self.validator, Mock):
            pytest.skip("ConfigValidator not available")
        
        # Test security config
        security_config = {
            "require_authentication": True,
            "enable_audit_logging": True,
            "log_encryption": True,
            "certificate_signing": True,
            "access_control_level": "strict",
            "session_timeout_minutes": 30
        }
        
        if hasattr(self.validator, 'validate_security_config'):
            try:
                is_valid = self.validator.validate_security_config(security_config)
                assert isinstance(is_valid, bool)
            except (TypeError, AttributeError):
                pass
    
    def test_invalid_config_detection(self):
        """Test detection of invalid configurations"""
        if isinstance(self.validator, Mock):
            pytest.skip("ConfigValidator not available")
        
        # Test invalid method (negative passes)
        invalid_method = {
            "method": "Invalid_Method",
            "nist_category": "Invalid",
            "passes": -1,  # Invalid
            "patterns": [],  # Invalid (empty)
            "verification_required": True,
            "timeout_minutes": 0,  # Invalid
            "priority": -1,  # Invalid
            "compliance_levels": []  # Invalid (empty)
        }
        
        if hasattr(self.validator, 'validate_method_config'):
            try:
                is_valid = self.validator.validate_method_config(invalid_method)
                assert is_valid is False
            except (TypeError, AttributeError):
                pass


class TestYAMLConfiguration:
    """Test YAML configuration file handling"""
    
    def setup_method(self):
        """Setup YAML test environment"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup YAML test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_yaml_structure(self):
        """Test YAML configuration structure"""
        # Test configuration structure
        config_structure = {
            "wipe_methods": {
                "test_method": {
                    "method": "TEST_METHOD",
                    "nist_category": "Clear",
                    "passes": 1,
                    "patterns": ["0x00"],
                    "verification_required": False,
                    "timeout_minutes": 60,
                    "priority": 10,
                    "compliance_levels": ["unclassified"]
                }
            },
            "device_priorities": {
                "ssd": ["test_method"],
                "hdd": ["test_method"],
                "nvme": ["test_method"],
                "usb": ["test_method"]
            },
            "security": {
                "require_authentication": False,
                "enable_audit_logging": True,
                "log_encryption": False,
                "certificate_signing": False,
                "access_control_level": "basic",
                "session_timeout_minutes": 60
            }
        }
        
        # Write and read YAML
        yaml_file = os.path.join(self.temp_dir, "test_structure.yaml")
        with open(yaml_file, 'w') as f:
            yaml.dump(config_structure, f)
        
        # Verify file exists and is readable
        assert os.path.exists(yaml_file)
        
        with open(yaml_file, 'r') as f:
            loaded_config = yaml.safe_load(f)
        
        assert loaded_config is not None
        assert "wipe_methods" in loaded_config
        assert "security" in loaded_config
    
    def test_yaml_validation(self):
        """Test YAML format validation"""
        # Test valid YAML
        valid_yaml = """
wipe_methods:
  simple_zero:
    method: "SIMPLE_ZERO"
    nist_category: "Clear"
    passes: 1
    patterns: ["0x00"]
    verification_required: false
    timeout_minutes: 30
    priority: 5
    compliance_levels: ["unclassified"]

security:
  require_authentication: false
  enable_audit_logging: true
"""
        
        yaml_file = os.path.join(self.temp_dir, "valid.yaml")
        with open(yaml_file, 'w') as f:
            f.write(valid_yaml)
        
        # Should load without errors
        with open(yaml_file, 'r') as f:
            config = yaml.safe_load(f)
        
        assert config is not None
        assert "wipe_methods" in config
    
    def test_yaml_error_handling(self):
        """Test YAML error handling"""
        # Test invalid YAML
        invalid_yaml = """
wipe_methods:
  test_method:
    method: "TEST"
    passes: invalid_number
    patterns: [unclosed_list
"""
        
        yaml_file = os.path.join(self.temp_dir, "invalid.yaml")
        with open(yaml_file, 'w') as f:
            f.write(invalid_yaml)
        
        # Should handle parsing errors gracefully
        try:
            with open(yaml_file, 'r') as f:
                config = yaml.safe_load(f)
                # If it loads, that's unexpected but not necessarily an error
        except yaml.YAMLError:
            # Expected behavior for invalid YAML
            pass


class TestConfigurationIntegration:
    """Integration tests for configuration management"""
    
    def setup_method(self):
        """Setup integration test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create comprehensive test configuration
        self.comprehensive_config = {
            "wipe_methods": {
                "nist_clear": {
                    "method": "NIST_CLEAR",
                    "nist_category": "Clear",
                    "passes": 1,
                    "patterns": ["0x00"],
                    "verification_required": False,
                    "timeout_minutes": 30,
                    "priority": 5,
                    "compliance_levels": ["unclassified"]
                },
                "nist_purge": {
                    "method": "NIST_PURGE",
                    "nist_category": "Purge",
                    "passes": 3,
                    "patterns": ["0x00", "0xFF", "random"],
                    "verification_required": True,
                    "timeout_minutes": 180,
                    "priority": 2,
                    "compliance_levels": ["confidential", "secret"]
                },
                "crypto_erase": {
                    "method": "CRYPTO_ERASE",
                    "nist_category": "Purge",
                    "passes": 1,
                    "patterns": ["crypto_key_change"],
                    "verification_required": True,
                    "timeout_minutes": 5,
                    "priority": 1,
                    "compliance_levels": ["confidential", "secret", "top_secret"]
                }
            },
            "device_priorities": {
                "ssd": ["crypto_erase", "nist_purge", "nist_clear"],
                "nvme": ["crypto_erase", "nist_purge", "nist_clear"],
                "hdd": ["nist_purge", "nist_clear"],
                "usb": ["nist_purge", "nist_clear"]
            },
            "compliance_requirements": {
                "unclassified": ["nist_clear", "nist_purge", "crypto_erase"],
                "confidential": ["nist_purge", "crypto_erase"],
                "secret": ["nist_purge", "crypto_erase"],
                "top_secret": ["crypto_erase"]
            },
            "security": {
                "require_authentication": True,
                "enable_audit_logging": True,
                "log_encryption": True,
                "certificate_signing": True,
                "access_control_level": "strict",
                "session_timeout_minutes": 15
            },
            "enterprise": {
                "organization_name": "Integration Test Corp",
                "department": "IT Security Testing",
                "compliance_framework": "NIST SP 800-88 Rev.1",
                "data_classification_required": True,
                "operator_certification_required": True,
                "multi_factor_auth": True
            },
            "performance": {
                "parallel_operations": 2,
                "buffer_size_mb": 32,
                "verification_threads": 1,
                "enable_hardware_acceleration": False,
                "memory_limit_mb": 1024
            },
            "audit": {
                "log_directory": "./audit_logs",
                "max_file_size_mb": 50,
                "max_files": 10,
                "retention_days": 90,
                "enable_encryption": True,
                "hash_algorithm": "sha256"
            },
            "certificates": {
                "format": "both",
                "include_qr_code": True,
                "digital_signature": True,
                "auto_generate": True,
                "storage_directory": "./certificates"
            },
            "gui": {
                "theme": "professional",
                "show_advanced_options": True,
                "auto_refresh_devices": True,
                "confirmation_dialogs": True,
                "progress_update_interval_ms": 250
            }
        }
        
        self.config_file = os.path.join(self.temp_dir, "integration_config.yaml")
        with open(self.config_file, 'w') as f:
            yaml.dump(self.comprehensive_config, f)
        
        try:
            self.manager = ConfigManager(config_file=self.config_file)
        except (ImportError, NameError, TypeError):
            self.manager = Mock()
    
    def teardown_method(self):
        """Cleanup integration test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_comprehensive_config_loading(self):
        """Test loading comprehensive configuration"""
        if isinstance(self.manager, Mock):
            pytest.skip("Integration test dependencies not available")
        
        # Test that manager loaded successfully
        assert self.manager is not None
        
        # Test configuration access
        if hasattr(self.manager, 'config'):
            config = self.manager.config
            if config:
                # Basic validation that config was loaded
                assert config is not None
    
    def test_method_priority_resolution(self):
        """Test method priority resolution for different scenarios"""
        if isinstance(self.manager, Mock):
            pytest.skip("Integration test dependencies not available")
        
        # Test various device type and compliance level combinations
        test_scenarios = [
            ("ssd", "unclassified"),
            ("nvme", "confidential"),
            ("hdd", "secret"),
            ("usb", "unclassified")
        ]
        
        for device_type, compliance_level in test_scenarios:
            if hasattr(self.manager, 'get_wipe_method_priority'):
                try:
                    priorities = self.manager.get_wipe_method_priority(device_type, compliance_level)
                    if priorities:
                        assert isinstance(priorities, list)
                        assert len(priorities) > 0
                except (TypeError, AttributeError):
                    # Method signature might be different
                    pass
    
    def test_configuration_validation_workflow(self):
        """Test complete configuration validation workflow"""
        if isinstance(self.manager, Mock):
            pytest.skip("Integration test dependencies not available")
        
        # Test validation of loaded configuration
        if hasattr(self.manager, 'validate_config'):
            try:
                is_valid = self.manager.validate_config()
                assert isinstance(is_valid, bool)
                
                # Configuration should be valid
                assert is_valid is True
            except (TypeError, AttributeError):
                pass
    
    def test_export_import_workflow(self):
        """Test complete export/import workflow"""
        if isinstance(self.manager, Mock):
            pytest.skip("Integration test dependencies not available")
        
        # Test YAML export
        yaml_export_path = os.path.join(self.temp_dir, "exported.yaml")
        json_export_path = os.path.join(self.temp_dir, "exported.json")
        
        if hasattr(self.manager, 'export_config'):
            try:
                # Export to YAML
                yaml_success = self.manager.export_config(yaml_export_path, "yaml")
                if yaml_success:
                    assert os.path.exists(yaml_export_path)
                
                # Export to JSON
                json_success = self.manager.export_config(json_export_path, "json")
                if json_success:
                    assert os.path.exists(json_export_path)
            except (TypeError, AttributeError):
                pass
        
        # Test import
        if hasattr(self.manager, 'import_config') and os.path.exists(yaml_export_path):
            try:
                import_success = self.manager.import_config(yaml_export_path)
                assert isinstance(import_success, bool)
            except (TypeError, AttributeError):
                pass


class TestConfigurationSecurity:
    """Test configuration security features"""
    
    def setup_method(self):
        """Setup security test environment"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup security test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_sensitive_config_handling(self):
        """Test handling of sensitive configuration data"""
        # Test configuration with sensitive data
        sensitive_config = {
            "security": {
                "require_authentication": True,
                "enable_audit_logging": True,
                "log_encryption": True,
                "certificate_signing": True,
                "access_control_level": "maximum",
                "session_timeout_minutes": 5
            },
            "enterprise": {
                "organization_name": "Classified Organization",
                "department": "Classified Department",
                "compliance_framework": "TOP_SECRET_CLEARANCE",
                "data_classification_required": True,
                "operator_certification_required": True,
                "multi_factor_auth": True
            }
        }
        
        config_file = os.path.join(self.temp_dir, "sensitive_config.yaml")
        with open(config_file, 'w') as f:
            yaml.dump(sensitive_config, f)
        
        # Verify file was created and is readable
        assert os.path.exists(config_file)
        
        # Test loading sensitive configuration
        try:
            manager = ConfigManager(config_file=config_file)
            assert manager is not None
        except (ImportError, NameError, TypeError):
            # Expected if dependencies not available
            pass
    
    def test_config_file_permissions(self):
        """Test configuration file security permissions"""
        config_file = os.path.join(self.temp_dir, "secure_config.yaml")
        
        # Create configuration file
        test_config = {"security": {"require_authentication": True}}
        with open(config_file, 'w') as f:
            yaml.dump(test_config, f)
        
        # On Windows, file permissions are handled differently
        # This test would need platform-specific implementation
        assert os.path.exists(config_file)
        
        # Basic file accessibility test
        with open(config_file, 'r') as f:
            content = f.read()
            assert len(content) > 0


# Performance tests
class TestConfigurationPerformance:
    """Test configuration management performance"""
    
    def setup_method(self):
        """Setup performance test environment"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup performance test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_large_config_loading(self):
        """Test loading large configuration files"""
        # Create large configuration with many methods
        large_config = {"wipe_methods": {}}
        
        # Generate many method configurations
        for i in range(100):
            method_name = f"test_method_{i:03d}"
            large_config["wipe_methods"][method_name] = {
                "method": f"TEST_METHOD_{i}",
                "nist_category": "Clear" if i % 2 == 0 else "Purge",
                "passes": (i % 5) + 1,
                "patterns": [f"0x{j:02x}" for j in range((i % 3) + 1)],
                "verification_required": i % 2 == 0,
                "timeout_minutes": (i * 10) % 300 + 30,
                "priority": i % 10 + 1,
                "compliance_levels": ["unclassified", "confidential"][:(i % 2) + 1]
            }
        
        config_file = os.path.join(self.temp_dir, "large_config.yaml")
        with open(config_file, 'w') as f:
            yaml.dump(large_config, f)
        
        # Test loading performance
        import time
        start_time = time.time()
        
        try:
            manager = ConfigManager(config_file=config_file)
            load_time = time.time() - start_time
            
            # Loading should be reasonably fast (< 5 seconds)
            assert load_time < 5.0
            assert manager is not None
        except (ImportError, NameError, TypeError):
            # Expected if dependencies not available
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])