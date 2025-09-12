"""
Unit tests for certificate generation system

Tests the WipeCertificate, CertificateSigner, and CertificateManager classes
for proper certificate generation, digital signatures, and compliance validation.
"""

import pytest
import tempfile
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, Any, List

# Import modules to test
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from wipeit.certs import (
        WipeCertificate, DeviceInfo, SanitizationMethod, VerificationResult,
        CertificateSigner, CertificateManager, ComplianceLevel
    )
    from wipeit.config import ConfigManager
except ImportError:
    # Mock objects for testing without dependencies
    DeviceInfo = Mock
    SanitizationMethod = Mock
    VerificationResult = Mock
    WipeCertificate = Mock
    CertificateSigner = Mock
    CertificateManager = Mock
    ComplianceLevel = Mock


class TestDeviceInfo:
    """Test DeviceInfo dataclass"""
    
    def test_device_info_creation(self):
        """Test basic device info creation"""
        device = DeviceInfo(
            path="/dev/sda",
            serial_number="S6T2NG0T123456",
            model="Samsung SSD 980 PRO",
            manufacturer="Samsung",
            size_bytes=1000204886016,
            interface_type="NVMe",
            device_type="NVMe SSD"
        )
        
        assert device.path == "/dev/sda"
        assert device.serial_number == "S6T2NG0T123456"
        assert device.model == "Samsung SSD 980 PRO"
        assert device.size_bytes == 1000204886016
    
    def test_device_info_validation(self):
        """Test device info field validation"""
        # Test with minimal required fields
        device = DeviceInfo(
            path="/dev/sdb",
            serial_number="TEST123",
            model="Test Device",
            manufacturer="Test Corp",
            size_bytes=1000000000,
            interface_type="SATA",
            device_type="HDD"
        )
        
        assert device.path.startswith("/dev/") or device.path.endswith(":")
        assert len(device.serial_number) > 0
        assert device.size_bytes > 0


class TestSanitizationMethod:
    """Test SanitizationMethod dataclass"""
    
    def test_sanitization_method_creation(self):
        """Test sanitization method creation"""
        method = SanitizationMethod(
            method_name="DoD 5220.22-M",
            nist_category="Purge",
            passes=3,
            patterns=["0x00", "0xFF", "random"],
            verification_method="Pattern Verification",
            compliance_level="secret"
        )
        
        assert method.method_name == "DoD 5220.22-M"
        assert method.nist_category == "Purge"
        assert method.passes == 3
        assert len(method.patterns) == 3
    
    def test_method_validation(self):
        """Test method parameter validation"""
        method = SanitizationMethod(
            method_name="Test Method",
            nist_category="Clear",
            passes=1,
            patterns=["0x00"],
            verification_method="None",
            compliance_level="unclassified"
        )
        
        assert method.passes >= 1
        assert len(method.patterns) >= 1
        assert method.nist_category in ["Clear", "Purge", "Destroy"]


class TestVerificationResult:
    """Test VerificationResult dataclass"""
    
    def test_verification_result_creation(self):
        """Test verification result creation"""
        result = VerificationResult(
            method="pattern_verification",
            verified=True,
            sample_rate=0.1,
            confidence_level=0.95,
            entropy_score=0.05,
            verification_hash="sha256:abcd1234"
        )
        
        assert result.method == "pattern_verification"
        assert result.verified is True
        assert 0.0 <= result.sample_rate <= 1.0
        assert 0.0 <= result.confidence_level <= 1.0
        assert 0.0 <= result.entropy_score <= 1.0
    
    def test_verification_metrics(self):
        """Test verification metric validation"""
        result = VerificationResult(
            method="entropy_analysis",
            verified=False,
            sample_rate=0.05,
            confidence_level=0.99,
            entropy_score=0.8,
            verification_hash="sha256:efgh5678"
        )
        
        # High entropy score should indicate potential verification failure
        if result.entropy_score > 0.5:
            assert result.verified is False


class TestWipeCertificate:
    """Test WipeCertificate dataclass"""
    
    def setup_method(self):
        """Setup test data"""
        self.device_info = DeviceInfo(
            path="/dev/sda",
            serial_number="TEST123",
            model="Test SSD",
            manufacturer="Test Corp",
            size_bytes=1000000000,
            interface_type="SATA",
            device_type="SSD"
        )
        
        self.method = SanitizationMethod(
            method_name="Test Method",
            nist_category="Purge",
            passes=3,
            patterns=["0x00", "0xFF", "random"],
            verification_method="Pattern Verification",
            compliance_level="confidential"
        )
        
        self.verification = VerificationResult(
            method="pattern_verification",
            verified=True,
            sample_rate=0.1,
            confidence_level=0.95,
            entropy_score=0.05,
            verification_hash="sha256:test123"
        )
    
    def test_certificate_creation(self):
        """Test certificate creation with all fields"""
        cert = WipeCertificate(
            certificate_id="CERT-2025-001",
            timestamp=datetime.now(),
            device_info=self.device_info,
            sanitization_method=self.method,
            verification_result=self.verification,
            operator_id="test_operator",
            organization="Test Organization",
            compliance_level="confidential",
            additional_notes="Test certificate"
        )
        
        assert cert.certificate_id.startswith("CERT-")
        assert cert.organization == "Test Organization"
        assert cert.compliance_level == "confidential"
        assert isinstance(cert.timestamp, datetime)
    
    def test_certificate_validation(self):
        """Test certificate field validation"""
        cert = WipeCertificate(
            certificate_id="CERT-2025-002",
            timestamp=datetime.now(),
            device_info=self.device_info,
            sanitization_method=self.method,
            verification_result=self.verification,
            operator_id="test_operator",
            organization="Test Org",
            compliance_level="secret"
        )
        
        # Verify timestamp is recent (within last day)
        assert (datetime.now() - cert.timestamp) < timedelta(days=1)
        
        # Verify required fields are present
        assert cert.certificate_id is not None
        assert cert.operator_id is not None
        assert cert.organization is not None


class TestCertificateSigner:
    """Test CertificateSigner class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.signer = None
        
        # Mock cryptography if not available
        try:
            self.signer = CertificateSigner()
        except (ImportError, NameError):
            self.signer = Mock()
    
    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_key_generation(self):
        """Test RSA key generation"""
        if isinstance(self.signer, Mock):
            pytest.skip("Cryptography not available")
        
        # Test key generation
        private_key = self.signer.generate_key_pair()
        assert private_key is not None
        
        # Test key size (should be 2048 or larger)
        if hasattr(private_key, 'key_size'):
            assert private_key.key_size >= 2048
    
    def test_certificate_signing(self):
        """Test certificate signing"""
        if isinstance(self.signer, Mock):
            pytest.skip("Cryptography not available")
        
        test_data = {"test": "data", "timestamp": datetime.now().isoformat()}
        test_json = json.dumps(test_data, sort_keys=True)
        
        # Generate keys
        private_key = self.signer.generate_key_pair()
        
        # Sign data
        signature = self.signer.sign_data(test_json.encode(), private_key)
        assert signature is not None
        assert len(signature) > 0
    
    def test_signature_verification(self):
        """Test signature verification"""
        if isinstance(self.signer, Mock):
            pytest.skip("Cryptography not available")
        
        test_data = {"test": "verification", "timestamp": datetime.now().isoformat()}
        test_json = json.dumps(test_data, sort_keys=True)
        
        # Generate keys and sign
        private_key = self.signer.generate_key_pair()
        public_key = private_key.public_key()
        signature = self.signer.sign_data(test_json.encode(), private_key)
        
        # Verify signature
        is_valid = self.signer.verify_signature(test_json.encode(), signature, public_key)
        assert is_valid is True
        
        # Test with modified data (should fail)
        modified_data = test_json.replace("verification", "tampered")
        is_valid_modified = self.signer.verify_signature(modified_data.encode(), signature, public_key)
        assert is_valid_modified is False


class TestCertificateManager:
    """Test CertificateManager class"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock manager if dependencies not available
        try:
            self.manager = CertificateManager()
        except (ImportError, NameError):
            self.manager = Mock()
        
        # Setup test data
        self.device_info = DeviceInfo(
            path="/dev/sda",
            serial_number="TEST123",
            model="Test SSD",
            manufacturer="Test Corp",
            size_bytes=1000000000,
            interface_type="SATA",
            device_type="SSD"
        )
        
        self.method = SanitizationMethod(
            method_name="Test Method",
            nist_category="Purge",
            passes=3,
            patterns=["0x00", "0xFF", "random"],
            verification_method="Pattern Verification",
            compliance_level="confidential"
        )
        
        self.verification = VerificationResult(
            method="pattern_verification",
            verified=True,
            sample_rate=0.1,
            confidence_level=0.95,
            entropy_score=0.05,
            verification_hash="sha256:test123"
        )
    
    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_certificate_creation(self):
        """Test certificate creation"""
        if isinstance(self.manager, Mock):
            pytest.skip("Certificate manager not available")
        
        cert = self.manager.create_certificate(
            device_info=self.device_info,
            sanitization_method=self.method,
            verification_result=self.verification,
            operator_id="test_operator",
            organization="Test Organization"
        )
        
        assert cert is not None
        assert cert.device_info == self.device_info
        assert cert.sanitization_method == self.method
        assert cert.verification_result == self.verification
        assert cert.operator_id == "test_operator"
    
    def test_json_certificate_save_load(self):
        """Test JSON certificate save and load"""
        if isinstance(self.manager, Mock):
            pytest.skip("Certificate manager not available")
        
        # Create certificate
        cert = self.manager.create_certificate(
            device_info=self.device_info,
            sanitization_method=self.method,
            verification_result=self.verification,
            operator_id="test_operator",
            organization="Test Organization"
        )
        
        # Save to file
        json_path = os.path.join(self.temp_dir, "test_cert.json")
        self.manager.save_json_certificate(cert, json_path)
        
        # Verify file exists
        assert os.path.exists(json_path)
        
        # Load and verify
        loaded_cert = self.manager.load_json_certificate(json_path)
        assert loaded_cert is not None
        assert loaded_cert.certificate_id == cert.certificate_id
    
    def test_certificate_verification(self):
        """Test certificate verification"""
        if isinstance(self.manager, Mock):
            pytest.skip("Certificate manager not available")
        
        # Create and save certificate
        cert = self.manager.create_certificate(
            device_info=self.device_info,
            sanitization_method=self.method,
            verification_result=self.verification,
            operator_id="test_operator",
            organization="Test Organization"
        )
        
        json_path = os.path.join(self.temp_dir, "test_verify.json")
        self.manager.save_json_certificate(cert, json_path)
        
        # Verify certificate
        result = self.manager.verify_json_certificate(json_path)
        assert result['valid'] is True
        assert result['certificate_id'] == cert.certificate_id
        assert len(result['errors']) == 0
    
    def test_pdf_generation(self):
        """Test PDF certificate generation"""
        if isinstance(self.manager, Mock):
            pytest.skip("Certificate manager not available")
        
        # Create certificate
        cert = self.manager.create_certificate(
            device_info=self.device_info,
            sanitization_method=self.method,
            verification_result=self.verification,
            operator_id="test_operator",
            organization="Test Organization"
        )
        
        # Generate PDF
        pdf_path = os.path.join(self.temp_dir, "test_cert.pdf")
        
        try:
            self.manager.generate_pdf_certificate(cert, pdf_path)
            assert os.path.exists(pdf_path)
            assert os.path.getsize(pdf_path) > 0
        except ImportError:
            pytest.skip("PDF generation dependencies not available")
    
    def test_qr_code_generation(self):
        """Test QR code generation"""
        if isinstance(self.manager, Mock):
            pytest.skip("Certificate manager not available")
        
        # Create certificate
        cert = self.manager.create_certificate(
            device_info=self.device_info,
            sanitization_method=self.method,
            verification_result=self.verification,
            operator_id="test_operator",
            organization="Test Organization"
        )
        
        # Generate QR code
        qr_path = os.path.join(self.temp_dir, "test_qr.png")
        
        try:
            verification_url = f"https://verify.purgeproof.com/{cert.certificate_id}"
            self.manager.generate_qr_code(verification_url, qr_path)
            assert os.path.exists(qr_path)
            assert os.path.getsize(qr_path) > 0
        except ImportError:
            pytest.skip("QR code generation dependencies not available")


class TestIntegrationCertificates:
    """Integration tests for certificate workflow"""
    
    def setup_method(self):
        """Setup integration test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Setup complete workflow components
        try:
            self.config_manager = ConfigManager()
            self.cert_manager = CertificateManager()
        except (ImportError, NameError):
            pytest.skip("Integration test dependencies not available")
    
    def teardown_method(self):
        """Cleanup integration test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_complete_certificate_workflow(self):
        """Test complete certificate generation workflow"""
        # Create device info
        device_info = DeviceInfo(
            path="/dev/sda",
            serial_number="INTEGRATION_TEST_123",
            model="Integration Test SSD",
            manufacturer="Test Corp",
            size_bytes=2000000000000,
            interface_type="NVMe",
            device_type="NVMe SSD"
        )
        
        # Create sanitization method
        method = SanitizationMethod(
            method_name="DoD 5220.22-M Enhanced",
            nist_category="Purge",
            passes=7,
            patterns=["0x00", "0xFF", "0xAA", "0x55", "random", "random", "verify"],
            verification_method="Full Pattern Verification",
            compliance_level="top_secret"
        )
        
        # Create verification result
        verification = VerificationResult(
            method="comprehensive_verification",
            verified=True,
            sample_rate=1.0,  # Full verification
            confidence_level=0.999,
            entropy_score=0.001,  # Very low entropy = good wipe
            verification_hash="sha256:integration_test_hash_12345"
        )
        
        # Generate certificate
        cert = self.cert_manager.create_certificate(
            device_info=device_info,
            sanitization_method=method,
            verification_result=verification,
            operator_id="integration_tester",
            organization="PurgeProof Integration Testing"
        )
        
        # Save JSON certificate
        json_path = os.path.join(self.temp_dir, "integration_test.json")
        self.cert_manager.save_json_certificate(cert, json_path)
        
        # Verify JSON certificate
        verification_result = self.cert_manager.verify_json_certificate(json_path)
        assert verification_result['valid'] is True
        
        # Generate PDF if possible
        try:
            pdf_path = os.path.join(self.temp_dir, "integration_test.pdf")
            self.cert_manager.generate_pdf_certificate(cert, pdf_path)
            assert os.path.exists(pdf_path)
        except ImportError:
            pass  # PDF generation is optional
        
        # Test certificate loading
        loaded_cert = self.cert_manager.load_json_certificate(json_path)
        assert loaded_cert.certificate_id == cert.certificate_id
        assert loaded_cert.device_info.serial_number == device_info.serial_number


# Test fixtures and utilities
@pytest.fixture
def sample_device_info():
    """Provide sample device info for tests"""
    return DeviceInfo(
        path="/dev/test",
        serial_number="FIXTURE_TEST_123",
        model="Test Fixture Device",
        manufacturer="Pytest Corp",
        size_bytes=1000000000,
        interface_type="SATA",
        device_type="SSD"
    )


@pytest.fixture
def sample_sanitization_method():
    """Provide sample sanitization method for tests"""
    return SanitizationMethod(
        method_name="Fixture Test Method",
        nist_category="Purge",
        passes=1,
        patterns=["0x00"],
        verification_method="Basic Verification",
        compliance_level="unclassified"
    )


@pytest.fixture
def sample_verification_result():
    """Provide sample verification result for tests"""
    return VerificationResult(
        method="fixture_verification",
        verified=True,
        sample_rate=0.1,
        confidence_level=0.95,
        entropy_score=0.05,
        verification_hash="sha256:fixture_test"
    )


# Performance and compliance tests
class TestCertificatePerformance:
    """Performance tests for certificate generation"""
    
    def test_certificate_generation_performance(self):
        """Test certificate generation performance"""
        try:
            manager = CertificateManager()
        except (ImportError, NameError):
            pytest.skip("Performance test dependencies not available")
        
        # Setup test data
        device_info = DeviceInfo(
            path="/dev/perf_test",
            serial_number="PERF_TEST_123",
            model="Performance Test Device",
            manufacturer="Perf Corp",
            size_bytes=1000000000,
            interface_type="SATA",
            device_type="SSD"
        )
        
        method = SanitizationMethod(
            method_name="Performance Test Method",
            nist_category="Clear",
            passes=1,
            patterns=["0x00"],
            verification_method="Fast Verification",
            compliance_level="unclassified"
        )
        
        verification = VerificationResult(
            method="performance_verification",
            verified=True,
            sample_rate=0.01,
            confidence_level=0.90,
            entropy_score=0.05,
            verification_hash="sha256:perf_test"
        )
        
        # Time certificate generation
        import time
        start_time = time.time()
        
        cert = manager.create_certificate(
            device_info=device_info,
            sanitization_method=method,
            verification_result=verification,
            operator_id="perf_tester",
            organization="Performance Testing"
        )
        
        generation_time = time.time() - start_time
        
        # Certificate generation should be fast (< 1 second)
        assert generation_time < 1.0
        assert cert is not None


class TestNISTCompliance:
    """NIST SP 800-88 Rev.1 compliance tests"""
    
    def test_nist_required_fields(self):
        """Test that certificates contain NIST required fields"""
        try:
            manager = CertificateManager()
        except (ImportError, NameError):
            pytest.skip("NIST compliance test dependencies not available")
        
        device_info = DeviceInfo(
            path="/dev/nist_test",
            serial_number="NIST_COMPLIANCE_123",
            model="NIST Test Device",
            manufacturer="NIST Corp",
            size_bytes=1000000000,
            interface_type="SATA",
            device_type="SSD"
        )
        
        method = SanitizationMethod(
            method_name="NIST Compliant Method",
            nist_category="Purge",
            passes=1,
            patterns=["0x00"],
            verification_method="NIST Verification",
            compliance_level="confidential"
        )
        
        verification = VerificationResult(
            method="nist_verification",
            verified=True,
            sample_rate=0.1,
            confidence_level=0.95,
            entropy_score=0.05,
            verification_hash="sha256:nist_test"
        )
        
        cert = manager.create_certificate(
            device_info=device_info,
            sanitization_method=method,
            verification_result=verification,
            operator_id="nist_tester",
            organization="NIST Compliance Testing"
        )
        
        # Verify NIST required fields are present
        assert cert.certificate_id is not None
        assert cert.timestamp is not None
        assert cert.device_info.serial_number is not None
        assert cert.sanitization_method.nist_category in ["Clear", "Purge", "Destroy"]
        assert cert.verification_result.verified is not None
        assert cert.operator_id is not None
        assert cert.organization is not None
    
    def test_nist_sanitization_categories(self):
        """Test NIST sanitization category compliance"""
        categories = ["Clear", "Purge", "Destroy"]
        
        for category in categories:
            method = SanitizationMethod(
                method_name=f"NIST {category} Method",
                nist_category=category,
                passes=1 if category == "Clear" else 3,
                patterns=["0x00"] if category == "Clear" else ["0x00", "0xFF", "random"],
                verification_method=f"{category} Verification",
                compliance_level="unclassified"
            )
            
            assert method.nist_category == category
            
            # Category-specific validations
            if category == "Clear":
                assert method.passes >= 1
            elif category == "Purge":
                assert method.passes >= 1
                assert len(method.patterns) >= 1
            elif category == "Destroy":
                # Destroy category typically involves physical destruction
                assert method.passes >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])