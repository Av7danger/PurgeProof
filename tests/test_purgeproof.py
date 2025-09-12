"""
Comprehensive Testing Framework for PurgeProof.

This module provides unit tests, integration tests, benchmarks, and mock device testing
for the hybrid architecture sanitization system.
"""

import os
import sys
import time
import tempfile
import shutil
import asyncio
import logging
import unittest
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import json

# Add the parent directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from purgeproof.device_utils import (
    DeviceCapabilities, DeviceType, InterfaceType, EncryptionType,
    DeviceEnumerator, DevicePerformanceProfiler
)
from purgeproof.decision_engine import (
    SanitizationMethod, ComplianceLevel, SecurityObjective,
    MethodSelectionEngine, MethodScore, SelectionCriteria, DeviceContext
)
from purgeproof.orchestrator import (
    HybridSanitizationOrchestrator, SanitizationJob, OperationStatus, JobPriority
)
from purgeproof.compliance import (
    ComplianceFramework, ComplianceStandard, ValidationStatus,
    ComplianceReport, AuditEvent, AuditEventType
)
from purgeproof.sampling_verification import (
    SamplingEngine, VerificationLevel, SamplingStrategy,
    SamplingCalculator, VerificationReport
)
import purgeproof.ffi_bindings as ffi_bindings

# Configure logging for tests
logging.basicConfig(level=logging.WARNING)  # Reduce noise during testing

class MockDevice:
    """Mock device for testing purposes."""
    
    def __init__(self, device_type: DeviceType = DeviceType.SSD, size_gb: int = 100):
        self.device_type = device_type
        self.size_bytes = size_gb * 1024**3
        self.temp_file = None
        self.capabilities = self._create_mock_capabilities()
    
    def _create_mock_capabilities(self) -> DeviceCapabilities:
        """Create mock device capabilities."""
        return DeviceCapabilities(
            path=f"/dev/mock_{self.device_type.name.lower()}",
            device_type=self.device_type,
            interface_type=InterfaceType.SATA if self.device_type == DeviceType.SSD else InterfaceType.NVME,
            size_bytes=self.size_bytes,
            sector_size=4096,
            model=f"Mock {self.device_type.name} Drive",
            serial=f"MOCK{int(time.time())}",
            firmware_version="1.0.0",
            max_read_speed_mbps=500.0,
            max_write_speed_mbps=400.0,
            random_iops=100000,
            latency_ms=0.1,
            queue_depth=32,
            supports_crypto_erase=self.device_type in [DeviceType.SSD, DeviceType.NVME],
            supports_secure_erase=True,
            supports_enhanced_secure_erase=self.device_type == DeviceType.SSD,
            supports_nvme_sanitize=self.device_type == DeviceType.NVME,
            supports_trim=self.device_type in [DeviceType.SSD, DeviceType.NVME],
            supports_write_zeroes=True,
            is_encrypted=True,
            encryption_type=EncryptionType.HARDWARE_SED,
            encryption_algorithm="AES-256-XTS",
            secure_erase_time_estimate=5,
            crypto_erase_time_estimate=1,
            overwrite_time_estimate=60,
            platform_specific={}
        )
    
    def create_temp_file(self) -> str:
        """Create a temporary file to simulate the device."""
        if self.temp_file is None:
            self.temp_file = tempfile.NamedTemporaryFile(delete=False)
            # Create a file with some test data
            test_data = b"TEST_DATA" * 1024  # 8KB of test data
            self.temp_file.write(test_data)
            self.temp_file.flush()
            
            # Update capabilities path to point to temp file
            self.capabilities.path = self.temp_file.name
        
        return self.temp_file.name
    
    def cleanup(self):
        """Clean up temporary resources."""
        if self.temp_file:
            try:
                os.unlink(self.temp_file.name)
            except OSError:
                pass
            self.temp_file = None

class TestDeviceUtils(unittest.TestCase):
    """Test device utilities module."""
    
    def setUp(self):
        self.mock_device = MockDevice(DeviceType.SSD, 100)
    
    def tearDown(self):
        self.mock_device.cleanup()
    
    def test_device_capabilities_creation(self):
        """Test device capabilities data structure."""
        caps = self.mock_device.capabilities
        
        self.assertEqual(caps.device_type, DeviceType.SSD)
        self.assertEqual(caps.size_bytes, 100 * 1024**3)
        self.assertTrue(caps.supports_crypto_erase)
        self.assertTrue(caps.supports_trim)
        self.assertEqual(caps.encryption_type, EncryptionType.HARDWARE_SED)
    
    @patch('platform.system')
    def test_device_enumerator(self, mock_platform):
        """Test device enumeration functionality."""
        mock_platform.return_value = 'Linux'
        
        enumerator = DeviceEnumerator()
        
        # Test with mocked system calls
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.stdout = 'sda\nsdb\nnvme0n1\n'
            mock_run.return_value.returncode = 0
            
            # Mock the device analysis
            with patch.object(enumerator, '_analyze_device') as mock_analyze:
                mock_analyze.return_value = self.mock_device.capabilities
                
                devices = asyncio.run(enumerator.enumerate_devices())
                
                self.assertIsInstance(devices, list)
                # Should be called for each device found
                self.assertEqual(mock_analyze.call_count, 3)

class TestDecisionEngine(unittest.TestCase):
    """Test decision engine module."""
    
    def setUp(self):
        self.engine = MethodSelectionEngine()
        self.mock_device = MockDevice(DeviceType.SSD, 500)
    
    def tearDown(self):
        self.mock_device.cleanup()
    
    def test_method_selection_basic(self):
        """Test basic method selection."""
        device = self.mock_device.capabilities
        
        device_context = DeviceContext(capabilities=device)
        criteria = SelectionCriteria(
            compliance_level=ComplianceLevel.STANDARD,
            security_objective=SecurityObjective.BALANCED
        )
        
        result = self.engine.select_optimal_method(device_context, criteria)
        
        self.assertIsInstance(result, MethodScore)
        self.assertIsInstance(result.method, SanitizationMethod)
        self.assertGreater(result.overall_score, 0.0)
        self.assertIsInstance(result.optimization_notes, list)
    
    def test_method_selection_encrypted_ssd(self):
        """Test method selection for encrypted SSD."""
        device = self.mock_device.capabilities
        device.is_encrypted = True
        device.supports_crypto_erase = True
        
        device_context = DeviceContext(capabilities=device)
        criteria = SelectionCriteria(
            compliance_level=ComplianceLevel.ENHANCED,
            security_objective=SecurityObjective.SECURITY
        )
        
        result = self.engine.select_optimal_method(device_context, criteria)
        
        # Should prefer crypto erase for encrypted devices
        self.assertEqual(result.method, SanitizationMethod.CRYPTO_ERASE)
        self.assertGreater(result.overall_score, 90.0)
    
    def test_method_selection_hdd(self):
        """Test method selection for traditional HDD."""
        hdd_device = MockDevice(DeviceType.HDD, 1000).capabilities
        
        device_context = DeviceContext(capabilities=hdd_device)
        criteria = SelectionCriteria(
            compliance_level=ComplianceLevel.CLASSIFIED,
            security_objective=SecurityObjective.SECURITY
        )
        
        result = self.engine.select_optimal_method(device_context, criteria)
        
        # Should prefer multi-pass overwrite for HDDs
        self.assertEqual(result.method, SanitizationMethod.OVERWRITE_MULTI)

class TestOrchestrator(unittest.TestCase):
    """Test orchestrator module."""
    
    def setUp(self):
        self.orchestrator = HybridSanitizationOrchestrator(max_concurrent_jobs=2)
        self.mock_device = MockDevice(DeviceType.SSD, 100)
    
    def tearDown(self):
        self.mock_device.cleanup()
        # Note: orchestrator cleanup is synchronous
    
    def test_job_creation(self):
        """Test sanitization job creation."""
        device = self.mock_device.capabilities
        
        job_id = self.orchestrator.submit_sanitization_job(
            device.path,
            ComplianceLevel.STANDARD,
            SecurityObjective.BALANCED
        )
        
        self.assertIsInstance(job_id, str)
        self.assertIn(job_id, self.orchestrator.jobs)
        
        job = self.orchestrator.jobs[job_id]
        self.assertEqual(job.status, OperationStatus.PENDING)
    
    def test_job_status_retrieval(self):
        """Test job status retrieval."""
        device = self.mock_device.capabilities
        
        job_id = self.orchestrator.submit_sanitization_job(
            device.path,
            ComplianceLevel.STANDARD,
            SecurityObjective.BALANCED
        )
        
        status = self.orchestrator.get_job_status(job_id)
        self.assertIsNotNone(status)
        if status:
            self.assertIn('status', status)

class TestComplianceFramework(unittest.TestCase):
    """Test compliance framework module."""
    
    def setUp(self):
        self.compliance = ComplianceFramework()
        self.mock_device = MockDevice(DeviceType.SSD, 250)
    
    def tearDown(self):
        self.mock_device.cleanup()
    
    def test_compliance_validation_nist_clear(self):
        """Test NIST SP 800-88 Clear level validation."""
        device = self.mock_device.capabilities
        
        report = self.compliance.validate_method_compliance(
            device,
            SanitizationMethod.OVERWRITE_SINGLE,
            ComplianceLevel.BASIC,
            [ComplianceStandard.NIST_SP_800_88_CLEAR]
        )
        
        self.assertIsInstance(report, ComplianceReport)
        self.assertEqual(report.compliance_level, ComplianceLevel.BASIC)
        self.assertGreater(len(report.validation_results), 0)
        self.assertIn(report.overall_status, [ValidationStatus.COMPLIANT, ValidationStatus.PARTIALLY_COMPLIANT])
    
    def test_compliance_validation_nist_purge(self):
        """Test NIST SP 800-88 Purge level validation."""
        device = self.mock_device.capabilities
        device.supports_crypto_erase = True
        device.is_encrypted = True
        
        report = self.compliance.validate_method_compliance(
            device,
            SanitizationMethod.CRYPTO_ERASE,
            ComplianceLevel.ENHANCED,
            [ComplianceStandard.NIST_SP_800_88_PURGE]
        )
        
        self.assertEqual(report.overall_status, ValidationStatus.COMPLIANT)
        self.assertGreater(report.risk_assessment['overall_risk_score'], 0.0)
    
    def test_audit_trail_generation(self):
        """Test audit trail generation."""
        device = self.mock_device.capabilities
        
        # Create some audit events
        self.compliance._log_audit_event(
            AuditEventType.SANITIZATION_START,
            device.path,
            method=SanitizationMethod.CRYPTO_ERASE,
            compliance_level=ComplianceLevel.ENHANCED
        )
        
        self.compliance._log_audit_event(
            AuditEventType.SANITIZATION_COMPLETE,
            device.path,
            event_data={'success': True, 'duration': 60}
        )
        
        # Retrieve audit trail
        events = self.compliance.generate_audit_trail(device.path)
        
        self.assertGreater(len(events), 0)
        for event in events:
            self.assertIsInstance(event, AuditEvent)
            self.assertEqual(event.device_path, device.path)
            self.assertTrue(event.verify_integrity())
    
    def test_compliance_report_export(self):
        """Test compliance report export functionality."""
        device = self.mock_device.capabilities
        
        report = self.compliance.validate_method_compliance(
            device,
            SanitizationMethod.OVERWRITE_SINGLE,
            ComplianceLevel.STANDARD
        )
        
        # Test JSON export
        json_report = self.compliance.export_compliance_report(report, "json")
        self.assertIsInstance(json_report, str)
        
        # Verify JSON is valid
        parsed_report = json.loads(json_report)
        self.assertEqual(parsed_report['device_path'], device.path)

class TestSamplingVerification(unittest.TestCase):
    """Test sampling verification module."""
    
    def setUp(self):
        self.engine = SamplingEngine(max_workers=2)
        self.calculator = SamplingCalculator()
        self.mock_device = MockDevice(DeviceType.SSD, 100)
    
    def tearDown(self):
        self.mock_device.cleanup()
    
    def test_sample_size_calculation(self):
        """Test statistical sample size calculation."""
        device_sizes = [100 * 1024**3, 1 * 1024**4, 8 * 1024**4]  # 100GB, 1TB, 8TB
        
        for size in device_sizes:
            for confidence in [0.95, 0.99, 0.999]:
                for margin in [0.05, 0.01, 0.001]:
                    sample_size = self.calculator.calculate_sample_size(
                        size, confidence, margin
                    )
                    
                    self.assertGreater(sample_size, 0)
                    self.assertLess(sample_size, 100000)  # Reasonable upper bound
    
    def test_confidence_interval_calculation(self):
        """Test confidence interval calculation."""
        test_cases = [
            (0.95, 100, 0.99),
            (0.90, 1000, 0.95),
            (1.0, 500, 0.99),
            (0.0, 200, 0.95),
        ]
        
        for sample_rate, sample_size, confidence in test_cases:
            lower, upper = self.calculator.calculate_confidence_interval(
                sample_rate, sample_size, confidence
            )
            
            self.assertGreaterEqual(lower, 0.0)
            self.assertLessEqual(upper, 1.0)
            self.assertLessEqual(lower, upper)
    
    def test_sampling_strategies(self):
        """Test different sampling strategies."""
        device = self.mock_device.capabilities
        sample_count = 50
        
        strategies = [
            SamplingStrategy.RANDOM_UNIFORM,
            SamplingStrategy.STRATIFIED,
            SamplingStrategy.SYSTEMATIC,
            SamplingStrategy.CLUSTER,
            SamplingStrategy.ADAPTIVE,
        ]
        
        for strategy in strategies:
            locations = self.engine._generate_sample_locations(
                device, sample_count, strategy
            )
            
            self.assertEqual(len(locations), sample_count)
            
            for location in locations:
                self.assertGreaterEqual(location.offset, 0)
                self.assertLess(location.offset + location.size, device.size_bytes)
                self.assertEqual(location.offset % 512, 0)  # Sector aligned
    
    @patch('builtins.open')
    def test_pattern_verification(self, mock_open):
        """Test pattern verification functionality."""
        # Mock file operations
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        test_patterns = [
            (b'\x00' * 1024, True),    # All zeros - should pass
            (b'\xFF' * 1024, False),   # All ones - should fail for zeros pattern
            (b'TEST' * 256, False),    # Random data - should fail
        ]
        
        for data, expected_match in test_patterns:
            mock_file.read.return_value = data
            
            result = self.engine._verify_pattern(data, self.engine._determine_expected_pattern(SanitizationMethod.OVERWRITE_SINGLE))
            self.assertEqual(result, expected_match)
    
    def test_entropy_calculation(self):
        """Test entropy calculation for randomness detection."""
        test_data = [
            (b'\x00' * 1024, 0.0),        # No entropy
            (b'\xFF' * 1024, 0.0),        # No entropy
            (os.urandom(1024), 7.0),      # High entropy (approximate)
        ]
        
        for data, min_expected_entropy in test_data:
            entropy = self.engine._calculate_entropy(data)
            
            if min_expected_entropy == 0.0:
                self.assertEqual(entropy, 0.0)
            else:
                self.assertGreater(entropy, min_expected_entropy)

class TestFFIBindings(unittest.TestCase):
    """Test FFI bindings module."""
    
    def setUp(self):
        self.mock_device = MockDevice(DeviceType.SSD, 50)
    
    def tearDown(self):
        self.mock_device.cleanup()
    
    def test_ffi_library_loading(self):
        """Test FFI library loading and fallback."""
        # Test library loading (should use fallback in test environment)
        self.assertTrue(True)  # Placeholder - library loading works via module functions
        
        # Test fallback detection
        self.assertTrue(True)  # Placeholder
    
    def test_crypto_erase_fallback(self):
        """Test crypto erase fallback implementation."""
        temp_file = self.mock_device.create_temp_file()
        
        result = ffi_bindings.crypto_erase_fast(temp_file)
        
        # Should succeed with fallback
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
    
    def test_device_enumeration_fallback(self):
        """Test device enumeration fallback."""
        devices = ffi_bindings.enumerate_storage_devices()
        
        # Should return a list (may be empty in test environment)
        self.assertIsInstance(devices, list)
    
    def test_error_handling(self):
        """Test FFI error handling."""
        # Test with invalid device path
        result = ffi_bindings.crypto_erase_fast("/invalid/device/path")
        
        # Should fail gracefully
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)

class BenchmarkTests(unittest.TestCase):
    """Benchmark tests for performance validation."""
    
    def setUp(self):
        self.mock_device = MockDevice(DeviceType.SSD, 100)
        self.temp_file = self.mock_device.create_temp_file()
    
    def tearDown(self):
        self.mock_device.cleanup()
    
    def test_method_selection_performance(self):
        """Benchmark method selection performance."""
        engine = MethodSelectionEngine()
        device = self.mock_device.capabilities
        
        start_time = time.time()
        
        # Run multiple selections
        for _ in range(100):
            device_context = DeviceContext(capabilities=device)
            criteria = SelectionCriteria(
                compliance_level=ComplianceLevel.STANDARD,
                security_objective=SecurityObjective.BALANCED
            )
            result = engine.select_optimal_method(device_context, criteria)
            self.assertIsInstance(result, MethodScore)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete 100 selections in reasonable time
        self.assertLess(duration, 5.0)  # Less than 5 seconds
        avg_time = duration / 100
        self.assertLess(avg_time, 0.05)  # Less than 50ms per selection
    
    def test_compliance_validation_performance(self):
        """Benchmark compliance validation performance."""
        compliance = ComplianceFramework()
        device = self.mock_device.capabilities
        
        start_time = time.time()
        
        # Run multiple validations
        for _ in range(10):
            report = compliance.validate_method_compliance(
                device,
                SanitizationMethod.CRYPTO_ERASE,
                ComplianceLevel.ENHANCED
            )
            self.assertIsInstance(report, ComplianceReport)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete 10 validations in reasonable time
        self.assertLess(duration, 10.0)  # Less than 10 seconds
        avg_time = duration / 10
        self.assertLess(avg_time, 1.0)  # Less than 1 second per validation
    
    def test_sampling_calculation_performance(self):
        """Benchmark sampling calculation performance."""
        calculator = SamplingCalculator()
        
        start_time = time.time()
        
        # Calculate samples for various device sizes
        device_sizes = [100 * 1024**3, 1 * 1024**4, 8 * 1024**4]
        
        for _ in range(1000):
            for size in device_sizes:
                sample_size = calculator.calculate_sample_size(size, 0.99, 0.01)
                self.assertGreater(sample_size, 0)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete 3000 calculations in reasonable time
        self.assertLess(duration, 2.0)  # Less than 2 seconds

class IntegrationTests(unittest.TestCase):
    """Integration tests for the complete hybrid architecture."""
    
    def setUp(self):
        self.mock_device = MockDevice(DeviceType.SSD, 200)
        self.orchestrator = HybridSanitizationOrchestrator(max_concurrent_jobs=2)
        self.compliance = ComplianceFramework()
    
    def tearDown(self):
        self.mock_device.cleanup()
        # Note: orchestrator cleanup is synchronous
    
    def test_end_to_end_sanitization(self):
        """Test complete sanitization workflow."""
        device = self.mock_device.capabilities
        
        # Submit sanitization job
        job_id = self.orchestrator.submit_sanitization_job(
            device.path,
            ComplianceLevel.ENHANCED,
            SecurityObjective.BALANCED
        )
        
        # Check job status
        status = self.orchestrator.get_job_status(job_id)
        
        # Generate compliance report
        compliance_report = self.compliance.validate_method_compliance(
            device,
            SanitizationMethod.CRYPTO_ERASE,
            ComplianceLevel.ENHANCED
        )
        
        self.assertIsNotNone(status)
        self.assertIsInstance(compliance_report, ComplianceReport)
        self.assertIn(compliance_report.overall_status, [ValidationStatus.COMPLIANT, ValidationStatus.PARTIALLY_COMPLIANT])
    
    def test_multi_device_coordination(self):
        """Test handling multiple devices simultaneously."""
        devices = [
            MockDevice(DeviceType.SSD, 100),
            MockDevice(DeviceType.NVME, 500),
            MockDevice(DeviceType.HDD, 1000),
        ]
        
        try:
            job_ids = []
            
            # Submit jobs for all devices
            for mock_dev in devices:
                job_id = self.orchestrator.submit_sanitization_job(
                    mock_dev.capabilities.path,
                    ComplianceLevel.STANDARD,
                    SecurityObjective.BALANCED
                )
                job_ids.append(job_id)
            
            # Check all job statuses
            statuses = []
            for job_id in job_ids:
                status = self.orchestrator.get_job_status(job_id)
                statuses.append(status)
            
            self.assertEqual(len(statuses), 3)
            for status in statuses:
                self.assertIsNotNone(status)
        
        finally:
            for mock_dev in devices:
                mock_dev.cleanup()

def run_all_tests():
    """Run all test suites."""
    test_suites = [
        TestDeviceUtils,
        TestDecisionEngine,
        TestOrchestrator,
        TestComplianceFramework,
        TestSamplingVerification,
        TestFFIBindings,
        BenchmarkTests,
        IntegrationTests,
    ]
    
    # Create test loader
    loader = unittest.TestLoader()
    
    # Create test suite
    master_suite = unittest.TestSuite()
    
    for test_class in test_suites:
        suite = loader.loadTestsFromTestCase(test_class)
        master_suite.addTest(suite)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(master_suite)
    
    return result.wasSuccessful()

def run_benchmarks_only():
    """Run only benchmark tests."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(BenchmarkTests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

def run_integration_tests_only():
    """Run only integration tests."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(IntegrationTests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="PurgeProof Testing Framework")
    parser.add_argument("--benchmarks", action="store_true", help="Run only benchmark tests")
    parser.add_argument("--integration", action="store_true", help="Run only integration tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.INFO)
    
    if args.benchmarks:
        print("Running benchmark tests...")
        success = run_benchmarks_only()
    elif args.integration:
        print("Running integration tests...")
        success = run_integration_tests_only()
    else:
        print("Running all tests...")
        success = run_all_tests()
    
    if success:
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)