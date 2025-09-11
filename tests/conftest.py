"""
PurgeProof Test Suite

Comprehensive testing for the PurgeProof data sanitization tool.
Includes unit tests, integration tests, and security validation.

Test Categories:
- Device Detection Tests
- Sanitization Engine Tests  
- Verification Tests
- Certificate Generation Tests
- GUI Tests
- CLI Tests
- Security Tests

Usage:
    pytest tests/
    pytest tests/test_device_utils.py -v
    pytest tests/ --cov=wipeit --cov-report=html
"""

import os
import sys
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add wipeit package to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'wipeit'))

# Test configuration
TEST_DATA_DIR = Path(__file__).parent / "data"
TEMP_DIR = None


def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "security: marks tests as security validation"
    )
    config.addinivalue_line(
        "markers", "gui: marks tests as GUI tests (require display)"
    )
    config.addinivalue_line(
        "markers", "hardware: marks tests that require actual hardware"
    )


@pytest.fixture(scope="session")
def temp_dir():
    """Create a temporary directory for test files."""
    global TEMP_DIR
    TEMP_DIR = tempfile.mkdtemp(prefix="purgeproof_test_")
    yield Path(TEMP_DIR)
    shutil.rmtree(TEMP_DIR, ignore_errors=True)


@pytest.fixture
def mock_device():
    """Create a mock device for testing."""
    from core.device_utils import DeviceInfo
    
    return DeviceInfo(
        path="/dev/test",
        model="Test Device",
        serial="TEST123456",
        size_bytes=1000000000,  # 1GB
        device_type="ssd",
        platform="linux",
        removable=True,
        mounted=False,
        mount_points=[],
        is_encrypted=False,
        encryption_type=None,
        capabilities={
            "secure_erase": True,
            "crypto_erase": False,
            "nvme_sanitize": False
        }
    )


@pytest.fixture
def test_file(temp_dir):
    """Create a test file for sanitization testing."""
    test_file_path = temp_dir / "test_data.bin"
    
    # Create test file with known pattern
    with open(test_file_path, "wb") as f:
        # Write 1MB of test data
        test_pattern = b"TESTDATA" * 128  # 1KB pattern
        for _ in range(1024):  # 1MB total
            f.write(test_pattern)
    
    return test_file_path


@pytest.fixture
def mock_wipe_result():
    """Create a mock wipe result for testing."""
    from core.wipe_engine import WipeResult, SanitizationMethod, WipeStatus
    
    return WipeResult(
        device_path="/dev/test",
        method_used=SanitizationMethod.OVERWRITE_SINGLE,
        result=WipeStatus.SUCCESS,
        start_time="2024-01-01T00:00:00Z",
        end_time="2024-01-01T00:01:00Z",
        duration_seconds=60.0,
        bytes_processed=1000000000,
        verification_passed=True,
        error_message=None,
        metadata={}
    )


class MockProgressCallback:
    """Mock progress callback for testing."""
    
    def __init__(self):
        self.calls = []
    
    def __call__(self, progress):
        self.calls.append(progress)


# Common test utilities
def create_test_device_file(path: Path, size_mb: int = 10):
    """Create a test device file for sanitization testing."""
    with open(path, "wb") as f:
        # Write test pattern
        pattern = b"ABCDEFGH" * 128  # 1KB pattern
        for _ in range(size_mb * 1024):  # size_mb MB
            f.write(pattern)
    return path


def verify_sanitization(file_path: Path, expected_pattern=None):
    """Verify that a file has been properly sanitized."""
    with open(file_path, "rb") as f:
        data = f.read(8192)  # Read first 8KB
        
        if expected_pattern:
            # Check for specific pattern
            return data.startswith(expected_pattern)
        else:
            # Check that original pattern is gone
            test_pattern = b"ABCDEFGH"
            return test_pattern not in data


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    import math
    from collections import Counter
    
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = Counter(data)
    data_len = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        if count > 0:
            frequency = count / data_len
            entropy -= frequency * math.log2(frequency)
    
    return entropy
