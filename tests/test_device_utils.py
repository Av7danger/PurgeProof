"""
Test suite for device detection and utilities.

Tests the core.device_utils module functionality including:
- Device detection and enumeration
- Device information gathering
- Safety checks and validation
- Cross-platform compatibility
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
from pathlib import Path

# Add purgeproof package to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'purgeproof'))

try:
    from core.device_utils import DeviceDetector, DeviceInfo
except ImportError as e:
    print(f"Warning: Could not import core modules: {e}")
    # Create mock classes for testing structure
    class DeviceDetector:
        pass
    class DeviceInfo:
        pass


class TestDeviceInfo(unittest.TestCase):
    """Test the DeviceInfo data class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.device_info = DeviceInfo(
            path="/dev/sdb",
            model="Samsung SSD 980",
            serial="S6B2NS0R123456",
            size_bytes=500000000000,  # 500GB
            device_type="ssd",
            platform="linux",
            removable=False,
            mounted=False,
            mount_points=[],
            is_encrypted=True,
            encryption_type="LUKS",
            capabilities={
                "secure_erase": True,
                "crypto_erase": True,
                "nvme_sanitize": True
            }
        )
    
    def test_device_info_creation(self):
        """Test DeviceInfo object creation."""
        self.assertEqual(self.device_info.path, "/dev/sdb")
        self.assertEqual(self.device_info.model, "Samsung SSD 980")
        self.assertEqual(self.device_info.serial, "S6B2NS0R123456")
        self.assertEqual(self.device_info.size_bytes, 500000000000)
        self.assertEqual(self.device_info.device_type, "ssd")
        self.assertTrue(self.device_info.is_encrypted)
        self.assertEqual(self.device_info.encryption_type, "LUKS")
    
    def test_device_capabilities(self):
        """Test device capabilities."""
        self.assertTrue(self.device_info.capabilities["secure_erase"])
        self.assertTrue(self.device_info.capabilities["crypto_erase"])
        self.assertTrue(self.device_info.capabilities["nvme_sanitize"])
    
    def test_size_calculations(self):
        """Test size calculations and conversions."""
        # Test GB conversion
        size_gb = self.device_info.size_bytes / (1024**3)
        self.assertAlmostEqual(size_gb, 465.66, places=1)  # 500GB in GiB
        
        # Test TB conversion for large drives
        large_device = DeviceInfo(
            path="/dev/sdc",
            model="Large Drive",
            serial="LARGE123",
            size_bytes=2000000000000,  # 2TB
            device_type="hdd",
            platform="linux"
        )
        size_tb = large_device.size_bytes / (1024**4)
        self.assertAlmostEqual(size_tb, 1.82, places=1)


class TestDeviceDetector(unittest.TestCase):
    """Test the DeviceDetector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = DeviceDetector()
    
    @patch('platform.system')
    def test_platform_detection(self, mock_system):
        """Test platform detection."""
        # Test Windows detection
        mock_system.return_value = 'Windows'
        detector = DeviceDetector()
        self.assertEqual(detector.platform, 'windows')
        
        # Test Linux detection
        mock_system.return_value = 'Linux'
        detector = DeviceDetector()
        self.assertEqual(detector.platform, 'linux')
        
        # Test macOS detection
        mock_system.return_value = 'Darwin'
        detector = DeviceDetector()
        self.assertEqual(detector.platform, 'darwin')
    
    @patch('core.device_utils.DeviceDetector._detect_windows_devices')
    @patch('platform.system')
    def test_windows_device_detection(self, mock_system, mock_detect):
        """Test Windows device detection."""
        mock_system.return_value = 'Windows'
        mock_device = DeviceInfo(
            path=r"\\.\PHYSICALDRIVE0",
            model="Test Drive",
            serial="TEST123",
            size_bytes=1000000000,
            device_type="hdd",
            platform="windows"
        )
        mock_detect.return_value = [mock_device]
        
        detector = DeviceDetector()
        devices = detector.list_storage_devices()
        
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].path, r"\\.\PHYSICALDRIVE0")
        self.assertEqual(devices[0].platform, "windows")
        mock_detect.assert_called_once()
    
    @patch('core.device_utils.DeviceDetector._detect_linux_devices')
    @patch('platform.system')
    def test_linux_device_detection(self, mock_system, mock_detect):
        """Test Linux device detection."""
        mock_system.return_value = 'Linux'
        mock_device = DeviceInfo(
            path="/dev/sdb",
            model="Test Drive",
            serial="TEST123",
            size_bytes=1000000000,
            device_type="ssd",
            platform="linux"
        )
        mock_detect.return_value = [mock_device]
        
        detector = DeviceDetector()
        devices = detector.list_storage_devices()
        
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].path, "/dev/sdb")
        self.assertEqual(devices[0].platform, "linux")
        mock_detect.assert_called_once()
    
    def test_safety_check_system_drive(self):
        """Test safety check for system drives."""
        # Create system drive device
        system_device = DeviceInfo(
            path="/dev/sda",  # Typically system drive on Linux
            model="System SSD",
            serial="SYS123",
            size_bytes=256000000000,
            device_type="ssd",
            platform="linux",
            mounted=True,
            mount_points=["/", "/boot"]
        )
        
        safe, reason = self.detector.is_device_safe_to_wipe(system_device)
        self.assertFalse(safe)
        self.assertIn("system", reason.lower())
    
    def test_safety_check_mounted_device(self):
        """Test safety check for mounted devices."""
        mounted_device = DeviceInfo(
            path="/dev/sdb",
            model="Data Drive",
            serial="DATA123",
            size_bytes=1000000000000,
            device_type="hdd",
            platform="linux",
            mounted=True,
            mount_points=["/home", "/data"]
        )
        
        safe, reason = self.detector.is_device_safe_to_wipe(mounted_device)
        self.assertFalse(safe)
        self.assertIn("mounted", reason.lower())
    
    def test_safety_check_safe_device(self):
        """Test safety check for safe devices."""
        safe_device = DeviceInfo(
            path="/dev/sdc",
            model="External Drive",
            serial="EXT123",
            size_bytes=500000000000,
            device_type="hdd",
            platform="linux",
            removable=True,
            mounted=False,
            mount_points=[]
        )
        
        safe, reason = self.detector.is_device_safe_to_wipe(safe_device)
        self.assertTrue(safe)
        self.assertIn("safe", reason.lower())
    
    @patch('subprocess.run')
    def test_linux_lsblk_parsing(self, mock_run):
        """Test Linux lsblk output parsing."""
        # Mock lsblk output
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = '''
{
   "blockdevices": [
      {
         "name": "sda",
         "size": "238.5G",
         "type": "disk",
         "mountpoint": null,
         "children": [
            {
               "name": "sda1",
               "size": "238.5G",
               "type": "part",
               "mountpoint": "/"
            }
         ]
      },
      {
         "name": "sdb",
         "size": "931.5G",
         "type": "disk",
         "mountpoint": null
      }
   ]
}
'''
        mock_run.return_value = mock_result
        
        detector = DeviceDetector()
        detector.platform = 'linux'
        
        # This would test the actual parsing logic
        # The implementation would need to be adjusted to make this testable
        pass
    
    def test_device_type_detection(self):
        """Test device type detection logic."""
        # Test SSD detection
        ssd_device = DeviceInfo(
            path="/dev/nvme0n1",
            model="Samsung SSD 980",
            serial="SSD123",
            size_bytes=500000000000,
            device_type="unknown",
            platform="linux"
        )
        
        # The detector should identify this as an SSD based on path and model
        detected_type = self.detector._detect_device_type(ssd_device.path, ssd_device.model)
        # This would require implementing the _detect_device_type method
        
    def test_encryption_detection(self):
        """Test encryption detection."""
        # Test LUKS detection
        encrypted_device = DeviceInfo(
            path="/dev/sdb",
            model="Encrypted Drive",
            serial="ENC123",
            size_bytes=1000000000000,
            device_type="ssd",
            platform="linux"
        )
        
        # Mock LUKS detection
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = "LUKS"
            mock_run.return_value = mock_result
            
            is_encrypted, enc_type = self.detector._detect_encryption(encrypted_device.path)
            # This would require implementing the _detect_encryption method


class TestDeviceCapabilities(unittest.TestCase):
    """Test device capability detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = DeviceDetector()
    
    def test_nvme_capability_detection(self):
        """Test NVMe capability detection."""
        nvme_device = DeviceInfo(
            path="/dev/nvme0n1",
            model="Samsung SSD 980 PRO",
            serial="NVME123",
            size_bytes=1000000000000,
            device_type="ssd",
            platform="linux"
        )
        
        # Mock nvme command availability
        with patch('shutil.which') as mock_which:
            mock_which.return_value = "/usr/sbin/nvme"
            
            capabilities = self.detector._detect_capabilities(nvme_device)
            # Should detect NVMe sanitize capability
            # This would require implementing the _detect_capabilities method
    
    def test_secure_erase_capability(self):
        """Test secure erase capability detection."""
        sata_device = DeviceInfo(
            path="/dev/sdb",
            model="Samsung SSD 860 EVO",
            serial="SATA123",
            size_bytes=500000000000,
            device_type="ssd",
            platform="linux"
        )
        
        # Mock hdparm output
        with patch('subprocess.run') as mock_run:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = "supported: enhanced erase"
            mock_run.return_value = mock_result
            
            capabilities = self.detector._detect_capabilities(sata_device)
            # Should detect secure erase capability


class TestCrossPlatform(unittest.TestCase):
    """Test cross-platform functionality."""
    
    @patch('platform.system')
    def test_fallback_detection(self, mock_system):
        """Test fallback detection for unknown platforms."""
        mock_system.return_value = 'Unknown'
        
        detector = DeviceDetector()
        devices = detector.list_storage_devices()
        
        # Should return empty list or use generic detection
        self.assertIsInstance(devices, list)
    
    def test_permission_handling(self):
        """Test handling of permission errors."""
        detector = DeviceDetector()
        
        # Mock permission denied error
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = PermissionError("Access denied")
            
            # Should handle gracefully and not crash
            devices = detector.list_storage_devices()
            self.assertIsInstance(devices, list)


if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
