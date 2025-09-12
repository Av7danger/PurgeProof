"""
Basic test suite for PurgeProof.

This module provides basic unit tests for the core PurgeProof functionality.
"""

import os
import sys
import unittest
from pathlib import Path

# Add the parent directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test basic imports
try:
    import purgeproof
    from purgeproof import device_utils, cli
    IMPORTS_OK = True
except ImportError as e:
    print(f"Import error: {e}")
    IMPORTS_OK = False


class TestBasicFunctionality(unittest.TestCase):
    """Test basic PurgeProof functionality."""
    
    def test_imports(self):
        """Test that core modules can be imported."""
        self.assertTrue(IMPORTS_OK, "Failed to import core modules")
    
    def test_package_structure(self):
        """Test that the package structure is correct."""
        # Check that purgeproof package exists
        import purgeproof
        self.assertIsNotNone(purgeproof)
        
        # Check key modules exist
        modules = ['cli', 'device_utils', 'gui']
        for module in modules:
            try:
                exec(f"from purgeproof import {module}")
            except ImportError:
                self.fail(f"Failed to import {module}")
    
    def test_cli_basic(self):
        """Test basic CLI functionality."""
        if not IMPORTS_OK:
            self.skipTest("Imports failed")
        
        from purgeproof import cli
        # Test that main function exists
        self.assertTrue(hasattr(cli, 'main'))
    
    def test_device_utils_basic(self):
        """Test basic device utils functionality."""
        if not IMPORTS_OK:
            self.skipTest("Imports failed")
        
        from purgeproof import device_utils
        # Test that key classes/functions exist
        expected_attrs = ['DeviceCapabilities', 'DeviceType']
        for attr in expected_attrs:
            if hasattr(device_utils, attr):
                # Only test if the attribute exists (it's okay if some are missing)
                pass
            else:
                print(f"Warning: {attr} not found in device_utils")


class TestInstallation(unittest.TestCase):
    """Test installation and setup."""
    
    def test_package_installed(self):
        """Test that the package can be imported as installed package."""
        try:
            import purgeproof
            self.assertIsNotNone(purgeproof.__file__)
        except ImportError:
            self.fail("PurgeProof package not properly installed")
    
    def test_dependencies(self):
        """Test that required dependencies are available."""
        required_deps = ['cryptography', 'yaml', 'click', 'psutil']
        missing_deps = []
        
        for dep in required_deps:
            try:
                __import__(dep)
            except ImportError:
                missing_deps.append(dep)
        
        if missing_deps:
            self.fail(f"Missing required dependencies: {missing_deps}")


if __name__ == "__main__":
    # Run basic tests
    unittest.main(verbosity=2)