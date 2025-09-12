#!/usr/bin/env python3
"""
PurgeProof Setup Script

Installation script for the PurgeProof enterprise data sanitization tool.
This script complements the pyproject.toml configuration and provides
additional setup functionality for the hybrid Rust/Python architecture.
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def check_python_version():
    """Check if Python version is supported."""
    if sys.version_info < (3, 8):
        print("Error: PurgeProof requires Python 3.8 or later")
        print(f"Current version: {sys.version}")
        return False
    return True

def check_rust_installation():
    """Check if Rust is installed for building the native engine."""
    try:
        result = subprocess.run(['cargo', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ Rust/Cargo found: {result.stdout.strip()}")
            return True
        else:
            print("✗ Rust/Cargo not found")
            return False
    except FileNotFoundError:
        print("✗ Rust/Cargo not found")
        return False

def build_native_engine():
    """Build the native Rust engine."""
    print("\nBuilding native engine...")
    
    engine_dir = Path(__file__).parent / "engine"
    
    if not engine_dir.exists():
        print("✗ Engine directory not found")
        return False
    
    try:
        # Build in release mode
        subprocess.run(['cargo', 'build', '--release'], 
                      cwd=engine_dir, check=True)
        print("✓ Native engine built successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to build native engine: {e}")
        return False

def run_tests():
    """Run the test suite to verify installation."""
    print("\nRunning test suite...")
    
    try:
        subprocess.run([sys.executable, '-m', 'pytest', 'tests/', '-v'], 
                      check=True)
        print("✓ All tests passed")
        return True
    
    except subprocess.CalledProcessError:
        print("⚠ Some tests failed - installation may have issues")
        return False

def main():
    """Main setup function."""
    print("PurgeProof Setup")
    print("=" * 50)
    
    # Check prerequisites
    if not check_python_version():
        return 1
    
    # Check for Rust
    if not check_rust_installation():
        print("\nRust is required for the native engine.")
        print("Install from: https://rustup.rs/")
        print("Then run: pip install -e .")
        return 1
    
    # Build native engine
    if not build_native_engine():
        print("⚠ Native engine build failed. Using Python fallback.")
    
    # Optional: Run tests
    if len(sys.argv) > 1 and '--test' in sys.argv:
        run_tests()
    
    print("\n" + "=" * 50)
    print("✓ PurgeProof setup completed!")
    print("\nInstall with: pip install -e .")
    print("\nUsage:")
    print("  purgeproof --gui          # GUI interface")
    print("  purgeproof list           # CLI interface")
    print("  purgeproof --help         # CLI help")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
