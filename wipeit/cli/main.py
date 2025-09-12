#!/usr/bin/env python3
"""
PurgeProof Working CLI

A functional CLI that works without requiring elevation for basic operations.
"""

import sys
import os
import argparse

# Add wipeit to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'wipeit'))

def show_methods():
    """Show available sanitization methods."""
    try:
        from wipeit.core.wipe_engine import SanitizationMethod
        
        print("\nAvailable Sanitization Methods:")
        print("=" * 40)
        
        methods = list(SanitizationMethod)
        for i, method in enumerate(methods, 1):
            print(f"{i}. {method.value}")
            
        print(f"\nTotal methods: {len(methods)}")
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_crypto():
    """Test cryptographic functions."""
    try:
        from wipeit.core.crypto_utils import CryptoManager
        
        print("\nCryptographic Functions Test:")
        print("=" * 35)
        
        crypto = CryptoManager()
        
        # Test hashing
        test_data = "PurgeProof CLI Test"
        hash_result = crypto.hash_data(test_data)
        print(f"✓ SHA-256 Hash: {hash_result[:40]}...")
        
        # Test key management
        key_pairs = crypto.list_key_pairs()
        print(f"✓ Available key pairs: {len(key_pairs)}")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

def show_info():
    """Show system information."""
    print("\nPurgeProof System Information:")
    print("=" * 35)
    print(f"Platform: {sys.platform}")
    print(f"Python: {sys.version.split()[0]}")
    
    # Test component availability
    components = {
        "Crypto Manager": False,
        "Sanitization Methods": False,
        "Device Detection": False
    }
    
    try:
        from wipeit.core.crypto_utils import CryptoManager
        CryptoManager()
        components["Crypto Manager"] = True
    except:
        pass
        
    try:
        from wipeit.core.wipe_engine import SanitizationMethod
        list(SanitizationMethod)
        components["Sanitization Methods"] = True
    except:
        pass
        
    # Device detection requires elevation, so we'll note that
    components["Device Detection"] = "Requires Admin"
    
    print("\nComponent Status:")
    for component, status in components.items():
        if status is True:
            print(f"  ✓ {component}: Available")
        elif status == "Requires Admin":
            print(f"  ⚠ {component}: Requires Administrator")
        else:
            print(f"  ✗ {component}: Not Available")

def list_devices():
    """Attempt to list devices (requires admin)."""
    print("\nAttempting to list storage devices...")
    print("Note: This operation requires administrator privileges.")
    
    try:
        from wipeit.core.device_utils import DeviceDetector
        
        detector = DeviceDetector()
        devices = detector.list_storage_devices()
        
        if devices:
            print(f"\nFound {len(devices)} storage devices:")
            print("-" * 50)
            for i, device in enumerate(devices, 1):
                size_gb = device.size_bytes / (1024**3) if device.size_bytes else 0
                print(f"{i}. {device.path} ({size_gb:.1f} GB) - {device.device_type}")
        else:
            print("No devices detected or insufficient privileges.")
            
    except Exception as e:
        print(f"Device detection failed: {e}")
        print("\nTo access storage devices:")
        print("1. Run as Administrator")
        print("2. Use: python launcher.py --tkinter")

def create_parser():
    """Create command line parser."""
    parser = argparse.ArgumentParser(
        description="PurgeProof - Working CLI Interface",
        epilog="""
Examples:
  python cli_working.py --methods      # Show sanitization methods
  python cli_working.py --crypto       # Test cryptographic functions  
  python cli_working.py --info         # Show system information
  python cli_working.py --devices      # List devices (requires admin)
  python cli_working.py --gui          # Launch GUI interface
        """
    )
    
    parser.add_argument('--methods', '-m', action='store_true',
                       help='Show available sanitization methods')
    parser.add_argument('--crypto', '-c', action='store_true',
                       help='Test cryptographic functions')
    parser.add_argument('--info', '-i', action='store_true', 
                       help='Show system information')
    parser.add_argument('--devices', '-d', action='store_true',
                       help='List storage devices (requires admin)')
    parser.add_argument('--gui', '-g', action='store_true',
                       help='Launch GUI interface')
    
    return parser

def main():
    """Main CLI function."""
    parser = create_parser()
    args = parser.parse_args()
    
    # If no arguments, show help and basic info
    if len(sys.argv) == 1:
        print("PurgeProof - Secure Data Sanitization Tool")
        print("=" * 45)
        parser.print_help()
        print("\nQuick test:")
        show_info()
        return 0
    
    success = True
    
    if args.methods:
        success &= show_methods()
        
    if args.crypto:
        success &= test_crypto()
        
    if args.info:
        show_info()
        
    if args.devices:
        list_devices()
        
    if args.gui:
        print("\nLaunching GUI interface...")
        try:
            os.system("python launcher.py --tkinter")
        except Exception as e:
            print(f"Failed to launch GUI: {e}")
            success = False
    
    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
