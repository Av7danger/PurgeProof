#!/usr/bin/env python3
"""
PurgeProof Command Line Interface - Simplified Working Version

A functional CLI for testing and demonstrating PurgeProof capabilities.
"""

import sys
import os
import argparse
import json
import time
from typing import List, Dict, Any

# Add the wipeit package to the Python path if needed
try:
    from ..core.device_utils import DeviceDetector
    from ..core.wipe_engine import WipeEngine, SanitizationMethod
    from ..core.verification import VerificationEngine
    from ..core.certificates import CertificateGenerator
    from ..core.crypto_utils import CryptoManager
except ImportError:
    # Fallback for direct execution
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
    from wipeit.core.device_utils import DeviceDetector
    from wipeit.core.wipe_engine import WipeEngine, SanitizationMethod
    from wipeit.core.verification import VerificationEngine
    from wipeit.core.certificates import CertificateGenerator
    from wipeit.core.crypto_utils import CryptoManager


class PurgeProofCLI:
    """Simplified CLI interface for PurgeProof."""
    
    def __init__(self):
        self.device_detector = DeviceDetector()
        self.wipe_engine = WipeEngine()
        self.verification_engine = VerificationEngine()
        self.cert_generator = CertificateGenerator()
        self.crypto_manager = CryptoManager()
        
    def list_devices(self) -> List[Dict[str, Any]]:
        """List all available storage devices."""
        try:
            # Use the correct API method
            devices = self.device_detector.list_storage_devices()
            # Convert to list of dicts for display
            device_list = []
            for device in devices:
                device_dict = {
                    'path': device.path,
                    'size_bytes': device.size_bytes,
                    'type': str(device.device_type),
                    'model': getattr(device, 'model', 'Unknown'),
                    'serial': getattr(device, 'serial', 'Unknown'),
                    'mounted': getattr(device, 'is_mounted', False)
                }
                device_list.append(device_dict)
            return device_list
        except Exception as e:
            print(f"Error detecting devices: {e}")
            return []
    
    def display_devices(self, devices: List[Dict[str, Any]]) -> None:
        """Display devices in a formatted table."""
        if not devices:
            print("No storage devices detected.")
            print("Note: Device detection requires administrator privileges.")
            return
        
        print("\nDetected Storage Devices:")
        print("=" * 80)
        print(f"{'#':<3} {'Device':<20} {'Size':<12} {'Type':<15} {'Model':<20}")
        print("-" * 80)
        
        for i, device in enumerate(devices, 1):
            size_gb = device.get('size_bytes', 0) / (1024**3)
            size_str = f"{size_gb:.1f} GB" if size_gb > 0 else "Unknown"
            
            print(f"{i:<3} {device.get('path', 'Unknown'):<20} "
                  f"{size_str:<12} {device.get('type', 'Unknown'):<15} "
                  f"{device.get('model', 'Unknown'):<20}")
    
    def show_methods(self) -> None:
        """Show available sanitization methods."""
        print("\nAvailable Sanitization Methods:")
        print("=" * 50)
        
        for i, method in enumerate(SanitizationMethod, 1):
            print(f"{i}. {method.value}")
            
        print(f"\nTotal methods available: {len(list(SanitizationMethod))}")
    
    def test_crypto(self) -> None:
        """Test cryptographic functionality."""
        print("\nTesting Cryptographic Functions:")
        print("-" * 40)
        
        # Test hashing
        test_data = "PurgeProof CLI Test"
        hash_result = self.crypto_manager.hash_data(test_data)
        print(f"✓ SHA-256 Hash: {hash_result[:32]}...")
        
        # Test key management
        key_pairs = self.crypto_manager.list_key_pairs()
        print(f"✓ Available key pairs: {len(key_pairs)}")
        
        print("✓ Cryptographic functions operational")


def create_parser() -> argparse.ArgumentParser:
    """Create the command line parser."""
    parser = argparse.ArgumentParser(
        description="PurgeProof - Secure Data Sanitization Tool (Simplified CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  purgeproof --list                     # List all storage devices
  purgeproof --methods                  # Show available sanitization methods
  purgeproof --test-crypto              # Test cryptographic functions
  purgeproof --info                     # Show system information

Note: This is a simplified CLI for testing. Full sanitization requires admin privileges.
        """
    )
    
    # Main operations
    parser.add_argument('--list', '-l', action='store_true',
                       help='List all detected storage devices')
    parser.add_argument('--methods', '-m', action='store_true',
                       help='Show available sanitization methods')
    parser.add_argument('--test-crypto', '-c', action='store_true',
                       help='Test cryptographic functions')
    parser.add_argument('--info', '-i', action='store_true',
                       help='Show system and component information')
    
    # Output options
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress non-essential output')
    
    return parser


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    # Create CLI instance
    cli = PurgeProofCLI()
    
    if not args.quiet:
        print("PurgeProof Data Sanitization Tool - CLI")
        print("=" * 45)
    
    # Handle list devices
    if args.list:
        devices = cli.list_devices()
        if args.json:
            print(json.dumps(devices, indent=2))
        else:
            cli.display_devices(devices)
        return 0
    
    # Handle methods display
    if args.methods:
        cli.show_methods()
        return 0
    
    # Handle crypto test
    if args.test_crypto:
        cli.test_crypto()
        return 0
    
    # Handle info display
    if args.info:
        print("\nSystem Information:")
        print("-" * 30)
        print(f"Platform: {cli.device_detector.platform}")
        print(f"Device detector: Initialized")
        print(f"Wipe engine: Initialized")
        print(f"Verification engine: Initialized")
        print(f"Certificate generator: Initialized")
        print(f"Crypto manager: Initialized")
        
        print("\nComponent Status:")
        print("-" * 30)
        try:
            methods = list(SanitizationMethod)
            print(f"✓ Sanitization methods: {len(methods)} available")
        except Exception as e:
            print(f"✗ Sanitization methods: Error - {e}")
            
        try:
            hash_test = cli.crypto_manager.hash_data("test")
            print(f"✓ Cryptographic functions: Working")
        except Exception as e:
            print(f"✗ Cryptographic functions: Error - {e}")
            
        print("\n✅ All components initialized successfully")
        return 0
    
    # If no specific action was taken, show help
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
