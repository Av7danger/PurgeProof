#!/usr/bin/env python3
"""
PurgeProof Command Line Interface

A comprehensive CLI for secure data sanitization and wiping operations.
Supports NIST SP 800-88 Rev.1 compliant sanitization methods.
"""

import sys
import os
import argparse
import json
import time
from pathlib import Path
from typing import List, Dict, Any

# Add the wipeit package to the Python path if needed
try:
    from ..core.device_utils import DeviceDetector
    from ..core.wipe_engine import WipeEngine
    from ..core.verification import VerificationEngine
    from ..core.certificates import CertificateGenerator
    from ..core.crypto_utils import CryptoManager
except ImportError:
    # Fallback for direct execution
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
    from wipeit.core.device_utils import DeviceDetector
    from wipeit.core.wipe_engine import WipeEngine
    from wipeit.core.verification import VerificationEngine
    from wipeit.core.certificates import CertificateGenerator
    from wipeit.core.crypto_utils import CryptoManager


class PurgeProofCLI:
    """Main CLI interface for PurgeProof."""
    
    def __init__(self):
        self.device_detector = DeviceDetector()
        self.wipe_engine = WipeEngine()
        self.verification_engine = VerificationEngine()
        self.cert_generator = CertificateGenerator()
        self.crypto_manager = CryptoManager()
        
    def list_devices(self) -> List[Dict[str, Any]]:
        """List all available storage devices."""
        try:
            devices = self.device_detector.get_all_devices()
            return devices
        except Exception as e:
            print(f"Error detecting devices: {e}")
            return []
    
    def display_devices(self, devices: List[Dict[str, Any]]) -> None:
        """Display devices in a formatted table."""
        if not devices:
            print("No storage devices detected.")
            return
        
        print("\nDetected Storage Devices:")
        print("=" * 80)
        print(f"{'#':<3} {'Device':<20} {'Size':<12} {'Type':<15} {'Status':<15}")
        print("-" * 80)
        
        for i, device in enumerate(devices, 1):
            size_gb = device.get('size_bytes', 0) / (1024**3)
            size_str = f"{size_gb:.1f} GB" if size_gb > 0 else "Unknown"
            
            print(f"{i:<3} {device.get('path', 'Unknown'):<20} "
                  f"{size_str:<12} {device.get('type', 'Unknown'):<15} "
                  f"{device.get('status', 'Unknown'):<15}")
    
    def get_device_info(self, device_path: str) -> Dict[str, Any]:
        """Get detailed information about a specific device."""
        try:
            return self.device_detector.get_device_info(device_path)
        except Exception as e:
            print(f"Error getting device info: {e}")
            return {}
    
    def sanitize_device(self, device_path: str, method: str = "secure_erase", 
                       verify: bool = True, generate_cert: bool = True) -> bool:
        """Sanitize a device with the specified method."""
        try:
            print(f"\nStarting sanitization of {device_path}")
            print(f"Method: {method}")
            print(f"Verification: {'Enabled' if verify else 'Disabled'}")
            print(f"Certificate generation: {'Enabled' if generate_cert else 'Disabled'}")
            
            # Get device info
            device_info = self.get_device_info(device_path)
            if not device_info:
                print("Failed to get device information.")
                return False
            
            # Check if device is mounted and warn user
            if device_info.get('mounted', False):
                print(f"\nWARNING: Device {device_path} appears to be mounted!")
                print("Sanitizing a mounted device can cause system instability.")
                
                response = input("Do you want to continue? (yes/no): ").lower().strip()
                if response not in ['yes', 'y']:
                    print("Operation cancelled by user.")
                    return False
            
            # Perform sanitization
            print("\nStarting sanitization process...")
            
            def progress_callback(progress: float, message: str):
                print(f"Progress: {progress:.1f}% - {message}")
            
            success = self.wipe_engine.sanitize_device(
                device_path, 
                method, 
                progress_callback=progress_callback
            )
            
            if not success:
                print("Sanitization failed!")
                return False
            
            print("Sanitization completed successfully!")
            
            # Perform verification if requested
            if verify:
                print("\nStarting verification process...")
                verification_result = self.verification_engine.verify_sanitization(
                    device_path,
                    progress_callback=progress_callback
                )
                
                if verification_result['passed']:
                    print("Verification passed!")
                else:
                    print(f"Verification failed: {verification_result.get('error', 'Unknown error')}")
                    return False
            
            # Generate certificate if requested
            if generate_cert:
                print("\nGenerating sanitization certificate...")
                cert_data = {
                    'device_path': device_path,
                    'device_info': device_info,
                    'sanitization_method': method,
                    'verification_enabled': verify,
                    'timestamp': time.time(),
                    'operator': os.getenv('USERNAME', 'Unknown'),
                    'system_info': {'platform': 'windows'}  # Simplified for CLI
                }
                
                cert_path = self.cert_generator.generate_certificate(cert_data)
                if cert_path:
                    print(f"Certificate generated: {cert_path}")
                else:
                    print("Failed to generate certificate.")
            
            return True
            
        except Exception as e:
            print(f"Error during sanitization: {e}")
            return False
    
    def verify_certificate(self, cert_path: str) -> bool:
        """Verify a sanitization certificate."""
        try:
            result = self.cert_manager.verify_certificate(cert_path)
            
            if result['valid']:
                print(f"Certificate {cert_path} is VALID")
                print(f"Device: {result['data'].get('device_path', 'Unknown')}")
                print(f"Method: {result['data'].get('sanitization_method', 'Unknown')}")
                print(f"Timestamp: {result['data'].get('timestamp', 'Unknown')}")
                print(f"Operator: {result['data'].get('operator', 'Unknown')}")
                return True
            else:
                print(f"Certificate {cert_path} is INVALID")
                print(f"Reason: {result.get('error', 'Unknown')}")
                return False
                
        except Exception as e:
            print(f"Error verifying certificate: {e}")
            return False


def create_parser() -> argparse.ArgumentParser:
    """Create the command line parser."""
    parser = argparse.ArgumentParser(
        description="PurgeProof - Secure Data Sanitization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  purgeproof --list                     # List all storage devices
  purgeproof --sanitize /dev/sdb        # Sanitize device with default method
  purgeproof --sanitize /dev/sdb --method overwrite_random  # Use specific method
  purgeproof --verify-cert cert.json    # Verify a sanitization certificate
  purgeproof --info /dev/sdb            # Get detailed device information

Sanitization Methods:
  secure_erase      - Hardware secure erase (fastest, recommended)
  overwrite_zeros   - Single pass with zeros
  overwrite_random  - Single pass with random data
  dod_3pass         - DoD 5220.22-M 3-pass method
  dod_7pass         - DoD 5220.22-M 7-pass method
  gutmann           - Gutmann 35-pass method (legacy drives)
  nist_basic        - NIST SP 800-88 Rev.1 basic method
  nist_enhanced     - NIST SP 800-88 Rev.1 enhanced method
        """
    )
    
    # Main operations
    parser.add_argument('--list', '-l', action='store_true',
                       help='List all detected storage devices')
    parser.add_argument('--sanitize', '-s', metavar='DEVICE',
                       help='Sanitize the specified device')
    parser.add_argument('--info', '-i', metavar='DEVICE',
                       help='Show detailed information about a device')
    parser.add_argument('--verify-cert', '-v', metavar='CERT_FILE',
                       help='Verify a sanitization certificate')
    
    # Sanitization options
    parser.add_argument('--method', '-m', default='secure_erase',
                       choices=['secure_erase', 'overwrite_zeros', 'overwrite_random',
                               'dod_3pass', 'dod_7pass', 'gutmann', 'nist_basic', 'nist_enhanced'],
                       help='Sanitization method (default: secure_erase)')
    parser.add_argument('--no-verify', action='store_true',
                       help='Skip verification after sanitization')
    parser.add_argument('--no-cert', action='store_true',
                       help='Skip certificate generation')
    
    # Output options
    parser.add_argument('--json', action='store_true',
                       help='Output results in JSON format')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress non-essential output')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose output')
    
    return parser


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Create CLI instance
    cli = PurgeProofCLI()
    
    # Handle list devices
    if args.list:
        devices = cli.list_devices()
        if args.json:
            print(json.dumps(devices, indent=2))
        else:
            cli.display_devices(devices)
        return 0
    
    # Handle device info
    if args.info:
        device_info = cli.get_device_info(args.info)
        if args.json:
            print(json.dumps(device_info, indent=2))
        else:
            if device_info:
                print(f"\nDevice Information for {args.info}:")
                print("=" * 50)
                for key, value in device_info.items():
                    print(f"{key}: {value}")
            else:
                print(f"Could not get information for device: {args.info}")
        return 0
    
    # Handle certificate verification
    if args.verify_cert:
        success = cli.verify_certificate(args.verify_cert)
        return 0 if success else 1
    
    # Handle sanitization
    if args.sanitize:
        if not args.quiet:
            print("PurgeProof Data Sanitization Tool")
            print("=" * 40)
            print("\nWARNING: This operation will permanently destroy all data!")
            print(f"Device: {args.sanitize}")
            print(f"Method: {args.method}")
            
            response = input("\nAre you absolutely sure you want to continue? (type 'YES' to confirm): ")
            if response != 'YES':
                print("Operation cancelled.")
                return 1
        
        success = cli.sanitize_device(
            args.sanitize,
            args.method,
            verify=not args.no_verify,
            generate_cert=not args.no_cert
        )
        return 0 if success else 1
    
    # If no specific action, show help
    parser.print_help()
    return 0


if __name__ == '__main__':
    sys.exit(main())
