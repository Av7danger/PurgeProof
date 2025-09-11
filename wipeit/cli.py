#!/usr/bin/env python3
"""
PurgeProof CLI - NIST SP 800-88 Rev.1 Compliant Data Sanitization Tool

Command-line interface for the PurgeProof data sanitization system.
Provides comprehensive device sanitization with verification and certification.

Usage:
    wipeit list-devices                    # List available storage devices
    wipeit <device> [options]              # Sanitize a device
    wipeit verify <certificate>            # Verify a certificate
    wipeit --help                          # Show help
"""

import os
import sys
import time
import logging
import argparse
from typing import Optional, List
from pathlib import Path

# Add the wipeit package to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from core.device_utils import DeviceDetector, DeviceInfo
    from core.wipe_engine import WipeEngine, SanitizationMethod, WipeProgress
    from core.verification import VerificationEngine, VerificationLevel
    from core.certificates import CertificateGenerator
    from core.crypto_utils import CryptoManager
except ImportError as e:
    print(f"Error importing PurgeProof modules: {e}")
    print("Please ensure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logger = logging.getLogger(__name__)


class ProgressDisplay:
    """Console progress display for CLI operations."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.last_update = 0
        self.update_interval = 1.0  # Update every second
    
    def update_progress(self, progress: WipeProgress) -> None:
        """Update progress display."""
        current_time = time.time()
        
        # Throttle updates to avoid spam
        if current_time - self.last_update < self.update_interval and progress.percent_complete < 100:
            return
        
        self.last_update = current_time
        
        # Create progress bar
        bar_width = 40
        filled_width = int(bar_width * progress.percent_complete / 100)
        bar = "█" * filled_width + "░" * (bar_width - filled_width)
        
        # Format time remaining
        if progress.estimated_time_remaining > 0:
            time_remaining = self._format_time(progress.estimated_time_remaining)
        else:
            time_remaining = "Unknown"
        
        # Display progress
        print(f"\\r[{bar}] {progress.percent_complete:6.2f}% | {progress.current_operation} | ETA: {time_remaining}", end="", flush=True)
        
        # Add newline on completion
        if progress.percent_complete >= 100:
            print()
        
        # Verbose details
        if self.verbose:
            print(f"\\n  Operation: {progress.current_operation}")
            print(f"  Bytes processed: {progress.bytes_processed:,}/{progress.total_bytes:,}")
            print(f"  Errors: {progress.errors_encountered}")
    
    def _format_time(self, seconds: int) -> str:
        """Format time in human-readable format."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"


def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> None:
    """Configure logging for CLI."""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)  # Only warnings and errors to console
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


def cmd_list_devices(args) -> int:
    """List available storage devices."""
    try:
        print("Detecting storage devices...")
        detector = DeviceDetector()
        devices = detector.list_storage_devices()
        
        if not devices:
            print("No storage devices found.")
            return 0
        
        print(f"\\nFound {len(devices)} storage device(s):")
        print("=" * 80)
        
        for i, device in enumerate(devices, 1):
            # Basic device info
            size_gb = device.size_bytes / (1024**3)
            print(f"{i}. {device.path}")
            print(f"   Model: {device.model}")
            print(f"   Serial: {device.serial}")
            print(f"   Type: {device.device_type.upper()}")
            print(f"   Size: {size_gb:.2f} GB")
            print(f"   Platform: {device.platform}")
            
            # Encryption status
            if device.is_encrypted:
                print(f"   Encryption: {device.encryption_type or 'Unknown type'}")
            else:
                print("   Encryption: None")
            
            # Safety check
            safe, reason = detector.is_device_safe_to_wipe(device)
            safety_status = "✓ SAFE" if safe else "⚠ WARNING"
            print(f"   Safety: {safety_status} - {reason}")
            
            # Capabilities
            capabilities = [cap for cap, supported in device.capabilities.items() if supported]
            if capabilities:
                print(f"   Capabilities: {', '.join(capabilities)}")
            
            print()
        
        return 0
    
    except Exception as e:
        print(f"Error listing devices: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_sanitize_device(args) -> int:
    """Sanitize a storage device."""
    try:
        device_path = args.device
        
        print(f"Initializing sanitization of {device_path}...")
        
        # Initialize components
        detector = DeviceDetector()
        wipe_engine = WipeEngine(detector)
        verification_engine = VerificationEngine()
        certificate_generator = CertificateGenerator()
        
        # Set up progress display
        progress_display = ProgressDisplay(args.verbose)
        wipe_engine.set_progress_callback(progress_display.update_progress)
        
        # Get device information
        print("Analyzing device...")
        device_info = detector.get_device_info(device_path)
        if not device_info:
            print(f"Error: Device not found or inaccessible: {device_path}")
            return 1
        
        # Display device information
        print(f"\\nDevice Information:")
        print(f"  Path: {device_info.path}")
        print(f"  Model: {device_info.model}")
        print(f"  Serial: {device_info.serial}")
        print(f"  Type: {device_info.device_type}")
        print(f"  Size: {device_info.size_bytes / (1024**3):.2f} GB")
        print(f"  Encrypted: {'Yes' if device_info.is_encrypted else 'No'}")
        
        # Safety check
        safe, reason = detector.is_device_safe_to_wipe(device_info)
        if not safe and not args.force:
            print(f"\\nSafety Check Failed: {reason}")
            print("Use --force to override this check (DANGEROUS!)")
            return 1
        elif not safe:
            print(f"\\nWARNING: {reason}")
            print("Proceeding due to --force flag...")
        
        # Select sanitization method
        if args.method:
            try:
                selected_method = SanitizationMethod(args.method)
            except ValueError:
                print(f"Error: Unknown sanitization method: {args.method}")
                print(f"Available methods: {[m.value for m in SanitizationMethod]}")
                return 1
        else:
            selected_method = wipe_engine.select_optimal_method(device_info)
        
        print(f"\\nSelected sanitization method: {selected_method.value}")
        
        # Confirm operation
        if not args.yes:
            print(f"\\n⚠ WARNING: This will PERMANENTLY DESTROY all data on {device_path}")
            print(f"Device: {device_info.model} ({device_info.serial})")
            print(f"Method: {selected_method.value}")
            response = input("\\nType 'DESTROY' to confirm: ")
            if response != "DESTROY":
                print("Operation cancelled.")
                return 0
        
        # Perform sanitization
        print(f"\\nStarting sanitization...")
        start_time = time.time()
        
        wipe_result = wipe_engine.sanitize_device(
            device_path,
            selected_method,
            verify=args.verify,
            force=args.force
        )
        
        duration = time.time() - start_time
        
        # Display results
        print(f"\\nSanitization completed in {duration:.2f} seconds")
        print(f"Result: {wipe_result.result.value.upper()}")
        
        if wipe_result.error_message:
            print(f"Error: {wipe_result.error_message}")
        
        print(f"Bytes processed: {wipe_result.bytes_processed:,}")
        
        # Verification results
        if args.verify:
            if wipe_result.verification_passed:
                print("✓ Verification: PASSED")
            else:
                print("✗ Verification: FAILED")
        
        # Generate certificate if requested
        if args.certificate and wipe_result.result.value != "failed":
            print("\\nGenerating certificate...")
            
            # Create verification report
            verification_level = VerificationLevel(args.verification_level)
            verification_report = verification_engine.verify_sanitization(
                device_info, wipe_result, verification_level
            )
            
            # Generate certificate
            cert_formats = args.certificate_format.split(',') if args.certificate_format else ["json", "pdf"]
            certificate_files = certificate_generator.generate_certificate(
                device_info, wipe_result, verification_report, formats=cert_formats
            )
            
            print("Certificate(s) generated:")
            for format_type, file_path in certificate_files.items():
                print(f"  {format_type.upper()}: {file_path}")
        
        # Return appropriate exit code
        if wipe_result.result.value == "success":
            return 0
        elif wipe_result.result.value == "partial":
            return 2
        else:
            return 1
    
    except KeyboardInterrupt:
        print("\\n\\nOperation cancelled by user.")
        return 1
    except Exception as e:
        print(f"\\nError during sanitization: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_verify_certificate(args) -> int:
    """Verify a certificate."""
    try:
        certificate_path = args.certificate
        
        if not os.path.exists(certificate_path):
            print(f"Error: Certificate file not found: {certificate_path}")
            return 1
        
        print(f"Verifying certificate: {certificate_path}")
        
        # Initialize certificate generator for verification
        certificate_generator = CertificateGenerator()
        
        # Verify certificate
        is_valid, message = certificate_generator.verify_certificate(certificate_path)
        
        print(f"\\nVerification Result: {'VALID' if is_valid else 'INVALID'}")
        print(f"Details: {message}")
        
        # Display certificate information if valid
        if is_valid and args.verbose:
            try:
                import json
                with open(certificate_path, 'r') as f:
                    cert_data = json.load(f)
                
                print(f"\\nCertificate Information:")
                print(f"  ID: {cert_data.get('certificate_id', 'Unknown')}")
                print(f"  Generated: {cert_data.get('generated_at_iso', 'Unknown')}")
                print(f"  Device: {cert_data.get('device_info', {}).get('model', 'Unknown')}")
                print(f"  Method: {cert_data.get('sanitization_details', {}).get('method_used', 'Unknown')}")
                print(f"  Compliant: {'Yes' if cert_data.get('compliance_assessment', {}).get('nist_sp_800_88_compliant', False) else 'No'}")
            
            except Exception as e:
                print(f"Error reading certificate details: {e}")
        
        return 0 if is_valid else 1
    
    except Exception as e:
        print(f"Error verifying certificate: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_list_certificates(args) -> int:
    """List available certificates."""
    try:
        certificate_generator = CertificateGenerator(output_directory=args.certificate_dir)
        certificates = certificate_generator.list_certificates()
        
        if not certificates:
            print("No certificates found.")
            return 0
        
        print(f"Found {len(certificates)} certificate(s):")
        print("=" * 100)
        
        for cert in certificates:
            status = "✓" if cert["compliance_status"] else "✗"
            print(f"{status} {cert['certificate_id']}")
            print(f"   Generated: {cert['generated_at']}")
            print(f"   Device: {cert['device_model']}")
            print(f"   Method: {cert['sanitization_method']}")
            print(f"   File: {cert['file_path']}")
            print()
        
        return 0
    
    except Exception as e:
        print(f"Error listing certificates: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PurgeProof - NIST SP 800-88 Rev.1 Compliant Data Sanitization Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list-devices                    # List all storage devices
  %(prog)s /dev/sda                        # Sanitize /dev/sda with optimal method
  %(prog)s /dev/sda --method crypto_erase  # Use cryptographic erase
  %(prog)s C:\\dev\\device0 --force --yes    # Force sanitize Windows device
  %(prog)s verify certificate.json        # Verify a certificate
  %(prog)s list-certificates               # List all certificates

For more information, visit: https://github.com/your-org/purgeproof
        """
    )
    
    # Global options
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Verbose output and logging")
    parser.add_argument("--log-file", help="Log file path")
    parser.add_argument("--certificate-dir", help="Certificate output directory")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # List devices command
    list_parser = subparsers.add_parser("list-devices", help="List available storage devices")
    
    # List certificates command
    list_certs_parser = subparsers.add_parser("list-certificates", help="List available certificates")
    
    # Verify certificate command
    verify_parser = subparsers.add_parser("verify", help="Verify a certificate")
    verify_parser.add_argument("certificate", help="Path to certificate file")
    
    # Sanitize device command (default when device path is provided)
    parser.add_argument("device", nargs="?", help="Device path to sanitize (e.g., /dev/sda, \\\\.\\PHYSICALDRIVE0)")
    parser.add_argument("--method", choices=[m.value for m in SanitizationMethod], 
                       help="Sanitization method (auto-select if not specified)")
    parser.add_argument("--verify", action="store_true", default=True,
                       help="Verify sanitization (default: enabled)")
    parser.add_argument("--no-verify", dest="verify", action="store_false",
                       help="Skip verification")
    parser.add_argument("--verification-level", choices=[l.value for l in VerificationLevel],
                       default="standard", help="Verification thoroughness level")
    parser.add_argument("--certificate", action="store_true", default=True,
                       help="Generate wipe certificate (default: enabled)")
    parser.add_argument("--no-certificate", dest="certificate", action="store_false",
                       help="Skip certificate generation")
    parser.add_argument("--certificate-format", default="json,pdf",
                       help="Certificate formats (comma-separated: json,pdf)")
    parser.add_argument("--force", action="store_true",
                       help="Force sanitization even if safety checks fail")
    parser.add_argument("--yes", "-y", action="store_true",
                       help="Skip confirmation prompts")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose, args.log_file)
    
    try:
        # Handle commands
        if args.command == "list-devices":
            return cmd_list_devices(args)
        elif args.command == "list-certificates":
            return cmd_list_certificates(args)
        elif args.command == "verify":
            return cmd_verify_certificate(args)
        elif args.device:
            return cmd_sanitize_device(args)
        else:
            parser.print_help()
            return 0
    
    except KeyboardInterrupt:
        print("\\nOperation cancelled by user.")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
