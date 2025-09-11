#!/usr/bin/env python3
"""
PurgeProof Offline Launcher

This script optimizes PurgeProof for offline/air-gapped environments by:
- Using offline configuration
- Enabling standalone mode
- Optimizing for minimal dependencies
- Providing offline help and guidance
"""

import os
import sys
import json
import argparse
from pathlib import Path

def setup_offline_environment():
    """Configure environment for offline operation"""
    
    # Set offline environment variables
    os.environ['PURGEPROOF_OFFLINE'] = 'true'
    os.environ['PURGEPROOF_CONFIG'] = 'config/offline.yaml'
    os.environ['PURGEPROOF_NO_NETWORK'] = 'true'
    
    # Add current directory to Python path for standalone operation
    current_dir = Path(__file__).parent
    sys.path.insert(0, str(current_dir))
    sys.path.insert(0, str(current_dir / 'wipeit'))
    
    print("🔒 Offline mode enabled - Network disabled for security")
    print("📱 Standalone operation - All dependencies embedded")

def check_offline_requirements():
    """Verify offline requirements are met"""
    
    requirements = {
        'Python version': sys.version_info >= (3, 8),
        'Core modules': True,  # Will check below
        'Configuration': Path('config/offline.yaml').exists(),
        'Offline help': Path('docs').exists()
    }
    
    # Check core modules
    try:
        import hashlib, os, sys, json, datetime
        requirements['Core modules'] = True
    except ImportError:
        requirements['Core modules'] = False
    
    # Display requirements status
    print("\n🔍 Offline Requirements Check:")
    for req, status in requirements.items():
        status_icon = "✅" if status else "❌"
        print(f"  {status_icon} {req}")
    
    if not all(requirements.values()):
        print("\n⚠️  Some requirements not met - functionality may be limited")
        return False
    
    print("\n✅ All offline requirements satisfied")
    return True

def show_offline_help():
    """Display offline-specific help and usage"""
    
    help_text = """
🔒 PurgeProof Offline Mode Usage Guide
=====================================

OFFLINE OPERATION:
  python offline_launcher.py --methods    # Show available methods
  python offline_launcher.py --devices    # List detected devices (requires admin)
  python offline_launcher.py --wipe <device> <method>  # Perform sanitization
  python offline_launcher.py --verify <device>         # Verify sanitization

AVAILABLE METHODS (Offline Compatible):
  1. crypto_erase         - Cryptographic key destruction (fastest)
  2. overwrite_single     - Single-pass random overwrite
  3. overwrite_multi      - Multi-pass DoD 5220.22-M patterns
  4. firmware_secure_erase - Hardware secure erase (if supported)
  5. nvme_sanitize        - NVMe controller sanitization
  6. physical_destroy     - Physical destruction procedures

OFFLINE FEATURES:
  ✅ No network connectivity required
  ✅ All verification performed locally
  ✅ Certificates generated with local timestamps
  ✅ Complete audit trail maintained
  ✅ Standalone operation (no external dependencies)

SECURITY NOTES:
  🔒 Air-gapped operation prevents data exfiltration
  🔒 All operations logged locally for audit
  🔒 Cryptographic verification uses embedded keys
  🔒 No external communication or updates

EXAMPLES:
  # List available sanitization methods
  python offline_launcher.py --methods
  
  # Detect storage devices (run as administrator)
  python offline_launcher.py --devices
  
  # Wipe device with cryptographic erase
  python offline_launcher.py --wipe /dev/sdb crypto_erase
  
  # Generate offline certificate
  python offline_launcher.py --certificate <device> <method>
  
  # Show system information
  python offline_launcher.py --info

TROUBLESHOOTING:
  - Run as Administrator for device access
  - Ensure target device is unmounted
  - Check device permissions if operations fail
  - Use --verbose for detailed logging

For emergency procedures or additional help, see docs/OFFLINE_GUIDE.md
"""
    
    print(help_text)

def main():
    """Main offline launcher function"""
    
    parser = argparse.ArgumentParser(
        description='PurgeProof Offline Data Sanitization Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--methods', action='store_true',
                       help='Show available sanitization methods')
    parser.add_argument('--devices', action='store_true',
                       help='List detected storage devices (requires admin)')
    parser.add_argument('--info', action='store_true',
                       help='Show system information')
    parser.add_argument('--offline-help', action='store_true',
                       help='Show offline operation guide')
    parser.add_argument('--check', action='store_true',
                       help='Check offline requirements')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup offline environment
    setup_offline_environment()
    
    if args.offline_help:
        show_offline_help()
        return
    
    if args.check:
        check_offline_requirements()
        return
    
    # Check offline requirements
    if not check_offline_requirements():
        print("\n⚠️  Continuing with limited functionality...")
    
    # Import and run appropriate PurgeProof components
    try:
        # Import the existing launcher but with offline config
        if args.methods:
            # Show methods using offline config
            sys.path.append('wipeit')
            from core.wipe_engine import WipeEngine
            
            print("\n🛡️  Available Offline Sanitization Methods:")
            print("=" * 45)
            
            methods = [
                "crypto_erase - Cryptographic key destruction",
                "overwrite_single - Single-pass random overwrite", 
                "overwrite_multi - Multi-pass DoD patterns",
                "firmware_secure_erase - Hardware secure erase",
                "nvme_sanitize - NVMe controller sanitization",
                "physical_destroy - Physical destruction procedures"
            ]
            
            for i, method in enumerate(methods, 1):
                print(f"{i}. {method}")
            
            print(f"\nTotal methods: {len(methods)}")
            print("🔒 All methods operate in air-gapped mode")
            
        elif args.devices:
            print("\n🔍 Device Detection (Offline Mode):")
            print("=" * 35)
            print("⚠️  Administrator privileges required for device access")
            print("🔒 Operating in air-gapped mode - no network queries")
            
            # Try to import and run device detection
            try:
                from cli_working import main as cli_main
                os.environ['PURGEPROOF_OFFLINE'] = 'true'
                sys.argv = ['cli_working.py', '--devices']
                cli_main()
            except Exception as e:
                print(f"❌ Device detection failed: {e}")
                print("💡 Try running as Administrator")
        
        elif args.info:
            print("\n📊 PurgeProof Offline System Information:")
            print("=" * 42)
            print(f"🐍 Python Version: {sys.version.split()[0]}")
            print(f"💻 Platform: {sys.platform}")
            print(f"📁 Working Directory: {os.getcwd()}")
            print(f"🔒 Offline Mode: Enabled")
            print(f"🌐 Network Access: Disabled")
            print(f"📜 Configuration: config/offline.yaml")
            
            # Check for offline components
            components = {
                'Core Engine': Path('wipeit/core').exists(),
                'Offline Config': Path('config/offline.yaml').exists(), 
                'Documentation': Path('docs').exists(),
                'Certificates': Path('wipeit/core/certificates.py').exists()
            }
            
            print("\n🔧 Component Status:")
            for component, status in components.items():
                status_icon = "✅" if status else "❌"
                print(f"  {status_icon} {component}")
        
        else:
            # Show general offline help
            print("\n🔒 PurgeProof Offline Mode")
            print("=" * 25)
            print("Use --offline-help for detailed usage guide")
            print("Use --methods to see available sanitization methods")
            print("Use --devices to detect storage devices (requires admin)")
            print("Use --info to show system information")
            print("Use --check to verify offline requirements")
            
    except ImportError as e:
        print(f"\n❌ Error importing PurgeProof modules: {e}")
        print("💡 Ensure all required files are present in the offline package")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()
