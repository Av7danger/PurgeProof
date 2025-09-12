#!/usr/bin/env python3
"""
PurgeProof - Enterprise Data Sanitization Tool

Main entry point that provides both CLI and GUI interfaces for the
PurgeProof hybrid sanitization system.
"""

import sys
import argparse
from pathlib import Path

# Add the parent directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent))

def main():
    """Main entry point with interface selection."""
    parser = argparse.ArgumentParser(
        description="PurgeProof - Enterprise Data Sanitization Tool",
        epilog="Use --gui for graphical interface or provide commands for CLI mode"
    )
    
    parser.add_argument('--gui', action='store_true', 
                       help='Launch graphical user interface')
    parser.add_argument('--version', action='version', version='PurgeProof 2.1.0')
    
    # If no arguments, show help
    if len(sys.argv) == 1:
        parser.print_help()
        print("\nQuick start:")
        print("  purgeproof --gui                    # Launch GUI interface")
        print("  purgeproof list                     # List available devices")
        print("  purgeproof analyze /dev/sdb         # Analyze specific device")
        print("  purgeproof sanitize /dev/sdb        # Sanitize device")
        print("\nFor detailed CLI help:")
        print("  python -m purgeproof.cli --help")
        return 1
    
    # Parse known args to check for --gui
    args, remaining = parser.parse_known_args()
    
    if args.gui:
        # Launch GUI interface
        try:
            from purgeproof.gui import main as gui_main
            return gui_main()
        except ImportError as e:
            print(f"GUI interface not available: {e}")
            print("Please install tkinter or use the CLI interface:")
            print("  python -m purgeproof.cli --help")
            return 1
    else:
        # Launch CLI interface with remaining arguments
        try:
            from purgeproof.cli import main as cli_main
            # Restore original argv for CLI parser
            sys.argv = [sys.argv[0]] + remaining
            return cli_main()
        except ImportError as e:
            print(f"CLI interface not available: {e}")
            return 1

if __name__ == "__main__":
    sys.exit(main())