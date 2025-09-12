#!/usr/bin/env python3
"""
PurgeProof Launcher

Automatically detects available GUI frameworks and launches the appropriate interface.
Falls back to CLI if no GUI framework is available.

Usage:
    python launcher.py [--cli] [--gui] [--pyqt] [--tkinter]
"""

import sys
import os
import argparse
from pathlib import Path

# Add the wipeit package to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wipeit'))


def check_dependencies():
    """Check which GUI frameworks are available."""
    available = {
        'tkinter': False,
        'pyqt6': False,
        'cli': True  # CLI is always available
    }
    
    # Check tkinter (usually bundled with Python)
    try:
        import tkinter
        available['tkinter'] = True
    except ImportError:
        pass
    
    # Check PyQt6
    try:
        import PyQt6
        available['pyqt6'] = True
    except ImportError:
        pass
    
    return available


def launch_tkinter_gui():
    """Launch the tkinter GUI."""
    try:
        from wipeit.gui.main import PurgeProofGUI
        app = PurgeProofGUI()
        app.run()
        return 0
    except Exception as e:
        print(f"Failed to launch tkinter GUI: {e}")
        return 1


def launch_pyqt_gui():
    """Launch the PyQt6 GUI."""
    try:
        from wipeit.gui.gui_pyqt import main as pyqt_main
        return pyqt_main()
    except Exception as e:
        print(f"Failed to launch PyQt6 GUI: {e}")
        return 1


def launch_cli(cli_args=None):
    """Launch the CLI interface."""
    try:
        from wipeit.cli.simple_main import main
        
        # If cli_args provided, temporarily replace sys.argv
        if cli_args:
            original_argv = sys.argv[:]
            sys.argv = ['cli.py'] + cli_args
            try:
                return main()
            finally:
                sys.argv = original_argv
        else:
            return main()
    except Exception as e:
        print(f"Failed to launch CLI: {e}")
        return 1


def show_gui_selection(available):
    """Show GUI selection menu."""
    print("\\nPurgeProof Data Sanitization Tool")
    print("==================================")
    print("\\nAvailable interfaces:")
    
    options = []
    
    if available['pyqt6']:
        print("1. PyQt6 GUI (Recommended - Modern interface)")
        options.append(('pyqt6', launch_pyqt_gui))
    
    if available['tkinter']:
        print("2. Tkinter GUI (Simple interface)")
        options.append(('tkinter', launch_tkinter_gui))
    
    print("3. Command Line Interface")
    options.append(('cli', launch_cli))
    
    print("\\nWhich interface would you like to use?")
    
    while True:
        try:
            choice = input("Enter choice (1-3): ").strip()
            choice_idx = int(choice) - 1
            
            if 0 <= choice_idx < len(options):
                interface_name, launcher = options[choice_idx]
                print(f"\\nLaunching {interface_name.upper()} interface...")
                return launcher()
            else:
                print("Invalid choice. Please enter a number between 1 and 3.")
        
        except (ValueError, KeyboardInterrupt):
            print("\\nExiting...")
            return 0


def main():
    """Main launcher function."""
    parser = argparse.ArgumentParser(
        description="PurgeProof Data Sanitization Tool Launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python launcher.py              # Auto-detect and show selection menu
  python launcher.py --cli        # Force CLI interface
  python launcher.py --pyqt       # Force PyQt6 GUI
  python launcher.py --tkinter    # Force tkinter GUI
  python launcher.py --gui        # Auto-detect best GUI
        """
    )
    
    parser.add_argument('--cli', action='store_true',
                       help='Force command-line interface')
    parser.add_argument('--gui', action='store_true',
                       help='Auto-detect and use best available GUI')
    parser.add_argument('--pyqt', action='store_true',
                       help='Force PyQt6 GUI interface')
    parser.add_argument('--tkinter', action='store_true',
                       help='Force tkinter GUI interface')
    parser.add_argument('--check', action='store_true',
                       help='Check available interfaces and exit')
    
    # Parse known args to allow passing through CLI arguments
    args, unknown_args = parser.parse_known_args()
    
    # Check available dependencies
    available = check_dependencies()
    
    if args.check:
        print("Available interfaces:")
        for interface, is_available in available.items():
            status = "✓" if is_available else "✗"
            print(f"  {status} {interface.upper()}")
        return 0
    
    # Handle forced interface selections
    if args.cli:
        print("Launching CLI interface...")
        return launch_cli(unknown_args if unknown_args else None)
    
    if args.pyqt:
        if available['pyqt6']:
            print("Launching PyQt6 GUI...")
            return launch_pyqt_gui()
        else:
            print("PyQt6 is not available. Please install it with:")
            print("  pip install PyQt6 PyQt6-tools")
            return 1
    
    if args.tkinter:
        if available['tkinter']:
            print("Launching tkinter GUI...")
            return launch_tkinter_gui()
        else:
            print("tkinter is not available. Please install it or use --cli")
            return 1
    
    if args.gui:
        # Auto-detect best GUI
        if available['pyqt6']:
            print("Launching PyQt6 GUI (best available)...")
            return launch_pyqt_gui()
        elif available['tkinter']:
            print("Launching tkinter GUI...")
            return launch_tkinter_gui()
        else:
            print("No GUI frameworks available. Launching CLI...")
            return launch_cli()
    
    # No specific interface requested - show selection menu
    if available['pyqt6'] or available['tkinter']:
        return show_gui_selection(available)
    else:
        print("No GUI frameworks available. Launching CLI interface...")
        return launch_cli()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\\nExiting...")
        sys.exit(0)
    except Exception as e:
        print(f"Launcher error: {e}")
        sys.exit(1)
