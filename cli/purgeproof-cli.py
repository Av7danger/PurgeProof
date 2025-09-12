#!/usr/bin/env python3
"""
PurgeProof Enterprise CLI Entry Point

Main executable for the PurgeProof Enterprise command-line interface.
Provides comprehensive data sanitization capabilities for enterprise environments.

Usage:
    purgeproof-cli [command] [options]
    
Commands:
    devices     - Device discovery and management
    certificates - Certificate generation and verification
    batch       - Batch processing operations
    compliance  - Compliance validation and reporting
    config      - Configuration management
    
For detailed help: purgeproof-cli --help
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import CLI modules
try:
    from cli.utils import setup_cli_environment, print_banner, CLIError
    from cli import main as cli_main
except ImportError as e:
    print(f"❌ Failed to import CLI modules: {e}")
    print("Please ensure PurgeProof Enterprise is properly installed.")
    sys.exit(1)


def main():
    """Main entry point for PurgeProof Enterprise CLI"""
    try:
        # Setup CLI environment
        config, logger, metrics = setup_cli_environment()
        
        # Check if --version flag is used
        if '--version' in sys.argv:
            print("PurgeProof Enterprise CLI v2.0.0")
            print("Enterprise Data Sanitization Solution")
            print("Copyright (c) 2024 PurgeProof Enterprise")
            return 0
        
        # Check if --banner flag is used or no arguments
        if '--banner' in sys.argv or len(sys.argv) == 1:
            print_banner()
            if len(sys.argv) == 1:
                print("Use 'purgeproof-cli --help' for usage information")
                print("Use 'purgeproof-cli --examples' for common examples")
                return 0
        
        # Check if --examples flag is used
        if '--examples' in sys.argv:
            from cli.utils import print_help_examples
            print_help_examples()
            return 0
        
        # Log CLI session start
        logger.info("PurgeProof Enterprise CLI session started")
        
        # Run main CLI
        result = cli_main()
        
        # Log session end
        logger.info("PurgeProof Enterprise CLI session completed")
        
        return result
        
    except CLIError as e:
        print(f"❌ CLI Error: {e}")
        return e.error_code
    except KeyboardInterrupt:
        print("\\n⚠️ Operation cancelled by user")
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        print(f"💥 Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())