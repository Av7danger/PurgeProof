#!/usr/bin/env python3
"""
PurgeProof Installation Script

Automated installation and setup for PurgeProof data sanitization tool.
Handles dependency installation, configuration, and platform-specific setup.

Usage:
    python install.py [options]

Options:
    --system          Install system-wide (requires sudo/admin)
    --user            Install for current user only (default)
    --dev             Install in development mode
    --gui             Install GUI dependencies (PyQt6)
    --minimal         Minimal installation (CLI only)
    --config          Create default configuration files
    --uninstall       Uninstall PurgeProof
    --check           Check installation status
    --help            Show this help message

Supported Platforms:
    - Windows 10/11 (PowerShell 5.1+)
    - Ubuntu/Debian Linux
    - Red Hat/CentOS/Fedora Linux
    - macOS 10.15+
"""

import os
import sys
import platform
import subprocess
import shutil
import json
from pathlib import Path
import argparse
import tempfile
import urllib.request
import zipfile
import tarfile


class PurgeProofInstaller:
    """PurgeProof installation manager."""
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.arch = platform.machine().lower()
        self.python_version = sys.version_info
        self.script_dir = Path(__file__).parent.absolute()
        self.project_root = self.script_dir
        
        # Installation paths
        self.system_install = False
        self.install_prefix = None
        self.config_dir = None
        self.data_dir = None
        
        # Features to install
        self.install_gui = False
        self.install_minimal = False
        self.install_dev = False
        
        # Colors for output
        self.colors = {
            'red': '\033[0;31m',
            'green': '\033[0;32m',
            'yellow': '\033[1;33m',
            'blue': '\033[0;34m',
            'purple': '\033[0;35m',
            'cyan': '\033[0;36m',
            'white': '\033[1;37m',
            'reset': '\033[0m'
        }
    
    def log(self, level, message):
        """Log a message with color coding."""
        if not sys.stdout.isatty():
            # No colors for non-terminal output
            colors = {k: '' for k in self.colors.keys()}
        else:
            colors = self.colors
        
        level_colors = {
            'info': colors['blue'],
            'success': colors['green'],
            'warning': colors['yellow'],
            'error': colors['red'],
            'debug': colors['purple']
        }
        
        color = level_colors.get(level, colors['reset'])
        reset = colors['reset']
        
        print(f"{color}[{level.upper()}]{reset} {message}")
    
    def run_command(self, command, shell=False, check=True, capture_output=True):
        """Run a system command."""
        try:
            if isinstance(command, str) and not shell:
                command = command.split()
            
            result = subprocess.run(
                command,
                shell=shell,
                check=check,
                capture_output=capture_output,
                text=True
            )
            
            return result
        
        except subprocess.CalledProcessError as e:
            self.log('error', f"Command failed: {' '.join(command) if isinstance(command, list) else command}")
            self.log('error', f"Error: {e}")
            if e.stdout:
                self.log('debug', f"Stdout: {e.stdout}")
            if e.stderr:
                self.log('debug', f"Stderr: {e.stderr}")
            raise
    
    def check_prerequisites(self):
        """Check system prerequisites."""
        self.log('info', "Checking system prerequisites...")
        
        # Check Python version
        if self.python_version < (3, 8):
            self.log('error', f"Python 3.8+ required, found {self.python_version.major}.{self.python_version.minor}")
            return False
        
        self.log('success', f"Python {self.python_version.major}.{self.python_version.minor}.{self.python_version.micro} ✓")
        
        # Check pip
        try:
            self.run_command([sys.executable, '-m', 'pip', '--version'])
            self.log('success', "pip available ✓")
        except subprocess.CalledProcessError:
            self.log('error', "pip not available. Please install pip.")
            return False
        
        # Check platform-specific prerequisites
        if self.platform == 'windows':
            return self._check_windows_prerequisites()
        elif self.platform == 'linux':
            return self._check_linux_prerequisites()
        elif self.platform == 'darwin':
            return self._check_macos_prerequisites()
        else:
            self.log('warning', f"Unknown platform: {self.platform}")
            return True
    
    def _check_windows_prerequisites(self):
        """Check Windows-specific prerequisites."""
        self.log('info', "Checking Windows prerequisites...")
        
        # Check PowerShell
        try:
            result = self.run_command(['powershell', '-Command', 'Get-Host'])
            self.log('success', "PowerShell available ✓")
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.log('warning', "PowerShell not available - some features may be limited")
        
        # Check for admin rights if system install
        if self.system_install:
            try:
                result = self.run_command(['net', 'session'], capture_output=True)
                self.log('success', "Administrator privileges ✓")
            except subprocess.CalledProcessError:
                self.log('error', "Administrator privileges required for system installation")
                return False
        
        return True
    
    def _check_linux_prerequisites(self):
        """Check Linux-specific prerequisites."""
        self.log('info', "Checking Linux prerequisites...")
        
        # Check for required system utilities
        utilities = ['lsblk', 'fdisk']
        optional_utilities = ['hdparm', 'nvme', 'smartctl']
        
        for utility in utilities:
            if shutil.which(utility):
                self.log('success', f"{utility} available ✓")
            else:
                self.log('error', f"Required utility missing: {utility}")
                return False
        
        for utility in optional_utilities:
            if shutil.which(utility):
                self.log('success', f"{utility} available ✓")
            else:
                self.log('warning', f"Optional utility missing: {utility}")
        
        # Check for sudo if system install
        if self.system_install:
            if os.geteuid() != 0:
                self.log('error', "Root privileges required for system installation (use sudo)")
                return False
            self.log('success', "Root privileges ✓")
        
        return True
    
    def _check_macos_prerequisites(self):
        """Check macOS-specific prerequisites."""
        self.log('info', "Checking macOS prerequisites...")
        
        # Check for diskutil
        if shutil.which('diskutil'):
            self.log('success', "diskutil available ✓")
        else:
            self.log('warning', "diskutil not found - some features may be limited")
        
        return True
    
    def determine_install_paths(self):
        """Determine installation paths based on platform and install type."""
        if self.system_install:
            if self.platform == 'windows':
                self.install_prefix = Path("C:/Program Files/PurgeProof")
                self.config_dir = Path("C:/ProgramData/PurgeProof")
                self.data_dir = Path(os.environ.get('ALLUSERSPROFILE', 'C:/ProgramData')) / "PurgeProof"
            else:
                self.install_prefix = Path("/opt/purgeproof")
                self.config_dir = Path("/etc/purgeproof")
                self.data_dir = Path("/var/lib/purgeproof")
        else:
            # User installation
            home = Path.home()
            if self.platform == 'windows':
                self.install_prefix = home / "AppData/Local/PurgeProof"
                self.config_dir = home / "AppData/Roaming/PurgeProof"
                self.data_dir = home / "Documents/PurgeProof"
            else:
                self.install_prefix = home / ".local/share/purgeproof"
                self.config_dir = home / ".config/purgeproof"
                self.data_dir = home / ".local/share/purgeproof/data"
        
        self.log('info', f"Install prefix: {self.install_prefix}")
        self.log('info', f"Config directory: {self.config_dir}")
        self.log('info', f"Data directory: {self.data_dir}")
    
    def install_python_dependencies(self):
        """Install Python dependencies."""
        self.log('info', "Installing Python dependencies...")
        
        # Core dependencies
        core_deps = [
            'cryptography>=41.0.0',
            'psutil>=5.9.0',
            'pyserial>=3.5',
            'reportlab>=4.0.0',
            'qrcode>=7.4.0',
            'Pillow>=10.0.0',
            'click>=8.1.0',
            'colorama>=0.4.6'
        ]
        
        # GUI dependencies
        gui_deps = [
            'PyQt6>=6.5.0'
        ]
        
        # Development dependencies
        dev_deps = [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'black>=23.0.0',
            'flake8>=6.0.0'
        ]
        
        # Platform-specific dependencies
        platform_deps = []
        if self.platform == 'windows':
            platform_deps.extend([
                'pywin32>=306',
                'wmi>=1.5.1'
            ])
        
        # Install dependencies
        deps_to_install = core_deps + platform_deps
        
        if self.install_gui:
            deps_to_install.extend(gui_deps)
        
        if self.install_dev:
            deps_to_install.extend(dev_deps)
        
        # Install in chunks to handle dependency conflicts
        for dep in deps_to_install:
            try:
                self.log('info', f"Installing {dep}...")
                self.run_command([
                    sys.executable, '-m', 'pip', 'install',
                    '--upgrade', dep
                ])
            except subprocess.CalledProcessError:
                self.log('warning', f"Failed to install {dep}, continuing...")
        
        self.log('success', "Python dependencies installed")
    
    def install_application_files(self):
        """Install application files."""
        self.log('info', "Installing application files...")
        
        # Create directories
        self.install_prefix.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy application files
        src_dir = self.project_root / "wipeit"
        dst_dir = self.install_prefix / "wipeit"
        
        if dst_dir.exists():
            shutil.rmtree(dst_dir)
        
        shutil.copytree(src_dir, dst_dir)
        
        # Copy launcher
        shutil.copy2(
            self.project_root / "launcher.py",
            self.install_prefix / "launcher.py"
        )
        
        # Copy configuration
        if (self.project_root / "config" / "default.yaml").exists():
            shutil.copy2(
                self.project_root / "config" / "default.yaml",
                self.config_dir / "default.yaml"
            )
        
        self.log('success', "Application files installed")
    
    def create_shortcuts(self):
        """Create desktop shortcuts and menu entries."""
        self.log('info', "Creating shortcuts...")
        
        if self.platform == 'windows':
            self._create_windows_shortcuts()
        elif self.platform == 'linux':
            self._create_linux_shortcuts()
        elif self.platform == 'darwin':
            self._create_macos_shortcuts()
    
    def _create_windows_shortcuts(self):
        """Create Windows shortcuts."""
        # Create Start Menu shortcut
        start_menu = Path(os.environ.get('APPDATA', '')) / "Microsoft/Windows/Start Menu/Programs"
        if self.system_install:
            start_menu = Path(os.environ.get('ALLUSERSPROFILE', '')) / "Microsoft/Windows/Start Menu/Programs"
        
        # Create batch file for launcher
        batch_content = f'''@echo off
cd /d "{self.install_prefix}"
python launcher.py %*
'''
        
        batch_file = self.install_prefix / "purgeproof.bat"
        with open(batch_file, 'w') as f:
            f.write(batch_content)
        
        # Add to PATH if system install
        if self.system_install:
            try:
                # Add to system PATH using PowerShell
                ps_command = f'''
$path = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($path -notlike "*{self.install_prefix}*") {{
    [Environment]::SetEnvironmentVariable("PATH", "$path;{self.install_prefix}", "Machine")
}}
'''
                self.run_command(['powershell', '-Command', ps_command])
                self.log('success', "Added to system PATH")
            except Exception as e:
                self.log('warning', f"Failed to add to PATH: {e}")
    
    def _create_linux_shortcuts(self):
        """Create Linux shortcuts."""
        # Create executable script
        bin_dir = Path.home() / ".local/bin"
        if self.system_install:
            bin_dir = Path("/usr/local/bin")
        
        bin_dir.mkdir(parents=True, exist_ok=True)
        
        script_content = f'''#!/bin/bash
cd "{self.install_prefix}"
python3 launcher.py "$@"
'''
        
        script_file = bin_dir / "purgeproof"
        with open(script_file, 'w') as f:
            f.write(script_content)
        
        script_file.chmod(0o755)
        
        # Create desktop entry
        desktop_entry = f'''[Desktop Entry]
Version=1.0
Type=Application
Name=PurgeProof
Comment=Secure data sanitization tool
Exec={script_file} --gui
Icon=security-high
Terminal=false
Categories=System;Security;
StartupNotify=true
'''
        
        # User desktop entry
        applications_dir = Path.home() / ".local/share/applications"
        if self.system_install:
            applications_dir = Path("/usr/share/applications")
        
        applications_dir.mkdir(parents=True, exist_ok=True)
        
        desktop_file = applications_dir / "purgeproof.desktop"
        with open(desktop_file, 'w') as f:
            f.write(desktop_entry)
        
        desktop_file.chmod(0o644)
        
        self.log('success', "Created Linux shortcuts")
    
    def _create_macos_shortcuts(self):
        """Create macOS shortcuts."""
        # Create executable script
        bin_dir = Path("/usr/local/bin")
        
        script_content = f'''#!/bin/bash
cd "{self.install_prefix}"
python3 launcher.py "$@"
'''
        
        script_file = bin_dir / "purgeproof"
        
        if self.system_install:
            with open(script_file, 'w') as f:
                f.write(script_content)
            script_file.chmod(0o755)
        
        self.log('success', "Created macOS shortcuts")
    
    def configure_application(self):
        """Configure the application."""
        self.log('info', "Configuring application...")
        
        # Create user config if it doesn't exist
        user_config = self.config_dir / "config.yaml"
        if not user_config.exists():
            default_config = self.config_dir / "default.yaml"
            if default_config.exists():
                shutil.copy2(default_config, user_config)
                self.log('success', "Created user configuration")
        
        # Create certificates directory
        cert_dir = self.data_dir / "certificates"
        cert_dir.mkdir(parents=True, exist_ok=True)
        
        # Create logs directory
        log_dir = self.data_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        self.log('success', "Application configured")
    
    def verify_installation(self):
        """Verify the installation."""
        self.log('info', "Verifying installation...")
        
        try:
            # Test import
            sys.path.insert(0, str(self.install_prefix))
            
            # Test launcher
            result = self.run_command([
                sys.executable,
                str(self.install_prefix / "launcher.py"),
                "--check"
            ], capture_output=True)
            
            if result.returncode == 0:
                self.log('success', "Installation verified ✓")
                return True
            else:
                self.log('error', "Installation verification failed")
                return False
        
        except Exception as e:
            self.log('error', f"Verification failed: {e}")
            return False
    
    def uninstall(self):
        """Uninstall PurgeProof."""
        self.log('info', "Uninstalling PurgeProof...")
        
        # Remove installation directory
        if self.install_prefix and self.install_prefix.exists():
            shutil.rmtree(self.install_prefix)
            self.log('success', f"Removed {self.install_prefix}")
        
        # Remove shortcuts
        if self.platform == 'windows':
            # Remove from PATH
            pass  # Implementation would require PowerShell
        elif self.platform == 'linux':
            # Remove executable
            bin_file = Path.home() / ".local/bin/purgeproof"
            if self.system_install:
                bin_file = Path("/usr/local/bin/purgeproof")
            
            if bin_file.exists():
                bin_file.unlink()
            
            # Remove desktop entry
            desktop_file = Path.home() / ".local/share/applications/purgeproof.desktop"
            if self.system_install:
                desktop_file = Path("/usr/share/applications/purgeproof.desktop")
            
            if desktop_file.exists():
                desktop_file.unlink()
        
        # Ask about config and data
        try:
            response = input("Remove configuration and data directories? [y/N]: ")
            if response.lower() in ['y', 'yes']:
                if self.config_dir and self.config_dir.exists():
                    shutil.rmtree(self.config_dir)
                    self.log('success', f"Removed {self.config_dir}")
                
                if self.data_dir and self.data_dir.exists():
                    shutil.rmtree(self.data_dir)
                    self.log('success', f"Removed {self.data_dir}")
        except KeyboardInterrupt:
            pass
        
        self.log('success', "Uninstallation complete")
    
    def check_installation(self):
        """Check installation status."""
        self.log('info', "Checking installation status...")
        
        self.determine_install_paths()
        
        status = {
            'installed': False,
            'install_prefix': str(self.install_prefix),
            'config_dir': str(self.config_dir),
            'data_dir': str(self.data_dir),
            'components': {}
        }
        
        # Check components
        components = {
            'core_files': self.install_prefix / "wipeit",
            'launcher': self.install_prefix / "launcher.py",
            'config': self.config_dir / "config.yaml",
            'certificates_dir': self.data_dir / "certificates",
            'logs_dir': self.data_dir / "logs"
        }
        
        for name, path in components.items():
            exists = path.exists()
            status['components'][name] = {
                'path': str(path),
                'exists': exists
            }
            
            if exists:
                self.log('success', f"{name}: ✓")
            else:
                self.log('warning', f"{name}: ✗")
        
        # Overall status
        core_exists = (
            status['components']['core_files']['exists'] and
            status['components']['launcher']['exists']
        )
        
        status['installed'] = core_exists
        
        if core_exists:
            self.log('success', "PurgeProof is installed")
        else:
            self.log('warning', "PurgeProof is not installed")
        
        return status
    
    def install(self):
        """Perform complete installation."""
        self.log('info', f"Starting PurgeProof installation on {self.platform}")
        
        try:
            # Check prerequisites
            if not self.check_prerequisites():
                self.log('error', "Prerequisites check failed")
                return False
            
            # Determine paths
            self.determine_install_paths()
            
            # Install components
            self.install_python_dependencies()
            self.install_application_files()
            self.create_shortcuts()
            self.configure_application()
            
            # Verify installation
            if self.verify_installation():
                self.log('success', "✅ Installation completed successfully!")
                self.log('info', f"Run 'purgeproof' to start the application")
                return True
            else:
                self.log('error', "❌ Installation verification failed")
                return False
        
        except Exception as e:
            self.log('error', f"Installation failed: {e}")
            return False


def main():
    """Main installation function."""
    parser = argparse.ArgumentParser(
        description="PurgeProof Installation Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python install.py                    # User installation
  sudo python install.py --system     # System installation
  python install.py --gui             # Install with GUI support
  python install.py --dev             # Development installation
  python install.py --uninstall       # Uninstall
  python install.py --check           # Check status
        """
    )
    
    parser.add_argument('--system', action='store_true',
                       help='Install system-wide (requires admin/sudo)')
    parser.add_argument('--user', action='store_true',
                       help='Install for current user (default)')
    parser.add_argument('--dev', action='store_true',
                       help='Install in development mode')
    parser.add_argument('--gui', action='store_true',
                       help='Install GUI dependencies')
    parser.add_argument('--minimal', action='store_true',
                       help='Minimal installation (CLI only)')
    parser.add_argument('--config', action='store_true',
                       help='Create default configuration files')
    parser.add_argument('--uninstall', action='store_true',
                       help='Uninstall PurgeProof')
    parser.add_argument('--check', action='store_true',
                       help='Check installation status')
    
    args = parser.parse_args()
    
    # Create installer
    installer = PurgeProofInstaller()
    
    # Set options
    installer.system_install = args.system
    installer.install_gui = args.gui
    installer.install_minimal = args.minimal
    installer.install_dev = args.dev
    
    # Execute requested action
    if args.uninstall:
        installer.determine_install_paths()
        installer.uninstall()
    elif args.check:
        status = installer.check_installation()
        print(json.dumps(status, indent=2))
    else:
        success = installer.install()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
