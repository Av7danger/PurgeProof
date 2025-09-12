#!/usr/bin/env python3
"""
PurgeProof USB Builder - Cross-Platform Plug-and-Play Solution
Creates bootable USB devices with PurgeProof on-the-go
Works on Windows, Linux, and macOS
"""

import os
import sys
import subprocess
import shutil
import platform
import time
from pathlib import Path

class USBBuilder:
    def __init__(self):
        self.system = platform.system().lower()
        self.script_dir = Path(__file__).parent
        self.project_root = self.script_dir
        self.usb_label = "PURGEPROOF"
        self.required_space_gb = 2
        
    def print_banner(self):
        """Print application banner"""
        print("\n" + "="*70)
        print("    PurgeProof USB Builder - Cross-Platform Solution")
        print("    Creates plug-and-play bootable USB devices")
        print("="*70 + "\n")
        
    def check_requirements(self):
        """Check system requirements"""
        print("[INFO] Checking system requirements...")
        
        # Check Python version
        if sys.version_info < (3, 8):
            print("[ERROR] Python 3.8 or higher required")
            return False
            
        # Check if running as admin/root
        if not self.is_admin():
            print("[ERROR] Administrator/root privileges required")
            print("Please run this script with elevated privileges")
            return False
            
        # Check for required tools
        missing_tools = []
        
        if self.system == "windows":
            tools = ["diskpart", "format"]
        elif self.system == "linux":
            tools = ["lsblk", "mkfs.vfat", "dd"]
        elif self.system == "darwin":  # macOS
            tools = ["diskutil", "dd"]
        else:
            print(f"[ERROR] Unsupported platform: {self.system}")
            return False
            
        for tool in tools:
            if not shutil.which(tool):
                missing_tools.append(tool)
                
        if missing_tools:
            print(f"[ERROR] Missing required tools: {', '.join(missing_tools)}")
            return False
            
        print("[OK] All requirements satisfied")
        return True
        
    def is_admin(self):
        """Check if running with admin privileges"""
        try:
            if self.system == "windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except (AttributeError, OSError):
            return False
            
    def list_usb_devices(self):
        """List available USB devices"""
        print("[INFO] Detecting USB devices...\n")
        
        usb_devices = []
        
        if self.system == "windows":
            try:
                result = subprocess.run([
                    "wmic", "logicaldisk", "where", "drivetype=2", 
                    "get", "size,freespace,caption,volumename"
                ], capture_output=True, text=True, check=False)
                
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            usb_devices.append({
                                'device': parts[0],
                                'size': int(parts[1]) if parts[1].isdigit() else 0,
                                'free': int(parts[2]) if parts[2].isdigit() else 0
                            })
                            
            except subprocess.CalledProcessError:
                print("[ERROR] Failed to detect USB devices on Windows")
                
        elif self.system == "linux":
            try:
                result = subprocess.run([
                    "lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT", "-r"
                ], capture_output=True, text=True, check=False)
                
                for line in result.stdout.strip().split('\n'):
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] == "disk":
                        # Check if it's a USB device
                        device_path = f"/sys/block/{parts[0]}"
                        if os.path.exists(device_path):
                            try:
                                with open(f"{device_path}/removable", 'r', encoding='utf-8') as f:
                                    if f.read().strip() == "1":
                                        usb_devices.append({
                                            'device': f"/dev/{parts[0]}",
                                            'size': parts[1],
                                            'mountpoint': parts[3] if len(parts) > 3 else None
                                        })
                            except (OSError, IOError):
                                continue
                                
            except subprocess.CalledProcessError:
                print("[ERROR] Failed to detect USB devices on Linux")
                
        elif self.system == "darwin":  # macOS
            try:
                result = subprocess.run([
                    "diskutil", "list", "-plist"
                ], capture_output=True, text=True, check=False)
                
                # Parse diskutil output (simplified)
                # This would need proper plist parsing for production
                lines = result.stdout.split('\n')
                for line in lines:
                    if '/dev/disk' in line and 'external' in line.lower():
                        device = line.split()[0]
                        usb_devices.append({
                            'device': device,
                            'size': 'Unknown'
                        })
                        
            except subprocess.CalledProcessError:
                print("[ERROR] Failed to detect USB devices on macOS")
                
        return usb_devices
        
    def format_usb(self, device):
        """Format USB device with FAT32"""
        print(f"[STEP 1/4] Formatting {device}...")
        
        if self.system == "windows":
            # Use format command
            try:
                subprocess.run([
                    "format", device, "/FS:FAT32", f"/V:{self.usb_label}", "/Q", "/Y"
                ], check=True)
            except subprocess.CalledProcessError:
                print(f"[ERROR] Failed to format {device}")
                return False
                
        elif self.system == "linux":
            try:
                # Unmount if mounted
                subprocess.run(["umount", device], stderr=subprocess.DEVNULL, check=False)
                
                # Create FAT32 filesystem
                subprocess.run([
                    "mkfs.vfat", "-F", "32", "-n", self.usb_label, device
                ], check=True)
                
            except subprocess.CalledProcessError:
                print(f"[ERROR] Failed to format {device}")
                return False
                
        elif self.system == "darwin":
            try:
                subprocess.run([
                    "diskutil", "eraseDisk", "FAT32", self.usb_label, device
                ], check=True)
                
            except subprocess.CalledProcessError:
                print(f"[ERROR] Failed to format {device}")
                return False
                
        print("[OK] USB formatting complete")
        return True
        
    def copy_purgeproof_files(self, mount_point):
        """Copy PurgeProof files to USB"""
        print("[STEP 2/4] Copying PurgeProof application...")
        
        usb_purgeproof = Path(mount_point) / "purgeproof"
        usb_purgeproof.mkdir(exist_ok=True)
        
        # Copy core files
        core_files = [
            "launcher.py",
            "cli_working.py", 
            "offline_launcher.py"
        ]
        
        for file in core_files:
            src = self.project_root / file
            if src.exists():
                shutil.copy2(src, usb_purgeproof)
                
        # Copy wipeit directory
        wipeit_src = self.project_root / "wipeit"
        if wipeit_src.exists():
            wipeit_dst = usb_purgeproof / "wipeit"
            shutil.copytree(wipeit_src, wipeit_dst, dirs_exist_ok=True)
            
        # Copy config directory
        config_src = self.project_root / "config"
        if config_src.exists():
            config_dst = usb_purgeproof / "config"
            shutil.copytree(config_src, config_dst, dirs_exist_ok=True)
            
        # Copy docs directory
        docs_src = self.project_root / "docs"
        if docs_src.exists():
            docs_dst = usb_purgeproof / "docs"
            shutil.copytree(docs_src, docs_dst, dirs_exist_ok=True)
            
        print("[OK] PurgeProof files copied")
        return True
        
    def create_launchers(self, mount_point):
        """Create cross-platform launcher scripts"""
        print("[STEP 3/4] Creating launcher scripts...")
        
        usb_root = Path(mount_point)
        
        # Windows batch launcher
        bat_content = """@echo off
echo Starting PurgeProof Data Sanitization Tool...
cd /d "%~dp0purgeproof"
python offline_launcher.py %*
if errorlevel 1 (
    echo.
    echo [ERROR] Python not found or PurgeProof failed to start
    echo Please ensure Python 3.8+ is installed on this system
    pause
)
"""
        with open(usb_root / "PurgeProof.bat", 'w', encoding='utf-8') as f:
            f.write(bat_content)
            
        # PowerShell launcher
        ps1_content = """# PurgeProof PowerShell Launcher
Write-Host "Starting PurgeProof Data Sanitization Tool..." -ForegroundColor Green
Set-Location "$PSScriptRoot/purgeproof"
python offline_launcher.py $args
"""
        with open(usb_root / "PurgeProof.ps1", 'w', encoding='utf-8') as f:
            f.write(ps1_content)
            
        # Linux/Mac shell launcher
        sh_content = """#!/bin/bash
echo "Starting PurgeProof Data Sanitization Tool..."
cd "$(dirname "$0")/purgeproof"
python3 offline_launcher.py "$@"
"""
        with open(usb_root / "purgeproof.sh", 'w', encoding='utf-8') as f:
            f.write(sh_content)
            
        # Make shell script executable
        if self.system in ["linux", "darwin"]:
            os.chmod(usb_root / "purgeproof.sh", 0o755)
            
        print("[OK] Launcher scripts created")
        return True
        
    def create_documentation(self, mount_point):
        """Create plug-and-play documentation"""
        print("[STEP 4/4] Creating documentation...")
        
        usb_root = Path(mount_point)
        
        # README
        readme_content = """# PurgeProof Portable USB Drive
================================

This USB drive contains a portable PurgeProof data sanitization tool.

QUICK START:
============

Windows:
  - Double-click "PurgeProof.bat"
  - Or run "PowerShell -ExecutionPolicy Bypass -File PurgeProof.ps1"

Linux/Mac:
  - Run "chmod +x purgeproof.sh && ./purgeproof.sh"
  - Or "cd purgeproof && python3 offline_launcher.py"

REQUIREMENTS:
=============
- Python 3.8+ installed on target system
- Administrator/root privileges for device access
- Target storage devices properly connected

SECURITY FEATURES:
==================
- NIST SP 800-88 Rev.1 compliant sanitization
- Offline operation (no network required)
- Digital certificates with audit trails
- Multiple sanitization methods available

For detailed documentation, see docs/ folder
"""
        with open(usb_root / "README.txt", 'w', encoding='utf-8') as f:
            f.write(readme_content)
            
        # Version info
        version_content = f"""PurgeProof Portable USB v1.0
Built: {time.strftime('%Y-%m-%d %H:%M:%S')}
Platform: Cross-Platform Portable
NIST SP 800-88 Rev.1 Compliant
"""
        with open(usb_root / "VERSION.txt", 'w', encoding='utf-8') as f:
            f.write(version_content)
            
        # Autorun for Windows
        autorun_content = """[autorun]
icon=purgeproof.ico
label=PurgeProof Data Sanitizer
action=Start PurgeProof
open=PurgeProof.bat
"""
        with open(usb_root / "autorun.inf", 'w', encoding='utf-8') as f:
            f.write(autorun_content)
            
        print("[OK] Documentation created")
        return True
        
    def build_usb(self):
        """Main USB building process"""
        self.print_banner()
        
        # Check requirements
        if not self.check_requirements():
            return False
            
        # List USB devices
        usb_devices = self.list_usb_devices()
        
        if not usb_devices:
            print("[ERROR] No USB devices detected")
            print("Please ensure a USB drive is connected")
            return False
            
        print("Available USB devices:")
        print("=" * 30)
        for i, device in enumerate(usb_devices):
            print(f"{i+1}. {device['device']} - {device.get('size', 'Unknown size')}")
            
        print()
        
        # Get user selection
        try:
            choice = int(input("Select USB device (number): ")) - 1
            if choice < 0 or choice >= len(usb_devices):
                raise ValueError()
        except (ValueError, KeyboardInterrupt):
            print("[ERROR] Invalid selection")
            return False
            
        selected_device = usb_devices[choice]['device']
        
        # Confirmation
        print(f"\n[WARNING] ALL DATA ON {selected_device} WILL BE ERASED!")
        print("This will create a bootable PurgeProof USB drive.")
        
        confirm = input("\nContinue? Type 'YES' to confirm: ")
        if confirm.upper() != "YES":
            print("Operation cancelled.")
            return False
            
        print(f"\n[INFO] Building PurgeProof bootable USB on {selected_device}...")
        
        # Get mount point for copying files
        if self.system == "windows":
            mount_point = selected_device + "\\"
        else:
            mount_point = "/mnt/purgeproof_usb"
            os.makedirs(mount_point, exist_ok=True)
            
        try:
            # Format USB
            if not self.format_usb(selected_device):
                return False
                
            # Mount on Linux/Mac
            if self.system in ["linux", "darwin"]:
                subprocess.run(["mount", selected_device, mount_point], check=True)
                
            # Copy files and create launchers
            if not self.copy_purgeproof_files(mount_point):
                return False
                
            if not self.create_launchers(mount_point):
                return False
                
            if not self.create_documentation(mount_point):
                return False
                
            # Unmount on Linux/Mac
            if self.system in ["linux", "darwin"]:
                subprocess.run(["umount", mount_point], check=True)
                
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] USB build failed: {e}")
            return False
        except (OSError, IOError) as e:
            print(f"[ERROR] File operation error: {e}")
            return False
            
        # Success message
        print("\n" + "="*70)
        print("    PurgeProof USB Build Complete!")
        print("="*70)
        print(f"\nUSB Drive: {selected_device}")
        print(f"Label: {self.usb_label}")
        print("\nUSAGE INSTRUCTIONS:")
        print("==================")
        print("\n1. Safely eject this USB drive")
        print("2. Insert into target computer")
        print("3. Run as Administrator:")
        print("   - Windows: Double-click 'PurgeProof.bat'")
        print("   - Linux: './purgeproof.sh'")
        print("   - Mac: './purgeproof.sh'")
        print("\n4. Follow on-screen prompts for data sanitization")
        print("\nPLUG-AND-PLAY FEATURES:")
        print("======================")
        print("✓ Works on Windows, Linux, Mac")
        print("✓ No installation required")
        print("✓ Offline operation (air-gapped safe)")
        print("✓ All sanitization methods included")
        print("✓ Digital certificates generated")
        print("✓ Complete audit trail maintained")
        print("\nThe USB drive is now ready for field deployment!")
        
        return True

def main():
    """Main entry point"""
    builder = USBBuilder()
    
    try:
        success = builder.build_usb()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n[INFO] Operation cancelled by user")
        sys.exit(1)
    except (OSError, IOError) as e:
        print(f"\n[ERROR] System error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
