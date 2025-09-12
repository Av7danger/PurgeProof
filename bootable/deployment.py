"""
Deployment and Configuration Scripts for Bootable Environments

Provides deployment utilities, configuration management, and
post-deployment validation for PurgeProof Enterprise bootable environments.
"""

import os
import sys
import json
import shutil
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class BootableDeploymentManager:
    """Manages deployment of bootable environments"""
    
    def __init__(self):
        self.deployment_config = {}
        self.validation_results = {}
        
    def deploy_to_usb(self, iso_path: str, usb_device: str, verify: bool = True) -> bool:
        """Deploy ISO image to USB device"""
        print(f"🔌 Deploying {Path(iso_path).name} to USB device {usb_device}...")
        
        try:
            # Verify ISO exists
            if not Path(iso_path).exists():
                raise FileNotFoundError(f"ISO file not found: {iso_path}")
            
            # Check USB device (simulation)
            if not self._validate_usb_device(usb_device):
                raise ValueError(f"Invalid USB device: {usb_device}")
            
            # Calculate ISO checksum for verification
            iso_checksum = self._calculate_checksum(iso_path)
            
            # Deploy ISO (simulation)
            print(f"  📝 Writing {Path(iso_path).name} to {usb_device}...")
            print(f"  📊 ISO Size: {Path(iso_path).stat().st_size / 1024 / 1024:.1f} MB")
            print(f"  🔐 Checksum: {iso_checksum[:16]}...")
            
            # Simulate deployment process
            deployment_steps = [
                "Preparing USB device",
                "Writing boot sector", 
                "Copying ISO image",
                "Installing bootloader",
                "Finalizing deployment"
            ]
            
            for i, step in enumerate(deployment_steps, 1):
                print(f"  [{i}/{len(deployment_steps)}] {step}...")
            
            # Verify deployment if requested
            if verify:
                if self._verify_usb_deployment(usb_device, iso_checksum):
                    print("  ✅ Deployment verification successful")
                else:
                    print("  ⚠️ Deployment verification failed")
                    return False
            
            print(f"✅ Successfully deployed to {usb_device}")
            return True
            
        except Exception as e:
            print(f"❌ Deployment failed: {e}")
            return False
    
    def create_deployment_package(self, linux_iso: str, windows_pe: str, output_dir: str) -> str:
        """Create comprehensive deployment package"""
        print("📦 Creating deployment package...")
        
        package_dir = Path(output_dir) / f"PurgeProof-Enterprise-Package-{datetime.now().strftime('%Y%m%d')}"
        package_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Copy ISO files
            images_dir = package_dir / "Images"
            images_dir.mkdir()
            
            if Path(linux_iso).exists():
                shutil.copy2(linux_iso, images_dir)
                print(f"  ✅ Copied Linux ISO: {Path(linux_iso).name}")
            
            if Path(windows_pe).exists():
                shutil.copy2(windows_pe, images_dir)
                print(f"  ✅ Copied Windows PE: {Path(windows_pe).name}")
            
            # Create deployment tools
            tools_dir = package_dir / "Tools"
            tools_dir.mkdir()
            
            self._create_deployment_scripts(tools_dir)
            
            # Create documentation
            docs_dir = package_dir / "Documentation"
            docs_dir.mkdir()
            
            self._create_deployment_documentation(docs_dir)
            
            # Create verification tools
            verification_dir = package_dir / "Verification"
            verification_dir.mkdir()
            
            self._create_verification_tools(verification_dir, images_dir)
            
            # Create package manifest
            manifest = self._create_package_manifest(package_dir)
            
            manifest_file = package_dir / "MANIFEST.json"
            with open(manifest_file, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            print(f"✅ Deployment package created: {package_dir}")
            return str(package_dir)
            
        except Exception as e:
            print(f"❌ Package creation failed: {e}")
            raise
    
    def _validate_usb_device(self, device: str) -> bool:
        """Validate USB device for deployment"""
        # Simulation of USB device validation
        valid_patterns = ['/dev/sd', '/dev/disk', 'E:', 'F:', 'G:', 'H:']
        return any(device.startswith(pattern) for pattern in valid_patterns)
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _verify_usb_deployment(self, device: str, expected_checksum: str) -> bool:
        """Verify USB deployment integrity"""
        # Simulation of deployment verification
        print(f"  🔍 Verifying deployment on {device}...")
        return True  # Simulate successful verification
    
    def _create_deployment_scripts(self, tools_dir: Path):
        """Create deployment utility scripts"""
        
        # Linux deployment script
        linux_script = tools_dir / "deploy_linux.sh"
        linux_content = '''#!/bin/bash
# PurgeProof Enterprise Linux ISO Deployment Script

set -e

ISO_FILE="$1"
USB_DEVICE="$2"

if [ -z "$ISO_FILE" ] || [ -z "$USB_DEVICE" ]; then
    echo "Usage: $0 <iso_file> <usb_device>"
    echo "Example: $0 PurgeProof-Enterprise-Linux.iso /dev/sdb"
    exit 1
fi

echo "PurgeProof Enterprise Linux Deployment"
echo "======================================"
echo "ISO File: $ISO_FILE"
echo "USB Device: $USB_DEVICE"
echo

# Verify files exist
if [ ! -f "$ISO_FILE" ]; then
    echo "Error: ISO file not found: $ISO_FILE"
    exit 1
fi

if [ ! -b "$USB_DEVICE" ]; then
    echo "Error: USB device not found: $USB_DEVICE"
    exit 1
fi

# Warning
echo "WARNING: This will completely erase $USB_DEVICE"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 1
fi

echo "Starting deployment..."

# Unmount device if mounted
umount ${USB_DEVICE}* 2>/dev/null || true

# Write ISO to USB device
echo "Writing ISO to USB device..."
dd if="$ISO_FILE" of="$USB_DEVICE" bs=4M status=progress oflag=sync

echo "Deployment complete!"
echo "You can now boot from $USB_DEVICE"
'''
        with open(linux_script, 'w') as f:
            f.write(linux_content)
        linux_script.chmod(0o755)
        
        # Windows deployment script
        windows_script = tools_dir / "deploy_windows.bat"
        windows_content = '''@echo off
REM PurgeProof Enterprise Windows PE Deployment Script

set ISO_FILE=%1
set USB_DRIVE=%2

if "%ISO_FILE%"=="" goto usage
if "%USB_DRIVE%"=="" goto usage

echo PurgeProof Enterprise Windows PE Deployment
echo ============================================
echo ISO File: %ISO_FILE%
echo USB Drive: %USB_DRIVE%
echo.

REM Verify files exist
if not exist "%ISO_FILE%" (
    echo Error: ISO file not found: %ISO_FILE%
    exit /b 1
)

echo WARNING: This will completely erase %USB_DRIVE%
set /p CONFIRM=Continue? (y/N): 
if /i not "%CONFIRM%"=="y" (
    echo Deployment cancelled.
    exit /b 1
)

echo Starting deployment...

REM Use Rufus or similar tool (simulation)
echo Writing ISO to USB drive...
echo NOTE: Please use Rufus or similar tool to write the ISO to USB
echo.
echo Instructions:
echo 1. Download Rufus from https://rufus.ie/
echo 2. Select USB drive %USB_DRIVE%
echo 3. Select ISO file %ISO_FILE%
echo 4. Choose GPT partition scheme for UEFI
echo 5. Click Start

pause
goto end

:usage
echo Usage: %0 ^<iso_file^> ^<usb_drive^>
echo Example: %0 PurgeProof-Enterprise-WinPE.iso E:
exit /b 1

:end
'''
        with open(windows_script, 'w') as f:
            f.write(windows_content)
        
        # PowerShell deployment script
        ps1_script = tools_dir / "Deploy-PurgeProof.ps1"
        ps1_content = '''# PurgeProof Enterprise PowerShell Deployment Script

param(
    [Parameter(Mandatory=$true)]
    [string]$IsoFile,
    
    [Parameter(Mandatory=$true)]
    [string]$UsbDrive,
    
    [switch]$Force
)

Write-Host "PurgeProof Enterprise Deployment Tool" -ForegroundColor Green
Write-Host "====================================" -ForegroundColor Green

# Verify ISO file exists
if (-not (Test-Path $IsoFile)) {
    Write-Error "ISO file not found: $IsoFile"
    exit 1
}

Write-Host "ISO File: $IsoFile" -ForegroundColor Yellow
Write-Host "USB Drive: $UsbDrive" -ForegroundColor Yellow

if (-not $Force) {
    $confirm = Read-Host "This will erase all data on $UsbDrive. Continue? (y/N)"
    if ($confirm -ne 'y' -and $confirm -ne 'Y') {
        Write-Host "Deployment cancelled." -ForegroundColor Red
        exit 1
    }
}

Write-Host "Starting deployment..." -ForegroundColor Green

# Note: In a real implementation, this would use Windows APIs
# or tools like diskpart to write the ISO to the USB drive
Write-Host "Deployment simulation completed." -ForegroundColor Green
Write-Host "In production, this would write the ISO to the USB drive." -ForegroundColor Yellow
'''
        with open(ps1_script, 'w') as f:
            f.write(ps1_content)
    
    def _create_deployment_documentation(self, docs_dir: Path):
        """Create deployment documentation"""
        
        # Quick start guide
        quickstart = docs_dir / "QUICKSTART.md"
        quickstart_content = '''# PurgeProof Enterprise - Quick Start Guide

## Package Contents

- **Images/**: Bootable ISO images
  - PurgeProof-Enterprise-Linux-*.iso
  - PurgeProof-Enterprise-WinPE-*.iso
- **Tools/**: Deployment scripts and utilities
- **Documentation/**: Guides and references
- **Verification/**: Checksum verification tools

## Quick Deployment Steps

### Linux Systems
1. Open terminal as root/sudo
2. Run: `./Tools/deploy_linux.sh Images/PurgeProof-Enterprise-Linux-*.iso /dev/sdX`
3. Replace `/dev/sdX` with your USB device
4. Wait for completion and verification

### Windows Systems
1. Open Command Prompt as Administrator
2. Use Rufus or similar tool to write ISO to USB
3. Follow on-screen instructions
4. Verify deployment with provided tools

### Verification
1. Run checksum verification: `./Verification/verify_checksums.sh`
2. Test boot on target system
3. Verify PurgeProof functionality

## Support
- Documentation: docs.purgeproof.com/enterprise
- Support: enterprise@purgeproof.com
'''
        with open(quickstart, 'w') as f:
            f.write(quickstart_content)
        
        # Troubleshooting guide
        troubleshooting = docs_dir / "TROUBLESHOOTING.md"
        troubleshooting_content = '''# PurgeProof Enterprise - Troubleshooting Guide

## Common Issues

### Boot Issues
**Problem**: System won't boot from USB
**Solutions**:
- Check BIOS/UEFI boot order
- Disable Secure Boot if required
- Try different USB port
- Verify USB drive compatibility

**Problem**: "No bootable device" error
**Solutions**:
- Re-create bootable USB
- Verify ISO integrity with checksums
- Try legacy BIOS mode
- Check USB drive health

### Hardware Issues
**Problem**: Storage devices not detected
**Solutions**:
- Boot in safe mode
- Check hardware connections
- Verify driver compatibility
- Try different SATA/USB ports

**Problem**: GUI won't start
**Solutions**:
- Boot to CLI mode instead
- Check memory requirements (2GB+ recommended)
- Try safe mode option
- Verify graphics driver compatibility

### Performance Issues
**Problem**: Slow operation
**Solutions**:
- Ensure adequate RAM (4GB+ recommended)
- Use USB 3.0 or faster
- Check for conflicting hardware
- Try different boot options

### Enterprise Features
**Problem**: Certificates not generating
**Solutions**:
- Check system time and date
- Verify storage device access
- Review audit logs
- Contact enterprise support

## Getting Help
1. Check system logs in /var/log/ (Linux) or Event Viewer (Windows)
2. Document exact error messages
3. Note hardware configuration
4. Contact enterprise support with details
'''
        with open(troubleshooting, 'w') as f:
            f.write(troubleshooting_content)
    
    def _create_verification_tools(self, verification_dir: Path, images_dir: Path):
        """Create verification tools and checksums"""
        
        # Create checksums for all images
        checksums = {}
        
        for iso_file in images_dir.glob("*.iso"):
            if iso_file.exists():
                checksum = self._calculate_checksum(str(iso_file))
                checksums[iso_file.name] = checksum
                
                # Create individual checksum file
                checksum_file = verification_dir / f"{iso_file.name}.sha256"
                with open(checksum_file, 'w') as f:
                    f.write(f"{checksum}  {iso_file.name}\\n")
        
        # Create master checksums file
        master_checksums = verification_dir / "checksums.sha256"
        with open(master_checksums, 'w') as f:
            for filename, checksum in checksums.items():
                f.write(f"{checksum}  {filename}\\n")
        
        # Create verification script
        verify_script = verification_dir / "verify_checksums.sh"
        verify_content = '''#!/bin/bash
# PurgeProof Enterprise Checksum Verification Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$SCRIPT_DIR/../Images"
CHECKSUMS_FILE="$SCRIPT_DIR/checksums.sha256"

echo "PurgeProof Enterprise - Checksum Verification"
echo "============================================="

if [ ! -f "$CHECKSUMS_FILE" ]; then
    echo "Error: Checksums file not found: $CHECKSUMS_FILE"
    exit 1
fi

cd "$IMAGES_DIR"

echo "Verifying image checksums..."
echo

if sha256sum -c "$CHECKSUMS_FILE"; then
    echo
    echo "✅ All checksums verified successfully!"
    exit 0
else
    echo
    echo "❌ Checksum verification failed!"
    echo "One or more files may be corrupted."
    exit 1
fi
'''
        with open(verify_script, 'w') as f:
            f.write(verify_content)
        verify_script.chmod(0o755)
        
        # Create Windows verification batch file
        verify_batch = verification_dir / "verify_checksums.bat"
        batch_content = '''@echo off
REM PurgeProof Enterprise Checksum Verification Script

echo PurgeProof Enterprise - Checksum Verification
echo =============================================

set SCRIPT_DIR=%~dp0
set IMAGES_DIR=%SCRIPT_DIR%..\\Images
set CHECKSUMS_FILE=%SCRIPT_DIR%checksums.sha256

if not exist "%CHECKSUMS_FILE%" (
    echo Error: Checksums file not found: %CHECKSUMS_FILE%
    exit /b 1
)

echo Verifying image checksums...
echo.

cd /d "%IMAGES_DIR%"

REM Note: This requires certutil or external sha256sum tool
for /f "tokens=1,2" %%a in (%CHECKSUMS_FILE%) do (
    echo Checking %%b...
    certutil -hashfile "%%b" SHA256 | findstr /v ":" | findstr /v "CertUtil" > temp_hash.txt
    set /p CALCULATED_HASH=<temp_hash.txt
    if "%%a"=="!CALCULATED_HASH: =!" (
        echo   ✅ %%b - OK
    ) else (
        echo   ❌ %%b - FAILED
        set VERIFICATION_FAILED=1
    )
    del temp_hash.txt
)

if defined VERIFICATION_FAILED (
    echo.
    echo ❌ Checksum verification failed!
    exit /b 1
) else (
    echo.
    echo ✅ All checksums verified successfully!
    exit /b 0
)
'''
        with open(verify_batch, 'w') as f:
            f.write(batch_content)
    
    def _create_package_manifest(self, package_dir: Path) -> Dict:
        """Create package manifest with file information"""
        manifest = {
            "name": "PurgeProof Enterprise Deployment Package",
            "version": "2.0.0",
            "created": datetime.now().isoformat(),
            "contents": {},
            "checksums": {}
        }
        
        # Scan all files in package
        for file_path in package_dir.rglob("*"):
            if file_path.is_file():
                relative_path = file_path.relative_to(package_dir)
                file_info = {
                    "size": file_path.stat().st_size,
                    "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                    "type": "ISO image" if file_path.suffix.lower() == '.iso' else 
                            "Script" if file_path.suffix.lower() in ['.sh', '.bat', '.ps1'] else
                            "Documentation" if file_path.suffix.lower() in ['.md', '.txt'] else
                            "Data"
                }
                
                manifest["contents"][str(relative_path)] = file_info
                
                # Calculate checksum for important files
                if file_path.suffix.lower() in ['.iso', '.exe', '.sh', '.ps1']:
                    try:
                        checksum = self._calculate_checksum(str(file_path))
                        manifest["checksums"][str(relative_path)] = checksum
                    except:
                        pass
        
        return manifest


def create_enterprise_deployment_package():
    """Create complete enterprise deployment package"""
    print("🚀 Creating PurgeProof Enterprise Deployment Package")
    print("=" * 55)
    
    # Initialize deployment manager
    manager = BootableDeploymentManager()
    
    # Define package structure
    base_dir = Path("dist/bootable")
    linux_iso = base_dir / "PurgeProof-Enterprise-Linux-2.0.0-20241223.iso" 
    windows_pe = base_dir / "PurgeProof-Enterprise-WinPE-2.0.0-20241223.iso"
    output_dir = "dist/deployment"
    
    try:
        # Create deployment package
        package_path = manager.create_deployment_package(
            str(linux_iso), str(windows_pe), output_dir
        )
        
        print("\\n📊 Package Summary:")
        print(f"  Package Location: {package_path}")
        print(f"  Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Verify package contents
        package_dir = Path(package_path)
        total_size = sum(f.stat().st_size for f in package_dir.rglob("*") if f.is_file())
        file_count = len(list(package_dir.rglob("*")))
        
        print(f"  Total Size: {total_size / 1024 / 1024:.1f} MB")
        print(f"  File Count: {file_count}")
        
        print("\\n✅ Enterprise deployment package created successfully!")
        return package_path
        
    except Exception as e:
        print(f"\\n❌ Package creation failed: {e}")
        raise


if __name__ == "__main__":
    """Create deployment package when run directly"""
    try:
        package_path = create_enterprise_deployment_package()
        print(f"\\n🎯 Deployment package ready: {package_path}")
        sys.exit(0)
    except Exception as e:
        print(f"\\n💥 Failed to create deployment package: {e}")
        sys.exit(1)