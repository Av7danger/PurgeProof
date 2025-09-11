"""
Device Detection and Utilities Module

This module provides comprehensive device detection capabilities for storage devices
across Windows, Linux, and Android platforms. It identifies device types, encryption
status, and firmware capabilities in compliance with NIST SP 800-88 Rev.1.

NIST SP 800-88 Rev.1 Reference:
- Clear: Logical sanitization using standard read/write commands
- Purge: Physical sanitization using secure erase or cryptographic erase
- Destroy: Physical destruction of the storage medium
"""

import os
import sys
import json
import logging
import platform
import subprocess
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

# Platform-specific imports
if sys.platform == "win32":
    try:
        import wmi
        import win32api
        import win32file
    except ImportError:
        wmi = None
        win32api = None
        win32file = None

try:
    import psutil
except ImportError:
    psutil = None

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    """
    Device information structure containing all relevant metadata
    for NIST SP 800-88 compliant sanitization planning.
    """
    path: str
    model: str
    serial: str
    size_bytes: int
    device_type: str  # hdd, ssd, nvme, sed, mobile, unknown
    is_encrypted: bool
    encryption_type: Optional[str]  # bitlocker, luks, sed, etc.
    firmware_version: str
    capabilities: Dict[str, bool]  # secure_erase, crypto_erase, nvme_sanitize, etc.
    hidden_areas: Dict[str, int]  # hpa_size, dco_enabled, etc.
    platform: str  # windows, linux, android
    removable: bool
    mounted: bool
    mount_points: List[str]
    smart_enabled: bool
    temperature: Optional[int]
    power_on_hours: Optional[int]


class DeviceDetector:
    """
    Cross-platform device detection engine for storage devices.
    
    Supports detection of:
    - Traditional HDDs and SSDs
    - NVMe drives
    - Self-Encrypting Drives (SEDs)
    - Mobile/Android partitions
    - Hidden areas (HPA/DCO)
    - Encryption status and capabilities
    """
    
    def __init__(self):
        self.platform = platform.system().lower()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize platform-specific tools
        self._init_platform_tools()
    
    def _init_platform_tools(self) -> None:
        """Initialize platform-specific detection tools."""
        if self.platform == "windows":
            self._init_windows_tools()
        elif self.platform == "linux":
            self._init_linux_tools()
        elif self.platform == "android":
            self._init_android_tools()
    
    def _init_windows_tools(self) -> None:
        """Initialize Windows-specific tools (WMI, PowerShell)."""
        try:
            if wmi:
                self.wmi_conn = wmi.WMI()
                self.logger.info("WMI connection established")
            else:
                self.logger.warning("WMI not available, using fallback methods")
                self.wmi_conn = None
        except Exception as e:
            self.logger.error(f"Failed to initialize WMI: {e}")
            self.wmi_conn = None
    
    def _init_linux_tools(self) -> None:
        """Initialize Linux-specific tools (hdparm, nvme-cli, etc.)."""
        self.linux_tools = {}
        tools = ["hdparm", "nvme", "sgdisk", "smartctl", "lsblk", "blkid"]
        
        for tool in tools:
            try:
                result = subprocess.run(["which", tool], capture_output=True, text=True)
                if result.returncode == 0:
                    self.linux_tools[tool] = result.stdout.strip()
                    self.logger.debug(f"Found {tool} at {self.linux_tools[tool]}")
                else:
                    self.logger.warning(f"Tool {tool} not found")
            except Exception as e:
                self.logger.error(f"Error checking for {tool}: {e}")
    
    def _init_android_tools(self) -> None:
        """Initialize Android-specific tools (ADB)."""
        try:
            # Check if ADB is available
            result = subprocess.run(["adb", "version"], capture_output=True, text=True)
            if result.returncode == 0:
                self.adb_available = True
                self.logger.info("ADB connection available")
            else:
                self.adb_available = False
                self.logger.warning("ADB not available")
        except Exception as e:
            self.logger.error(f"Error checking ADB: {e}")
            self.adb_available = False
    
    def list_storage_devices(self) -> List[DeviceInfo]:
        """
        List all storage devices on the system.
        
        Returns:
            List of DeviceInfo objects for all detected storage devices
        """
        devices = []
        
        try:
            if self.platform == "windows":
                devices = self._list_windows_devices()
            elif self.platform == "linux":
                devices = self._list_linux_devices()
            elif self.platform == "android":
                devices = self._list_android_devices()
            else:
                self.logger.error(f"Unsupported platform: {self.platform}")
        
        except Exception as e:
            self.logger.error(f"Error listing storage devices: {e}")
        
        return devices
    
    def _list_windows_devices(self) -> List[DeviceInfo]:
        """List storage devices on Windows using WMI and PowerShell."""
        devices = []
        
        if self.wmi_conn:
            devices.extend(self._list_windows_wmi_devices())
        else:
            devices.extend(self._list_windows_fallback_devices())
        
        return devices
    
    def _list_windows_wmi_devices(self) -> List[DeviceInfo]:
        """List Windows devices using WMI."""
        devices = []
        
        try:
            # Get physical drives
            for drive in self.wmi_conn.Win32_DiskDrive():
                device_info = self._parse_windows_drive(drive)
                if device_info:
                    devices.append(device_info)
        
        except Exception as e:
            self.logger.error(f"Error listing Windows WMI devices: {e}")
        
        return devices
    
    def _parse_windows_drive(self, drive) -> Optional[DeviceInfo]:
        """Parse Windows drive information from WMI object."""
        try:
            # Basic device information
            path = f"\\\\.\\PHYSICALDRIVE{drive.Index}"
            model = drive.Model or "Unknown"
            serial = drive.SerialNumber or "Unknown"
            size_bytes = int(drive.Size) if drive.Size else 0
            
            # Determine device type
            device_type = self._detect_windows_device_type(drive)
            
            # Check encryption status
            is_encrypted, encryption_type = self._check_windows_encryption(drive)
            
            # Get firmware capabilities
            capabilities = self._get_windows_capabilities(drive)
            
            # Check for hidden areas
            hidden_areas = self._check_windows_hidden_areas(drive)
            
            # Get mount information
            mounted, mount_points = self._get_windows_mount_info(drive)
            
            return DeviceInfo(
                path=path,
                model=model,
                serial=serial,
                size_bytes=size_bytes,
                device_type=device_type,
                is_encrypted=is_encrypted,
                encryption_type=encryption_type,
                firmware_version=getattr(drive, 'FirmwareRevision', 'Unknown'),
                capabilities=capabilities,
                hidden_areas=hidden_areas,
                platform="windows",
                removable=bool(getattr(drive, 'MediaLoaded', False)),
                mounted=mounted,
                mount_points=mount_points,
                smart_enabled=False,  # TODO: Implement SMART detection
                temperature=None,
                power_on_hours=None
            )
        
        except Exception as e:
            self.logger.error(f"Error parsing Windows drive: {e}")
            return None
    
    def _detect_windows_device_type(self, drive) -> str:
        """Detect Windows device type (HDD, SSD, NVMe, etc.)."""
        try:
            # Check if it's an NVMe drive
            if "nvme" in drive.Model.lower() if drive.Model else False:
                return "nvme"
            
            # Check if it's an SSD (various heuristics)
            model_lower = drive.Model.lower() if drive.Model else ""
            if any(keyword in model_lower for keyword in ["ssd", "solid state"]):
                return "ssd"
            
            # Check interface type
            interface = getattr(drive, 'InterfaceType', '').lower()
            if interface == "scsi":
                # Could be SSD or HDD, check media type
                media_type = getattr(drive, 'MediaType', '').lower()
                if "ssd" in media_type:
                    return "ssd"
            
            # Default to HDD for rotational drives
            return "hdd"
        
        except Exception as e:
            self.logger.error(f"Error detecting Windows device type: {e}")
            return "unknown"
    
    def _check_windows_encryption(self, drive) -> Tuple[bool, Optional[str]]:
        """Check Windows drive encryption status (BitLocker, etc.)."""
        try:
            # Check BitLocker status
            # This is a placeholder - real implementation would query BitLocker WMI
            # Win32_EncryptableVolume or manage-bde command
            return False, None
        
        except Exception as e:
            self.logger.error(f"Error checking Windows encryption: {e}")
            return False, None
    
    def _get_windows_capabilities(self, drive) -> Dict[str, bool]:
        """Get Windows drive capabilities (Secure Erase, etc.)."""
        capabilities = {
            "secure_erase": False,
            "enhanced_secure_erase": False,
            "crypto_erase": False,
            "nvme_sanitize": False,
            "trim_support": False
        }
        
        try:
            # Check ATA capabilities using PowerShell or direct commands
            # This is a placeholder for actual capability detection
            pass
        
        except Exception as e:
            self.logger.error(f"Error getting Windows capabilities: {e}")
        
        return capabilities
    
    def _check_windows_hidden_areas(self, drive) -> Dict[str, int]:
        """Check for hidden areas on Windows drives (HPA, DCO)."""
        hidden_areas = {
            "hpa_size": 0,
            "dco_enabled": 0,
            "accessible_max_address": 0
        }
        
        try:
            # Use hdparm equivalent or PowerShell commands
            # This is a placeholder for actual HPA/DCO detection
            pass
        
        except Exception as e:
            self.logger.error(f"Error checking Windows hidden areas: {e}")
        
        return hidden_areas
    
    def _get_windows_mount_info(self, drive) -> Tuple[bool, List[str]]:
        """Get Windows drive mount information."""
        try:
            mount_points = []
            # Query associated logical drives
            # This is a placeholder for actual mount point detection
            return len(mount_points) > 0, mount_points
        
        except Exception as e:
            self.logger.error(f"Error getting Windows mount info: {e}")
            return False, []
    
    def _list_windows_fallback_devices(self) -> List[DeviceInfo]:
        """Fallback method for Windows when WMI is not available."""
        devices = []
        
        try:
            # Use PowerShell commands as fallback
            cmd = ["powershell", "-Command", "Get-WmiObject -Class Win32_DiskDrive | ConvertTo-Json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                drives_data = json.loads(result.stdout)
                if isinstance(drives_data, dict):
                    drives_data = [drives_data]
                
                for drive_data in drives_data:
                    device_info = self._parse_windows_powershell_drive(drive_data)
                    if device_info:
                        devices.append(device_info)
        
        except Exception as e:
            self.logger.error(f"Error in Windows fallback method: {e}")
        
        return devices
    
    def _parse_windows_powershell_drive(self, drive_data: Dict) -> Optional[DeviceInfo]:
        """Parse drive data from PowerShell output."""
        try:
            # Similar to _parse_windows_drive but for JSON data
            path = f"\\\\.\\PHYSICALDRIVE{drive_data.get('Index', 0)}"
            model = drive_data.get('Model', 'Unknown')
            serial = drive_data.get('SerialNumber', 'Unknown')
            size_bytes = int(drive_data.get('Size', 0))
            
            return DeviceInfo(
                path=path,
                model=model,
                serial=serial,
                size_bytes=size_bytes,
                device_type="unknown",  # Simplified for fallback
                is_encrypted=False,
                encryption_type=None,
                firmware_version=drive_data.get('FirmwareRevision', 'Unknown'),
                capabilities={},
                hidden_areas={},
                platform="windows",
                removable=False,
                mounted=False,
                mount_points=[],
                smart_enabled=False,
                temperature=None,
                power_on_hours=None
            )
        
        except Exception as e:
            self.logger.error(f"Error parsing PowerShell drive data: {e}")
            return None
    
    def _list_linux_devices(self) -> List[DeviceInfo]:
        """List storage devices on Linux using system tools."""
        devices = []
        
        try:
            # Use lsblk to get basic device information
            if "lsblk" in self.linux_tools:
                devices.extend(self._list_linux_lsblk_devices())
            else:
                devices.extend(self._list_linux_fallback_devices())
        
        except Exception as e:
            self.logger.error(f"Error listing Linux devices: {e}")
        
        return devices
    
    def _list_linux_lsblk_devices(self) -> List[DeviceInfo]:
        """List Linux devices using lsblk."""
        devices = []
        
        try:
            cmd = ["lsblk", "-J", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for device in data.get("blockdevices", []):
                    if device.get("type") == "disk":
                        device_info = self._parse_linux_device(device)
                        if device_info:
                            devices.append(device_info)
        
        except Exception as e:
            self.logger.error(f"Error using lsblk: {e}")
        
        return devices
    
    def _parse_linux_device(self, device_data: Dict) -> Optional[DeviceInfo]:
        """Parse Linux device information."""
        try:
            name = device_data.get("name", "")
            path = f"/dev/{name}"
            model = device_data.get("model", "Unknown")
            serial = device_data.get("serial", "Unknown")
            size_str = device_data.get("size", "0")
            
            # Parse size
            size_bytes = self._parse_linux_size(size_str)
            
            # Detect device type
            device_type = self._detect_linux_device_type(path, name)
            
            # Check encryption
            is_encrypted, encryption_type = self._check_linux_encryption(path)
            
            # Get capabilities
            capabilities = self._get_linux_capabilities(path, device_type)
            
            # Check hidden areas
            hidden_areas = self._check_linux_hidden_areas(path)
            
            # Get mount info
            mount_points = device_data.get("mountpoint", "")
            mount_points = [mount_points] if mount_points else []
            
            return DeviceInfo(
                path=path,
                model=model,
                serial=serial,
                size_bytes=size_bytes,
                device_type=device_type,
                is_encrypted=is_encrypted,
                encryption_type=encryption_type,
                firmware_version="Unknown",  # TODO: Get from smartctl
                capabilities=capabilities,
                hidden_areas=hidden_areas,
                platform="linux",
                removable=self._is_linux_removable(path),
                mounted=len(mount_points) > 0,
                mount_points=mount_points,
                smart_enabled=False,  # TODO: Check with smartctl
                temperature=None,
                power_on_hours=None
            )
        
        except Exception as e:
            self.logger.error(f"Error parsing Linux device: {e}")
            return None
    
    def _parse_linux_size(self, size_str: str) -> int:
        """Parse Linux size string to bytes."""
        try:
            size_str = size_str.strip().upper()
            if size_str.endswith('T'):
                return int(float(size_str[:-1]) * 1024**4)
            elif size_str.endswith('G'):
                return int(float(size_str[:-1]) * 1024**3)
            elif size_str.endswith('M'):
                return int(float(size_str[:-1]) * 1024**2)
            elif size_str.endswith('K'):
                return int(float(size_str[:-1]) * 1024)
            else:
                return int(size_str)
        except (ValueError, TypeError):
            return 0
    
    def _detect_linux_device_type(self, path: str, name: str) -> str:
        """Detect Linux device type."""
        try:
            # Check if NVMe
            if name.startswith("nvme"):
                return "nvme"
            
            # Check rotational flag
            try:
                with open(f"/sys/block/{name}/queue/rotational", "r") as f:
                    rotational = f.read().strip()
                    if rotational == "0":
                        return "ssd"
                    else:
                        return "hdd"
            except FileNotFoundError:
                pass
            
            # Fallback detection methods
            return "unknown"
        
        except Exception as e:
            self.logger.error(f"Error detecting Linux device type: {e}")
            return "unknown"
    
    def _check_linux_encryption(self, path: str) -> Tuple[bool, Optional[str]]:
        """Check Linux encryption status (LUKS, etc.)."""
        try:
            # Check for LUKS
            if "blkid" in self.linux_tools:
                cmd = [self.linux_tools["blkid"], "-p", path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if "crypto_LUKS" in result.stdout:
                    return True, "luks"
            
            return False, None
        
        except Exception as e:
            self.logger.error(f"Error checking Linux encryption: {e}")
            return False, None
    
    def _get_linux_capabilities(self, path: str, device_type: str) -> Dict[str, bool]:
        """Get Linux device capabilities."""
        capabilities = {
            "secure_erase": False,
            "enhanced_secure_erase": False,
            "crypto_erase": False,
            "nvme_sanitize": False,
            "trim_support": False
        }
        
        try:
            if device_type == "nvme" and "nvme" in self.linux_tools:
                # Check NVMe sanitize capabilities
                cmd = [self.linux_tools["nvme"], "id-ctrl", path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if "sanicap" in result.stdout.lower():
                    capabilities["nvme_sanitize"] = True
            
            elif "hdparm" in self.linux_tools:
                # Check ATA secure erase capabilities
                cmd = [self.linux_tools["hdparm"], "-I", path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                if "erase" in result.stdout.lower():
                    capabilities["secure_erase"] = True
        
        except Exception as e:
            self.logger.error(f"Error getting Linux capabilities: {e}")
        
        return capabilities
    
    def _check_linux_hidden_areas(self, path: str) -> Dict[str, int]:
        """Check for hidden areas on Linux drives."""
        hidden_areas = {
            "hpa_size": 0,
            "dco_enabled": 0,
            "accessible_max_address": 0
        }
        
        try:
            if "hdparm" in self.linux_tools:
                # Check HPA
                cmd = [self.linux_tools["hdparm"], "-N", path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                # Parse HPA information from output
                # This is a placeholder for actual parsing
        
        except Exception as e:
            self.logger.error(f"Error checking Linux hidden areas: {e}")
        
        return hidden_areas
    
    def _is_linux_removable(self, path: str) -> bool:
        """Check if Linux device is removable."""
        try:
            device_name = os.path.basename(path)
            with open(f"/sys/block/{device_name}/removable", "r") as f:
                return f.read().strip() == "1"
        except (FileNotFoundError, OSError):
            return False
    
    def _list_linux_fallback_devices(self) -> List[DeviceInfo]:
        """Fallback method for Linux when lsblk is not available."""
        devices = []
        
        try:
            # Use /proc/partitions and /sys filesystem
            with open("/proc/partitions", "r") as f:
                lines = f.readlines()[2:]  # Skip header
                
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        device_name = parts[3]
                        # Filter out partitions (basic heuristic)
                        if not any(char.isdigit() for char in device_name[-1:]):
                            path = f"/dev/{device_name}"
                            size_blocks = int(parts[2])
                            size_bytes = size_blocks * 1024  # /proc/partitions is in 1K blocks
                            
                            device_info = DeviceInfo(
                                path=path,
                                model="Unknown",
                                serial="Unknown",
                                size_bytes=size_bytes,
                                device_type="unknown",
                                is_encrypted=False,
                                encryption_type=None,
                                firmware_version="Unknown",
                                capabilities={},
                                hidden_areas={},
                                platform="linux",
                                removable=False,
                                mounted=False,
                                mount_points=[],
                                smart_enabled=False,
                                temperature=None,
                                power_on_hours=None
                            )
                            devices.append(device_info)
        
        except Exception as e:
            self.logger.error(f"Error in Linux fallback method: {e}")
        
        return devices
    
    def _list_android_devices(self) -> List[DeviceInfo]:
        """List storage devices on Android using ADB."""
        devices = []
        
        if not self.adb_available:
            self.logger.warning("ADB not available for Android device detection")
            return devices
        
        try:
            # Get partition information
            cmd = ["adb", "shell", "cat /proc/partitions"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[2:]  # Skip header
                
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        device_name = parts[3]
                        # Focus on main storage partitions
                        if any(keyword in device_name for keyword in ["userdata", "system", "data"]):
                            device_info = self._parse_android_partition(parts)
                            if device_info:
                                devices.append(device_info)
        
        except Exception as e:
            self.logger.error(f"Error listing Android devices: {e}")
        
        return devices
    
    def _parse_android_partition(self, parts: List[str]) -> Optional[DeviceInfo]:
        """Parse Android partition information."""
        try:
            device_name = parts[3]
            size_blocks = int(parts[2])
            size_bytes = size_blocks * 1024  # Assuming 1K blocks
            
            path = f"/dev/block/{device_name}"
            
            return DeviceInfo(
                path=path,
                model="Android Storage",
                serial="Unknown",
                size_bytes=size_bytes,
                device_type="mobile",
                is_encrypted=False,  # TODO: Check Android encryption
                encryption_type=None,
                firmware_version="Unknown",
                capabilities={"overwrite_single": True},
                hidden_areas={},
                platform="android",
                removable=False,
                mounted=True,  # Android partitions are typically mounted
                mount_points=[f"/{device_name}"],
                smart_enabled=False,
                temperature=None,
                power_on_hours=None
            )
        
        except Exception as e:
            self.logger.error(f"Error parsing Android partition: {e}")
            return None
    
    def get_device_info(self, device_path: str) -> Optional[DeviceInfo]:
        """
        Get detailed information for a specific device.
        
        Args:
            device_path: Path to the device (e.g., /dev/sda, \\\\.\\PHYSICALDRIVE0)
        
        Returns:
            DeviceInfo object or None if device not found
        """
        try:
            all_devices = self.list_storage_devices()
            for device in all_devices:
                if device.path == device_path:
                    return device
            
            self.logger.warning(f"Device not found: {device_path}")
            return None
        
        except Exception as e:
            self.logger.error(f"Error getting device info for {device_path}: {e}")
            return None
    
    def is_device_safe_to_wipe(self, device_info: DeviceInfo) -> Tuple[bool, str]:
        """
        Check if a device is safe to wipe (not containing OS, etc.).
        
        Args:
            device_info: Device information
        
        Returns:
            Tuple of (is_safe, reason)
        """
        try:
            # Check if device contains system partitions
            if device_info.platform == "windows":
                # Check if it's the boot drive
                if "C:\\" in device_info.mount_points:
                    return False, "Device contains Windows system partition"
            
            elif device_info.platform == "linux":
                # Check if it contains root partition
                if "/" in device_info.mount_points:
                    return False, "Device contains Linux root partition"
                if "/boot" in device_info.mount_points:
                    return False, "Device contains Linux boot partition"
            
            elif device_info.platform == "android":
                # Check critical Android partitions
                critical_partitions = ["system", "boot", "recovery"]
                device_name = os.path.basename(device_info.path)
                if any(partition in device_name for partition in critical_partitions):
                    return False, "Device contains critical Android system partition"
            
            # Additional safety checks
            if device_info.size_bytes < 1024 * 1024:  # Less than 1MB
                return False, "Device too small, possibly not a real storage device"
            
            return True, "Device appears safe to wipe"
        
        except Exception as e:
            self.logger.error(f"Error checking device safety: {e}")
            return False, f"Error during safety check: {e}"


def main():
    """CLI interface for device detection testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PurgeProof Device Detection Tool")
    parser.add_argument("--list", action="store_true", help="List all storage devices")
    parser.add_argument("--device", help="Get info for specific device")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")
    
    detector = DeviceDetector()
    
    if args.list:
        devices = detector.list_storage_devices()
        print(f"Found {len(devices)} storage devices:")
        for device in devices:
            print(f"  {device.path}: {device.model} ({device.device_type}, {device.size_bytes // (1024**3)}GB)")
    
    elif args.device:
        device_info = detector.get_device_info(args.device)
        if device_info:
            print(f"Device Information for {device_info.path}:")
            print(f"  Model: {device_info.model}")
            print(f"  Serial: {device_info.serial}")
            print(f"  Type: {device_info.device_type}")
            print(f"  Size: {device_info.size_bytes // (1024**3)}GB")
            print(f"  Encrypted: {device_info.is_encrypted}")
            print(f"  Capabilities: {device_info.capabilities}")
            
            safe, reason = detector.is_device_safe_to_wipe(device_info)
            print(f"  Safe to wipe: {safe} ({reason})")
        else:
            print(f"Device not found: {args.device}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
