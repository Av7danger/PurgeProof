"""
Enhanced device utilities with comprehensive capability detection and platform optimizations.

This module provides intelligent device enumeration, capability analysis, and performance
profiling for optimal sanitization method selection and execution planning.
"""

import os
import sys
import json
import time
import asyncio
import logging
import platform
from typing import Dict, List, Tuple, Optional, NamedTuple, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum, auto
import subprocess
import concurrent.futures

# Try to import the native Rust engine
try:
    from . import ffi_bindings
    NATIVE_ENGINE_AVAILABLE = True
except ImportError:
    NATIVE_ENGINE_AVAILABLE = False
    logging.warning("Native Rust engine not available, falling back to Python implementations")

logger = logging.getLogger(__name__)

class DeviceType(Enum):
    """Storage device types with performance characteristics."""
    HDD = auto()
    SSD = auto()
    NVME = auto()
    EMMC = auto()
    USB = auto()
    UNKNOWN = auto()

class InterfaceType(Enum):
    """Storage interface types."""
    SATA = auto()
    NVME = auto()
    SCSI = auto()
    USB = auto()
    IDE = auto()
    EMMC = auto()
    UNKNOWN = auto()

class EncryptionType(Enum):
    """Encryption implementation types."""
    NONE = auto()
    SOFTWARE = auto()  # LUKS, BitLocker, FileVault
    HARDWARE_SED = auto()  # Self-Encrypting Drive
    HARDWARE_OPAL = auto()  # TCG Opal
    UNKNOWN = auto()

@dataclass
class DeviceCapabilities:
    """Comprehensive device capabilities and characteristics."""
    # Basic device information
    path: str
    device_type: DeviceType
    interface_type: InterfaceType
    size_bytes: int
    sector_size: int
    model: str
    serial: str
    firmware_version: str
    
    # Performance characteristics
    max_read_speed_mbps: float
    max_write_speed_mbps: float
    random_iops: int
    latency_ms: float
    queue_depth: int
    
    # Security and sanitization capabilities
    supports_crypto_erase: bool
    supports_secure_erase: bool
    supports_enhanced_secure_erase: bool
    supports_nvme_sanitize: bool
    supports_trim: bool
    supports_write_zeroes: bool
    
    # Encryption information
    is_encrypted: bool
    encryption_type: EncryptionType
    encryption_algorithm: Optional[str]
    
    # Timing estimates (minutes)
    secure_erase_time_estimate: Optional[int]
    crypto_erase_time_estimate: Optional[int]
    overwrite_time_estimate: Optional[int]
    
    # Platform-specific features
    platform_specific: Dict[str, any]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary with enum serialization."""
        result = asdict(self)
        result['device_type'] = self.device_type.name
        result['interface_type'] = self.interface_type.name
        result['encryption_type'] = self.encryption_type.name
        return result
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'DeviceCapabilities':
        """Create from dictionary with enum deserialization."""
        # Convert enum strings back to enums
        data['device_type'] = DeviceType[data['device_type']]
        data['interface_type'] = InterfaceType[data['interface_type']]
        data['encryption_type'] = EncryptionType[data['encryption_type']]
        return cls(**data)

@dataclass
class PerformanceProfile:
    """Device performance profile for optimization."""
    optimal_read_chunk_size: int
    optimal_write_chunk_size: int
    max_concurrent_operations: int
    preferred_queue_depth: int
    supports_native_commands: bool
    hardware_acceleration: List[str]
    benchmark_scores: Dict[str, float]

class DeviceEnumerator:
    """High-performance device enumeration with caching and async support."""
    
    def __init__(self, cache_duration: int = 30):
        self.cache_duration = cache_duration
        self._cache: Dict[str, DeviceCapabilities] = {}
        self._cache_timestamp = 0
        self._lock = asyncio.Lock()
        
    async def enumerate_devices(self, force_refresh: bool = False) -> List[DeviceCapabilities]:
        """
        Enumerate all storage devices with comprehensive capability detection.
        
        Args:
            force_refresh: Force cache refresh even if recent
            
        Returns:
            List of device capabilities
        """
        async with self._lock:
            current_time = time.time()
            
            # Check cache validity
            if not force_refresh and (current_time - self._cache_timestamp) < self.cache_duration:
                logger.debug("Returning cached device list")
                return list(self._cache.values())
            
            logger.info("Enumerating storage devices...")
            devices = []
            
            if NATIVE_ENGINE_AVAILABLE:
                # Use native Rust engine for optimal performance
                devices = await self._enumerate_with_native_engine()
            else:
                # Fallback to Python implementations
                devices = await self._enumerate_with_python()
            
            # Update cache
            self._cache = {dev.path: dev for dev in devices}
            self._cache_timestamp = current_time
            
            logger.info(f"Found {len(devices)} storage devices")
            return devices
    
    async def _enumerate_with_native_engine(self) -> List[DeviceCapabilities]:
        """Use native Rust engine for device enumeration."""
        try:
            # Call native enumeration function
            raw_devices = ffi_bindings.enumerate_storage_devices()
            devices = []
            
            for raw_device in raw_devices:
                # Convert from native format to Python DeviceCapabilities
                device = self._convert_from_native_format(raw_device)
                if device:
                    devices.append(device)
            
            return devices
        except Exception as e:
            logger.error(f"Native enumeration failed: {e}")
            # Fallback to Python implementation
            return await self._enumerate_with_python()
    
    async def _enumerate_with_python(self) -> List[DeviceCapabilities]:
        """Python fallback implementation."""
        if platform.system() == "Windows":
            return await self._enumerate_windows_devices()
        elif platform.system() == "Linux":
            return await self._enumerate_linux_devices()
        elif platform.system() == "Darwin":
            return await self._enumerate_macos_devices()
        else:
            logger.warning(f"Unsupported platform: {platform.system()}")
            return []
    
    async def _enumerate_windows_devices(self) -> List[DeviceCapabilities]:
        """Windows-specific device enumeration."""
        devices = []
        
        try:
            # Use WMI to enumerate physical drives
            import wmi
            
            c = wmi.WMI()
            
            # Get physical drives
            for disk in c.Win32_DiskDrive():
                device_path = f"\\\\.\\PHYSICALDRIVE{disk.Index}"
                
                try:
                    capabilities = await self._analyze_windows_device(disk, device_path)
                    if capabilities:
                        devices.append(capabilities)
                except Exception as e:
                    logger.warning(f"Failed to analyze Windows device {device_path}: {e}")
            
        except ImportError:
            logger.warning("WMI not available, using basic Windows enumeration")
            # Fallback to basic enumeration
            devices = await self._enumerate_windows_basic()
        except Exception as e:
            logger.error(f"Windows enumeration failed: {e}")
        
        return devices
    
    async def _enumerate_windows_basic(self) -> List[DeviceCapabilities]:
        """Basic Windows enumeration without WMI."""
        devices = []
        
        # Enumerate drive letters
        for i in range(26):
            drive_letter = chr(ord('A') + i)
            drive_path = f"{drive_letter}:\\"
            
            if os.path.exists(drive_path):
                try:
                    device_path = f"\\\\.\\{drive_letter}:"
                    capabilities = await self._analyze_windows_device_basic(device_path)
                    if capabilities:
                        devices.append(capabilities)
                except Exception as e:
                    logger.warning(f"Failed to analyze Windows drive {drive_path}: {e}")
        
        return devices
    
    async def _enumerate_linux_devices(self) -> List[DeviceCapabilities]:
        """Linux-specific device enumeration."""
        devices = []
        
        # Scan /sys/block for block devices
        block_dir = Path("/sys/block")
        if not block_dir.exists():
            logger.warning("/sys/block not found")
            return devices
        
        for device_dir in block_dir.iterdir():
            if not device_dir.is_dir():
                continue
            
            device_name = device_dir.name
            
            # Skip virtual devices
            if any(device_name.startswith(prefix) for prefix in ['loop', 'ram', 'dm-', 'md']):
                continue
            
            device_path = f"/dev/{device_name}"
            
            try:
                capabilities = await self._analyze_linux_device(device_path, device_dir)
                if capabilities:
                    devices.append(capabilities)
            except Exception as e:
                logger.warning(f"Failed to analyze Linux device {device_path}: {e}")
        
        return devices
    
    async def _enumerate_macos_devices(self) -> List[DeviceCapabilities]:
        """macOS-specific device enumeration."""
        devices = []
        
        try:
            # Use diskutil to enumerate devices
            result = subprocess.run(
                ['diskutil', 'list', '-plist'],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse diskutil output (plist format)
            import plistlib
            disk_data = plistlib.loads(result.stdout.encode())
            
            for disk_info in disk_data.get('AllDisksAndPartitions', []):
                device_id = disk_info.get('DeviceIdentifier', '')
                device_path = f"/dev/{device_id}"
                
                try:
                    capabilities = await self._analyze_macos_device(device_path, disk_info)
                    if capabilities:
                        devices.append(capabilities)
                except Exception as e:
                    logger.warning(f"Failed to analyze macOS device {device_path}: {e}")
        
        except subprocess.CalledProcessError as e:
            logger.error(f"diskutil command failed: {e}")
        except Exception as e:
            logger.error(f"macOS enumeration failed: {e}")
        
        return devices
    
    async def _analyze_windows_device(self, disk_wmi, device_path: str) -> Optional[DeviceCapabilities]:
        """Analyze Windows device using WMI information."""
        try:
            # Basic device information from WMI
            size_bytes = int(disk_wmi.Size) if disk_wmi.Size else 0
            model = disk_wmi.Model or "Unknown Model"
            serial = disk_wmi.SerialNumber or "Unknown Serial"
            interface = disk_wmi.InterfaceType or "Unknown"
            
            # Determine device type
            device_type = DeviceType.UNKNOWN
            interface_type = InterfaceType.UNKNOWN
            
            if hasattr(disk_wmi, 'MediaType'):
                media_type = disk_wmi.MediaType or ""
                if "SSD" in media_type.upper() or "SOLID STATE" in media_type.upper():
                    device_type = DeviceType.SSD
                elif "NVME" in media_type.upper():
                    device_type = DeviceType.NVME
                else:
                    device_type = DeviceType.HDD
            
            # Determine interface type
            if "NVME" in interface.upper():
                interface_type = InterfaceType.NVME
            elif "SATA" in interface.upper():
                interface_type = InterfaceType.SATA
            elif "SCSI" in interface.upper():
                interface_type = InterfaceType.SCSI
            elif "USB" in interface.upper():
                interface_type = InterfaceType.USB
            
            # Detect capabilities
            capabilities = await self._detect_device_capabilities(
                device_path, device_type, interface_type, size_bytes
            )
            
            return DeviceCapabilities(
                path=device_path,
                device_type=device_type,
                interface_type=interface_type,
                size_bytes=size_bytes,
                sector_size=512,  # Default
                model=model,
                serial=serial,
                firmware_version="Unknown",
                max_read_speed_mbps=capabilities.get('max_read_speed', 100.0),
                max_write_speed_mbps=capabilities.get('max_write_speed', 100.0),
                random_iops=capabilities.get('random_iops', 1000),
                latency_ms=capabilities.get('latency_ms', 10.0),
                queue_depth=capabilities.get('queue_depth', 32),
                supports_crypto_erase=capabilities.get('crypto_erase', False),
                supports_secure_erase=capabilities.get('secure_erase', False),
                supports_enhanced_secure_erase=capabilities.get('enhanced_secure_erase', False),
                supports_nvme_sanitize=capabilities.get('nvme_sanitize', False),
                supports_trim=capabilities.get('trim', False),
                supports_write_zeroes=capabilities.get('write_zeroes', True),
                is_encrypted=capabilities.get('is_encrypted', False),
                encryption_type=capabilities.get('encryption_type', EncryptionType.NONE),
                encryption_algorithm=capabilities.get('encryption_algorithm'),
                secure_erase_time_estimate=capabilities.get('secure_erase_time'),
                crypto_erase_time_estimate=capabilities.get('crypto_erase_time'),
                overwrite_time_estimate=capabilities.get('overwrite_time'),
                platform_specific={'wmi_data': disk_wmi}
            )
            
        except Exception as e:
            logger.error(f"Windows device analysis failed for {device_path}: {e}")
            return None
    
    async def _analyze_linux_device(self, device_path: str, sys_dir: Path) -> Optional[DeviceCapabilities]:
        """Analyze Linux device using sysfs information."""
        try:
            # Get basic device information
            size_bytes = self._read_sysfs_value(sys_dir / "size", int, 0) * 512
            model = self._read_sysfs_value(sys_dir / "device" / "model", str, "Unknown Model").strip()
            
            # Determine device type
            is_rotational = self._read_sysfs_value(sys_dir / "queue" / "rotational", int, 1)
            device_name = device_path.split('/')[-1]
            
            if device_name.startswith('nvme'):
                device_type = DeviceType.NVME
                interface_type = InterfaceType.NVME
            elif is_rotational == 0:
                device_type = DeviceType.SSD
                interface_type = InterfaceType.SATA
            else:
                device_type = DeviceType.HDD
                interface_type = InterfaceType.SATA
            
            # Get additional information
            serial = self._get_linux_device_serial(device_path, sys_dir)
            firmware = self._read_sysfs_value(sys_dir / "device" / "rev", str, "Unknown").strip()
            
            # Detect capabilities
            capabilities = await self._detect_device_capabilities(
                device_path, device_type, interface_type, size_bytes
            )
            
            return DeviceCapabilities(
                path=device_path,
                device_type=device_type,
                interface_type=interface_type,
                size_bytes=size_bytes,
                sector_size=self._read_sysfs_value(sys_dir / "queue" / "logical_block_size", int, 512),
                model=model,
                serial=serial,
                firmware_version=firmware,
                max_read_speed_mbps=capabilities.get('max_read_speed', 100.0),
                max_write_speed_mbps=capabilities.get('max_write_speed', 100.0),
                random_iops=capabilities.get('random_iops', 1000),
                latency_ms=capabilities.get('latency_ms', 10.0),
                queue_depth=capabilities.get('queue_depth', 32),
                supports_crypto_erase=capabilities.get('crypto_erase', False),
                supports_secure_erase=capabilities.get('secure_erase', False),
                supports_enhanced_secure_erase=capabilities.get('enhanced_secure_erase', False),
                supports_nvme_sanitize=capabilities.get('nvme_sanitize', False),
                supports_trim=capabilities.get('trim', False),
                supports_write_zeroes=capabilities.get('write_zeroes', True),
                is_encrypted=capabilities.get('is_encrypted', False),
                encryption_type=capabilities.get('encryption_type', EncryptionType.NONE),
                encryption_algorithm=capabilities.get('encryption_algorithm'),
                secure_erase_time_estimate=capabilities.get('secure_erase_time'),
                crypto_erase_time_estimate=capabilities.get('crypto_erase_time'),
                overwrite_time_estimate=capabilities.get('overwrite_time'),
                platform_specific={'sysfs_path': str(sys_dir)}
            )
            
        except Exception as e:
            logger.error(f"Linux device analysis failed for {device_path}: {e}")
            return None
    
    def _read_sysfs_value(self, path: Path, value_type: type, default):
        """Safely read a value from sysfs."""
        try:
            if path.exists():
                content = path.read_text().strip()
                return value_type(content)
        except Exception:
            pass
        return default
    
    def _get_linux_device_serial(self, device_path: str, sys_dir: Path) -> str:
        """Get device serial number on Linux."""
        # Try various methods to get serial number
        methods = [
            lambda: self._read_sysfs_value(sys_dir / "device" / "serial", str, ""),
            lambda: self._read_sysfs_value(sys_dir / "device" / "wwid", str, ""),
            lambda: self._get_serial_via_udev(device_path),
            lambda: self._get_serial_via_lsblk(device_path),
        ]
        
        for method in methods:
            try:
                serial = method()
                if serial and serial.strip():
                    return serial.strip()
            except Exception:
                continue
        
        return "Unknown Serial"
    
    def _get_serial_via_udev(self, device_path: str) -> str:
        """Get serial via udevadm."""
        try:
            result = subprocess.run(
                ['udevadm', 'info', '--query=property', f'--name={device_path}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            for line in result.stdout.split('\n'):
                if line.startswith('ID_SERIAL='):
                    return line.split('=', 1)[1]
                elif line.startswith('ID_SERIAL_SHORT='):
                    return line.split('=', 1)[1]
        except Exception:
            pass
        return ""
    
    def _get_serial_via_lsblk(self, device_path: str) -> str:
        """Get serial via lsblk."""
        try:
            result = subprocess.run(
                ['lsblk', '-n', '-o', 'SERIAL', device_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            serial = result.stdout.strip()
            if serial and serial != 'null':
                return serial
        except Exception:
            pass
        return ""
    
    async def _detect_device_capabilities(self, device_path: str, device_type: DeviceType, 
                                        interface_type: InterfaceType, size_bytes: int) -> Dict:
        """Detect device capabilities and performance characteristics."""
        capabilities = {}
        
        # Performance estimates based on device type
        if device_type == DeviceType.NVME:
            capabilities.update({
                'max_read_speed': 3500.0,
                'max_write_speed': 3000.0,
                'random_iops': 500000,
                'latency_ms': 0.1,
                'queue_depth': 64,
                'crypto_erase': True,
                'secure_erase': True,
                'enhanced_secure_erase': True,
                'nvme_sanitize': True,
                'trim': True,
                'crypto_erase_time': 1,  # Instant
                'secure_erase_time': 2,
                'overwrite_time': max(1, size_bytes // (3000 * 1024 * 1024) // 60),
            })
        elif device_type == DeviceType.SSD:
            capabilities.update({
                'max_read_speed': 550.0,
                'max_write_speed': 520.0,
                'random_iops': 100000,
                'latency_ms': 0.2,
                'queue_depth': 32,
                'crypto_erase': False,
                'secure_erase': True,
                'enhanced_secure_erase': True,
                'nvme_sanitize': False,
                'trim': True,
                'secure_erase_time': 5,
                'overwrite_time': max(1, size_bytes // (520 * 1024 * 1024) // 60),
            })
        else:  # HDD
            capabilities.update({
                'max_read_speed': 150.0,
                'max_write_speed': 120.0,
                'random_iops': 200,
                'latency_ms': 8.5,
                'queue_depth': 8,
                'crypto_erase': False,
                'secure_erase': False,
                'enhanced_secure_erase': False,
                'nvme_sanitize': False,
                'trim': False,
                'overwrite_time': max(10, size_bytes // (120 * 1024 * 1024) // 60),
            })
        
        # Always support write zeroes
        capabilities['write_zeroes'] = True
        
        # Detect encryption
        encryption_info = await self._detect_encryption(device_path)
        capabilities.update(encryption_info)
        
        return capabilities
    
    async def _detect_encryption(self, device_path: str) -> Dict:
        """Detect device encryption status."""
        encryption_info = {
            'is_encrypted': False,
            'encryption_type': EncryptionType.NONE,
            'encryption_algorithm': None,
        }
        
        if platform.system() == "Linux":
            # Check for LUKS encryption
            try:
                result = subprocess.run(
                    ['cryptsetup', 'isLuks', device_path],
                    capture_output=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    encryption_info.update({
                        'is_encrypted': True,
                        'encryption_type': EncryptionType.SOFTWARE,
                        'encryption_algorithm': 'LUKS',
                    })
                    return encryption_info
            except Exception:
                pass
        
        elif platform.system() == "Windows":
            # Check for BitLocker
            try:
                # Extract drive letter from device path
                drive_letter = device_path.replace('\\\\.\\', '').replace(':', '')
                
                result = subprocess.run(
                    ['manage-bde', '-status', f'{drive_letter}:'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if 'Protection On' in result.stdout:
                    encryption_info.update({
                        'is_encrypted': True,
                        'encryption_type': EncryptionType.SOFTWARE,
                        'encryption_algorithm': 'BitLocker',
                    })
                    return encryption_info
            except Exception:
                pass
        
        # TODO: Add hardware SED/Opal detection
        
        return encryption_info
    
    def _convert_from_native_format(self, raw_device: Dict) -> Optional[DeviceCapabilities]:
        """Convert from native Rust format to Python DeviceCapabilities."""
        try:
            # This would convert from the native Rust device format
            # to our Python DeviceCapabilities structure
            
            device_type_map = {
                'HDD': DeviceType.HDD,
                'SSD': DeviceType.SSD,
                'NVMe': DeviceType.NVME,
                'eMMC': DeviceType.EMMC,
                'USB': DeviceType.USB,
            }
            
            interface_type_map = {
                'SATA': InterfaceType.SATA,
                'NVMe': InterfaceType.NVME,
                'SCSI': InterfaceType.SCSI,
                'USB': InterfaceType.USB,
                'IDE': InterfaceType.IDE,
            }
            
            encryption_type_map = {
                'None': EncryptionType.NONE,
                'Software': EncryptionType.SOFTWARE,
                'Hardware': EncryptionType.HARDWARE_SED,
                'Opal': EncryptionType.HARDWARE_OPAL,
            }
            
            return DeviceCapabilities(
                path=raw_device.get('path', ''),
                device_type=device_type_map.get(raw_device.get('device_type'), DeviceType.UNKNOWN),
                interface_type=interface_type_map.get(raw_device.get('interface_type'), InterfaceType.UNKNOWN),
                size_bytes=raw_device.get('size_bytes', 0),
                sector_size=raw_device.get('sector_size', 512),
                model=raw_device.get('model', 'Unknown'),
                serial=raw_device.get('serial', 'Unknown'),
                firmware_version=raw_device.get('firmware_version', 'Unknown'),
                max_read_speed_mbps=raw_device.get('max_read_speed_mbps', 100.0),
                max_write_speed_mbps=raw_device.get('max_write_speed_mbps', 100.0),
                random_iops=raw_device.get('random_iops', 1000),
                latency_ms=raw_device.get('latency_ms', 10.0),
                queue_depth=raw_device.get('queue_depth', 32),
                supports_crypto_erase=raw_device.get('supports_crypto_erase', False),
                supports_secure_erase=raw_device.get('supports_secure_erase', False),
                supports_enhanced_secure_erase=raw_device.get('supports_enhanced_secure_erase', False),
                supports_nvme_sanitize=raw_device.get('supports_nvme_sanitize', False),
                supports_trim=raw_device.get('supports_trim', False),
                supports_write_zeroes=raw_device.get('supports_write_zeroes', True),
                is_encrypted=raw_device.get('is_encrypted', False),
                encryption_type=encryption_type_map.get(raw_device.get('encryption_type'), EncryptionType.UNKNOWN),
                encryption_algorithm=raw_device.get('encryption_algorithm'),
                secure_erase_time_estimate=raw_device.get('secure_erase_time_estimate'),
                crypto_erase_time_estimate=raw_device.get('crypto_erase_time_estimate'),
                overwrite_time_estimate=raw_device.get('overwrite_time_estimate'),
                platform_specific=raw_device.get('platform_specific', {})
            )
            
        except Exception as e:
            logger.error(f"Failed to convert native device format: {e}")
            return None

class DevicePerformanceProfiler:
    """Profile device performance characteristics for optimization."""
    
    def __init__(self):
        self.benchmark_cache = {}
        
    async def profile_device(self, device: DeviceCapabilities, 
                           quick_test: bool = True) -> PerformanceProfile:
        """
        Profile device performance characteristics.
        
        Args:
            device: Device to profile
            quick_test: If True, use estimates. If False, run actual benchmarks.
            
        Returns:
            Performance profile with optimization recommendations
        """
        if quick_test:
            return self._estimate_performance_profile(device)
        else:
            return await self._benchmark_device_performance(device)
    
    def _estimate_performance_profile(self, device: DeviceCapabilities) -> PerformanceProfile:
        """Estimate performance profile based on device characteristics."""
        if device.device_type == DeviceType.NVME:
            return PerformanceProfile(
                optimal_read_chunk_size=1024 * 1024 * 4,  # 4MB
                optimal_write_chunk_size=1024 * 1024 * 2,  # 2MB
                max_concurrent_operations=8,
                preferred_queue_depth=64,
                supports_native_commands=True,
                hardware_acceleration=['nvme_sanitize', 'crypto_erase'],
                benchmark_scores={
                    'sequential_read': device.max_read_speed_mbps,
                    'sequential_write': device.max_write_speed_mbps,
                    'random_read': device.random_iops / 1000.0,
                    'random_write': device.random_iops / 1200.0,
                }
            )
        elif device.device_type == DeviceType.SSD:
            return PerformanceProfile(
                optimal_read_chunk_size=1024 * 1024 * 2,  # 2MB
                optimal_write_chunk_size=1024 * 1024,     # 1MB
                max_concurrent_operations=4,
                preferred_queue_depth=32,
                supports_native_commands=True,
                hardware_acceleration=['secure_erase', 'trim'],
                benchmark_scores={
                    'sequential_read': device.max_read_speed_mbps,
                    'sequential_write': device.max_write_speed_mbps,
                    'random_read': device.random_iops / 1000.0,
                    'random_write': device.random_iops / 1200.0,
                }
            )
        else:  # HDD
            return PerformanceProfile(
                optimal_read_chunk_size=1024 * 1024,      # 1MB
                optimal_write_chunk_size=1024 * 512,      # 512KB
                max_concurrent_operations=2,
                preferred_queue_depth=8,
                supports_native_commands=False,
                hardware_acceleration=[],
                benchmark_scores={
                    'sequential_read': device.max_read_speed_mbps,
                    'sequential_write': device.max_write_speed_mbps,
                    'random_read': device.random_iops / 1000.0,
                    'random_write': device.random_iops / 1200.0,
                }
            )
    
    async def _benchmark_device_performance(self, device: DeviceCapabilities) -> PerformanceProfile:
        """Run actual performance benchmarks (implementation depends on requirements)."""
        # This would run actual I/O benchmarks if needed
        # For now, return estimated profile
        return self._estimate_performance_profile(device)

# Global device enumerator instance
_device_enumerator = DeviceEnumerator()

async def enumerate_devices(force_refresh: bool = False) -> List[DeviceCapabilities]:
    """
    Convenience function to enumerate devices.
    
    Args:
        force_refresh: Force cache refresh
        
    Returns:
        List of device capabilities
    """
    return await _device_enumerator.enumerate_devices(force_refresh)

async def get_device_capabilities(device_path: str) -> Optional[DeviceCapabilities]:
    """
    Get capabilities for a specific device.
    
    Args:
        device_path: Path to device
        
    Returns:
        Device capabilities or None if not found
    """
    devices = await enumerate_devices()
    for device in devices:
        if device.path == device_path:
            return device
    return None

def get_optimal_chunk_size(device: DeviceCapabilities, operation_type: str = "write") -> int:
    """
    Get optimal chunk size for device operations.
    
    Args:
        device: Device capabilities
        operation_type: Type of operation ('read' or 'write')
        
    Returns:
        Optimal chunk size in bytes
    """
    profiler = DevicePerformanceProfiler()
    profile = profiler._estimate_performance_profile(device)
    
    if operation_type == "read":
        return profile.optimal_read_chunk_size
    else:
        return profile.optimal_write_chunk_size

if __name__ == "__main__":
    # Example usage
    async def main():
        devices = await enumerate_devices()
        
        print(f"Found {len(devices)} storage devices:")
        for device in devices:
            print(f"  {device.path}: {device.model} ({device.device_type.name}, {device.size_bytes // (1024**3)} GB)")
            print(f"    Supports: crypto_erase={device.supports_crypto_erase}, "
                  f"secure_erase={device.supports_secure_erase}, trim={device.supports_trim}")
            
            # Get performance profile
            profiler = DevicePerformanceProfiler()
            profile = await profiler.profile_device(device)
            print(f"    Optimal chunk size: {profile.optimal_write_chunk_size // 1024} KB")
            print()
    
    asyncio.run(main())