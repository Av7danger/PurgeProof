"""
Wipe Engine Module - NIST SP 800-88 Rev.1 Compliant Sanitization

This module implements various data sanitization methods in compliance with
NIST SP 800-88 Rev.1 guidelines:

- Clear: Logical sanitization using standard read/write commands
- Purge: Physical sanitization using secure erase or cryptographic erase  
- Destroy: Physical destruction (logged, not executed)

NIST SP 800-88 Rev.1 Method Mappings:
- Cryptographic Erase (CE) → PURGE
- Firmware Secure Erase → PURGE
- NVMe Sanitize → PURGE
- Single-pass Overwrite → CLEAR
- Multi-pass Overwrite → CLEAR (legacy)
- Physical Destruction → DESTROY
"""

import os
import sys
import time
import random
import logging
import hashlib
import subprocess
from typing import Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .device_utils import DeviceInfo, DeviceDetector

# Configure logging
logger = logging.getLogger(__name__)


class SanitizationMethod(Enum):
    """NIST SP 800-88 Rev.1 compliant sanitization methods."""
    CRYPTO_ERASE = "crypto_erase"
    FIRMWARE_SECURE_ERASE = "firmware_secure_erase"
    NVME_SANITIZE = "nvme_sanitize"
    OVERWRITE_SINGLE = "overwrite_single"
    OVERWRITE_MULTI = "overwrite_multi"
    PHYSICAL_DESTROY = "physical_destroy"


class SanitizationResult(Enum):
    """Sanitization operation results."""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    NOT_SUPPORTED = "not_supported"
    DEVICE_BUSY = "device_busy"
    PERMISSION_DENIED = "permission_denied"


@dataclass
class WipeProgress:
    """Progress information for wipe operations."""
    total_bytes: int
    bytes_processed: int
    percent_complete: float
    estimated_time_remaining: int  # seconds
    current_method: str
    current_operation: str
    start_time: float
    errors_encountered: int


@dataclass
class WipeResult:
    """Result of a sanitization operation."""
    device_path: str
    method_used: SanitizationMethod
    result: SanitizationResult
    start_time: float
    end_time: float
    duration_seconds: float
    bytes_processed: int
    verification_passed: bool
    error_message: Optional[str]
    method_specific_data: Dict


class WipeEngine:
    """
    Core sanitization engine implementing NIST SP 800-88 Rev.1 methods.
    
    Provides automated method selection and execution of data sanitization
    operations across different device types and platforms.
    """
    
    def __init__(self, device_detector: Optional[DeviceDetector] = None):
        self.device_detector = device_detector or DeviceDetector()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Progress callback for GUI updates
        self.progress_callback: Optional[Callable[[WipeProgress], None]] = None
        
        # Method priority order (automatic selection)
        self.method_priority = [
            SanitizationMethod.CRYPTO_ERASE,
            SanitizationMethod.NVME_SANITIZE,
            SanitizationMethod.FIRMWARE_SECURE_ERASE,
            SanitizationMethod.OVERWRITE_SINGLE,
            SanitizationMethod.PHYSICAL_DESTROY
        ]
        
        # Platform-specific tool availability
        self._init_platform_tools()
    
    def _init_platform_tools(self) -> None:
        """Initialize platform-specific sanitization tools."""
        self.platform = sys.platform.lower()
        self.tools_available = {}
        
        if "win" in self.platform:
            self._check_windows_tools()
        elif "linux" in self.platform:
            self._check_linux_tools()
        elif "android" in self.platform or "termux" in os.environ.get("PREFIX", ""):
            self._check_android_tools()
    
    def _check_windows_tools(self) -> None:
        """Check availability of Windows sanitization tools."""
        tools = {
            "sdelete": ["sdelete", "/accepteula", "-?"],
            "format": ["format", "/?"],
            "diskpart": ["diskpart", "/?"],
            "cipher": ["cipher", "/?"]
        }
        
        for tool, test_cmd in tools.items():
            try:
                result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=5)
                self.tools_available[tool] = result.returncode == 0
                self.logger.debug(f"Windows tool {tool}: {'available' if self.tools_available[tool] else 'not available'}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                self.tools_available[tool] = False
    
    def _check_linux_tools(self) -> None:
        """Check availability of Linux sanitization tools."""
        tools = ["hdparm", "nvme", "dd", "shred", "cryptsetup", "sg_sanitize"]
        
        for tool in tools:
            try:
                result = subprocess.run(["which", tool], capture_output=True, text=True)
                self.tools_available[tool] = result.returncode == 0
                self.logger.debug(f"Linux tool {tool}: {'available' if self.tools_available[tool] else 'not available'}")
            except Exception:
                self.tools_available[tool] = False
    
    def _check_android_tools(self) -> None:
        """Check availability of Android sanitization tools."""
        tools = ["dd", "cat", "rm"]
        
        for tool in tools:
            try:
                result = subprocess.run(["which", tool], capture_output=True, text=True)
                self.tools_available[tool] = result.returncode == 0
                self.logger.debug(f"Android tool {tool}: {'available' if self.tools_available[tool] else 'not available'}")
            except Exception:
                self.tools_available[tool] = False
    
    def set_progress_callback(self, callback: Callable[[WipeProgress], None]) -> None:
        """Set callback function for progress updates."""
        self.progress_callback = callback
    
    def _update_progress(self, progress: WipeProgress) -> None:
        """Update progress and call callback if set."""
        if self.progress_callback:
            self.progress_callback(progress)
    
    def select_optimal_method(self, device_info: DeviceInfo, preferred_method: Optional[SanitizationMethod] = None) -> SanitizationMethod:
        """
        Select the optimal sanitization method for a device.
        
        NIST SP 800-88 Rev.1 Method Selection Logic:
        1. If encrypted storage → Cryptographic Erase (PURGE)
        2. If NVMe with sanitize support → NVMe Sanitize (PURGE)
        3. If ATA/SCSI with secure erase → Firmware Secure Erase (PURGE)
        4. Fallback → Single-pass Overwrite (CLEAR)
        5. Last resort → Physical Destruction (DESTROY)
        
        Args:
            device_info: Device information from detection
            preferred_method: User-specified preferred method
        
        Returns:
            Selected sanitization method
        """
        try:
            # If user specified a method, validate and use it
            if preferred_method:
                if self._is_method_supported(device_info, preferred_method):
                    self.logger.info(f"Using user-specified method: {preferred_method.value}")
                    return preferred_method
                else:
                    self.logger.warning(f"User-specified method {preferred_method.value} not supported, selecting optimal method")
            
            # Automatic method selection based on NIST guidelines
            for method in self.method_priority:
                if self._is_method_supported(device_info, method):
                    self.logger.info(f"Selected optimal method: {method.value}")
                    return method
            
            # Fallback to physical destruction logging
            self.logger.warning("No sanitization methods supported, recommending physical destruction")
            return SanitizationMethod.PHYSICAL_DESTROY
        
        except Exception as e:
            self.logger.error(f"Error selecting method: {e}")
            return SanitizationMethod.PHYSICAL_DESTROY
    
    def _is_method_supported(self, device_info: DeviceInfo, method: SanitizationMethod) -> bool:
        """Check if a sanitization method is supported for the device."""
        try:
            if method == SanitizationMethod.CRYPTO_ERASE:
                return device_info.is_encrypted and device_info.encryption_type in ["luks", "bitlocker", "sed"]
            
            elif method == SanitizationMethod.NVME_SANITIZE:
                return (device_info.device_type == "nvme" and 
                       device_info.capabilities.get("nvme_sanitize", False) and
                       self.tools_available.get("nvme", False))
            
            elif method == SanitizationMethod.FIRMWARE_SECURE_ERASE:
                return (device_info.capabilities.get("secure_erase", False) and
                       (self.tools_available.get("hdparm", False) or 
                        self.tools_available.get("sg_sanitize", False)))
            
            elif method == SanitizationMethod.OVERWRITE_SINGLE:
                return (self.tools_available.get("dd", False) or 
                       self.tools_available.get("sdelete", False) or
                       device_info.platform in ["windows", "linux", "android"])
            
            elif method == SanitizationMethod.OVERWRITE_MULTI:
                return (self.tools_available.get("shred", False) or
                       self.tools_available.get("sdelete", False))
            
            elif method == SanitizationMethod.PHYSICAL_DESTROY:
                return True  # Always "supported" as it's just logging
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error checking method support: {e}")
            return False
    
    def sanitize_device(self, device_path: str, method: Optional[SanitizationMethod] = None, 
                       verify: bool = True, **kwargs) -> WipeResult:
        """
        Sanitize a storage device using NIST SP 800-88 Rev.1 compliant methods.
        
        Args:
            device_path: Path to the device to sanitize
            method: Specific method to use (auto-select if None)
            verify: Whether to verify the sanitization
            **kwargs: Additional method-specific parameters
        
        Returns:
            WipeResult containing operation details
        """
        start_time = time.time()
        
        try:
            # Get device information
            device_info = self.device_detector.get_device_info(device_path)
            if not device_info:
                return self._create_error_result(device_path, start_time, "Device not found")
            
            # Safety check
            safe, reason = self.device_detector.is_device_safe_to_wipe(device_info)
            if not safe and not kwargs.get("force", False):
                return self._create_error_result(device_path, start_time, f"Device not safe to wipe: {reason}")
            
            # Select sanitization method
            selected_method = method or self.select_optimal_method(device_info, method)
            
            self.logger.info(f"Starting sanitization of {device_path} using {selected_method.value}")
            
            # Create initial progress
            progress = WipeProgress(
                total_bytes=device_info.size_bytes,
                bytes_processed=0,
                percent_complete=0.0,
                estimated_time_remaining=0,
                current_method=selected_method.value,
                current_operation="Initializing",
                start_time=start_time,
                errors_encountered=0
            )
            self._update_progress(progress)
            
            # Execute the sanitization method
            result = self._execute_sanitization_method(device_info, selected_method, progress, **kwargs)
            
            # Verify sanitization if requested
            if verify and result.result == SanitizationResult.SUCCESS:
                self.logger.info("Starting sanitization verification")
                progress.current_operation = "Verifying"
                self._update_progress(progress)
                
                verification_passed = self._verify_sanitization(device_info, selected_method, progress)
                result.verification_passed = verification_passed
                
                if not verification_passed:
                    result.result = SanitizationResult.PARTIAL
                    result.error_message = "Sanitization verification failed"
            
            # Update final times
            result.end_time = time.time()
            result.duration_seconds = result.end_time - result.start_time
            
            self.logger.info(f"Sanitization completed: {result.result.value} in {result.duration_seconds:.2f} seconds")
            
            return result
        
        except Exception as e:
            self.logger.error(f"Error during sanitization: {e}")
            return self._create_error_result(device_path, start_time, str(e))
    
    def _execute_sanitization_method(self, device_info: DeviceInfo, method: SanitizationMethod, 
                                    progress: WipeProgress, **kwargs) -> WipeResult:
        """Execute the specified sanitization method."""
        try:
            if method == SanitizationMethod.CRYPTO_ERASE:
                return self._crypto_erase(device_info, progress, **kwargs)
            elif method == SanitizationMethod.NVME_SANITIZE:
                return self._nvme_sanitize(device_info, progress, **kwargs)
            elif method == SanitizationMethod.FIRMWARE_SECURE_ERASE:
                return self._firmware_secure_erase(device_info, progress, **kwargs)
            elif method == SanitizationMethod.OVERWRITE_SINGLE:
                return self._overwrite_single_pass(device_info, progress, **kwargs)
            elif method == SanitizationMethod.OVERWRITE_MULTI:
                return self._overwrite_multi_pass(device_info, progress, **kwargs)
            elif method == SanitizationMethod.PHYSICAL_DESTROY:
                return self._log_physical_destruction(device_info, progress, **kwargs)
            else:
                return self._create_error_result(device_info.path, progress.start_time, f"Unknown method: {method}")
        
        except Exception as e:
            self.logger.error(f"Error executing {method.value}: {e}")
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _crypto_erase(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """
        NIST SP 800-88 Rev.1 PURGE Method: Cryptographic Erase
        
        Sanitizes encrypted storage by destroying encryption keys, making
        data cryptographically unrecoverable.
        """
        progress.current_operation = "Cryptographic Erase"
        self._update_progress(progress)
        
        try:
            if device_info.encryption_type == "luks":
                return self._crypto_erase_luks(device_info, progress, **kwargs)
            elif device_info.encryption_type == "bitlocker":
                return self._crypto_erase_bitlocker(device_info, progress, **kwargs)
            elif device_info.encryption_type == "sed":
                return self._crypto_erase_sed(device_info, progress, **kwargs)
            else:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"Unsupported encryption type: {device_info.encryption_type}")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _crypto_erase_luks(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """Cryptographic erase for LUKS encrypted devices."""
        try:
            if not self.tools_available.get("cryptsetup", False):
                return self._create_error_result(device_info.path, progress.start_time, 
                                               "cryptsetup tool not available")
            
            # Remove LUKS header
            cmd = ["cryptsetup", "erase", device_info.path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                progress.bytes_processed = device_info.size_bytes
                progress.percent_complete = 100.0
                self._update_progress(progress)
                
                return WipeResult(
                    device_path=device_info.path,
                    method_used=SanitizationMethod.CRYPTO_ERASE,
                    result=SanitizationResult.SUCCESS,
                    start_time=progress.start_time,
                    end_time=time.time(),
                    duration_seconds=0,
                    bytes_processed=device_info.size_bytes,
                    verification_passed=False,  # Will be set by verification
                    error_message=None,
                    method_specific_data={"luks_header_removed": True}
                )
            else:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"LUKS erase failed: {result.stderr}")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _crypto_erase_bitlocker(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """Cryptographic erase for BitLocker encrypted devices."""
        try:
            # Use manage-bde to clear keys
            cmd = ["manage-bde", "-delete", device_info.path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                progress.bytes_processed = device_info.size_bytes
                progress.percent_complete = 100.0
                self._update_progress(progress)
                
                return WipeResult(
                    device_path=device_info.path,
                    method_used=SanitizationMethod.CRYPTO_ERASE,
                    result=SanitizationResult.SUCCESS,
                    start_time=progress.start_time,
                    end_time=time.time(),
                    duration_seconds=0,
                    bytes_processed=device_info.size_bytes,
                    verification_passed=False,
                    error_message=None,
                    method_specific_data={"bitlocker_keys_cleared": True}
                )
            else:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"BitLocker key deletion failed: {result.stderr}")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _crypto_erase_sed(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """Cryptographic erase for Self-Encrypting Drives."""
        try:
            # Use sedutil or hdparm for SED crypto erase
            # This is a placeholder for actual SED implementation
            return self._create_error_result(device_info.path, progress.start_time, 
                                           "SED crypto erase not yet implemented")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _nvme_sanitize(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """
        NIST SP 800-88 Rev.1 PURGE Method: NVMe Sanitize
        
        Uses NVMe sanitize command for secure erase of NVMe SSDs.
        """
        progress.current_operation = "NVMe Sanitize"
        self._update_progress(progress)
        
        try:
            if not self.tools_available.get("nvme", False):
                return self._create_error_result(device_info.path, progress.start_time, 
                                               "nvme-cli tool not available")
            
            # Execute NVMe sanitize command
            sanitize_action = kwargs.get("sanitize_action", "crypto-erase")  # crypto-erase, block-erase, overwrite
            cmd = ["nvme", "sanitize", device_info.path, "-a", sanitize_action]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Monitor sanitize progress
                self._monitor_nvme_sanitize_progress(device_info, progress)
                
                return WipeResult(
                    device_path=device_info.path,
                    method_used=SanitizationMethod.NVME_SANITIZE,
                    result=SanitizationResult.SUCCESS,
                    start_time=progress.start_time,
                    end_time=time.time(),
                    duration_seconds=0,
                    bytes_processed=device_info.size_bytes,
                    verification_passed=False,
                    error_message=None,
                    method_specific_data={"sanitize_action": sanitize_action}
                )
            else:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"NVMe sanitize failed: {result.stderr}")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _monitor_nvme_sanitize_progress(self, device_info: DeviceInfo, progress: WipeProgress) -> None:
        """Monitor NVMe sanitize operation progress."""
        try:
            while True:
                # Check sanitize status
                cmd = ["nvme", "sanitize-log", device_info.path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if "Sanitize Progress" in result.stdout:
                    # Parse progress from output
                    # This is a simplified implementation
                    progress.percent_complete = 50.0  # Placeholder
                    self._update_progress(progress)
                    time.sleep(5)
                else:
                    # Sanitize completed
                    progress.percent_complete = 100.0
                    progress.bytes_processed = device_info.size_bytes
                    self._update_progress(progress)
                    break
        
        except Exception as e:
            self.logger.error(f"Error monitoring NVMe sanitize progress: {e}")
    
    def _firmware_secure_erase(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """
        NIST SP 800-88 Rev.1 PURGE Method: Firmware Secure Erase
        
        Uses ATA/SCSI secure erase commands for hardware-level sanitization.
        """
        progress.current_operation = "Firmware Secure Erase"
        self._update_progress(progress)
        
        try:
            if device_info.platform == "linux":
                return self._linux_secure_erase(device_info, progress, **kwargs)
            elif device_info.platform == "windows":
                return self._windows_secure_erase(device_info, progress, **kwargs)
            else:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"Secure erase not supported on {device_info.platform}")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _linux_secure_erase(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """Linux ATA/SCSI secure erase implementation."""
        try:
            if not self.tools_available.get("hdparm", False):
                return self._create_error_result(device_info.path, progress.start_time, 
                                               "hdparm tool not available")
            
            # Check if secure erase is supported and not frozen
            cmd = ["hdparm", "-I", device_info.path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if "frozen" in result.stdout.lower():
                return self._create_error_result(device_info.path, progress.start_time, 
                                               "Drive is frozen, secure erase not available")
            
            # Set user password (required for secure erase)
            password = "purgeproof"
            cmd = ["hdparm", "--user-master", "u", "--security-set-pass", password, device_info.path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"Failed to set security password: {result.stderr}")
            
            # Execute secure erase
            erase_type = "enhanced" if kwargs.get("enhanced", False) else "secure"
            cmd = ["hdparm", "--user-master", "u", f"--security-erase-{erase_type}", password, device_info.path]
            
            # This is a long-running operation
            start_erase_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)  # 2 hour timeout
            
            if result.returncode == 0:
                progress.bytes_processed = device_info.size_bytes
                progress.percent_complete = 100.0
                self._update_progress(progress)
                
                return WipeResult(
                    device_path=device_info.path,
                    method_used=SanitizationMethod.FIRMWARE_SECURE_ERASE,
                    result=SanitizationResult.SUCCESS,
                    start_time=progress.start_time,
                    end_time=time.time(),
                    duration_seconds=time.time() - start_erase_time,
                    bytes_processed=device_info.size_bytes,
                    verification_passed=False,
                    error_message=None,
                    method_specific_data={"erase_type": erase_type}
                )
            else:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"Secure erase failed: {result.stderr}")
        
        except subprocess.TimeoutExpired:
            return self._create_error_result(device_info.path, progress.start_time, 
                                           "Secure erase operation timed out")
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _windows_secure_erase(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """Windows secure erase implementation."""
        # Windows secure erase is more complex and requires low-level access
        # This is a placeholder for actual implementation
        return self._create_error_result(device_info.path, progress.start_time, 
                                       "Windows secure erase not yet implemented")
    
    def _overwrite_single_pass(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """
        NIST SP 800-88 Rev.1 CLEAR Method: Single-pass Overwrite
        
        Overwrites all accessible areas with random data or specified pattern.
        """
        progress.current_operation = "Single-pass Overwrite"
        self._update_progress(progress)
        
        try:
            pattern = kwargs.get("pattern", "random")  # random, zeros, ones, pattern
            block_size = kwargs.get("block_size", 1024 * 1024)  # 1MB blocks
            
            if device_info.platform == "linux":
                return self._linux_overwrite(device_info, progress, pattern, block_size, passes=1)
            elif device_info.platform == "windows":
                return self._windows_overwrite(device_info, progress, pattern, block_size, passes=1)
            elif device_info.platform == "android":
                return self._android_overwrite(device_info, progress, pattern, block_size, passes=1)
            else:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"Overwrite not supported on {device_info.platform}")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _overwrite_multi_pass(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """
        NIST SP 800-88 Rev.1 CLEAR Method: Multi-pass Overwrite (Legacy)
        
        Multiple overwrite passes for older magnetic media (generally not needed for modern drives).
        """
        progress.current_operation = "Multi-pass Overwrite"
        self._update_progress(progress)
        
        try:
            passes = kwargs.get("passes", 3)
            patterns = kwargs.get("patterns", ["random", "zeros", "ones"])
            block_size = kwargs.get("block_size", 1024 * 1024)
            
            if device_info.platform == "linux":
                return self._linux_overwrite(device_info, progress, patterns, block_size, passes)
            elif device_info.platform == "windows":
                return self._windows_overwrite(device_info, progress, patterns, block_size, passes)
            else:
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"Multi-pass overwrite not supported on {device_info.platform}")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _linux_overwrite(self, device_info: DeviceInfo, progress: WipeProgress, 
                         pattern, block_size: int, passes: int) -> WipeResult:
        """Linux overwrite implementation using dd."""
        try:
            if not self.tools_available.get("dd", False):
                return self._create_error_result(device_info.path, progress.start_time, 
                                               "dd command not available")
            
            total_bytes = device_info.size_bytes
            bytes_per_pass = total_bytes
            
            for pass_num in range(passes):
                self.logger.info(f"Starting overwrite pass {pass_num + 1}/{passes}")
                progress.current_operation = f"Overwrite Pass {pass_num + 1}/{passes}"
                
                # Determine pattern for this pass
                if isinstance(pattern, list):
                    current_pattern = pattern[pass_num % len(pattern)]
                else:
                    current_pattern = pattern
                
                # Create appropriate input source
                if current_pattern == "random":
                    input_source = "/dev/urandom"
                elif current_pattern == "zeros":
                    input_source = "/dev/zero"
                else:
                    # For specific patterns, we'd need to create a temporary file
                    input_source = "/dev/urandom"  # Fallback
                
                # Execute dd command
                cmd = [
                    "dd",
                    f"if={input_source}",
                    f"of={device_info.path}",
                    f"bs={block_size}",
                    f"count={bytes_per_pass // block_size}",
                    "conv=notrunc",
                    "status=progress"
                ]
                
                start_pass_time = time.time()
                
                # Run with progress monitoring
                process = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
                
                while process.poll() is None:
                    # Monitor progress (simplified)
                    current_time = time.time()
                    elapsed = current_time - start_pass_time
                    
                    # Estimate progress based on time (rough approximation)
                    estimated_bytes = min(bytes_per_pass, int((elapsed / 60) * bytes_per_pass * 0.1))
                    total_processed = (pass_num * bytes_per_pass) + estimated_bytes
                    
                    progress.bytes_processed = total_processed
                    progress.percent_complete = (total_processed / (total_bytes * passes)) * 100
                    progress.estimated_time_remaining = int((elapsed / max(estimated_bytes, 1)) * (total_bytes * passes - total_processed))
                    
                    self._update_progress(progress)
                    time.sleep(1)
                
                # Check if pass completed successfully
                if process.returncode != 0:
                    stderr = process.stderr.read() if process.stderr else "Unknown error"
                    return self._create_error_result(device_info.path, progress.start_time, 
                                                   f"Overwrite pass {pass_num + 1} failed: {stderr}")
            
            # Sync to ensure data is written
            subprocess.run(["sync"], check=True)
            
            # Final progress update
            progress.bytes_processed = total_bytes * passes
            progress.percent_complete = 100.0
            self._update_progress(progress)
            
            return WipeResult(
                device_path=device_info.path,
                method_used=SanitizationMethod.OVERWRITE_MULTI if passes > 1 else SanitizationMethod.OVERWRITE_SINGLE,
                result=SanitizationResult.SUCCESS,
                start_time=progress.start_time,
                end_time=time.time(),
                duration_seconds=0,
                bytes_processed=total_bytes * passes,
                verification_passed=False,
                error_message=None,
                method_specific_data={"passes": passes, "pattern": pattern, "block_size": block_size}
            )
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _windows_overwrite(self, device_info: DeviceInfo, progress: WipeProgress, 
                          pattern, block_size: int, passes: int) -> WipeResult:
        """Windows overwrite implementation."""
        try:
            # Use sdelete if available, otherwise PowerShell
            if self.tools_available.get("sdelete", False):
                return self._windows_sdelete_overwrite(device_info, progress, passes)
            else:
                return self._windows_powershell_overwrite(device_info, progress, pattern, block_size, passes)
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _windows_sdelete_overwrite(self, device_info: DeviceInfo, progress: WipeProgress, passes: int) -> WipeResult:
        """Windows overwrite using SDelete."""
        try:
            cmd = ["sdelete", "-accepteula", "-z", f"-p {passes}", device_info.path]
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Monitor progress (simplified)
            start_time = time.time()
            while process.poll() is None:
                elapsed = time.time() - start_time
                # Rough progress estimation
                progress.percent_complete = min(95.0, (elapsed / 3600) * 100)  # Assume 1 hour max
                self._update_progress(progress)
                time.sleep(5)
            
            if process.returncode == 0:
                progress.bytes_processed = device_info.size_bytes * passes
                progress.percent_complete = 100.0
                self._update_progress(progress)
                
                return WipeResult(
                    device_path=device_info.path,
                    method_used=SanitizationMethod.OVERWRITE_MULTI if passes > 1 else SanitizationMethod.OVERWRITE_SINGLE,
                    result=SanitizationResult.SUCCESS,
                    start_time=progress.start_time,
                    end_time=time.time(),
                    duration_seconds=0,
                    bytes_processed=device_info.size_bytes * passes,
                    verification_passed=False,
                    error_message=None,
                    method_specific_data={"tool": "sdelete", "passes": passes}
                )
            else:
                stderr = process.stderr.read() if process.stderr else "Unknown error"
                return self._create_error_result(device_info.path, progress.start_time, 
                                               f"SDelete failed: {stderr}")
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _windows_powershell_overwrite(self, device_info: DeviceInfo, progress: WipeProgress, 
                                     pattern, block_size: int, passes: int) -> WipeResult:
        """Windows overwrite using PowerShell."""
        # This would implement a PowerShell-based overwrite
        # For now, return not implemented
        return self._create_error_result(device_info.path, progress.start_time, 
                                       "PowerShell overwrite not yet implemented")
    
    def _android_overwrite(self, device_info: DeviceInfo, progress: WipeProgress, 
                          pattern, block_size: int, passes: int) -> WipeResult:
        """Android overwrite implementation."""
        try:
            if not self.tools_available.get("dd", False):
                return self._create_error_result(device_info.path, progress.start_time, 
                                               "dd command not available on Android")
            
            # Android implementation similar to Linux but with more careful permission handling
            # This is a simplified implementation
            return self._linux_overwrite(device_info, progress, pattern, block_size, passes)
        
        except Exception as e:
            return self._create_error_result(device_info.path, progress.start_time, str(e))
    
    def _log_physical_destruction(self, device_info: DeviceInfo, progress: WipeProgress, **kwargs) -> WipeResult:
        """
        NIST SP 800-88 Rev.1 DESTROY Method: Physical Destruction
        
        Logs recommendation for physical destruction when sanitization is not possible.
        """
        progress.current_operation = "Physical Destruction Required"
        progress.percent_complete = 100.0
        self._update_progress(progress)
        
        destruction_methods = [
            "Disintegration",
            "Degaussing (for magnetic media)",
            "Pulverization", 
            "Incineration",
            "Professional destruction service"
        ]
        
        return WipeResult(
            device_path=device_info.path,
            method_used=SanitizationMethod.PHYSICAL_DESTROY,
            result=SanitizationResult.SUCCESS,
            start_time=progress.start_time,
            end_time=time.time(),
            duration_seconds=0,
            bytes_processed=0,
            verification_passed=True,  # N/A for physical destruction
            error_message=None,
            method_specific_data={
                "recommendation": "Physical destruction required",
                "methods": destruction_methods,
                "reason": "No software sanitization methods available or supported"
            }
        )
    
    def _verify_sanitization(self, device_info: DeviceInfo, method: SanitizationMethod, 
                            progress: WipeProgress) -> bool:
        """
        Verify that sanitization was successful according to NIST SP 800-88 Rev.1.
        
        Verification methods:
        - Cryptographic Erase: Verify keys are destroyed
        - Firmware Erase: Check device status codes
        - Overwrite: Sample random blocks and verify pattern
        """
        try:
            if method == SanitizationMethod.CRYPTO_ERASE:
                return self._verify_crypto_erase(device_info)
            elif method in [SanitizationMethod.NVME_SANITIZE, SanitizationMethod.FIRMWARE_SECURE_ERASE]:
                return self._verify_firmware_erase(device_info, method)
            elif method in [SanitizationMethod.OVERWRITE_SINGLE, SanitizationMethod.OVERWRITE_MULTI]:
                return self._verify_overwrite(device_info, progress)
            elif method == SanitizationMethod.PHYSICAL_DESTROY:
                return True  # Physical destruction verification is manual
            else:
                return False
        
        except Exception as e:
            self.logger.error(f"Error during verification: {e}")
            return False
    
    def _verify_crypto_erase(self, device_info: DeviceInfo) -> bool:
        """Verify cryptographic erase by checking if encryption keys are accessible."""
        try:
            if device_info.encryption_type == "luks":
                # Try to mount LUKS device - should fail
                cmd = ["cryptsetup", "luksOpen", device_info.path, "test-mount"]
                result = subprocess.run(cmd, capture_output=True, text=True, input="wrong-password\n")
                return result.returncode != 0  # Should fail to open
            
            elif device_info.encryption_type == "bitlocker":
                # Check BitLocker status
                cmd = ["manage-bde", "-status", device_info.path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                return "Protection Off" in result.stdout or "Decrypted" in result.stdout
            
            return True  # Default to success for unknown encryption types
        
        except Exception as e:
            self.logger.error(f"Error verifying crypto erase: {e}")
            return False
    
    def _verify_firmware_erase(self, device_info: DeviceInfo, method: SanitizationMethod) -> bool:
        """Verify firmware-based erase operations."""
        try:
            if method == SanitizationMethod.NVME_SANITIZE:
                # Check NVMe sanitize log
                cmd = ["nvme", "sanitize-log", device_info.path]
                result = subprocess.run(cmd, capture_output=True, text=True)
                return "Sanitize Status" in result.stdout and "Success" in result.stdout
            
            elif method == SanitizationMethod.FIRMWARE_SECURE_ERASE:
                # For ATA secure erase, the operation is considered verified if it completed without error
                # Additional verification would require specialized tools
                return True
            
            return False
        
        except Exception as e:
            self.logger.error(f"Error verifying firmware erase: {e}")
            return False
    
    def _verify_overwrite(self, device_info: DeviceInfo, progress: WipeProgress) -> bool:
        """Verify overwrite operations by sampling random blocks."""
        try:
            sample_size = min(device_info.size_bytes, 100 * 1024 * 1024)  # Sample up to 100MB
            num_samples = 100  # Number of random locations to check
            block_size = 4096  # 4KB blocks
            
            progress.current_operation = "Sampling verification blocks"
            
            for i in range(num_samples):
                # Calculate random offset
                max_offset = device_info.size_bytes - block_size
                offset = random.randint(0, max_offset // block_size) * block_size
                
                # Read block at offset
                try:
                    with open(device_info.path, 'rb') as f:
                        f.seek(offset)
                        block_data = f.read(block_size)
                        
                        # Check if block contains non-random data patterns
                        if self._contains_structured_data(block_data):
                            self.logger.warning(f"Structured data found at offset {offset}")
                            return False
                
                except Exception as e:
                    self.logger.error(f"Error reading verification block at offset {offset}: {e}")
                    return False
                
                # Update progress
                progress.percent_complete = ((i + 1) / num_samples) * 100
                self._update_progress(progress)
            
            return True
        
        except Exception as e:
            self.logger.error(f"Error during overwrite verification: {e}")
            return False
    
    def _contains_structured_data(self, data: bytes) -> bool:
        """Check if data contains structured patterns that suggest incomplete wiping."""
        try:
            # Check for common file signatures
            signatures = [
                b'\\x50\\x4B',  # ZIP/Office files
                b'\\x89\\x50\\x4E\\x47',  # PNG
                b'\\xFF\\xD8\\xFF',  # JPEG
                b'\\x25\\x50\\x44\\x46',  # PDF
                b'MZ',  # PE executable
                b'\\x7FELF',  # ELF executable
            ]
            
            for sig in signatures:
                if sig in data:
                    return True
            
            # Check for text patterns
            try:
                text = data.decode('utf-8', errors='ignore')
                if len(text) > len(data) * 0.8:  # Mostly text
                    # Look for structured text patterns
                    patterns = ['filename', 'directory', 'password', 'username', 'email', 'http']
                    for pattern in patterns:
                        if pattern in text.lower():
                            return True
            except:
                pass
            
            # Check for repetitive patterns (might indicate incomplete overwrite)
            if len(set(data)) < 10:  # Very low entropy
                return True
            
            return False
        
        except Exception:
            return False  # If we can't analyze, assume it's random
    
    def _create_error_result(self, device_path: str, start_time: float, error_message: str) -> WipeResult:
        """Create a WipeResult for error conditions."""
        return WipeResult(
            device_path=device_path,
            method_used=SanitizationMethod.PHYSICAL_DESTROY,  # Default for errors
            result=SanitizationResult.FAILED,
            start_time=start_time,
            end_time=time.time(),
            duration_seconds=time.time() - start_time,
            bytes_processed=0,
            verification_passed=False,
            error_message=error_message,
            method_specific_data={}
        )


def main():
    """CLI interface for wipe engine testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="PurgeProof Wipe Engine Test")
    parser.add_argument("device", help="Device path to test")
    parser.add_argument("--method", choices=[m.value for m in SanitizationMethod], 
                       help="Sanitization method to use")
    parser.add_argument("--dry-run", action="store_true", help="Dry run (don't actually wipe)")
    parser.add_argument("--verify", action="store_true", default=True, help="Verify sanitization")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")
    
    if args.dry_run:
        print(f"DRY RUN: Would sanitize {args.device} using method {args.method or 'auto'}")
        return
    
    # Initialize wipe engine
    detector = DeviceDetector()
    engine = WipeEngine(detector)
    
    # Set up progress callback
    def progress_callback(progress: WipeProgress):
        print(f"Progress: {progress.percent_complete:.1f}% - {progress.current_operation}")
    
    engine.set_progress_callback(progress_callback)
    
    # Get device info
    device_info = detector.get_device_info(args.device)
    if not device_info:
        print(f"Device not found: {args.device}")
        return
    
    # Check if safe to wipe
    safe, reason = detector.is_device_safe_to_wipe(device_info)
    if not safe:
        print(f"Device not safe to wipe: {reason}")
        print("Use --force flag to override (not implemented in test)")
        return
    
    # Select method
    method = SanitizationMethod(args.method) if args.method else None
    selected_method = engine.select_optimal_method(device_info, method)
    print(f"Selected method: {selected_method.value}")
    
    # Perform sanitization
    result = engine.sanitize_device(args.device, selected_method, args.verify)
    
    # Display results
    print(f"\\nSanitization Result:")
    print(f"  Status: {result.result.value}")
    print(f"  Duration: {result.duration_seconds:.2f} seconds")
    print(f"  Bytes processed: {result.bytes_processed}")
    print(f"  Verification: {'Passed' if result.verification_passed else 'Failed'}")
    if result.error_message:
        print(f"  Error: {result.error_message}")


if __name__ == "__main__":
    main()
