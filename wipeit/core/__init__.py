"""
PurgeProof Core - NIST SP 800-88 Rev.1 Compliant Data Sanitization

This package provides the core functionality for secure data sanitization
across multiple platforms and storage device types.

Modules:
    device_utils: Device detection and classification
    wipe_engine: Sanitization method implementations
    verification: Data wipe verification and validation
    certificates: Certificate generation and digital signing
    crypto_utils: Cryptographic utilities and key management
"""

__version__ = "1.0.0"
__author__ = "PurgeProof Team"
__license__ = "MIT"

# NIST SP 800-88 Rev.1 compliance level
NIST_COMPLIANCE_LEVEL = "Rev.1"

# Supported sanitization methods
SANITIZATION_METHODS = {
    "crypto_erase": "Cryptographic Erase (NIST Clear/Purge)",
    "firmware_secure_erase": "Firmware Secure Erase (NIST Purge)", 
    "nvme_sanitize": "NVMe Sanitize Command (NIST Purge)",
    "overwrite_single": "Single-pass Overwrite (NIST Clear)",
    "overwrite_multi": "Multi-pass Overwrite (Legacy)",
    "physical_destroy": "Physical Destruction (NIST Destroy)"
}

# Supported device types
DEVICE_TYPES = {
    "hdd": "Hard Disk Drive (Magnetic)",
    "ssd": "Solid State Drive", 
    "nvme": "NVMe SSD",
    "sed": "Self-Encrypting Drive",
    "mobile": "Mobile/Android Partition",
    "unknown": "Unknown Device Type"
}

from .device_utils import DeviceDetector
from .wipe_engine import WipeEngine
from .verification import VerificationEngine
from .certificates import CertificateGenerator
from .crypto_utils import CryptoManager

__all__ = [
    "DeviceDetector",
    "WipeEngine", 
    "VerificationEngine",
    "CertificateGenerator",
    "CryptoManager",
    "SANITIZATION_METHODS",
    "DEVICE_TYPES",
    "NIST_COMPLIANCE_LEVEL"
]
