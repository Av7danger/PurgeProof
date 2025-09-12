"""
WipeIt - Secure Data Wiping Utility

A comprehensive tool for secure data erasure with verification capabilities.
"""

__version__ = "0.1.0"
__author__ = "Your Name <your.email@example.com>"
__license__ = "MIT"

# Import core functionality
from .core import (
    wipe_engine,
    device_utils,
    crypto_utils,
    verification,
    certificates
)

__all__ = [
    'wipe_engine',
    'device_utils',
    'crypto_utils',
    'verification',
    'certificates',
]
