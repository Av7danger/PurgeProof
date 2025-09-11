"""
PurgeProof GUI Package

Graphical user interface components for the PurgeProof data sanitization tool.

This package provides:
- Main GUI application (main.py)
- PyQt6-based modern interface (gui_pyqt.py)
- Web-based interface (gui_web.py)
- Common GUI utilities and widgets

Usage:
    from gui.main import PurgeProofGUI
    
    app = PurgeProofGUI()
    app.run()
"""

__version__ = "1.0.0"
__author__ = "PurgeProof Development Team"

# Import main classes for convenience
try:
    from .main import PurgeProofGUI
    __all__ = ["PurgeProofGUI"]
except ImportError:
    # Handle missing dependencies gracefully
    __all__ = []
