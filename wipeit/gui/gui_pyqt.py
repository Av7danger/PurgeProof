"""
PurgeProof PyQt6 GUI - Modern Data Sanitization Interface

A modern, feature-rich graphical interface using PyQt6.
This provides a more polished user experience compared to the tkinter version.

Requirements:
    pip install PyQt6 PyQt6-tools
"""

import os
import sys
from pathlib import Path
from typing import Optional, List, Dict, Any
import threading
import time

# Check for PyQt6 availability
try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QGridLayout, QLabel, QPushButton, QComboBox, QTextEdit, QProgressBar,
        QCheckBox, QGroupBox, QMessageBox, QFileDialog, QSplitter,
        QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
        QStatusBar, QMenuBar, QToolBar, QFrame, QScrollArea
    )
    from PyQt6.QtCore import (
        Qt, QThread, pyqtSignal, QTimer, QSettings, QSize, QRect,
        QPropertyAnimation, QEasingCurve, QParallelAnimationGroup
    )
    from PyQt6.QtGui import (
        QIcon, QFont, QPixmap, QPalette, QColor, QAction,
        QPainter, QBrush, QPen, QLinearGradient
    )
    
    PYQT6_AVAILABLE = True
except ImportError:
    PYQT6_AVAILABLE = False
    # Create dummy classes for type hints
    class QMainWindow: pass
    class QThread: pass
    class pyqtSignal: 
        def __init__(self, *args): pass

# Add the wipeit package to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if PYQT6_AVAILABLE:
    try:
        from core.device_utils import DeviceDetector, DeviceInfo
        from core.wipe_engine import WipeEngine, SanitizationMethod, WipeProgress, WipeResult
        from core.verification import VerificationEngine, VerificationLevel
        from core.certificates import CertificateGenerator
        from core.crypto_utils import CryptoManager
    except ImportError as e:
        print(f"Error importing PurgeProof modules: {e}")
        sys.exit(1)


class SanitizationWorker(QThread):
    """Worker thread for sanitization operations."""
    
    # Signals
    progress_updated = pyqtSignal(object)  # WipeProgress
    sanitization_completed = pyqtSignal(object)  # WipeResult
    sanitization_error = pyqtSignal(str)
    
    def __init__(self, wipe_engine: 'WipeEngine', device: 'DeviceInfo', 
                 method: Optional['SanitizationMethod'], verify: bool):
        super().__init__()
        self.wipe_engine = wipe_engine
        self.device = device
        self.method = method
        self.verify = verify
        self._stop_requested = False
        
        # Set progress callback
        self.wipe_engine.set_progress_callback(self._on_progress)
    
    def _on_progress(self, progress: 'WipeProgress'):
        """Handle progress updates."""
        self.progress_updated.emit(progress)
    
    def request_stop(self):
        """Request the worker to stop."""
        self._stop_requested = True
    
    def run(self):
        """Execute sanitization in the worker thread."""
        try:
            result = self.wipe_engine.sanitize_device(
                self.device.path,
                method=self.method,
                verify=self.verify,
                force=True
            )
            
            if not self._stop_requested:
                self.sanitization_completed.emit(result)
        
        except Exception as e:
            if not self._stop_requested:
                self.sanitization_error.emit(str(e))


class DeviceInfoWidget(QWidget):
    """Widget for displaying device information."""
    
    def __init__(self):
        super().__init__()
        self._setup_ui()
    
    def _setup_ui(self):
        """Set up the widget UI."""
        layout = QVBoxLayout(self)
        
        # Create table for device info
        self.info_table = QTableWidget(0, 2)
        self.info_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.info_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.info_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.info_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.info_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.info_table)
    
    def update_device_info(self, device: 'DeviceInfo', device_detector: 'DeviceDetector'):
        """Update the display with device information."""
        if not device:
            self.info_table.setRowCount(0)
            return
        
        info_items = [
            ("Device Path", device.path),
            ("Model", device.model),
            ("Serial Number", device.serial),
            ("Device Type", device.device_type.upper()),
            ("Storage Capacity", f"{device.size_bytes / (1024**3):.2f} GB"),
            ("Platform", device.platform.title()),
            ("Removable", "Yes" if device.removable else "No"),
            ("Encryption", device.encryption_type if device.is_encrypted else "None"),
            ("Mounted", "Yes" if device.mounted else "No"),
        ]
        
        if device.mounted and device.mount_points:
            info_items.append(("Mount Points", ", ".join(device.mount_points)))
        
        # Add capabilities
        capabilities = [cap for cap, supported in device.capabilities.items() if supported]
        if capabilities:
            info_items.append(("Capabilities", ", ".join(capabilities)))
        
        # Safety check
        safe, reason = device_detector.is_device_safe_to_wipe(device)
        safety_status = "✓ SAFE TO WIPE" if safe else "⚠ WARNING"
        info_items.extend([
            ("Safety Check", safety_status),
            ("Safety Reason", reason)
        ])
        
        # Update table
        self.info_table.setRowCount(len(info_items))
        for row, (prop, value) in enumerate(info_items):
            self.info_table.setItem(row, 0, QTableWidgetItem(prop))
            self.info_table.setItem(row, 1, QTableWidgetItem(str(value)))


class PurgeProofQtGUI(QMainWindow):
    """Main PyQt6 application window."""
    
    def __init__(self):
        super().__init__()
        
        # Application state
        self.devices: List['DeviceInfo'] = []
        self.selected_device: Optional['DeviceInfo'] = None
        self.sanitization_worker: Optional[SanitizationWorker] = None
        self.settings = QSettings("PurgeProof", "DataSanitizer")
        
        # Initialize core components
        self.device_detector = DeviceDetector()
        self.wipe_engine = WipeEngine(self.device_detector)
        self.verification_engine = VerificationEngine()
        self.certificate_generator = CertificateGenerator()
        
        # Set up UI
        self._setup_ui()
        self._setup_menu()
        self._setup_toolbar()
        self._setup_statusbar()
        self._load_settings()
        
        # Refresh devices on startup
        QTimer.singleShot(100, self._refresh_devices)
    
    def _setup_ui(self):
        """Set up the main user interface."""
        self.setWindowTitle("PurgeProof - Professional Data Sanitization")
        self.setMinimumSize(1000, 700)
        self.resize(1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create splitter for main content
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel
        left_panel = self._create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel
        right_panel = self._create_right_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([400, 600])
        
        # Progress section
        progress_section = self._create_progress_section()
        main_layout.addWidget(progress_section)
        
        # Action buttons
        buttons_section = self._create_buttons_section()
        main_layout.addWidget(buttons_section)
    
    def _create_left_panel(self) -> QWidget:
        """Create the left panel with device selection and options."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Device selection group
        device_group = QGroupBox("Device Selection")
        device_layout = QVBoxLayout(device_group)
        
        # Device combo box
        device_layout.addWidget(QLabel("Storage Devices:"))
        self.device_combo = QComboBox()
        self.device_combo.setMinimumHeight(30)
        self.device_combo.currentIndexChanged.connect(self._on_device_selected)
        device_layout.addWidget(self.device_combo)
        
        # Refresh button
        self.refresh_button = QPushButton("🔄 Refresh Devices")
        self.refresh_button.clicked.connect(self._refresh_devices)
        device_layout.addWidget(self.refresh_button)
        
        layout.addWidget(device_group)
        
        # Options group
        options_group = QGroupBox("Sanitization Options")
        options_layout = QGridLayout(options_group)
        
        # Method selection
        options_layout.addWidget(QLabel("Method:"), 0, 0)
        self.method_combo = QComboBox()
        methods = ["auto"] + [method.value for method in SanitizationMethod]
        self.method_combo.addItems(methods)
        options_layout.addWidget(self.method_combo, 0, 1)
        
        # Verification level
        options_layout.addWidget(QLabel("Verification:"), 1, 0)
        self.verification_combo = QComboBox()
        verification_levels = [level.value for level in VerificationLevel]
        self.verification_combo.addItems(verification_levels)
        self.verification_combo.setCurrentText("standard")
        options_layout.addWidget(self.verification_combo, 1, 1)
        
        # Checkboxes
        self.verify_checkbox = QCheckBox("Verify sanitization")
        self.verify_checkbox.setChecked(True)
        options_layout.addWidget(self.verify_checkbox, 2, 0, 1, 2)
        
        self.certificate_checkbox = QCheckBox("Generate certificate")
        self.certificate_checkbox.setChecked(True)
        options_layout.addWidget(self.certificate_checkbox, 3, 0, 1, 2)
        
        layout.addWidget(options_group)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        return panel
    
    def _create_right_panel(self) -> QWidget:
        """Create the right panel with device information and logs."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Device info tab
        self.device_info_widget = DeviceInfoWidget()
        self.tab_widget.addTab(self.device_info_widget, "Device Information")
        
        # Log tab
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Consolas", 9))
        self.tab_widget.addTab(self.log_text, "Activity Log")
        
        layout.addWidget(self.tab_widget)
        
        return panel
    
    def _create_progress_section(self) -> QWidget:
        """Create the progress section."""
        section = QGroupBox("Progress")
        layout = QVBoxLayout(section)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimumHeight(25)
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        
        # Progress label
        self.progress_label = QLabel("Ready")
        layout.addWidget(self.progress_label)
        
        return section
    
    def _create_buttons_section(self) -> QWidget:
        """Create the action buttons section."""
        section = QWidget()
        layout = QHBoxLayout(section)
        
        # Sanitize button
        self.sanitize_button = QPushButton("🗑️ Sanitize Device")
        self.sanitize_button.setMinimumHeight(40)
        self.sanitize_button.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                font-weight: bold;
                border: none;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #b71c1c;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        self.sanitize_button.clicked.connect(self._start_sanitization)
        self.sanitize_button.setEnabled(False)
        layout.addWidget(self.sanitize_button)
        
        # Stop button
        self.stop_button = QPushButton("⏹️ Stop")
        self.stop_button.setMinimumHeight(40)
        self.stop_button.clicked.connect(self._stop_sanitization)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)
        
        # View certificates button
        self.certificates_button = QPushButton("📄 View Certificates")
        self.certificates_button.setMinimumHeight(40)
        self.certificates_button.clicked.connect(self._view_certificates)
        layout.addWidget(self.certificates_button)
        
        # Help button
        self.help_button = QPushButton("❓ Help")
        self.help_button.setMinimumHeight(40)
        self.help_button.clicked.connect(self._show_help)
        layout.addWidget(self.help_button)
        
        layout.addStretch()
        
        return section
    
    def _setup_menu(self):
        """Set up the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        
        refresh_action = QAction("&Refresh Devices", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self._refresh_devices)
        file_menu.addAction(refresh_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("&Tools")
        
        certificates_action = QAction("View &Certificates", self)
        certificates_action.triggered.connect(self._view_certificates)
        tools_menu.addAction(certificates_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        
        help_action = QAction("&User Guide", self)
        help_action.triggered.connect(self._show_help)
        help_menu.addAction(help_action)
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _setup_toolbar(self):
        """Set up the toolbar."""
        toolbar = self.addToolBar("Main")
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        
        # Refresh action
        refresh_action = QAction("🔄", self)
        refresh_action.setText("Refresh")
        refresh_action.setToolTip("Refresh device list (F5)")
        refresh_action.triggered.connect(self._refresh_devices)
        toolbar.addAction(refresh_action)
        
        toolbar.addSeparator()
        
        # Sanitize action
        sanitize_action = QAction("🗑️", self)
        sanitize_action.setText("Sanitize")
        sanitize_action.setToolTip("Start sanitization")
        sanitize_action.triggered.connect(self._start_sanitization)
        toolbar.addAction(sanitize_action)
        
        # Stop action
        stop_action = QAction("⏹️", self)
        stop_action.setText("Stop")
        stop_action.setToolTip("Stop sanitization")
        stop_action.triggered.connect(self._stop_sanitization)
        toolbar.addAction(stop_action)
    
    def _setup_statusbar(self):
        """Set up the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def _load_settings(self):
        """Load application settings."""
        # Restore window geometry
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        
        # Restore window state
        state = self.settings.value("windowState")
        if state:
            self.restoreState(state)
    
    def _save_settings(self):
        """Save application settings."""
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
    
    def _refresh_devices(self):
        """Refresh the device list."""
        self.status_bar.showMessage("Scanning for devices...")
        self._log("Scanning for storage devices...")
        
        try:
            self.devices = self.device_detector.list_storage_devices()
            
            # Update combo box
            self.device_combo.clear()
            
            for device in self.devices:
                size_gb = device.size_bytes / (1024**3)
                text = f"{device.path} - {device.model} ({size_gb:.1f} GB)"
                self.device_combo.addItem(text)
            
            if self.devices:
                self.device_combo.setCurrentIndex(0)
                self._on_device_selected(0)
                message = f"Found {len(self.devices)} storage device(s)"
                self.status_bar.showMessage(message)
                self._log(message)
            else:
                self.selected_device = None
                self.device_info_widget.update_device_info(None, self.device_detector)
                self.sanitize_button.setEnabled(False)
                message = "No storage devices found"
                self.status_bar.showMessage(message)
                self._log(message)
        
        except Exception as e:
            error_msg = f"Failed to refresh devices: {e}"
            self.status_bar.showMessage(error_msg)
            self._log(f"ERROR: {error_msg}")
            QMessageBox.critical(self, "Error", error_msg)
    
    def _on_device_selected(self, index: int):
        """Handle device selection."""
        if 0 <= index < len(self.devices):
            self.selected_device = self.devices[index]
            self.device_info_widget.update_device_info(self.selected_device, self.device_detector)
            self.sanitize_button.setEnabled(True)
            self._log(f"Selected device: {self.selected_device.path}")
        else:
            self.selected_device = None
            self.sanitize_button.setEnabled(False)
    
    def _start_sanitization(self):
        """Start the sanitization process."""
        if not self.selected_device:
            QMessageBox.warning(self, "Warning", "No device selected")
            return
        
        if self.sanitization_worker and self.sanitization_worker.isRunning():
            QMessageBox.warning(self, "Warning", "Sanitization already in progress")
            return
        
        # Safety confirmation
        device = self.selected_device
        safe, reason = self.device_detector.is_device_safe_to_wipe(device)
        
        if not safe:
            reply = QMessageBox.question(
                self, "Safety Warning",
                f"Safety check failed: {reason}\\n\\n"
                f"This device may contain important system data. "
                f"Proceeding will PERMANENTLY DESTROY all data on the device.\\n\\n"
                f"Do you want to continue anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        # Final confirmation
        reply = QMessageBox.question(
            self, "Confirm Sanitization",
            f"⚠ WARNING: This will PERMANENTLY DESTROY all data on:\\n\\n"
            f"Device: {device.path}\\n"
            f"Model: {device.model}\\n"
            f"Serial: {device.serial}\\n"
            f"Size: {device.size_bytes / (1024**3):.2f} GB\\n\\n"
            f"This action cannot be undone!\\n\\n"
            f"Are you absolutely sure you want to continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Prepare sanitization
        method = None
        if self.method_combo.currentText() != "auto":
            method = SanitizationMethod(self.method_combo.currentText())
        
        verify = self.verify_checkbox.isChecked()
        
        # Start worker thread
        self.sanitization_worker = SanitizationWorker(
            self.wipe_engine, device, method, verify
        )
        self.sanitization_worker.progress_updated.connect(self._on_progress_updated)
        self.sanitization_worker.sanitization_completed.connect(self._on_sanitization_completed)
        self.sanitization_worker.sanitization_error.connect(self._on_sanitization_error)
        
        self.sanitization_worker.start()
        
        # Update UI state
        self._update_ui_state(sanitizing=True)
        self.status_bar.showMessage("Sanitization started")
        self._log(f"Starting sanitization of {device.path}")
    
    def _stop_sanitization(self):
        """Stop the sanitization process."""
        if self.sanitization_worker and self.sanitization_worker.isRunning():
            reply = QMessageBox.question(
                self, "Stop Sanitization",
                "Stopping sanitization may leave the device in an unsafe state.\\n\\n"
                "Are you sure you want to stop?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.sanitization_worker.request_stop()
                self.sanitization_worker.wait(5000)  # Wait up to 5 seconds
                self._update_ui_state(sanitizing=False)
                self.status_bar.showMessage("Sanitization stopped by user")
                self._log("Sanitization stopped by user")
    
    def _on_progress_updated(self, progress: 'WipeProgress'):
        """Handle progress updates."""
        self.progress_bar.setValue(int(progress.percent_complete))
        
        if progress.estimated_time_remaining > 0:
            time_remaining = self._format_time(progress.estimated_time_remaining)
            progress_text = f"{progress.current_operation} - {progress.percent_complete:.1f}% - ETA: {time_remaining}"
        else:
            progress_text = f"{progress.current_operation} - {progress.percent_complete:.1f}%"
        
        self.progress_label.setText(progress_text)
        self.status_bar.showMessage(f"Sanitizing: {progress.current_operation}")
    
    def _on_sanitization_completed(self, wipe_result: 'WipeResult'):
        """Handle sanitization completion."""
        self._update_ui_state(sanitizing=False)
        
        if wipe_result.result.value == "success":
            # Generate certificate if requested
            certificate_info = ""
            if self.certificate_checkbox.isChecked():
                try:
                    verification_level = VerificationLevel(self.verification_combo.currentText())
                    verification_report = self.verification_engine.verify_sanitization(
                        self.selected_device, wipe_result, verification_level
                    )
                    
                    certificate_files = self.certificate_generator.generate_certificate(
                        self.selected_device, wipe_result, verification_report,
                        formats=["json", "pdf"]
                    )
                    
                    certificate_info = "\\n\\nCertificates generated:\\n"
                    for format_type, file_path in certificate_files.items():
                        certificate_info += f"  {format_type.upper()}: {file_path}\\n"
                
                except Exception as e:
                    certificate_info = f"\\n\\nCertificate generation failed: {e}"
            
            message = (
                f"✓ Sanitization completed successfully!\\n\\n"
                f"Method: {wipe_result.method_used.value}\\n"
                f"Duration: {wipe_result.duration_seconds:.2f} seconds\\n"
                f"Bytes processed: {wipe_result.bytes_processed:,}\\n"
            )
            
            if self.verify_checkbox.isChecked():
                verification_status = "✓ PASSED" if wipe_result.verification_passed else "✗ FAILED"
                message += f"Verification: {verification_status}\\n"
            
            message += certificate_info
            
            QMessageBox.information(self, "Sanitization Complete", message)
            self.status_bar.showMessage("Sanitization completed successfully")
            self._log("Sanitization completed successfully")
        
        else:
            error_msg = (
                f"✗ Sanitization failed or incomplete\\n\\n"
                f"Status: {wipe_result.result.value}\\n"
            )
            if wipe_result.error_message:
                error_msg += f"Error: {wipe_result.error_message}\\n"
            
            QMessageBox.critical(self, "Sanitization Failed", error_msg)
            self.status_bar.showMessage("Sanitization failed")
            self._log(f"Sanitization failed: {wipe_result.error_message}")
    
    def _on_sanitization_error(self, error_message: str):
        """Handle sanitization error."""
        self._update_ui_state(sanitizing=False)
        
        QMessageBox.critical(self, "Sanitization Error", 
                           f"Sanitization failed with error:\\n\\n{error_message}")
        self.status_bar.showMessage("Sanitization error")
        self._log(f"Sanitization error: {error_message}")
    
    def _update_ui_state(self, sanitizing: bool):
        """Update UI state based on sanitization status."""
        # Buttons
        self.sanitize_button.setEnabled(not sanitizing and self.selected_device is not None)
        self.stop_button.setEnabled(sanitizing)
        self.refresh_button.setEnabled(not sanitizing)
        
        # Controls
        self.device_combo.setEnabled(not sanitizing)
        self.method_combo.setEnabled(not sanitizing)
        self.verification_combo.setEnabled(not sanitizing)
        self.verify_checkbox.setEnabled(not sanitizing)
        self.certificate_checkbox.setEnabled(not sanitizing)
        
        # Progress
        if not sanitizing:
            self.progress_bar.setValue(0)
            self.progress_label.setText("Ready")
    
    def _format_time(self, seconds: int) -> str:
        """Format time in human-readable format."""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"
    
    def _log(self, message: str):
        """Add a message to the activity log."""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
    
    def _view_certificates(self):
        """Open certificate directory."""
        try:
            cert_dir = self.certificate_generator.output_directory
            cert_dir.mkdir(parents=True, exist_ok=True)
            
            # Open directory in file explorer
            import subprocess
            import platform
            
            system = platform.system()
            if system == "Windows":
                subprocess.run(["explorer", str(cert_dir)])
            elif system == "Darwin":  # macOS
                subprocess.run(["open", str(cert_dir)])
            else:  # Linux
                subprocess.run(["xdg-open", str(cert_dir)])
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open certificates directory: {e}")
    
    def _show_help(self):
        """Show help dialog."""
        help_text = """
<h2>PurgeProof Data Sanitization Tool</h2>

<p>This tool securely erases data from storage devices in compliance with 
<b>NIST SP 800-88 Rev.1</b> guidelines.</p>

<h3>Usage:</h3>
<ol>
<li>Select a storage device from the dropdown list</li>
<li>Choose sanitization options (method, verification level)</li>
<li>Click "Sanitize Device" to begin</li>
<li>Follow the confirmation prompts</li>
<li>Wait for completion and review the results</li>
</ol>

<h3>Sanitization Methods:</h3>
<ul>
<li><b>Auto:</b> Automatically selects the best method for the device</li>
<li><b>Crypto Erase:</b> Destroys encryption keys (for encrypted devices)</li>
<li><b>Firmware Secure Erase:</b> Uses hardware-level sanitization</li>
<li><b>NVMe Sanitize:</b> Uses NVMe sanitization commands</li>
<li><b>Overwrite:</b> Overwrites data with random patterns</li>
</ul>

<h3>Verification Levels:</h3>
<ul>
<li><b>Basic:</b> Quick verification (10 samples)</li>
<li><b>Standard:</b> Normal verification (100 samples)</li>
<li><b>Thorough:</b> Comprehensive verification (1000 samples)</li>
<li><b>Forensic:</b> Maximum verification (10000 samples)</li>
</ul>

<p><b>WARNING:</b> This tool permanently destroys data. Ensure you have 
proper authorization before sanitizing any device.</p>

<p>For more information, visit: 
<a href="https://github.com/your-org/purgeproof">GitHub Repository</a></p>
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Help - PurgeProof")
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setText(help_text)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.exec()
    
    def _show_about(self):
        """Show about dialog."""
        about_text = """
<h2>PurgeProof</h2>
<h3>Professional Data Sanitization Tool</h3>

<p><b>Version:</b> 1.0.0</p>
<p><b>Compliance:</b> NIST SP 800-88 Rev.1</p>

<p>A secure, cross-platform data wiping application that provides 
tamper-proof certificates and enterprise-grade sanitization.</p>

<p><b>Features:</b></p>
<ul>
<li>NIST-compliant sanitization methods</li>
<li>Cross-platform support (Windows, Linux, Android)</li>
<li>Tamper-proof certificates with digital signatures</li>
<li>Enterprise-scale operations</li>
<li>Comprehensive verification engine</li>
</ul>

<p><b>Copyright © 2024 PurgeProof Development Team</b></p>
        """
        
        msg = QMessageBox(self)
        msg.setWindowTitle("About PurgeProof")
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setText(about_text)
        msg.setIcon(QMessageBox.Icon.Information)
        msg.exec()
    
    def closeEvent(self, event):
        """Handle application closing."""
        if self.sanitization_worker and self.sanitization_worker.isRunning():
            reply = QMessageBox.question(
                self, "Exit Application",
                "Sanitization is in progress. Exiting may leave the device in an unsafe state.\\n\\n"
                "Are you sure you want to exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            
            # Stop worker
            self.sanitization_worker.request_stop()
            self.sanitization_worker.wait(3000)
        
        # Save settings
        self._save_settings()
        event.accept()


def main():
    """Main entry point for the PyQt6 GUI application."""
    if not PYQT6_AVAILABLE:
        print("PyQt6 is not available. Please install PyQt6:")
        print("  pip install PyQt6 PyQt6-tools")
        return 1
    
    try:
        app = QApplication(sys.argv)
        app.setApplicationName("PurgeProof")
        app.setApplicationVersion("1.0.0")
        app.setOrganizationName("PurgeProof Development Team")
        
        # Set application style
        app.setStyle("Fusion")
        
        # Create and show main window
        window = PurgeProofQtGUI()
        window.show()
        
        return app.exec()
    
    except Exception as e:
        print(f"Failed to start PyQt6 GUI application: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
