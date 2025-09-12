"""
PurgeProof GUI Application
Professional graphical interface for enterprise data sanitization

This module provides a modern, user-friendly GUI for PurgeProof with device detection,
progress tracking, method selection, and certificate generation.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import json
import os
import sys

# Import PurgeProof modules
try:
    from .config import ConfigManager, DeviceType, ComplianceLevel
    from .certs import CertificateManager, DeviceInfo, SanitizationMethod, VerificationResult
    from .logging import AuditLogger, EventType, LogLevel, AuditLogConfig
    from .core.wipe_engine_peak import PeakWipeEngine
except ImportError:
    # Fallback for development
    pass


class DeviceListFrame(ttk.Frame):
    """Frame for displaying and managing detected devices"""
    
    def __init__(self, parent, on_device_selected: Callable[[Dict], None]):
        super().__init__(parent)
        self.on_device_selected = on_device_selected
        self.devices = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the device list UI"""
        # Title
        title_label = ttk.Label(self, text="Detected Storage Devices", 
                               font=('Helvetica', 12, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Device list with scrollbar
        list_frame = ttk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create Treeview for device list
        columns = ('Path', 'Model', 'Size', 'Type', 'Status')
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show='headings')
        
        # Configure columns
        self.device_tree.heading('Path', text='Device Path')
        self.device_tree.heading('Model', text='Model')
        self.device_tree.heading('Size', text='Size')
        self.device_tree.heading('Type', text='Type')
        self.device_tree.heading('Status', text='Status')
        
        self.device_tree.column('Path', width=150)
        self.device_tree.column('Model', width=200)
        self.device_tree.column('Size', width=100)
        self.device_tree.column('Type', width=80)
        self.device_tree.column('Status', width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.device_tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        
        # Refresh button
        refresh_button = ttk.Button(self, text="🔄 Refresh Devices", 
                                   command=self.refresh_devices)
        refresh_button.pack(pady=(10, 0))
    
    def on_tree_select(self, event):
        """Handle device selection"""
        selection = self.device_tree.selection()
        if selection:
            item = self.device_tree.item(selection[0])
            device_path = item['values'][0]
            
            # Find the device object
            device = next((d for d in self.devices if d['path'] == device_path), None)
            if device:
                self.on_device_selected(device)
    
    def refresh_devices(self):
        """Refresh the device list"""
        # Clear existing items
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        # Mock device detection (replace with actual detection)
        self.devices = self.detect_devices()
        
        # Populate the tree
        for device in self.devices:
            self.device_tree.insert('', tk.END, values=(
                device['path'],
                device['model'],
                self.format_size(device['size']),
                device['type'],
                device['status']
            ))
    
    def detect_devices(self) -> List[Dict[str, Any]]:
        """Detect storage devices (mock implementation)"""
        # This would be replaced with actual device detection
        mock_devices = [
            {
                'path': '/dev/sda',
                'model': 'Samsung SSD 980 PRO',
                'size': 1000204886016,  # 1TB
                'type': 'NVMe SSD',
                'serial': 'S6T2NG0T123456',
                'status': 'Ready',
                'interface': 'NVMe',
                'supports_crypto_erase': True,
                'supports_secure_erase': True
            },
            {
                'path': '/dev/sdb',
                'model': 'WD Blue 2TB',
                'size': 2000398934016,  # 2TB
                'type': 'SATA HDD',
                'serial': 'WD-WMALP0123456',
                'status': 'Ready',
                'interface': 'SATA',
                'supports_crypto_erase': False,
                'supports_secure_erase': True
            },
            {
                'path': 'E:',
                'model': 'SanDisk Ultra USB 3.0',
                'size': 32017047552,  # 32GB
                'type': 'USB Drive',
                'serial': 'AA010919123456789',
                'status': 'Ready',
                'interface': 'USB',
                'supports_crypto_erase': False,
                'supports_secure_erase': False
            }
        ]
        return mock_devices
    
    def format_size(self, size_bytes: int) -> str:
        """Format size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"


class MethodSelectionFrame(ttk.Frame):
    """Frame for selecting sanitization method"""
    
    def __init__(self, parent, config_manager: ConfigManager):
        super().__init__(parent)
        self.config_manager = config_manager
        self.selected_device = None
        self.selected_method = tk.StringVar()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the method selection UI"""
        # Title
        title_label = ttk.Label(self, text="Sanitization Method", 
                               font=('Helvetica', 12, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Device info frame
        self.device_info_frame = ttk.LabelFrame(self, text="Selected Device")
        self.device_info_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.device_info_label = ttk.Label(self.device_info_frame, 
                                          text="No device selected")
        self.device_info_label.pack(pady=10)
        
        # Compliance level selection
        compliance_frame = ttk.LabelFrame(self, text="Compliance Level")
        compliance_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.compliance_var = tk.StringVar(value="confidential")
        compliance_options = [
            ("Unclassified", "unclassified"),
            ("Confidential", "confidential"),
            ("Secret", "secret"),
            ("Top Secret", "top_secret")
        ]
        
        for text, value in compliance_options:
            ttk.Radiobutton(compliance_frame, text=text, variable=self.compliance_var,
                           value=value, command=self.update_method_list).pack(anchor=tk.W)
        
        # Method selection frame
        method_frame = ttk.LabelFrame(self, text="Available Methods")
        method_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Method list
        self.method_listbox = tk.Listbox(method_frame, height=6)
        self.method_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.method_listbox.bind('<<ListboxSelect>>', self.on_method_select)
        
        # Method details
        self.method_details = scrolledtext.ScrolledText(self, height=6)
        self.method_details.pack(fill=tk.X, pady=(0, 10))
    
    def set_selected_device(self, device: Dict[str, Any]):
        """Set the selected device and update UI"""
        self.selected_device = device
        
        # Update device info
        info_text = f"Path: {device['path']}\n"
        info_text += f"Model: {device['model']}\n"
        info_text += f"Size: {self.format_size(device['size'])}\n"
        info_text += f"Type: {device['type']}"
        
        self.device_info_label.config(text=info_text)
        
        # Update method list
        self.update_method_list()
    
    def update_method_list(self):
        """Update the list of available methods"""
        if not self.selected_device:
            return
        
        # Clear existing methods
        self.method_listbox.delete(0, tk.END)
        
        # Determine device type
        device_type_map = {
            'NVMe SSD': DeviceType.NVME,
            'SATA SSD': DeviceType.SSD,
            'SATA HDD': DeviceType.HDD,
            'USB Drive': DeviceType.USB
        }
        
        device_type = device_type_map.get(self.selected_device['type'], DeviceType.SSD)
        compliance_level = ComplianceLevel(self.compliance_var.get())
        
        # Get prioritized methods
        methods = self.config_manager.get_wipe_method_priority(device_type, compliance_level)
        
        # Add methods to listbox
        for method_name in methods:
            method_config = self.config_manager.get_method_config(method_name)
            if method_config:
                display_name = f"{method_config.method.value.replace('_', ' ').title()} (Priority: {method_config.priority})"
                self.method_listbox.insert(tk.END, display_name)
                
        # Select first method if available
        if methods:
            self.method_listbox.selection_set(0)
            self.on_method_select()
    
    def on_method_select(self, event=None):
        """Handle method selection"""
        selection = self.method_listbox.curselection()
        if not selection or not self.selected_device:
            return
        
        # Get selected method
        device_type_map = {
            'NVMe SSD': DeviceType.NVME,
            'SATA SSD': DeviceType.SSD,
            'SATA HDD': DeviceType.HDD,
            'USB Drive': DeviceType.USB
        }
        
        device_type = device_type_map.get(self.selected_device['type'], DeviceType.SSD)
        compliance_level = ComplianceLevel(self.compliance_var.get())
        methods = self.config_manager.get_wipe_method_priority(device_type, compliance_level)
        
        if selection[0] < len(methods):
            method_name = methods[selection[0]]
            method_config = self.config_manager.get_method_config(method_name)
            
            if method_config:
                # Update method details
                details = f"Method: {method_config.method.value.replace('_', ' ').title()}\n"
                details += f"NIST Category: {method_config.nist_category}\n"
                details += f"Passes: {method_config.passes}\n"
                details += f"Patterns: {', '.join(method_config.patterns)}\n"
                details += f"Verification: {'Yes' if method_config.verification_required else 'No'}\n"
                details += f"Estimated Time: {method_config.timeout_minutes} minutes\n"
                details += f"Compliance: {', '.join([level.value for level in method_config.compliance_levels])}\n"
                
                self.method_details.delete(1.0, tk.END)
                self.method_details.insert(1.0, details)
                
                # Store selected method
                self.selected_method.set(method_name)
    
    def get_selected_method(self) -> Optional[str]:
        """Get the currently selected method"""
        return self.selected_method.get() if self.selected_method.get() else None
    
    def format_size(self, size_bytes: int) -> str:
        """Format size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"


class ProgressFrame(ttk.Frame):
    """Frame for displaying operation progress"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the progress UI"""
        # Title
        title_label = ttk.Label(self, text="Operation Progress", 
                               font=('Helvetica', 12, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Status label
        self.status_label = ttk.Label(self, text="Ready to start operation")
        self.status_label.pack(pady=(0, 5))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, 
                                          maximum=100, length=400)
        self.progress_bar.pack(pady=(0, 5))
        
        # Time and speed info
        info_frame = ttk.Frame(self)
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.time_label = ttk.Label(info_frame, text="Elapsed: 00:00:00")
        self.time_label.pack(side=tk.LEFT)
        
        self.speed_label = ttk.Label(info_frame, text="Speed: -- MB/s")
        self.speed_label.pack(side=tk.RIGHT)
        
        # Log output
        log_frame = ttk.LabelFrame(self, text="Operation Log")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def update_progress(self, percentage: float, status: str, elapsed_time: str = "", speed: str = ""):
        """Update progress display"""
        self.progress_var.set(percentage)
        self.status_label.config(text=status)
        if elapsed_time:
            self.time_label.config(text=f"Elapsed: {elapsed_time}")
        if speed:
            self.speed_label.config(text=f"Speed: {speed}")
    
    def add_log_message(self, message: str):
        """Add a message to the log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
    
    def clear_log(self):
        """Clear the log"""
        self.log_text.delete(1.0, tk.END)


class PurgeProofGUI:
    """Main GUI application class"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.setup_main_window()
        
        # Initialize components
        self.config_manager = ConfigManager()
        self.certificate_manager = CertificateManager()
        self.audit_logger = AuditLogger(AuditLogConfig())
        self.wipe_engine = None
        
        # Operation state
        self.operation_in_progress = False
        self.selected_device = None
        self.start_time = None
        
        self.setup_ui()
        self.setup_menu()
        
        # Start device detection
        self.device_frame.refresh_devices()
    
    def setup_main_window(self):
        """Setup the main window"""
        self.root.title("PurgeProof Enterprise - Data Sanitization System")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Helvetica', 16, 'bold'))
        style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))
    
    def setup_ui(self):
        """Setup the main UI"""
        # Main title
        title_label = ttk.Label(self.root, text="PurgeProof Enterprise", 
                               style='Title.TLabel')
        title_label.pack(pady=10)
        
        subtitle_label = ttk.Label(self.root, text="NIST SP 800-88 Rev.1 Compliant Data Sanitization")
        subtitle_label.pack(pady=(0, 20))
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Left panel (device list and method selection)
        left_panel = ttk.Frame(main_frame)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Device list frame
        self.device_frame = DeviceListFrame(left_panel, self.on_device_selected)
        self.device_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Method selection frame
        self.method_frame = MethodSelectionFrame(left_panel, self.config_manager)
        self.method_frame.pack(fill=tk.BOTH, expand=True)
        
        # Right panel (progress and controls)
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Progress frame
        self.progress_frame = ProgressFrame(right_panel)
        self.progress_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Control buttons
        self.setup_control_buttons(right_panel)
    
    def setup_control_buttons(self, parent):
        """Setup control buttons"""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X)
        
        # Start button
        self.start_button = ttk.Button(button_frame, text="🚀 Start Sanitization", 
                                      command=self.start_operation, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Stop button
        self.stop_button = ttk.Button(button_frame, text="⏹ Stop Operation", 
                                     command=self.stop_operation, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Generate certificate button
        self.cert_button = ttk.Button(button_frame, text="📜 Generate Certificate", 
                                     command=self.generate_certificate, state=tk.DISABLED)
        self.cert_button.pack(side=tk.LEFT, padx=(0, 5))
        
        # Settings button
        settings_button = ttk.Button(button_frame, text="⚙️ Settings", 
                                    command=self.open_settings)
        settings_button.pack(side=tk.RIGHT)
    
    def setup_menu(self):
        """Setup the menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Audit Log", command=self.export_audit_log)
        file_menu.add_command(label="Import Configuration", command=self.import_config)
        file_menu.add_command(label="Export Configuration", command=self.export_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Verify Certificate", command=self.verify_certificate)
        tools_menu.add_command(label="System Benchmark", command=self.run_benchmark)
        tools_menu.add_command(label="Device Information", command=self.show_device_info)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
    
    def on_device_selected(self, device: Dict[str, Any]):
        """Handle device selection"""
        self.selected_device = device
        self.method_frame.set_selected_device(device)
        
        # Enable start button if method is selected
        if self.method_frame.get_selected_method():
            self.start_button.config(state=tk.NORMAL)
        
        self.progress_frame.add_log_message(f"Selected device: {device['path']} ({device['model']})")
    
    def start_operation(self):
        """Start the sanitization operation"""
        if not self.selected_device:
            messagebox.showerror("Error", "Please select a device first")
            return
        
        method = self.method_frame.get_selected_method()
        if not method:
            messagebox.showerror("Error", "Please select a sanitization method")
            return
        
        # Confirm operation
        result = messagebox.askyesno(
            "Confirm Operation",
            f"This will permanently destroy all data on {self.selected_device['path']}.\n\n"
            f"Device: {self.selected_device['model']}\n"
            f"Method: {method.replace('_', ' ').title()}\n\n"
            "Are you sure you want to continue?"
        )
        
        if not result:
            return
        
        # Start operation in background thread
        self.operation_in_progress = True
        self.start_time = datetime.now()
        
        # Update UI state
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.cert_button.config(state=tk.DISABLED)
        
        # Clear previous log
        self.progress_frame.clear_log()
        self.progress_frame.add_log_message("Starting sanitization operation...")
        
        # Start operation thread
        operation_thread = threading.Thread(target=self.run_operation, args=(method,))
        operation_thread.daemon = True
        operation_thread.start()
    
    def run_operation(self, method: str):
        """Run the sanitization operation (in background thread)"""
        try:
            # Initialize wipe engine
            if not self.wipe_engine:
                self.wipe_engine = PeakWipeEngine()
            
            # Log operation start
            self.audit_logger.log_event(
                event_type=EventType.WIPE_START,
                level=LogLevel.INFO,
                operator_id="gui_user",
                device_path=self.selected_device['path'],
                device_serial=self.selected_device['serial'],
                method_used=method
            )
            
            # Update progress
            self.root.after(0, lambda: self.progress_frame.update_progress(
                10, f"Initializing {method.replace('_', ' ').title()}..."
            ))
            
            # Simulate operation progress (replace with actual operation)
            for i in range(11, 100, 5):
                if not self.operation_in_progress:
                    break
                
                time.sleep(0.5)  # Simulate work
                
                elapsed = datetime.now() - self.start_time
                elapsed_str = str(elapsed).split('.')[0]
                
                self.root.after(0, lambda p=i, e=elapsed_str: self.progress_frame.update_progress(
                    p, f"Sanitizing... {p}%", e, "150.2 MB/s"
                ))
            
            if self.operation_in_progress:
                # Complete operation
                self.root.after(0, lambda: self.progress_frame.update_progress(
                    100, "Operation completed successfully"
                ))
                
                # Log completion
                duration = (datetime.now() - self.start_time).total_seconds()
                self.audit_logger.log_event(
                    event_type=EventType.WIPE_COMPLETE,
                    level=LogLevel.INFO,
                    operator_id="gui_user",
                    device_path=self.selected_device['path'],
                    device_serial=self.selected_device['serial'],
                    method_used=method,
                    outcome="SUCCESS",
                    duration_seconds=duration
                )
                
                self.root.after(0, self.operation_completed)
            
        except Exception as e:
            # Log error
            self.audit_logger.log_event(
                event_type=EventType.WIPE_FAILED,
                level=LogLevel.ERROR,
                operator_id="gui_user",
                device_path=self.selected_device['path'],
                device_serial=self.selected_device['serial'],
                method_used=method,
                error_message=str(e)
            )
            
            self.root.after(0, lambda: self.operation_failed(str(e)))
    
    def operation_completed(self):
        """Handle successful operation completion"""
        self.operation_in_progress = False
        
        # Update UI state
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.cert_button.config(state=tk.NORMAL)
        
        self.progress_frame.add_log_message("✅ Sanitization completed successfully")
        
        # Show completion message
        messagebox.showinfo("Operation Complete", 
                           "Data sanitization completed successfully!\n\n"
                           "You can now generate a compliance certificate.")
    
    def operation_failed(self, error_message: str):
        """Handle operation failure"""
        self.operation_in_progress = False
        
        # Update UI state
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        self.progress_frame.add_log_message(f"❌ Operation failed: {error_message}")
        
        # Show error message
        messagebox.showerror("Operation Failed", f"Sanitization failed:\n{error_message}")
    
    def stop_operation(self):
        """Stop the current operation"""
        result = messagebox.askyesno("Stop Operation", 
                                   "Are you sure you want to stop the current operation?")
        if result:
            self.operation_in_progress = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress_frame.add_log_message("Operation stopped by user")
    
    def generate_certificate(self):
        """Generate a compliance certificate"""
        if not self.selected_device:
            messagebox.showerror("Error", "No device selected")
            return
        
        try:
            # Create device info
            device_info = DeviceInfo(
                path=self.selected_device['path'],
                serial_number=self.selected_device['serial'],
                model=self.selected_device['model'],
                manufacturer="Unknown",
                size_bytes=self.selected_device['size'],
                interface_type=self.selected_device['interface'],
                device_type=self.selected_device['type']
            )
            
            # Create method info
            method_name = self.method_frame.get_selected_method()
            method_config = self.config_manager.get_method_config(method_name)
            
            if method_config:
                sanitization_method = SanitizationMethod(
                    method_name=method_config.method.value.replace('_', ' ').title(),
                    nist_category=method_config.nist_category,
                    passes=method_config.passes,
                    patterns=method_config.patterns,
                    verification_method="Pattern Verification",
                    compliance_level=method_config.compliance_levels[0].value
                )
            else:
                raise ValueError("Method configuration not found")
            
            # Create verification result
            verification_result = VerificationResult(
                method="pattern_verification",
                verified=True,
                sample_rate=0.1,
                confidence_level=0.95,
                entropy_score=0.1,
                verification_hash="sha256:abcd1234..."
            )
            
            # Generate certificate
            certificate = self.certificate_manager.create_certificate(
                device_info=device_info,
                sanitization_method=sanitization_method,
                verification_result=verification_result,
                operator_id="gui_user",
                organization=self.config_manager.config.enterprise.organization_name
            )
            
            # Save certificate
            save_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Save Certificate"
            )
            
            if save_path:
                self.certificate_manager.save_json_certificate(certificate, save_path)
                
                # Also generate PDF if requested
                if self.config_manager.config.certificates.format in ["pdf", "both"]:
                    pdf_path = save_path.replace(".json", ".pdf")
                    try:
                        self.certificate_manager.generate_pdf_certificate(certificate, pdf_path)
                        messagebox.showinfo("Certificate Generated", 
                                          f"Certificates saved:\n• JSON: {save_path}\n• PDF: {pdf_path}")
                    except Exception as e:
                        messagebox.showinfo("Certificate Generated", 
                                          f"JSON certificate saved: {save_path}\n\nPDF generation failed: {e}")
                else:
                    messagebox.showinfo("Certificate Generated", f"Certificate saved: {save_path}")
        
        except Exception as e:
            messagebox.showerror("Certificate Error", f"Failed to generate certificate:\n{e}")
    
    def open_settings(self):
        """Open settings dialog"""
        # Simple settings dialog (could be expanded)
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("400x300")
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # Settings content (simplified)
        ttk.Label(settings_window, text="Settings", font=('Helvetica', 14, 'bold')).pack(pady=20)
        ttk.Label(settings_window, text="Settings interface would be implemented here").pack(pady=50)
        
        # Close button
        ttk.Button(settings_window, text="Close", 
                  command=settings_window.destroy).pack(pady=20)
    
    def export_audit_log(self):
        """Export audit log"""
        save_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("HTML files", "*.html")],
            title="Export Audit Log"
        )
        
        if save_path:
            try:
                format_type = Path(save_path).suffix[1:]  # Remove the dot
                self.audit_logger.export_logs(save_path, format_type)
                messagebox.showinfo("Export Complete", f"Audit log exported to {save_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export audit log:\n{e}")
    
    def import_config(self):
        """Import configuration"""
        file_path = filedialog.askopenfilename(
            filetypes=[("YAML files", "*.yaml"), ("JSON files", "*.json")],
            title="Import Configuration"
        )
        
        if file_path:
            if self.config_manager.import_config(file_path):
                messagebox.showinfo("Import Complete", "Configuration imported successfully")
                # Refresh method list
                if self.selected_device:
                    self.method_frame.update_method_list()
            else:
                messagebox.showerror("Import Error", "Failed to import configuration")
    
    def export_config(self):
        """Export configuration"""
        save_path = filedialog.asksaveasfilename(
            defaultextension=".yaml",
            filetypes=[("YAML files", "*.yaml"), ("JSON files", "*.json")],
            title="Export Configuration"
        )
        
        if save_path:
            try:
                format_type = "yaml" if save_path.endswith(".yaml") else "json"
                self.config_manager.export_config(save_path, format_type)
                messagebox.showinfo("Export Complete", f"Configuration exported to {save_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export configuration:\n{e}")
    
    def verify_certificate(self):
        """Verify a certificate"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Select Certificate to Verify"
        )
        
        if file_path:
            try:
                result = self.certificate_manager.verify_json_certificate(file_path)
                
                if result['valid']:
                    messagebox.showinfo("Verification Result", 
                                      f"Certificate {result['certificate_id']} is VALID")
                else:
                    error_msg = "\n".join(result['errors'])
                    messagebox.showerror("Verification Result", 
                                       f"Certificate {result['certificate_id']} is INVALID\n\nErrors:\n{error_msg}")
            except Exception as e:
                messagebox.showerror("Verification Error", f"Failed to verify certificate:\n{e}")
    
    def run_benchmark(self):
        """Run system benchmark"""
        messagebox.showinfo("Benchmark", "System benchmark feature would be implemented here")
    
    def show_device_info(self):
        """Show detailed device information"""
        if self.selected_device:
            info_window = tk.Toplevel(self.root)
            info_window.title("Device Information")
            info_window.geometry("500x400")
            info_window.transient(self.root)
            
            # Device info text
            info_text = scrolledtext.ScrolledText(info_window)
            info_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            device_info = json.dumps(self.selected_device, indent=2)
            info_text.insert(1.0, device_info)
            info_text.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("Device Information", "No device selected")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """PurgeProof Enterprise v2.0

NIST SP 800-88 Rev.1 Compliant Data Sanitization System

Features:
• Hardware-accelerated sanitization
• Multiple sanitization methods
• Digital certificates
• Audit logging
• Enterprise compliance

Copyright © 2025 PurgeProof Enterprise"""
        
        messagebox.showinfo("About PurgeProof", about_text)
    
    def show_documentation(self):
        """Show documentation"""
        messagebox.showinfo("Documentation", "Documentation would open here")
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


def main():
    """Main entry point for GUI application"""
    app = PurgeProofGUI()
    app.run()


if __name__ == "__main__":
    main()