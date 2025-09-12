#!/usr/bin/env python3
"""
PurgeProof GUI Interface.

Cross-platform graphical interface for the PurgeProof hybrid sanitization system,
providing enterprise-grade device sanitization with real-time monitoring.
"""

import sys
import os
import asyncio
import threading
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime

# Platform detection for GUI framework
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, simpledialog
    GUI_AVAILABLE = True
except ImportError:
    print("Warning: tkinter not available. GUI interface disabled.")
    GUI_AVAILABLE = False

# Add the parent directory to the path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from purgeproof import (
        scan_devices, sanitize, get_stats, get_orchestrator,
        DeviceCapabilities, SanitizationMethod, ComplianceLevel, SecurityObjective
    )
    from purgeproof.compliance import get_compliance_framework
    from purgeproof.sampling_verification import SamplingEngine, VerificationLevel
    from purgeproof.decision_engine import MethodSelectionEngine, SelectionCriteria, DeviceContext
except ImportError as e:
    print(f"Error importing PurgeProof modules: {e}")
    if GUI_AVAILABLE:
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        messagebox.showerror("Import Error", f"Failed to import PurgeProof modules: {e}")
        root.destroy()
    sys.exit(1)

class DeviceListFrame(ttk.Frame):
    """Device list and selection frame."""
    
    def __init__(self, parent, on_device_select=None):
        super().__init__(parent)
        self.on_device_select = on_device_select
        self.devices = []
        
        self.setup_ui()
        self.refresh_devices()
    
    def setup_ui(self):
        """Set up the device list UI."""
        # Title and refresh button
        title_frame = ttk.Frame(self)
        title_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(title_frame, text="Storage Devices", font=('Arial', 12, 'bold')).pack(side=tk.LEFT)
        ttk.Button(title_frame, text="Refresh", command=self.refresh_devices).pack(side=tk.RIGHT)
        
        # Device tree
        columns = ('path', 'model', 'size', 'type', 'capabilities')
        self.tree = ttk.Treeview(self, columns=columns, show='tree headings', height=8)
        
        self.tree.heading('#0', text='Device')
        self.tree.heading('path', text='Path')
        self.tree.heading('model', text='Model')
        self.tree.heading('size', text='Size (GB)')
        self.tree.heading('type', text='Type')
        self.tree.heading('capabilities', text='Capabilities')
        
        self.tree.column('#0', width=50)
        self.tree.column('path', width=150)
        self.tree.column('model', width=200)
        self.tree.column('size', width=80)
        self.tree.column('type', width=80)
        self.tree.column('capabilities', width=200)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
    
    def refresh_devices(self):
        """Refresh the device list."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        try:
            self.devices = scan_devices()
            
            for i, device in enumerate(self.devices):
                # Build capabilities string
                capabilities = []
                if device.supports_crypto_erase:
                    capabilities.append("Crypto")
                if device.supports_secure_erase:
                    capabilities.append("Secure")
                if device.supports_nvme_sanitize:
                    capabilities.append("NVMe")
                if device.supports_trim:
                    capabilities.append("TRIM")
                
                cap_str = ", ".join(capabilities) if capabilities else "Overwrite only"
                
                # Insert device into tree
                self.tree.insert('', 'end', iid=str(i),
                    text=f"Device {i+1}",
                    values=(
                        device.path,
                        device.model,
                        f"{device.size_bytes / (1024**3):.1f}",
                        device.device_type.name,
                        cap_str
                    )
                )
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan devices: {e}")
    
    def on_tree_select(self, event):
        """Handle device selection."""
        selection = self.tree.selection()
        if selection and self.on_device_select:
            device_index = int(selection[0])
            if 0 <= device_index < len(self.devices):
                self.on_device_select(self.devices[device_index])

class DeviceInfoFrame(ttk.Frame):
    """Device information and analysis frame."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.device = None
        self.method_selector = MethodSelectionEngine()
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the device info UI."""
        # Title
        ttk.Label(self, text="Device Information", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        # Info text area
        self.info_text = tk.Text(self, height=15, width=50, wrap=tk.WORD, state=tk.DISABLED)
        info_scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=info_scrollbar.set)
        
        self.info_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        info_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.update_info(None)
    
    def update_info(self, device):
        """Update device information display."""
        self.device = device
        
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        
        if device is None:
            self.info_text.insert(tk.END, "No device selected.\n\nSelect a device from the list to view detailed information and sanitization recommendations.")
        else:
            info = self._format_device_info(device)
            self.info_text.insert(tk.END, info)
        
        self.info_text.config(state=tk.DISABLED)
    
    def _format_device_info(self, device):
        """Format device information as text."""
        info = f"Path: {device.path}\n"
        info += f"Model: {device.model}\n"
        info += f"Serial: {device.serial}\n"
        info += f"Size: {device.size_bytes / (1024**3):.1f} GB\n"
        info += f"Type: {device.device_type.name}\n"
        info += f"Interface: {device.interface_type.name}\n"
        info += f"Sector Size: {device.sector_size} bytes\n\n"
        
        if device.is_encrypted:
            info += f"Encryption: {device.encryption_type.name}\n"
            info += f"Algorithm: {device.encryption_algorithm}\n\n"
        
        info += "Performance Characteristics:\n"
        info += f"  Read Speed: {device.max_read_speed_mbps:.0f} MB/s\n"
        info += f"  Write Speed: {device.max_write_speed_mbps:.0f} MB/s\n"
        info += f"  Random IOPS: {device.random_iops:,}\n"
        info += f"  Latency: {device.latency_ms:.2f} ms\n\n"
        
        info += "Supported Sanitization Methods:\n"
        if device.supports_crypto_erase:
            info += f"  • Crypto Erase (~{device.crypto_erase_time_estimate} min)\n"
        if device.supports_secure_erase:
            info += f"  • Secure Erase (~{device.secure_erase_time_estimate} min)\n"
        if device.supports_nvme_sanitize:
            info += "  • NVMe Sanitize\n"
        if device.supports_trim:
            info += "  • TRIM/Discard\n"
        info += f"  • Overwrite (~{device.overwrite_time_estimate} min)\n\n"
        
        # Get method recommendation
        try:
            device_context = DeviceContext(capabilities=device)
            criteria = SelectionCriteria(
                compliance_level=ComplianceLevel.STANDARD,
                security_objective=SecurityObjective.BALANCED
            )
            
            recommendation = self.method_selector.select_optimal_method(device_context, criteria)
            
            info += "Recommended Method (Standard/Balanced):\n"
            info += f"  Method: {recommendation.method.name}\n"
            info += f"  Score: {recommendation.overall_score:.1f}/100\n"
            info += f"  Duration: {recommendation.estimated_duration_minutes:.1f} minutes\n"
            info += f"  Security Level: {recommendation.security_level}\n"
            
            if recommendation.optimization_notes:
                info += f"  Notes: {'; '.join(recommendation.optimization_notes)}\n"
        
        except Exception as e:
            info += f"Method recommendation error: {e}\n"
        
        return info

class SanitizationFrame(ttk.Frame):
    """Sanitization configuration and execution frame."""
    
    def __init__(self, parent, on_start_sanitization=None):
        super().__init__(parent)
        self.on_start_sanitization = on_start_sanitization
        self.device = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the sanitization UI."""
        # Title
        ttk.Label(self, text="Sanitization Settings", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        # Settings frame
        settings_frame = ttk.LabelFrame(self, text="Configuration", padding=10)
        settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Compliance level
        ttk.Label(settings_frame, text="Compliance Level:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.compliance_var = tk.StringVar(value="STANDARD")
        compliance_combo = ttk.Combobox(settings_frame, textvariable=self.compliance_var,
                                      values=["BASIC", "STANDARD", "ENHANCED", "CLASSIFIED", "TOP_SECRET"],
                                      state="readonly", width=15)
        compliance_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Security objective
        ttk.Label(settings_frame, text="Security Objective:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.objective_var = tk.StringVar(value="BALANCED")
        objective_combo = ttk.Combobox(settings_frame, textvariable=self.objective_var,
                                     values=["SPEED", "SECURITY", "COMPLIANCE", "BALANCED"],
                                     state="readonly", width=15)
        objective_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Method override
        ttk.Label(settings_frame, text="Force Method:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.method_var = tk.StringVar(value="AUTO")
        method_combo = ttk.Combobox(settings_frame, textvariable=self.method_var,
                                  values=["AUTO", "CRYPTO_ERASE", "SECURE_ERASE", "NVME_SANITIZE", 
                                         "TRIM_DISCARD", "OVERWRITE_SINGLE", "OVERWRITE_MULTI"],
                                  state="readonly", width=15)
        method_combo.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Options
        options_frame = ttk.LabelFrame(self, text="Options", padding=10)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Perform verification after sanitization",
                       variable=self.verify_var).pack(anchor=tk.W)
        
        self.compliance_report_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Generate compliance report",
                       variable=self.compliance_report_var).pack(anchor=tk.W)
        
        # Warning
        warning_frame = ttk.Frame(self)
        warning_frame.pack(fill=tk.X, padx=5, pady=5)
        
        warning_text = "⚠️ WARNING: Sanitization will permanently destroy all data on the selected device!"
        warning_label = ttk.Label(warning_frame, text=warning_text, foreground="red", 
                                font=('Arial', 10, 'bold'))
        warning_label.pack()
        
        # Start button
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.start_button = ttk.Button(button_frame, text="Start Sanitization",
                                     command=self.start_sanitization, state=tk.DISABLED)
        self.start_button.pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(button_frame, text="Export Settings",
                  command=self.export_settings).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(button_frame, text="Import Settings",
                  command=self.import_settings).pack(side=tk.RIGHT, padx=5)
    
    def set_device(self, device):
        """Set the device for sanitization."""
        self.device = device
        self.start_button.config(state=tk.NORMAL if device else tk.DISABLED)
    
    def start_sanitization(self):
        """Start the sanitization process."""
        if not self.device:
            messagebox.showerror("Error", "No device selected")
            return
        
        # Confirmation dialog
        response = messagebox.askyesno(
            "Confirm Sanitization",
            f"Are you sure you want to sanitize {self.device.path}?\n\n"
            f"Device: {self.device.model}\n"
            f"Size: {self.device.size_bytes / (1024**3):.1f} GB\n"
            f"Compliance: {self.compliance_var.get()}\n"
            f"Objective: {self.objective_var.get()}\n\n"
            "This operation cannot be undone!"
        )
        
        if not response:
            return
        
        # Prepare sanitization parameters
        params = {
            'device': self.device,
            'compliance_level': getattr(ComplianceLevel, self.compliance_var.get()),
            'security_objective': getattr(SecurityObjective, self.objective_var.get()),
            'method': None if self.method_var.get() == "AUTO" else getattr(SanitizationMethod, self.method_var.get()),
            'verify': self.verify_var.get(),
            'compliance_report': self.compliance_report_var.get()
        }
        
        if self.on_start_sanitization:
            self.on_start_sanitization(params)
    
    def export_settings(self):
        """Export current settings to file."""
        try:
            filename = filedialog.asksaveasfilename(
                title="Export Settings",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                settings = {
                    'compliance_level': self.compliance_var.get(),
                    'security_objective': self.objective_var.get(),
                    'method': self.method_var.get(),
                    'verify': self.verify_var.get(),
                    'compliance_report': self.compliance_report_var.get()
                }
                
                with open(filename, 'w') as f:
                    json.dump(settings, f, indent=2)
                
                messagebox.showinfo("Success", f"Settings exported to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export settings: {e}")
    
    def import_settings(self):
        """Import settings from file."""
        try:
            filename = filedialog.askopenfilename(
                title="Import Settings",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'r') as f:
                    settings = json.load(f)
                
                self.compliance_var.set(settings.get('compliance_level', 'STANDARD'))
                self.objective_var.set(settings.get('security_objective', 'BALANCED'))
                self.method_var.set(settings.get('method', 'AUTO'))
                self.verify_var.set(settings.get('verify', True))
                self.compliance_report_var.set(settings.get('compliance_report', True))
                
                messagebox.showinfo("Success", f"Settings imported from {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import settings: {e}")

class ProgressFrame(ttk.Frame):
    """Job progress monitoring frame."""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.current_job_id = None
        self.orchestrator = get_orchestrator()
        
        self.setup_ui()
        self.start_monitoring()
    
    def setup_ui(self):
        """Set up the progress UI."""
        # Title
        ttk.Label(self, text="Operation Progress", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=5, pady=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var).pack(anchor=tk.W, padx=5, pady=2)
        
        # Details text
        self.details_text = tk.Text(self, height=8, wrap=tk.WORD, state=tk.DISABLED)
        details_scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scrollbar.set)
        
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Control buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.cancel_button = ttk.Button(button_frame, text="Cancel", 
                                      command=self.cancel_job, state=tk.DISABLED)
        self.cancel_button.pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(button_frame, text="Clear Log",
                  command=self.clear_log).pack(side=tk.RIGHT, padx=5)
    
    def start_monitoring(self):
        """Start the progress monitoring thread."""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self.monitor_progress, daemon=True)
        self.monitor_thread.start()
    
    def monitor_progress(self):
        """Monitor job progress in background thread."""
        import time
        
        while self.monitoring:
            try:
                if self.current_job_id:
                    status = self.orchestrator.get_job_status(self.current_job_id)
                    
                    if status:
                        # Update UI in main thread
                        self.after_idle(self.update_progress_ui, status)
                        
                        # Check if job is complete
                        job_status = status.get('status', 'unknown')
                        if job_status in ['completed', 'failed', 'cancelled']:
                            self.after_idle(self.job_finished, status)
                            self.current_job_id = None
                
                time.sleep(1)
            
            except Exception as e:
                self.after_idle(self.log_message, f"Monitoring error: {e}")
                time.sleep(5)
    
    def update_progress_ui(self, status):
        """Update progress UI with job status."""
        progress = status.get('progress', 0)
        job_status = status.get('status', 'unknown')
        
        self.progress_var.set(progress)
        self.status_var.set(f"{job_status.title()}: {progress:.1f}%")
        
        # Log status updates
        if 'message' in status:
            self.log_message(status['message'])
    
    def job_finished(self, status):
        """Handle job completion."""
        job_status = status.get('status', 'unknown')
        
        if job_status == 'completed':
            self.log_message("✅ Sanitization completed successfully!")
            result = status.get('result', {})
            if result:
                self.log_message(f"Method: {result.get('method', 'Unknown')}")
                self.log_message(f"Duration: {result.get('duration', 0):.1f} minutes")
                self.log_message(f"Bytes processed: {result.get('bytes_processed', 0):,}")
        
        elif job_status == 'failed':
            error = status.get('error', 'Unknown error')
            self.log_message(f"❌ Sanitization failed: {error}")
        
        elif job_status == 'cancelled':
            self.log_message("⏹️ Sanitization cancelled by user")
        
        self.cancel_button.config(state=tk.DISABLED)
    
    def start_job(self, job_id):
        """Start monitoring a new job."""
        self.current_job_id = job_id
        self.progress_var.set(0)
        self.status_var.set("Starting...")
        self.cancel_button.config(state=tk.NORMAL)
        self.log_message(f"Started job {job_id}")
    
    def cancel_job(self):
        """Cancel the current job."""
        if self.current_job_id:
            try:
                self.orchestrator.cancel_job(self.current_job_id)
                self.log_message("Cancellation requested...")
            except Exception as e:
                self.log_message(f"Failed to cancel job: {e}")
    
    def log_message(self, message):
        """Add a message to the details log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.details_text.see(tk.END)
        self.details_text.config(state=tk.DISABLED)
    
    def clear_log(self):
        """Clear the details log."""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)

class PurgeProofGUI:
    """Main GUI application class."""
    
    def __init__(self):
        if not GUI_AVAILABLE:
            raise RuntimeError("GUI not available - tkinter not installed")
        
        self.root = tk.Tk()
        self.root.title("PurgeProof - Enterprise Data Sanitization")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Initialize components
        self.orchestrator = get_orchestrator()
        self.selected_device = None
        
        self.setup_ui()
        self.setup_menu()
        
        # Set window icon (if available)
        try:
            # You can add an icon file here
            # self.root.iconbitmap("purgeproof.ico")
            pass
        except:
            pass
    
    def setup_menu(self):
        """Set up the application menu."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Compliance Report...", command=self.export_compliance_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="System Statistics", command=self.show_statistics)
        tools_menu.add_command(label="Refresh All", command=self.refresh_all)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def setup_ui(self):
        """Set up the main UI layout."""
        # Create main paned window
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel
        left_frame = ttk.Frame(main_paned, width=400)
        left_frame.pack_propagate(False)
        main_paned.add(left_frame, weight=1)
        
        # Device list
        self.device_list = DeviceListFrame(left_frame, on_device_select=self.on_device_select)
        self.device_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Right panel
        right_paned = ttk.PanedWindow(main_paned, orient=tk.VERTICAL)
        main_paned.add(right_paned, weight=2)
        
        # Device info frame
        self.device_info = DeviceInfoFrame(right_paned)
        right_paned.add(self.device_info, weight=1)
        
        # Sanitization frame
        self.sanitization = SanitizationFrame(right_paned, on_start_sanitization=self.start_sanitization)
        right_paned.add(self.sanitization, weight=1)
        
        # Progress frame
        self.progress = ProgressFrame(right_paned)
        right_paned.add(self.progress, weight=1)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def on_device_select(self, device):
        """Handle device selection."""
        self.selected_device = device
        self.device_info.update_info(device)
        self.sanitization.set_device(device)
        self.status_var.set(f"Selected: {device.path} ({device.model})")
    
    def start_sanitization(self, params):
        """Start sanitization with given parameters."""
        try:
            # Submit job to orchestrator
            job_id = self.orchestrator.submit_sanitization_job(
                params['device'].path,
                params['compliance_level'],
                params['security_objective']
            )
            
            # Start monitoring
            self.progress.start_job(job_id)
            self.status_var.set(f"Sanitizing {params['device'].path}...")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start sanitization: {e}")
    
    def export_compliance_report(self):
        """Export compliance report."""
        if not self.selected_device:
            messagebox.showwarning("Warning", "Please select a device first")
            return
        
        try:
            filename = filedialog.asksaveasfilename(
                title="Export Compliance Report",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("PDF files", "*.pdf"), ("All files", "*.*")]
            )
            
            if filename:
                # Generate and export report
                compliance_framework = get_compliance_framework()
                report = compliance_framework.validate_method_compliance(
                    self.selected_device,
                    SanitizationMethod.OVERWRITE_SINGLE,
                    ComplianceLevel.STANDARD
                )
                
                if filename.endswith('.pdf'):
                    exported = compliance_framework.export_compliance_report(report, "pdf")
                else:
                    exported = compliance_framework.export_compliance_report(report, "json")
                
                with open(filename, 'w' if filename.endswith('.json') else 'wb') as f:
                    f.write(exported)
                
                messagebox.showinfo("Success", f"Compliance report exported to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report: {e}")
    
    def show_statistics(self):
        """Show system statistics dialog."""
        try:
            stats = get_stats()
            
            stats_window = tk.Toplevel(self.root)
            stats_window.title("System Statistics")
            stats_window.geometry("400x300")
            stats_window.resizable(False, False)
            
            # Center the window
            stats_window.transient(self.root)
            stats_window.grab_set()
            
            # Statistics content
            stats_text = tk.Text(stats_window, wrap=tk.WORD, state=tk.DISABLED)
            stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            content = "PurgeProof System Statistics\n"
            content += "=" * 30 + "\n\n"
            content += f"Total Jobs: {stats.get('total_jobs', 0)}\n"
            content += f"Completed Jobs: {stats.get('completed_jobs', 0)}\n"
            content += f"Failed Jobs: {stats.get('failed_jobs', 0)}\n"
            content += f"Total Bytes Processed: {stats.get('total_bytes_processed', 0):,}\n"
            content += f"Native Engine: {'Available' if stats.get('native_engine_available', False) else 'Fallback Mode'}\n"
            
            if 'active_jobs' in stats:
                content += f"\nActive Jobs: {len(stats['active_jobs'])}\n"
                for job_id in stats['active_jobs']:
                    content += f"  - {job_id}\n"
            
            stats_text.config(state=tk.NORMAL)
            stats_text.insert(tk.END, content)
            stats_text.config(state=tk.DISABLED)
            
            # Close button
            ttk.Button(stats_window, text="Close", 
                      command=stats_window.destroy).pack(pady=10)
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get statistics: {e}")
    
    def refresh_all(self):
        """Refresh all components."""
        self.device_list.refresh_devices()
        self.status_var.set("Refreshed device list")
    
    def show_about(self):
        """Show about dialog."""
        about_text = """PurgeProof Enterprise Data Sanitization Tool
Version 2.1.0

A hybrid Rust + Python solution for secure data sanitization
with NIST SP 800-88 compliance and enterprise auditability.

Features:
• Hardware-accelerated sanitization methods
• NIST SP 800-88 Rev.1 compliance validation
• Statistical sampling verification
• Real-time progress monitoring
• Comprehensive audit trails

© 2024 PurgeProof Project"""
        
        messagebox.showinfo("About PurgeProof", about_text)
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()

def main():
    """Main entry point for GUI."""
    if not GUI_AVAILABLE:
        print("Error: GUI interface requires tkinter")
        print("Please install tkinter or use the CLI interface instead:")
        print("  python -m purgeproof.cli --help")
        return 1
    
    try:
        app = PurgeProofGUI()
        app.run()
        return 0
    
    except Exception as e:
        if GUI_AVAILABLE:
            messagebox.showerror("Fatal Error", f"Application failed to start: {e}")
        else:
            print(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())