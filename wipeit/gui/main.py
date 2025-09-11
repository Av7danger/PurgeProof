"""
PurgeProof GUI - Simple Data Sanitization Interface

A user-friendly graphical interface for the PurgeProof data sanitization tool.
Provides one-click sanitization with progress tracking and certificate generation.

This implementation uses tkinter for cross-platform compatibility and simplicity.
For a more modern interface, consider using PyQt6 or Electron (see gui_pyqt.py).
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import time
from typing import Optional, List, Dict, Any

# Add the wipeit package to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from core.device_utils import DeviceDetector, DeviceInfo
    from core.wipe_engine import WipeEngine, SanitizationMethod, WipeProgress, WipeResult
    from core.verification import VerificationEngine, VerificationLevel
    from core.certificates import CertificateGenerator
    from core.crypto_utils import CryptoManager
except ImportError as e:
    print(f"Error importing PurgeProof modules: {e}")
    print("Please ensure all dependencies are installed and the application is run from the correct directory.")
    sys.exit(1)


class PurgeProofGUI:
    """Main GUI application class."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PurgeProof - Data Sanitization Tool")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Application state
        self.devices: List[DeviceInfo] = []
        self.selected_device: Optional[DeviceInfo] = None
        self.sanitization_thread: Optional[threading.Thread] = None
        self.is_sanitizing = False
        
        # Initialize core components
        self.device_detector = DeviceDetector()
        self.wipe_engine = WipeEngine(self.device_detector)
        self.verification_engine = VerificationEngine()
        self.certificate_generator = CertificateGenerator()
        
        # Set up progress callback
        self.wipe_engine.set_progress_callback(self._update_progress)
        
        # Create GUI
        self._create_widgets()
        self._refresh_devices()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _create_widgets(self):
        """Create the main GUI widgets."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="PurgeProof Data Sanitization", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Device selection frame
        device_frame = ttk.LabelFrame(main_frame, text="Device Selection", padding="10")
        device_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        device_frame.columnconfigure(1, weight=1)
        
        # Device list
        ttk.Label(device_frame, text="Storage Devices:").grid(row=0, column=0, sticky=tk.W)
        
        self.device_var = tk.StringVar()
        self.device_combobox = ttk.Combobox(device_frame, textvariable=self.device_var, 
                                           state="readonly", width=50)
        self.device_combobox.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 5))
        self.device_combobox.bind("<<ComboboxSelected>>", self._on_device_selected)
        
        refresh_btn = ttk.Button(device_frame, text="Refresh", command=self._refresh_devices)
        refresh_btn.grid(row=0, column=2, padx=(5, 0))
        
        # Device info frame
        info_frame = ttk.LabelFrame(main_frame, text="Device Information", padding="10")
        info_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        info_frame.columnconfigure(0, weight=1)
        info_frame.rowconfigure(0, weight=1)
        
        self.device_info_text = scrolledtext.ScrolledText(info_frame, height=8, width=60)
        self.device_info_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Sanitization Options", padding="10")
        options_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        options_frame.columnconfigure(1, weight=1)
        
        # Method selection
        ttk.Label(options_frame, text="Method:").grid(row=0, column=0, sticky=tk.W)
        self.method_var = tk.StringVar(value="auto")
        method_options = ["auto"] + [method.value for method in SanitizationMethod]
        self.method_combobox = ttk.Combobox(options_frame, textvariable=self.method_var,
                                           values=method_options, state="readonly")
        self.method_combobox.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(10, 0))
        
        # Verification level
        ttk.Label(options_frame, text="Verification:").grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        self.verification_var = tk.StringVar(value="standard")
        verification_options = [level.value for level in VerificationLevel]
        self.verification_combobox = ttk.Combobox(options_frame, textvariable=self.verification_var,
                                                 values=verification_options, state="readonly")
        self.verification_combobox.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(10, 0), pady=(5, 0))
        
        # Checkboxes
        self.verify_var = tk.BooleanVar(value=True)
        self.verify_check = ttk.Checkbutton(options_frame, text="Verify sanitization", 
                                           variable=self.verify_var)
        self.verify_check.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))
        
        self.certificate_var = tk.BooleanVar(value=True)
        self.certificate_check = ttk.Checkbutton(options_frame, text="Generate certificate", 
                                                 variable=self.certificate_var)
        self.certificate_check.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))
        
        # Progress frame
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="10")
        progress_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, 
                                           maximum=100, length=400)
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.progress_label = ttk.Label(progress_frame, text="Ready")
        self.progress_label.grid(row=1, column=0, sticky=tk.W)
        
        # Action buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=5, column=0, columnspan=3, pady=(0, 10))
        
        self.sanitize_button = ttk.Button(buttons_frame, text="Sanitize Device", 
                                         command=self._start_sanitization, style="Accent.TButton")
        self.sanitize_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop", command=self._stop_sanitization,
                                     state="disabled")
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(buttons_frame, text="View Certificates", 
                  command=self._view_certificates).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(buttons_frame, text="Help", command=self._show_help).pack(side=tk.LEFT)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def _refresh_devices(self):
        """Refresh the list of available devices."""
        try:
            self.status_var.set("Scanning for devices...")
            self.root.update()
            
            self.devices = self.device_detector.list_storage_devices()
            
            # Update combobox
            device_options = []
            for device in self.devices:
                size_gb = device.size_bytes / (1024**3)
                option = f"{device.path} - {device.model} ({size_gb:.1f} GB)"
                device_options.append(option)
            
            self.device_combobox['values'] = device_options
            
            if device_options:
                self.device_combobox.current(0)
                self._on_device_selected()
                self.status_var.set(f"Found {len(self.devices)} device(s)")
            else:
                self.device_combobox.set("")
                self.device_info_text.delete(1.0, tk.END)
                self.device_info_text.insert(tk.END, "No storage devices found.")
                self.status_var.set("No devices found")
                self.sanitize_button['state'] = 'disabled'
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh devices: {e}")
            self.status_var.set("Error scanning devices")
    
    def _on_device_selected(self, event=None):
        """Handle device selection."""
        try:
            selection = self.device_combobox.current()
            if selection >= 0 and selection < len(self.devices):
                self.selected_device = self.devices[selection]
                self._update_device_info()
                self.sanitize_button['state'] = 'normal'
            else:
                self.selected_device = None
                self.sanitize_button['state'] = 'disabled'
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to select device: {e}")
    
    def _update_device_info(self):
        """Update the device information display."""
        if not self.selected_device:
            return
        
        device = self.selected_device
        
        # Clear existing text
        self.device_info_text.delete(1.0, tk.END)
        
        # Device details
        info = []
        info.append(f"Device Path: {device.path}")
        info.append(f"Model: {device.model}")
        info.append(f"Serial Number: {device.serial}")
        info.append(f"Device Type: {device.device_type.upper()}")
        info.append(f"Storage Capacity: {device.size_bytes / (1024**3):.2f} GB")
        info.append(f"Platform: {device.platform.title()}")
        info.append(f"Removable: {'Yes' if device.removable else 'No'}")
        
        # Encryption status
        if device.is_encrypted:
            info.append(f"Encryption: {device.encryption_type or 'Unknown Type'}")
        else:
            info.append("Encryption: None")
        
        # Mount status
        if device.mounted:
            info.append(f"Mounted: Yes ({', '.join(device.mount_points)})")
        else:
            info.append("Mounted: No")
        
        # Capabilities
        capabilities = [cap for cap, supported in device.capabilities.items() if supported]
        if capabilities:
            info.append(f"Capabilities: {', '.join(capabilities)}")
        else:
            info.append("Capabilities: None detected")
        
        # Safety check
        safe, reason = self.device_detector.is_device_safe_to_wipe(device)
        safety_status = "✓ SAFE TO WIPE" if safe else "⚠ WARNING"
        info.append(f"\\nSafety Check: {safety_status}")
        info.append(f"Reason: {reason}")
        
        # Recommended method
        optimal_method = self.wipe_engine.select_optimal_method(device)
        info.append(f"\\nRecommended Method: {optimal_method.value}")
        
        # Display info
        self.device_info_text.insert(tk.END, "\\n".join(info))
    
    def _start_sanitization(self):
        """Start the sanitization process."""
        if not self.selected_device:
            messagebox.showerror("Error", "No device selected")
            return
        
        if self.is_sanitizing:
            messagebox.showwarning("Warning", "Sanitization already in progress")
            return
        
        # Safety confirmation
        device = self.selected_device
        safe, reason = self.device_detector.is_device_safe_to_wipe(device)
        
        if not safe:
            response = messagebox.askyesno(
                "Safety Warning",
                f"Safety check failed: {reason}\\n\\n"
                f"This device may contain important system data. "
                f"Proceeding will PERMANENTLY DESTROY all data on the device.\\n\\n"
                f"Do you want to continue anyway?",
                icon="warning"
            )
            if not response:
                return
        
        # Final confirmation
        response = messagebox.askyesno(
            "Confirm Sanitization",
            f"⚠ WARNING: This will PERMANENTLY DESTROY all data on:\\n\\n"
            f"Device: {device.path}\\n"
            f"Model: {device.model}\\n"
            f"Serial: {device.serial}\\n"
            f"Size: {device.size_bytes / (1024**3):.2f} GB\\n\\n"
            f"This action cannot be undone!\\n\\n"
            f"Are you absolutely sure you want to continue?",
            icon="warning"
        )
        
        if not response:
            return
        
        # Start sanitization in separate thread
        self.is_sanitizing = True
        self._update_ui_state()
        
        self.sanitization_thread = threading.Thread(target=self._sanitization_worker)
        self.sanitization_thread.daemon = True
        self.sanitization_thread.start()
    
    def _sanitization_worker(self):
        """Worker thread for sanitization."""
        try:
            # Determine method
            method = None
            if self.method_var.get() != "auto":
                method = SanitizationMethod(self.method_var.get())
            
            # Perform sanitization
            wipe_result = self.wipe_engine.sanitize_device(
                self.selected_device.path,
                method=method,
                verify=self.verify_var.get(),
                force=True  # User already confirmed
            )
            
            # Update UI on completion
            self.root.after(0, self._sanitization_completed, wipe_result)
        
        except Exception as e:
            self.root.after(0, self._sanitization_error, str(e))
    
    def _sanitization_completed(self, wipe_result: WipeResult):
        """Handle sanitization completion."""
        try:
            self.is_sanitizing = False
            self._update_ui_state()
            
            # Show results
            if wipe_result.result.value == "success":
                result_msg = f"✓ Sanitization completed successfully!\\n\\n"
                result_msg += f"Method: {wipe_result.method_used.value}\\n"
                result_msg += f"Duration: {wipe_result.duration_seconds:.2f} seconds\\n"
                result_msg += f"Bytes processed: {wipe_result.bytes_processed:,}\\n"
                
                if self.verify_var.get():
                    verification_status = "✓ PASSED" if wipe_result.verification_passed else "✗ FAILED"
                    result_msg += f"Verification: {verification_status}\\n"
                
                # Generate certificate if requested
                if self.certificate_var.get():
                    try:
                        verification_level = VerificationLevel(self.verification_var.get())
                        verification_report = self.verification_engine.verify_sanitization(
                            self.selected_device, wipe_result, verification_level
                        )
                        
                        certificate_files = self.certificate_generator.generate_certificate(
                            self.selected_device, wipe_result, verification_report, 
                            formats=["json", "pdf"]
                        )
                        
                        result_msg += f"\\nCertificates generated:\\n"
                        for format_type, file_path in certificate_files.items():
                            result_msg += f"  {format_type.upper()}: {file_path}\\n"
                    
                    except Exception as e:
                        result_msg += f"\\nCertificate generation failed: {e}\\n"
                
                messagebox.showinfo("Sanitization Complete", result_msg)
                self.status_var.set("Sanitization completed successfully")
            
            else:
                error_msg = f"✗ Sanitization failed or incomplete\\n\\n"
                error_msg += f"Status: {wipe_result.result.value}\\n"
                if wipe_result.error_message:
                    error_msg += f"Error: {wipe_result.error_message}\\n"
                
                messagebox.showerror("Sanitization Failed", error_msg)
                self.status_var.set("Sanitization failed")
        
        except Exception as e:
            messagebox.showerror("Error", f"Error processing results: {e}")
    
    def _sanitization_error(self, error_message: str):
        """Handle sanitization error."""
        self.is_sanitizing = False
        self._update_ui_state()
        
        messagebox.showerror("Sanitization Error", f"Sanitization failed with error:\\n\\n{error_message}")
        self.status_var.set("Sanitization error")
    
    def _stop_sanitization(self):
        """Stop the sanitization process."""
        # Note: This is a placeholder. Actual implementation would need
        # proper thread synchronization and cleanup
        response = messagebox.askyesno(
            "Stop Sanitization",
            "Stopping sanitization may leave the device in an unsafe state.\\n\\n"
            "Are you sure you want to stop?",
            icon="warning"
        )
        
        if response:
            self.is_sanitizing = False
            self._update_ui_state()
            self.status_var.set("Sanitization stopped by user")
    
    def _update_progress(self, progress: WipeProgress):
        """Update the progress display."""
        try:
            # Update progress bar
            self.progress_var.set(progress.percent_complete)
            
            # Update progress label
            if progress.estimated_time_remaining > 0:
                time_remaining = self._format_time(progress.estimated_time_remaining)
                progress_text = f"{progress.current_operation} - {progress.percent_complete:.1f}% - ETA: {time_remaining}"
            else:
                progress_text = f"{progress.current_operation} - {progress.percent_complete:.1f}%"
            
            self.progress_label.config(text=progress_text)
            
            # Update status
            self.status_var.set(f"Sanitizing: {progress.current_operation}")
            
            # Update UI
            self.root.update_idletasks()
        
        except Exception as e:
            print(f"Error updating progress: {e}")
    
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
    
    def _update_ui_state(self):
        """Update UI state based on sanitization status."""
        if self.is_sanitizing:
            self.sanitize_button['state'] = 'disabled'
            self.stop_button['state'] = 'normal'
            self.device_combobox['state'] = 'disabled'
            self.method_combobox['state'] = 'disabled'
            self.verification_combobox['state'] = 'disabled'
            self.verify_check['state'] = 'disabled'
            self.certificate_check['state'] = 'disabled'
        else:
            self.sanitize_button['state'] = 'normal' if self.selected_device else 'disabled'
            self.stop_button['state'] = 'disabled'
            self.device_combobox['state'] = 'readonly'
            self.method_combobox['state'] = 'readonly'
            self.verification_combobox['state'] = 'readonly'
            self.verify_check['state'] = 'normal'
            self.certificate_check['state'] = 'normal'
            
            # Reset progress
            self.progress_var.set(0)
            self.progress_label.config(text="Ready")
    
    def _view_certificates(self):
        """Open certificate directory."""
        try:
            cert_dir = self.certificate_generator.output_directory
            
            # Create directory if it doesn't exist
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
            messagebox.showerror("Error", f"Failed to open certificates directory: {e}")
    
    def _show_help(self):
        """Show help dialog."""
        help_text = """
PurgeProof Data Sanitization Tool

This tool securely erases data from storage devices in compliance with NIST SP 800-88 Rev.1 guidelines.

USAGE:
1. Select a storage device from the dropdown list
2. Choose sanitization options (method, verification level)
3. Click "Sanitize Device" to begin
4. Follow the confirmation prompts
5. Wait for completion and review the results

SANITIZATION METHODS:
• Auto: Automatically selects the best method for the device
• Crypto Erase: Destroys encryption keys (for encrypted devices)
• Firmware Secure Erase: Uses hardware-level sanitization
• NVMe Sanitize: Uses NVMe sanitization commands
• Overwrite: Overwrites data with random patterns

VERIFICATION LEVELS:
• Basic: Quick verification (10 samples)
• Standard: Normal verification (100 samples)
• Thorough: Comprehensive verification (1000 samples)
• Forensic: Maximum verification (10000 samples)

WARNING:
This tool permanently destroys data. Ensure you have proper authorization before sanitizing any device.

For more information, visit: https://github.com/your-org/purgeproof
        """
        
        help_window = tk.Toplevel(self.root)
        help_window.title("Help - PurgeProof")
        help_window.geometry("600x500")
        help_window.resizable(True, True)
        
        help_text_widget = scrolledtext.ScrolledText(help_window, wrap=tk.WORD, padx=10, pady=10)
        help_text_widget.pack(fill=tk.BOTH, expand=True)
        help_text_widget.insert(tk.END, help_text)
        help_text_widget.config(state=tk.DISABLED)
    
    def _on_closing(self):
        """Handle application closing."""
        if self.is_sanitizing:
            response = messagebox.askyesno(
                "Exit Application",
                "Sanitization is in progress. Exiting may leave the device in an unsafe state.\\n\\n"
                "Are you sure you want to exit?",
                icon="warning"
            )
            if not response:
                return
        
        self.root.destroy()
    
    def run(self):
        """Start the GUI application."""
        try:
            # Configure style for better appearance
            style = ttk.Style()
            style.theme_use('clam')  # Use a modern theme
            
            # Run main loop
            self.root.mainloop()
        
        except Exception as e:
            messagebox.showerror("Error", f"Application error: {e}")


def main():
    """Main entry point for the GUI application."""
    try:
        # Check for required dependencies
        missing_deps = []
        
        try:
            import tkinter
        except ImportError:
            missing_deps.append("tkinter")
        
        if missing_deps:
            print(f"Missing required dependencies: {', '.join(missing_deps)}")
            print("Please install the missing dependencies and try again.")
            return 1
        
        # Create and run the GUI
        app = PurgeProofGUI()
        app.run()
        
        return 0
    
    except Exception as e:
        print(f"Failed to start GUI application: {e}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
