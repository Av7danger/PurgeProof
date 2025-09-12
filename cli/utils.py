"""
Enterprise CLI Utilities and Helper Functions

Provides utility functions, configuration management, and helper
classes for the PurgeProof Enterprise CLI interface.
"""

import os
import sys
import json
import configparser
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import logging


class CLIConfig:
    """Configuration management for CLI operations"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._get_default_config_path()
        self.config = {}
        self.load_config()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        if os.name == 'nt':  # Windows
            config_dir = os.path.expandvars(r'%APPDATA%\\PurgeProof')
        else:  # Linux/Unix
            config_dir = os.path.expanduser('~/.config/purgeproof')
        
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, 'cli_config.json')
    
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            except Exception as e:
                print(f"⚠️ Failed to load config: {e}")
                self.config = self._get_default_config()
        else:
            self.config = self._get_default_config()
            self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed to save config: {e}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'default_method': 'NIST SP 800-88',
            'default_operator': 'CLI-User',
            'certificate_directory': 'certificates',
            'batch_results_directory': 'batch_results',
            'compliance_reports_directory': 'compliance_reports',
            'log_level': 'INFO',
            'output_format': 'table',
            'auto_detect_devices': True,
            'verify_certificates': True,
            'enterprise_features': {
                'audit_logging': True,
                'compliance_validation': True,
                'batch_processing': True,
                'certificate_generation': True
            },
            'device_filters': {
                'exclude_system_drives': True,
                'min_size_gb': 0,
                'max_size_gb': 0,
                'allowed_interfaces': ['USB', 'SATA', 'NVMe']
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value"""
        self.config[key] = value
        self.save_config()
    
    def get_nested(self, keys: List[str], default: Any = None) -> Any:
        """Get nested configuration value"""
        current = self.config
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return default
        return current
    
    def set_nested(self, keys: List[str], value: Any):
        """Set nested configuration value"""
        current = self.config
        for key in keys[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value
        self.save_config()


class CLILogger:
    """Logging utilities for CLI operations"""
    
    def __init__(self, log_level: str = 'INFO', log_file: Optional[str] = None):
        self.logger = logging.getLogger('purgeproof_cli')
        self.setup_logging(log_level, log_file)
    
    def setup_logging(self, log_level: str, log_file: Optional[str] = None):
        """Setup logging configuration"""
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Set log level
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            try:
                os.makedirs(os.path.dirname(log_file), exist_ok=True)
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except Exception as e:
                print(f"⚠️ Failed to setup file logging: {e}")
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)
    
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)


class OutputFormatter:
    """Output formatting utilities for CLI"""
    
    @staticmethod
    def format_table(data: List[Dict[str, Any]], headers: Optional[List[str]] = None) -> str:
        """Format data as a table"""
        if not data:
            return "No data to display"
        
        # Get headers
        if headers is None:
            headers = list(data[0].keys())
        
        # Calculate column widths
        col_widths = {}
        for header in headers:
            col_widths[header] = len(header)
            for row in data:
                value = str(row.get(header, ''))
                col_widths[header] = max(col_widths[header], len(value))
        
        # Build table
        lines = []
        
        # Header line
        header_line = ' | '.join(header.ljust(col_widths[header]) for header in headers)
        lines.append(header_line)
        
        # Separator line
        separator = '-+-'.join('-' * col_widths[header] for header in headers)
        lines.append(separator)
        
        # Data lines
        for row in data:
            data_line = ' | '.join(str(row.get(header, '')).ljust(col_widths[header]) for header in headers)
            lines.append(data_line)
        
        return '\\n'.join(lines)
    
    @staticmethod
    def format_json(data: Any, indent: int = 2) -> str:
        """Format data as JSON"""
        return json.dumps(data, indent=indent, default=str)
    
    @staticmethod
    def format_csv(data: List[Dict[str, Any]], headers: Optional[List[str]] = None) -> str:
        """Format data as CSV"""
        if not data:
            return ""
        
        import csv
        import io
        
        output = io.StringIO()
        
        if headers is None:
            headers = list(data[0].keys())
        
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        writer.writerows(data)
        
        return output.getvalue()
    
    @staticmethod
    def format_yaml(data: Any) -> str:
        """Format data as YAML"""
        try:
            import yaml
            return yaml.dump(data, default_flow_style=False)
        except ImportError:
            # Fallback to JSON if yaml not available
            return OutputFormatter.format_json(data)
    
    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format size in bytes to human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
        unit_index = 0
        size = float(size_bytes)
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        else:
            return f"{size:.1f} {units[unit_index]}"
    
    @staticmethod
    def format_duration(seconds: int) -> str:
        """Format duration in seconds to human readable format"""
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            minutes = seconds // 60
            secs = seconds % 60
            return f"{minutes}m {secs}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            secs = seconds % 60
            return f"{hours}h {minutes}m {secs}s"


class ProgressIndicator:
    """Progress indication for long-running operations"""
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = datetime.now()
    
    def update(self, increment: int = 1):
        """Update progress"""
        self.current += increment
        self._display_progress()
    
    def set_progress(self, current: int):
        """Set absolute progress"""
        self.current = current
        self._display_progress()
    
    def _display_progress(self):
        """Display progress bar"""
        if self.total == 0:
            return
        
        percentage = min(100, int(self.current / self.total * 100))
        bar_length = 40
        filled_length = int(bar_length * self.current / self.total)
        
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        # Calculate ETA
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = OutputFormatter.format_duration(int(eta))
        else:
            eta_str = "N/A"
        
        # Print progress (overwrite previous line)
        print(f"\\r{self.description}: [{bar}] {percentage}% ({self.current}/{self.total}) ETA: {eta_str}", end='', flush=True)
        
        if self.current >= self.total:
            print()  # New line when complete


class CLIValidator:
    """Input validation utilities for CLI"""
    
    @staticmethod
    def validate_device_id(device_id: str) -> bool:
        """Validate device ID format"""
        if not device_id:
            return False
        
        # Windows device patterns
        windows_patterns = [
            r'\\\\.\\PHYSICALDRIVE\\d+',
            r'[A-Z]:',
        ]
        
        # Linux device patterns
        linux_patterns = [
            r'/dev/sd[a-z]+',
            r'/dev/nvme\\d+n\\d+',
            r'/dev/hd[a-z]+',
            r'/dev/mmc\\w+',
        ]
        
        import re
        all_patterns = windows_patterns + linux_patterns
        
        return any(re.match(pattern, device_id) for pattern in all_patterns)
    
    @staticmethod
    def validate_sanitization_method(method: str) -> bool:
        """Validate sanitization method"""
        valid_methods = [
            'NIST SP 800-88',
            'DoD 5220.22-M',
            'ATA Secure Erase',
            'NVMe Format',
            'Crypto Erase',
            'Physical Destruction'
        ]
        
        return method in valid_methods
    
    @staticmethod
    def validate_compliance_standard(standard: str) -> bool:
        """Validate compliance standard"""
        valid_standards = [
            'nist_sp_800_88',
            'dod_5220_22',
            'common_criteria',
            'iso_27001',
            'hipaa',
            'gdpr'
        ]
        
        return standard in valid_standards
    
    @staticmethod
    def validate_file_path(file_path: str, must_exist: bool = True) -> bool:
        """Validate file path"""
        if not file_path:
            return False
        
        path = Path(file_path)
        
        if must_exist:
            return path.exists() and path.is_file()
        else:
            # Check if parent directory exists
            return path.parent.exists()


class CLIError(Exception):
    """Custom CLI error with error codes"""
    
    def __init__(self, message: str, error_code: int = 1):
        super().__init__(message)
        self.error_code = error_code


class EnterpriseMetrics:
    """Metrics collection and reporting for enterprise operations"""
    
    def __init__(self):
        self.metrics = {
            'operations': [],
            'performance': {},
            'compliance': {},
            'devices': {}
        }
        self.start_time = datetime.now()
    
    def record_operation(self, operation_type: str, device_id: str, method: str, duration: float, success: bool):
        """Record operation metrics"""
        operation = {
            'timestamp': datetime.now().isoformat(),
            'type': operation_type,
            'device_id': device_id,
            'method': method,
            'duration': duration,
            'success': success
        }
        
        self.metrics['operations'].append(operation)
    
    def record_performance(self, metric_name: str, value: float, unit: str = ''):
        """Record performance metric"""
        if metric_name not in self.metrics['performance']:
            self.metrics['performance'][metric_name] = []
        
        self.metrics['performance'][metric_name].append({
            'timestamp': datetime.now().isoformat(),
            'value': value,
            'unit': unit
        })
    
    def record_compliance(self, standard: str, compliant: bool, issues: List[str] = None):
        """Record compliance check"""
        if standard not in self.metrics['compliance']:
            self.metrics['compliance'][standard] = []
        
        self.metrics['compliance'][standard].append({
            'timestamp': datetime.now().isoformat(),
            'compliant': compliant,
            'issues': issues or []
        })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        total_operations = len(self.metrics['operations'])
        successful_operations = len([op for op in self.metrics['operations'] if op['success']])
        
        summary = {
            'session_duration': (datetime.now() - self.start_time).total_seconds(),
            'total_operations': total_operations,
            'successful_operations': successful_operations,
            'success_rate': (successful_operations / total_operations * 100) if total_operations > 0 else 0,
            'performance_metrics': len(self.metrics['performance']),
            'compliance_checks': sum(len(checks) for checks in self.metrics['compliance'].values())
        }
        
        return summary
    
    def export_metrics(self, file_path: str, format_type: str = 'json'):
        """Export metrics to file"""
        data = {
            'summary': self.get_summary(),
            'detailed_metrics': self.metrics,
            'exported': datetime.now().isoformat()
        }
        
        if format_type.lower() == 'json':
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        elif format_type.lower() == 'csv':
            self._export_csv_metrics(file_path, data)
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_csv_metrics(self, file_path: str, data: Dict[str, Any]):
        """Export metrics as CSV"""
        import csv
        
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write operations
            writer.writerow(['Operations'])
            writer.writerow(['Timestamp', 'Type', 'Device', 'Method', 'Duration', 'Success'])
            
            for op in data['detailed_metrics']['operations']:
                writer.writerow([
                    op['timestamp'],
                    op['type'],
                    op['device_id'],
                    op['method'],
                    op['duration'],
                    op['success']
                ])
            
            writer.writerow([])  # Empty row separator


def setup_cli_environment(config_file: Optional[str] = None) -> tuple:
    """Setup CLI environment with configuration and logging"""
    # Load configuration
    config = CLIConfig(config_file)
    
    # Setup logging
    log_level = config.get('log_level', 'INFO')
    log_file = config.get('log_file')
    logger = CLILogger(log_level, log_file)
    
    # Initialize metrics
    metrics = EnterpriseMetrics()
    
    # Create necessary directories
    cert_dir = config.get('certificate_directory', 'certificates')
    batch_dir = config.get('batch_results_directory', 'batch_results')
    compliance_dir = config.get('compliance_reports_directory', 'compliance_reports')
    
    for directory in [cert_dir, batch_dir, compliance_dir]:
        os.makedirs(directory, exist_ok=True)
    
    return config, logger, metrics


def print_banner():
    """Print CLI banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    PurgeProof Enterprise CLI                 ║
║              Secure Data Sanitization Solution              ║
║                          v2.0.0                             ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)


def print_help_examples():
    """Print helpful CLI examples"""
    examples = """
Common CLI Examples:
════════════════════

Device Management:
  purgeproof-cli devices list
  purgeproof-cli devices list --removable-only
  purgeproof-cli devices info /dev/sdb
  purgeproof-cli devices info \\\\.\\PHYSICALDRIVE1

Certificate Operations:
  purgeproof-cli certificates generate /dev/sdb "NIST SP 800-88"
  purgeproof-cli certificates verify CERT-20241223-120000
  purgeproof-cli certificates list --limit 10
  purgeproof-cli certificates export CERT-20241223-120000 --format pdf

Batch Processing:
  purgeproof-cli batch create "/dev/sdb,/dev/sdc" "DoD 5220.22-M"
  purgeproof-cli batch process BATCH-20241223-120000 --simulate
  purgeproof-cli batch status BATCH-20241223-120000
  purgeproof-cli batch report BATCH-20241223-120000 --format html

Compliance Validation:
  purgeproof-cli compliance validate operation.json nist_sp_800_88

Configuration:
  purgeproof-cli config show
  purgeproof-cli config set default_method "NIST SP 800-88"
  purgeproof-cli config set output_format json
"""
    print(examples)


if __name__ == "__main__":
    """Run utility functions when executed directly"""
    print_banner()
    print_help_examples()