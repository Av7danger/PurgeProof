"""
PurgeProof Audit Logging Framework
Tamper-evident logging system for NIST SP 800-88 Rev.1 compliance

This module provides comprehensive audit logging with hash-chain integrity,
operator tracking, and configurable retention policies for enterprise compliance.
"""

import json
import hashlib
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from dataclasses import dataclass, asdict, field
from enum import Enum
import gzip
import shutil
import os
import fcntl
import logging
from logging.handlers import RotatingFileHandler


class LogLevel(Enum):
    """Audit log severity levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    SECURITY = "SECURITY"


class EventType(Enum):
    """Types of audit events"""
    WIPE_START = "wipe_start"
    WIPE_COMPLETE = "wipe_complete"
    WIPE_FAILED = "wipe_failed"
    VERIFICATION_START = "verification_start"
    VERIFICATION_COMPLETE = "verification_complete"
    VERIFICATION_FAILED = "verification_failed"
    CERTIFICATE_CREATED = "certificate_created"
    CERTIFICATE_VERIFIED = "certificate_verified"
    SYSTEM_START = "system_start"
    SYSTEM_SHUTDOWN = "system_shutdown"
    CONFIG_CHANGED = "config_changed"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    ERROR_OCCURRED = "error_occurred"
    SECURITY_VIOLATION = "security_violation"


@dataclass
class AuditEvent:
    """Individual audit log event"""
    event_id: str
    timestamp: str
    event_type: EventType
    level: LogLevel
    operator_id: str
    session_id: str
    device_path: Optional[str] = None
    device_serial: Optional[str] = None
    method_used: Optional[str] = None
    outcome: Optional[str] = None
    error_message: Optional[str] = None
    duration_seconds: Optional[float] = None
    verification_result: Optional[bool] = None
    certificate_id: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)
    previous_hash: Optional[str] = None
    event_hash: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp,
            'event_type': self.event_type.value,
            'level': self.level.value,
            'operator_id': self.operator_id,
            'session_id': self.session_id,
            'device_path': self.device_path,
            'device_serial': self.device_serial,
            'method_used': self.method_used,
            'outcome': self.outcome,
            'error_message': self.error_message,
            'duration_seconds': self.duration_seconds,
            'verification_result': self.verification_result,
            'certificate_id': self.certificate_id,
            'additional_data': self.additional_data,
            'previous_hash': self.previous_hash,
            'event_hash': self.event_hash
        }
    
    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of event data"""
        # Create canonical representation for hashing
        event_data = self.to_dict()
        event_data['event_hash'] = None  # Exclude hash from hash calculation
        
        canonical_json = json.dumps(event_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()


@dataclass
class LogRetentionPolicy:
    """Log retention and rotation policy"""
    max_size_mb: int = 100
    max_files: int = 10
    max_age_days: int = 365
    compress_old_logs: bool = True
    secure_delete_old_logs: bool = True


@dataclass
class AuditLogConfig:
    """Audit logging configuration"""
    log_directory: str = "logs"
    log_filename: str = "purgeproof_audit.log"
    hash_chain_enabled: bool = True
    real_time_verification: bool = True
    encryption_enabled: bool = False
    encryption_key_path: Optional[str] = None
    retention_policy: LogRetentionPolicy = field(default_factory=LogRetentionPolicy)
    backup_enabled: bool = True
    backup_directory: Optional[str] = None
    syslog_enabled: bool = False
    syslog_server: Optional[str] = None
    syslog_port: int = 514


class HashChainVerifier:
    """Verifies integrity of hash-chained audit logs"""
    
    def __init__(self):
        self.last_verified_hash = None
    
    def verify_chain(self, events: List[AuditEvent]) -> Dict[str, Any]:
        """Verify the integrity of a hash chain"""
        result = {
            'valid': True,
            'total_events': len(events),
            'verified_events': 0,
            'broken_chains': [],
            'invalid_hashes': [],
            'errors': []
        }
        
        if not events:
            return result
        
        previous_hash = None
        
        for i, event in enumerate(events):
            # Verify event hash
            calculated_hash = event.calculate_hash()
            if event.event_hash != calculated_hash:
                result['valid'] = False
                result['invalid_hashes'].append({
                    'event_id': event.event_id,
                    'position': i,
                    'expected': calculated_hash,
                    'actual': event.event_hash
                })
                continue
            
            # Verify chain linkage (except for first event)
            if i > 0 and event.previous_hash != previous_hash:
                result['valid'] = False
                result['broken_chains'].append({
                    'event_id': event.event_id,
                    'position': i,
                    'expected_previous': previous_hash,
                    'actual_previous': event.previous_hash
                })
            
            previous_hash = event.event_hash
            result['verified_events'] += 1
        
        return result
    
    def get_chain_summary(self, events: List[AuditEvent]) -> Dict[str, Any]:
        """Get summary of hash chain"""
        if not events:
            return {'chain_length': 0, 'first_event': None, 'last_event': None}
        
        return {
            'chain_length': len(events),
            'first_event': {
                'event_id': events[0].event_id,
                'timestamp': events[0].timestamp,
                'hash': events[0].event_hash
            },
            'last_event': {
                'event_id': events[-1].event_id,
                'timestamp': events[-1].timestamp,
                'hash': events[-1].event_hash
            },
            'time_span_hours': self._calculate_time_span(events)
        }
    
    def _calculate_time_span(self, events: List[AuditEvent]) -> float:
        """Calculate time span of events in hours"""
        if len(events) < 2:
            return 0.0
        
        try:
            first_time = datetime.fromisoformat(events[0].timestamp.replace('Z', '+00:00'))
            last_time = datetime.fromisoformat(events[-1].timestamp.replace('Z', '+00:00'))
            return (last_time - first_time).total_seconds() / 3600
        except:
            return 0.0


class AuditLogger:
    """Main audit logging system with tamper-evident hash chains"""
    
    def __init__(self, config: AuditLogConfig):
        self.config = config
        self.lock = threading.Lock()
        self.current_session_id = self._generate_session_id()
        self.last_event_hash = None
        self.event_counter = 0
        
        # Setup logging directory
        self.log_dir = Path(self.config.log_directory)
        self.log_dir.mkdir(exist_ok=True)
        
        self.log_file_path = self.log_dir / self.config.log_filename
        
        # Initialize hash chain
        self._initialize_hash_chain()
        
        # Setup file rotation if needed
        self._setup_log_rotation()
        
        # Log system startup
        self.log_event(
            event_type=EventType.SYSTEM_START,
            level=LogLevel.INFO,
            operator_id="system",
            additional_data={'config': asdict(self.config)}
        )
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = str(int(time.time() * 1000))
        random_data = os.urandom(8).hex()
        return f"SESSION-{timestamp}-{random_data[:8].upper()}"
    
    def _generate_event_id(self) -> str:
        """Generate unique event ID"""
        with self.lock:
            self.event_counter += 1
            timestamp = str(int(time.time() * 1000))
            return f"EVENT-{timestamp}-{self.event_counter:06d}"
    
    def _initialize_hash_chain(self):
        """Initialize or resume hash chain from existing logs"""
        if self.log_file_path.exists():
            # Read last event to get last hash
            try:
                last_event = self._read_last_event()
                if last_event:
                    self.last_event_hash = last_event.event_hash
            except Exception as e:
                # If we can't read last event, start fresh
                self.last_event_hash = None
    
    def _read_last_event(self) -> Optional[AuditEvent]:
        """Read the last event from the log file"""
        try:
            with open(self.log_file_path, 'r') as f:
                lines = f.readlines()
                if lines:
                    last_line = lines[-1].strip()
                    if last_line:
                        event_dict = json.loads(last_line)
                        return self._dict_to_event(event_dict)
        except:
            pass
        return None
    
    def _dict_to_event(self, event_dict: Dict[str, Any]) -> AuditEvent:
        """Convert dictionary to AuditEvent"""
        return AuditEvent(
            event_id=event_dict['event_id'],
            timestamp=event_dict['timestamp'],
            event_type=EventType(event_dict['event_type']),
            level=LogLevel(event_dict['level']),
            operator_id=event_dict['operator_id'],
            session_id=event_dict['session_id'],
            device_path=event_dict.get('device_path'),
            device_serial=event_dict.get('device_serial'),
            method_used=event_dict.get('method_used'),
            outcome=event_dict.get('outcome'),
            error_message=event_dict.get('error_message'),
            duration_seconds=event_dict.get('duration_seconds'),
            verification_result=event_dict.get('verification_result'),
            certificate_id=event_dict.get('certificate_id'),
            additional_data=event_dict.get('additional_data', {}),
            previous_hash=event_dict.get('previous_hash'),
            event_hash=event_dict.get('event_hash')
        )
    
    def _setup_log_rotation(self):
        """Setup automatic log rotation"""
        max_bytes = self.config.retention_policy.max_size_mb * 1024 * 1024
        
        # Use Python's RotatingFileHandler for backup management
        self.rotating_handler = RotatingFileHandler(
            str(self.log_file_path),
            maxBytes=max_bytes,
            backupCount=self.config.retention_policy.max_files
        )
    
    def log_event(
        self,
        event_type: EventType,
        level: LogLevel,
        operator_id: str,
        device_path: Optional[str] = None,
        device_serial: Optional[str] = None,
        method_used: Optional[str] = None,
        outcome: Optional[str] = None,
        error_message: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        verification_result: Optional[bool] = None,
        certificate_id: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Log an audit event with hash chain integrity"""
        
        with self.lock:
            event = AuditEvent(
                event_id=self._generate_event_id(),
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=event_type,
                level=level,
                operator_id=operator_id,
                session_id=self.current_session_id,
                device_path=device_path,
                device_serial=device_serial,
                method_used=method_used,
                outcome=outcome,
                error_message=error_message,
                duration_seconds=duration_seconds,
                verification_result=verification_result,
                certificate_id=certificate_id,
                additional_data=additional_data or {},
                previous_hash=self.last_event_hash
            )
            
            # Calculate and set event hash
            event.event_hash = event.calculate_hash()
            
            # Write to log file
            self._write_event(event)
            
            # Update last hash for chain
            self.last_event_hash = event.event_hash
            
            return event.event_id
    
    def _write_event(self, event: AuditEvent):
        """Write event to log file with file locking"""
        try:
            # Ensure directory exists
            self.log_file_path.parent.mkdir(exist_ok=True)
            
            # Write with exclusive lock
            with open(self.log_file_path, 'a') as f:
                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                    json.dump(event.to_dict(), f, separators=(',', ':'))
                    f.write('\n')
                    f.flush()
                    os.fsync(f.fileno())
                except:
                    # Fallback for Windows (no fcntl)
                    json.dump(event.to_dict(), f, separators=(',', ':'))
                    f.write('\n')
                    f.flush()
        except Exception as e:
            # Critical: Log to stderr if file logging fails
            print(f"CRITICAL: Audit logging failed: {e}", file=sys.stderr)
    
    def read_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[EventType]] = None,
        operator_id: Optional[str] = None,
        device_path: Optional[str] = None,
        limit: Optional[int] = None
    ) -> List[AuditEvent]:
        """Read events from log with optional filtering"""
        
        events = []
        
        try:
            with open(self.log_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        event_dict = json.loads(line)
                        event = self._dict_to_event(event_dict)
                        
                        # Apply filters
                        if self._event_matches_filters(
                            event, start_time, end_time, event_types, operator_id, device_path
                        ):
                            events.append(event)
                            
                            if limit and len(events) >= limit:
                                break
                    
                    except json.JSONDecodeError:
                        continue  # Skip malformed lines
                        
        except FileNotFoundError:
            pass  # No events yet
        
        return events
    
    def _event_matches_filters(
        self,
        event: AuditEvent,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        event_types: Optional[List[EventType]],
        operator_id: Optional[str],
        device_path: Optional[str]
    ) -> bool:
        """Check if event matches all filters"""
        
        # Time filter
        if start_time or end_time:
            try:
                event_time = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                if start_time and event_time < start_time:
                    return False
                if end_time and event_time > end_time:
                    return False
            except:
                return False
        
        # Event type filter
        if event_types and event.event_type not in event_types:
            return False
        
        # Operator filter
        if operator_id and event.operator_id != operator_id:
            return False
        
        # Device filter
        if device_path and event.device_path != device_path:
            return False
        
        return True
    
    def verify_log_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the entire audit log"""
        events = self.read_events()
        verifier = HashChainVerifier()
        return verifier.verify_chain(events)
    
    def get_log_summary(self) -> Dict[str, Any]:
        """Get summary of audit log"""
        events = self.read_events()
        verifier = HashChainVerifier()
        
        summary = verifier.get_chain_summary(events)
        summary['integrity_check'] = verifier.verify_chain(events)
        
        # Event type statistics
        event_type_counts = {}
        operator_counts = {}
        
        for event in events:
            event_type_counts[event.event_type.value] = event_type_counts.get(event.event_type.value, 0) + 1
            operator_counts[event.operator_id] = operator_counts.get(event.operator_id, 0) + 1
        
        summary['event_statistics'] = {
            'by_type': event_type_counts,
            'by_operator': operator_counts
        }
        
        return summary
    
    def export_logs(
        self,
        output_path: str,
        format: str = 'json',
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        include_integrity_proof: bool = True
    ):
        """Export audit logs in various formats"""
        
        events = self.read_events(start_time=start_time, end_time=end_time)
        
        if format == 'json':
            self._export_json(events, output_path, include_integrity_proof)
        elif format == 'csv':
            self._export_csv(events, output_path)
        elif format == 'html':
            self._export_html(events, output_path, include_integrity_proof)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_json(self, events: List[AuditEvent], output_path: str, include_integrity: bool):
        """Export events as JSON"""
        export_data = {
            'export_timestamp': datetime.now(timezone.utc).isoformat(),
            'total_events': len(events),
            'events': [event.to_dict() for event in events]
        }
        
        if include_integrity:
            verifier = HashChainVerifier()
            export_data['integrity_verification'] = verifier.verify_chain(events)
            export_data['chain_summary'] = verifier.get_chain_summary(events)
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
    
    def _export_csv(self, events: List[AuditEvent], output_path: str):
        """Export events as CSV"""
        import csv
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Event ID', 'Timestamp', 'Event Type', 'Level', 'Operator ID',
                'Device Path', 'Device Serial', 'Method Used', 'Outcome',
                'Duration (s)', 'Verification Result', 'Certificate ID', 'Error Message'
            ])
            
            # Write events
            for event in events:
                writer.writerow([
                    event.event_id,
                    event.timestamp,
                    event.event_type.value,
                    event.level.value,
                    event.operator_id,
                    event.device_path or '',
                    event.device_serial or '',
                    event.method_used or '',
                    event.outcome or '',
                    event.duration_seconds or '',
                    event.verification_result or '',
                    event.certificate_id or '',
                    event.error_message or ''
                ])
    
    def _export_html(self, events: List[AuditEvent], output_path: str, include_integrity: bool):
        """Export events as HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PurgeProof Audit Log Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
                .summary { margin: 20px 0; }
                .events { margin-top: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .verified { color: green; }
                .failed { color: red; }
                .warning { color: orange; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>PurgeProof Audit Log Report</h1>
                <p>Generated: {timestamp}</p>
                <p>Total Events: {total_events}</p>
            </div>
            
            {integrity_section}
            
            <div class="events">
                <h2>Audit Events</h2>
                <table>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Level</th>
                        <th>Operator</th>
                        <th>Device</th>
                        <th>Method</th>
                        <th>Outcome</th>
                        <th>Duration</th>
                    </tr>
                    {event_rows}
                </table>
            </div>
        </body>
        </html>
        """
        
        event_rows = []
        for event in events:
            css_class = ""
            if event.verification_result is True:
                css_class = "verified"
            elif event.verification_result is False:
                css_class = "failed"
            elif event.level == LogLevel.WARNING:
                css_class = "warning"
            
            row = f"""
            <tr class="{css_class}">
                <td>{event.timestamp}</td>
                <td>{event.event_type.value}</td>
                <td>{event.level.value}</td>
                <td>{event.operator_id}</td>
                <td>{event.device_path or 'N/A'}</td>
                <td>{event.method_used or 'N/A'}</td>
                <td>{event.outcome or 'N/A'}</td>
                <td>{event.duration_seconds or 'N/A'}</td>
            </tr>
            """
            event_rows.append(row)
        
        integrity_section = ""
        if include_integrity:
            verifier = HashChainVerifier()
            integrity_result = verifier.verify_chain(events)
            status = "VALID" if integrity_result['valid'] else "INVALID"
            integrity_section = f"""
            <div class="summary">
                <h2>Integrity Verification</h2>
                <p><strong>Status:</strong> <span class="{'verified' if integrity_result['valid'] else 'failed'}">{status}</span></p>
                <p><strong>Verified Events:</strong> {integrity_result['verified_events']}/{integrity_result['total_events']}</p>
            </div>
            """
        
        html_content = html_template.format(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_events=len(events),
            integrity_section=integrity_section,
            event_rows=''.join(event_rows)
        )
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def cleanup_old_logs(self):
        """Clean up old log files based on retention policy"""
        if not self.config.retention_policy.max_age_days:
            return
        
        cutoff_date = datetime.now() - timedelta(days=self.config.retention_policy.max_age_days)
        
        # Find old log files
        for log_file in self.log_dir.glob("*.log*"):
            try:
                file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                if file_mtime < cutoff_date:
                    if self.config.retention_policy.secure_delete_old_logs:
                        self._secure_delete_file(log_file)
                    else:
                        log_file.unlink()
            except Exception as e:
                print(f"Warning: Could not cleanup old log file {log_file}: {e}")
    
    def _secure_delete_file(self, file_path: Path):
        """Securely delete a log file"""
        try:
            # Simple secure delete - overwrite with random data
            file_size = file_path.stat().st_size
            with open(file_path, 'wb') as f:
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
            
            file_path.unlink()
        except Exception as e:
            print(f"Warning: Secure delete failed for {file_path}: {e}")
            # Fallback to regular delete
            try:
                file_path.unlink()
            except:
                pass


# Factory functions for common log events
def create_audit_logger(log_directory: str = "logs", hash_chain: bool = True) -> AuditLogger:
    """Create audit logger with default configuration"""
    config = AuditLogConfig(
        log_directory=log_directory,
        hash_chain_enabled=hash_chain
    )
    return AuditLogger(config)


def log_wipe_start(logger: AuditLogger, operator_id: str, device_path: str, device_serial: str, method: str) -> str:
    """Log the start of a wipe operation"""
    return logger.log_event(
        event_type=EventType.WIPE_START,
        level=LogLevel.INFO,
        operator_id=operator_id,
        device_path=device_path,
        device_serial=device_serial,
        method_used=method
    )


def log_wipe_complete(logger: AuditLogger, operator_id: str, device_path: str, device_serial: str, 
                     method: str, duration: float, certificate_id: str) -> str:
    """Log successful completion of a wipe operation"""
    return logger.log_event(
        event_type=EventType.WIPE_COMPLETE,
        level=LogLevel.INFO,
        operator_id=operator_id,
        device_path=device_path,
        device_serial=device_serial,
        method_used=method,
        outcome="SUCCESS",
        duration_seconds=duration,
        certificate_id=certificate_id
    )


def log_wipe_failed(logger: AuditLogger, operator_id: str, device_path: str, device_serial: str,
                   method: str, error_message: str, duration: float) -> str:
    """Log failed wipe operation"""
    return logger.log_event(
        event_type=EventType.WIPE_FAILED,
        level=LogLevel.ERROR,
        operator_id=operator_id,
        device_path=device_path,
        device_serial=device_serial,
        method_used=method,
        outcome="FAILED",
        error_message=error_message,
        duration_seconds=duration
    )