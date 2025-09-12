"""
NIST SP 800-88 Compliance Framework for PurgeProof.

This module provides comprehensive compliance validation, audit trail generation,
and certification support for NIST SP 800-88 Rev. 1 and other standards.
"""

import json
import time
import hashlib
import logging
from typing import Dict, List, Optional, Any, Tuple, NamedTuple
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from pathlib import Path
from datetime import datetime, timezone
import uuid

from .device_utils import DeviceCapabilities, DeviceType
from .decision_engine import SanitizationMethod, ComplianceLevel

logger = logging.getLogger(__name__)

class ComplianceStandard(Enum):
    """Supported compliance standards."""
    NIST_SP_800_88_CLEAR = auto()
    NIST_SP_800_88_PURGE = auto()
    NIST_SP_800_88_DESTROY = auto()
    DOD_5220_22_M = auto()
    COMMON_CRITERIA_EAL4 = auto()
    COMMON_CRITERIA_EAL5 = auto()
    NSA_CSS_POLICY = auto()
    FIPS_140_2 = auto()
    ISO_27001 = auto()

class ValidationStatus(Enum):
    """Validation result status."""
    COMPLIANT = auto()
    NON_COMPLIANT = auto()
    PARTIALLY_COMPLIANT = auto()
    REQUIRES_REVIEW = auto()
    UNKNOWN = auto()

class AuditEventType(Enum):
    """Types of audit events."""
    DEVICE_ANALYSIS = auto()
    METHOD_SELECTION = auto()
    SANITIZATION_START = auto()
    SANITIZATION_PROGRESS = auto()
    SANITIZATION_COMPLETE = auto()
    VERIFICATION_START = auto()
    VERIFICATION_COMPLETE = auto()
    COMPLIANCE_CHECK = auto()
    ERROR_OCCURRED = auto()
    SECURITY_VIOLATION = auto()

@dataclass
class ComplianceRequirement:
    """Individual compliance requirement definition."""
    standard: ComplianceStandard
    requirement_id: str
    title: str
    description: str
    applicable_methods: List[SanitizationMethod]
    applicable_device_types: List[DeviceType]
    verification_required: bool
    documentation_required: bool
    witness_required: bool
    automated_check: bool
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW

@dataclass
class ValidationResult:
    """Result of compliance validation."""
    requirement: ComplianceRequirement
    status: ValidationStatus
    evidence: List[str]
    violations: List[str]
    recommendations: List[str]
    validated_at: datetime
    validator_id: str
    automated: bool

@dataclass
class AuditEvent:
    """Individual audit trail event."""
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    device_path: str
    user_id: str
    session_id: str
    method_used: Optional[SanitizationMethod]
    compliance_level: Optional[ComplianceLevel]
    event_data: Dict[str, Any]
    integrity_hash: str
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if not self.integrity_hash:
            self.integrity_hash = self._calculate_hash()
    
    def _calculate_hash(self) -> str:
        """Calculate integrity hash for audit event."""
        data = {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.name,
            'device_path': self.device_path,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'method_used': self.method_used.name if self.method_used else None,
            'compliance_level': self.compliance_level.name if self.compliance_level else None,
            'event_data': self.event_data,
        }
        
        json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify the integrity hash of this event."""
        calculated_hash = self._calculate_hash()
        return calculated_hash == self.integrity_hash

@dataclass
class ComplianceReport:
    """Comprehensive compliance assessment report."""
    report_id: str
    generated_at: datetime
    device_path: str
    device_capabilities: DeviceCapabilities
    sanitization_method: SanitizationMethod
    compliance_level: ComplianceLevel
    target_standards: List[ComplianceStandard]
    validation_results: List[ValidationResult]
    overall_status: ValidationStatus
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    audit_trail: List[AuditEvent]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.report_id:
            self.report_id = f"CR-{int(time.time())}-{uuid.uuid4().hex[:8]}"

class ComplianceFramework:
    """Main compliance framework for NIST SP 800-88 and other standards."""
    
    def __init__(self, audit_log_path: Optional[Path] = None):
        self.requirements_db = self._load_compliance_requirements()
        self.audit_log_path = audit_log_path or Path("purgeproof_audit.jsonl")
        self.session_id = str(uuid.uuid4())
        
        # Ensure audit log directory exists
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Compliance framework initialized (session: {self.session_id})")
    
    def validate_method_compliance(self, 
                                 device: DeviceCapabilities,
                                 method: SanitizationMethod,
                                 compliance_level: ComplianceLevel,
                                 target_standards: Optional[List[ComplianceStandard]] = None) -> ComplianceReport:
        """
        Validate sanitization method against compliance requirements.
        
        Args:
            device: Device capabilities
            method: Selected sanitization method
            compliance_level: Required compliance level
            target_standards: Specific standards to validate against
            
        Returns:
            Comprehensive compliance report
        """
        logger.info(f"Validating compliance for {method.name} on {device.path}")
        
        # Determine target standards if not specified
        if target_standards is None:
            target_standards = self._get_standards_for_compliance_level(compliance_level)
        
        # Log compliance check event
        self._log_audit_event(
            AuditEventType.COMPLIANCE_CHECK,
            device.path,
            method=method,
            compliance_level=compliance_level,
            event_data={
                'target_standards': [std.name for std in target_standards],
                'device_type': device.device_type.name,
                'device_model': device.model,
            }
        )
        
        # Validate against each standard
        validation_results = []
        for standard in target_standards:
            results = self._validate_against_standard(device, method, standard)
            validation_results.extend(results)
        
        # Determine overall status
        overall_status = self._determine_overall_status(validation_results)
        
        # Generate risk assessment
        risk_assessment = self._assess_compliance_risks(device, method, validation_results)
        
        # Generate recommendations
        recommendations = self._generate_compliance_recommendations(validation_results, risk_assessment)
        
        # Create compliance report
        report = ComplianceReport(
            report_id="",  # Will be auto-generated
            generated_at=datetime.now(timezone.utc),
            device_path=device.path,
            device_capabilities=device,
            sanitization_method=method,
            compliance_level=compliance_level,
            target_standards=target_standards,
            validation_results=validation_results,
            overall_status=overall_status,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            audit_trail=self._get_recent_audit_events(device.path),
            metadata={
                'framework_version': '2.1.0',
                'validation_timestamp': datetime.now(timezone.utc).isoformat(),
                'automated': True,
            }
        )
        
        logger.info(f"Compliance validation complete: {overall_status.name}")
        return report
    
    def generate_audit_trail(self, device_path: str, 
                           start_time: Optional[datetime] = None,
                           end_time: Optional[datetime] = None) -> List[AuditEvent]:
        """
        Generate audit trail for a device within a time range.
        
        Args:
            device_path: Device path to filter events
            start_time: Start of time range (default: beginning of log)
            end_time: End of time range (default: now)
            
        Returns:
            List of audit events
        """
        events = []
        
        if not self.audit_log_path.exists():
            return events
        
        try:
            with open(self.audit_log_path, 'r') as f:
                for line in f:
                    try:
                        event_data = json.loads(line.strip())
                        event = AuditEvent(
                            event_id=event_data['event_id'],
                            timestamp=datetime.fromisoformat(event_data['timestamp']),
                            event_type=AuditEventType[event_data['event_type']],
                            device_path=event_data['device_path'],
                            user_id=event_data['user_id'],
                            session_id=event_data['session_id'],
                            method_used=SanitizationMethod[event_data['method_used']] if event_data.get('method_used') else None,
                            compliance_level=ComplianceLevel[event_data['compliance_level']] if event_data.get('compliance_level') else None,
                            event_data=event_data['event_data'],
                            integrity_hash=event_data['integrity_hash']
                        )
                        
                        # Filter by device path
                        if event.device_path != device_path:
                            continue
                        
                        # Filter by time range
                        if start_time and event.timestamp < start_time:
                            continue
                        if end_time and event.timestamp > end_time:
                            continue
                        
                        # Verify integrity
                        if not event.verify_integrity():
                            logger.warning(f"Audit event integrity check failed: {event.event_id}")
                            continue
                        
                        events.append(event)
                        
                    except Exception as e:
                        logger.warning(f"Failed to parse audit event: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Failed to read audit log: {e}")
        
        return sorted(events, key=lambda x: x.timestamp)
    
    def export_compliance_report(self, report: ComplianceReport, 
                               format: str = "json") -> str:
        """
        Export compliance report in specified format.
        
        Args:
            report: Compliance report to export
            format: Export format (json, html, pdf)
            
        Returns:
            Exported report as string
        """
        if format.lower() == "json":
            return self._export_json_report(report)
        elif format.lower() == "html":
            return self._export_html_report(report)
        elif format.lower() == "pdf":
            return self._export_pdf_report(report)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _load_compliance_requirements(self) -> Dict[ComplianceStandard, List[ComplianceRequirement]]:
        """Load compliance requirements database."""
        return {
            ComplianceStandard.NIST_SP_800_88_CLEAR: [
                ComplianceRequirement(
                    standard=ComplianceStandard.NIST_SP_800_88_CLEAR,
                    requirement_id="NIST-88-CLEAR-01",
                    title="Single Overwrite Pattern",
                    description="Apply a single overwrite pass with any pattern",
                    applicable_methods=[SanitizationMethod.OVERWRITE_SINGLE, SanitizationMethod.TRIM_DISCARD],
                    applicable_device_types=[DeviceType.HDD, DeviceType.SSD, DeviceType.NVME],
                    verification_required=True,
                    documentation_required=True,
                    witness_required=False,
                    automated_check=True,
                    severity="MEDIUM"
                ),
                ComplianceRequirement(
                    standard=ComplianceStandard.NIST_SP_800_88_CLEAR,
                    requirement_id="NIST-88-CLEAR-02",
                    title="Logical Data Removal",
                    description="Remove logical access to data through file system operations",
                    applicable_methods=[SanitizationMethod.TRIM_DISCARD],
                    applicable_device_types=[DeviceType.SSD, DeviceType.NVME],
                    verification_required=False,
                    documentation_required=True,
                    witness_required=False,
                    automated_check=True,
                    severity="LOW"
                ),
            ],
            
            ComplianceStandard.NIST_SP_800_88_PURGE: [
                ComplianceRequirement(
                    standard=ComplianceStandard.NIST_SP_800_88_PURGE,
                    requirement_id="NIST-88-PURGE-01",
                    title="Hardware-Based Sanitization",
                    description="Use hardware-based sanitization commands when available",
                    applicable_methods=[SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.NVME_SANITIZE, SanitizationMethod.SECURE_ERASE],
                    applicable_device_types=[DeviceType.SSD, DeviceType.NVME],
                    verification_required=True,
                    documentation_required=True,
                    witness_required=False,
                    automated_check=True,
                    severity="HIGH"
                ),
                ComplianceRequirement(
                    standard=ComplianceStandard.NIST_SP_800_88_PURGE,
                    requirement_id="NIST-88-PURGE-02",
                    title="Cryptographic Erase Validation",
                    description="Validate cryptographic key destruction for encrypted devices",
                    applicable_methods=[SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.HYBRID_CRYPTO],
                    applicable_device_types=[DeviceType.SSD, DeviceType.NVME],
                    verification_required=True,
                    documentation_required=True,
                    witness_required=False,
                    automated_check=True,
                    severity="CRITICAL"
                ),
                ComplianceRequirement(
                    standard=ComplianceStandard.NIST_SP_800_88_PURGE,
                    requirement_id="NIST-88-PURGE-03",
                    title="Multiple Pass Overwrite",
                    description="Apply multiple overwrite passes for traditional magnetic media",
                    applicable_methods=[SanitizationMethod.OVERWRITE_MULTI],
                    applicable_device_types=[DeviceType.HDD],
                    verification_required=True,
                    documentation_required=True,
                    witness_required=False,
                    automated_check=True,
                    severity="HIGH"
                ),
            ],
            
            ComplianceStandard.DOD_5220_22_M: [
                ComplianceRequirement(
                    standard=ComplianceStandard.DOD_5220_22_M,
                    requirement_id="DOD-5220-22-M-01",
                    title="Three-Pass Overwrite Pattern",
                    description="Apply three-pass overwrite with specific patterns (0x00, 0xFF, random)",
                    applicable_methods=[SanitizationMethod.OVERWRITE_MULTI],
                    applicable_device_types=[DeviceType.HDD, DeviceType.SSD],
                    verification_required=True,
                    documentation_required=True,
                    witness_required=True,
                    automated_check=True,
                    severity="HIGH"
                ),
                ComplianceRequirement(
                    standard=ComplianceStandard.DOD_5220_22_M,
                    requirement_id="DOD-5220-22-M-02",
                    title="Verification Sampling",
                    description="Verify sanitization through statistical sampling",
                    applicable_methods=[method for method in SanitizationMethod],
                    applicable_device_types=[device_type for device_type in DeviceType],
                    verification_required=True,
                    documentation_required=True,
                    witness_required=True,
                    automated_check=True,
                    severity="CRITICAL"
                ),
            ],
            
            ComplianceStandard.COMMON_CRITERIA_EAL4: [
                ComplianceRequirement(
                    standard=ComplianceStandard.COMMON_CRITERIA_EAL4,
                    requirement_id="CC-EAL4-01",
                    title="Formal Security Testing",
                    description="Conduct formal security testing of sanitization process",
                    applicable_methods=[method for method in SanitizationMethod],
                    applicable_device_types=[device_type for device_type in DeviceType],
                    verification_required=True,
                    documentation_required=True,
                    witness_required=True,
                    automated_check=False,
                    severity="CRITICAL"
                ),
                ComplianceRequirement(
                    standard=ComplianceStandard.COMMON_CRITERIA_EAL4,
                    requirement_id="CC-EAL4-02",
                    title="Hardware Security Validation",
                    description="Validate hardware security features and proper usage",
                    applicable_methods=[SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.NVME_SANITIZE],
                    applicable_device_types=[DeviceType.SSD, DeviceType.NVME],
                    verification_required=True,
                    documentation_required=True,
                    witness_required=True,
                    automated_check=False,
                    severity="HIGH"
                ),
            ],
        }
    
    def _get_standards_for_compliance_level(self, level: ComplianceLevel) -> List[ComplianceStandard]:
        """Get applicable standards for compliance level."""
        mapping = {
            ComplianceLevel.BASIC: [ComplianceStandard.NIST_SP_800_88_CLEAR],
            ComplianceLevel.STANDARD: [ComplianceStandard.NIST_SP_800_88_CLEAR, ComplianceStandard.NIST_SP_800_88_PURGE],
            ComplianceLevel.ENHANCED: [ComplianceStandard.NIST_SP_800_88_PURGE, ComplianceStandard.COMMON_CRITERIA_EAL4],
            ComplianceLevel.CLASSIFIED: [ComplianceStandard.NIST_SP_800_88_PURGE, ComplianceStandard.DOD_5220_22_M, ComplianceStandard.COMMON_CRITERIA_EAL4],
            ComplianceLevel.TOP_SECRET: [ComplianceStandard.NSA_CSS_POLICY, ComplianceStandard.COMMON_CRITERIA_EAL5, ComplianceStandard.DOD_5220_22_M],
        }
        return mapping.get(level, [ComplianceStandard.NIST_SP_800_88_CLEAR])
    
    def _validate_against_standard(self, device: DeviceCapabilities, 
                                 method: SanitizationMethod,
                                 standard: ComplianceStandard) -> List[ValidationResult]:
        """Validate method against specific standard."""
        requirements = self.requirements_db.get(standard, [])
        results = []
        
        for requirement in requirements:
            # Check if requirement applies to this method and device type
            if (method in requirement.applicable_methods and 
                device.device_type in requirement.applicable_device_types):
                
                result = self._validate_requirement(device, method, requirement)
                results.append(result)
        
        return results
    
    def _validate_requirement(self, device: DeviceCapabilities,
                            method: SanitizationMethod,
                            requirement: ComplianceRequirement) -> ValidationResult:
        """Validate specific compliance requirement."""
        evidence = []
        violations = []
        recommendations = []
        
        # Method-specific validation logic
        if requirement.requirement_id == "NIST-88-CLEAR-01":
            if method in [SanitizationMethod.OVERWRITE_SINGLE, SanitizationMethod.TRIM_DISCARD]:
                status = ValidationStatus.COMPLIANT
                evidence.append(f"Method {method.name} provides single overwrite/clear capability")
            else:
                status = ValidationStatus.NON_COMPLIANT
                violations.append(f"Method {method.name} does not provide required single overwrite")
        
        elif requirement.requirement_id == "NIST-88-PURGE-01":
            if method in [SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.NVME_SANITIZE, SanitizationMethod.SECURE_ERASE]:
                if device.supports_crypto_erase or device.supports_nvme_sanitize or device.supports_secure_erase:
                    status = ValidationStatus.COMPLIANT
                    evidence.append(f"Hardware-based method {method.name} supported by device")
                else:
                    status = ValidationStatus.NON_COMPLIANT
                    violations.append(f"Device does not support hardware-based method {method.name}")
            else:
                status = ValidationStatus.PARTIALLY_COMPLIANT
                violations.append(f"Method {method.name} is not hardware-based")
                recommendations.append("Consider using hardware-based sanitization methods")
        
        elif requirement.requirement_id == "NIST-88-PURGE-02":
            if method in [SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.HYBRID_CRYPTO]:
                if device.is_encrypted:
                    status = ValidationStatus.COMPLIANT
                    evidence.append("Cryptographic erase applicable to encrypted device")
                else:
                    status = ValidationStatus.NON_COMPLIANT
                    violations.append("Cryptographic erase requires encrypted device")
            else:
                status = ValidationStatus.NON_COMPLIANT
                violations.append(f"Method {method.name} does not provide cryptographic erase")
        
        elif requirement.requirement_id == "DOD-5220-22-M-01":
            if method == SanitizationMethod.OVERWRITE_MULTI:
                status = ValidationStatus.COMPLIANT
                evidence.append("Multi-pass overwrite method meets DoD 5220.22-M requirements")
            else:
                status = ValidationStatus.NON_COMPLIANT
                violations.append("DoD 5220.22-M requires three-pass overwrite method")
        
        else:
            # Default validation for other requirements
            if method in requirement.applicable_methods:
                status = ValidationStatus.COMPLIANT
                evidence.append(f"Method {method.name} is approved for {requirement.standard.name}")
            else:
                status = ValidationStatus.NON_COMPLIANT
                violations.append(f"Method {method.name} not approved for {requirement.standard.name}")
        
        return ValidationResult(
            requirement=requirement,
            status=status,
            evidence=evidence,
            violations=violations,
            recommendations=recommendations,
            validated_at=datetime.now(timezone.utc),
            validator_id="automated_validator",
            automated=True
        )
    
    def _determine_overall_status(self, validation_results: List[ValidationResult]) -> ValidationStatus:
        """Determine overall compliance status from individual results."""
        if not validation_results:
            return ValidationStatus.UNKNOWN
        
        statuses = [result.status for result in validation_results]
        
        # Any critical failures result in non-compliance
        critical_failures = [
            result for result in validation_results 
            if result.status == ValidationStatus.NON_COMPLIANT and result.requirement.severity == "CRITICAL"
        ]
        
        if critical_failures:
            return ValidationStatus.NON_COMPLIANT
        
        # Check for any non-compliance
        if ValidationStatus.NON_COMPLIANT in statuses:
            return ValidationStatus.PARTIALLY_COMPLIANT
        
        # Check for partial compliance
        if ValidationStatus.PARTIALLY_COMPLIANT in statuses:
            return ValidationStatus.PARTIALLY_COMPLIANT
        
        # Check for unknown status
        if ValidationStatus.UNKNOWN in statuses:
            return ValidationStatus.REQUIRES_REVIEW
        
        # All compliant
        return ValidationStatus.COMPLIANT
    
    def _assess_compliance_risks(self, device: DeviceCapabilities,
                               method: SanitizationMethod,
                               validation_results: List[ValidationResult]) -> Dict[str, Any]:
        """Assess compliance risks and generate risk score."""
        risks = {
            'overall_risk_score': 0.0,
            'critical_risks': [],
            'high_risks': [],
            'medium_risks': [],
            'low_risks': [],
            'mitigations': [],
        }
        
        # Calculate risk score based on violations
        for result in validation_results:
            if result.status == ValidationStatus.NON_COMPLIANT:
                risk_item = {
                    'requirement': result.requirement.requirement_id,
                    'title': result.requirement.title,
                    'severity': result.requirement.severity,
                    'violations': result.violations,
                }
                
                if result.requirement.severity == "CRITICAL":
                    risks['critical_risks'].append(risk_item)
                    risks['overall_risk_score'] += 25
                elif result.requirement.severity == "HIGH":
                    risks['high_risks'].append(risk_item)
                    risks['overall_risk_score'] += 15
                elif result.requirement.severity == "MEDIUM":
                    risks['medium_risks'].append(risk_item)
                    risks['overall_risk_score'] += 10
                else:
                    risks['low_risks'].append(risk_item)
                    risks['overall_risk_score'] += 5
        
        # Device-specific risks
        if device.device_type == DeviceType.SSD and method == SanitizationMethod.OVERWRITE_SINGLE:
            risks['medium_risks'].append({
                'requirement': 'DEVICE_SPECIFIC',
                'title': 'SSD Overwrite Limitations',
                'severity': 'MEDIUM',
                'violations': ['Single overwrite may not be effective on SSDs due to wear leveling'],
            })
            risks['mitigations'].append('Consider using TRIM/discard or secure erase for SSDs')
        
        # Encryption-specific risks
        if device.is_encrypted and method not in [SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.HYBRID_CRYPTO]:
            risks['high_risks'].append({
                'requirement': 'ENCRYPTION_SPECIFIC',
                'title': 'Encrypted Device Risk',
                'severity': 'HIGH',
                'violations': ['Non-cryptographic methods may leave encrypted data recoverable'],
            })
            risks['mitigations'].append('Use cryptographic erase for encrypted devices')
        
        # Cap risk score at 100
        risks['overall_risk_score'] = min(100.0, risks['overall_risk_score'])
        
        return risks
    
    def _generate_compliance_recommendations(self, validation_results: List[ValidationResult],
                                           risk_assessment: Dict[str, Any]) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        # Collect all recommendations from validation results
        for result in validation_results:
            recommendations.extend(result.recommendations)
        
        # Add risk-based recommendations
        recommendations.extend(risk_assessment.get('mitigations', []))
        
        # Add general recommendations based on risk score
        risk_score = risk_assessment.get('overall_risk_score', 0)
        
        if risk_score > 50:
            recommendations.append("High compliance risk detected - consider alternative sanitization methods")
        
        if risk_assessment.get('critical_risks'):
            recommendations.append("Critical compliance issues must be resolved before proceeding")
        
        # Remove duplicates and return
        return list(set(recommendations))
    
    def _log_audit_event(self, event_type: AuditEventType, device_path: str,
                        method: Optional[SanitizationMethod] = None,
                        compliance_level: Optional[ComplianceLevel] = None,
                        event_data: Optional[Dict[str, Any]] = None,
                        user_id: str = "system"):
        """Log an audit event."""
        event = AuditEvent(
            event_id="",  # Will be auto-generated
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            device_path=device_path,
            user_id=user_id,
            session_id=self.session_id,
            method_used=method,
            compliance_level=compliance_level,
            event_data=event_data or {},
            integrity_hash=""  # Will be auto-calculated
        )
        
        # Write to audit log
        try:
            with open(self.audit_log_path, 'a') as f:
                event_json = {
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type.name,
                    'device_path': event.device_path,
                    'user_id': event.user_id,
                    'session_id': event.session_id,
                    'method_used': event.method_used.name if event.method_used else None,
                    'compliance_level': event.compliance_level.name if event.compliance_level else None,
                    'event_data': event.event_data,
                    'integrity_hash': event.integrity_hash,
                }
                f.write(json.dumps(event_json) + '\n')
        except Exception as e:
            logger.error(f"Failed to write audit event: {e}")
    
    def _get_recent_audit_events(self, device_path: str, limit: int = 10) -> List[AuditEvent]:
        """Get recent audit events for a device."""
        events = self.generate_audit_trail(device_path)
        return events[-limit:] if events else []
    
    def _export_json_report(self, report: ComplianceReport) -> str:
        """Export report as JSON."""
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Object {obj} is not JSON serializable")
        
        report_dict = asdict(report)
        return json.dumps(report_dict, indent=2, default=serialize_datetime)
    
    def _export_html_report(self, report: ComplianceReport) -> str:
        """Export report as HTML."""
        # TODO: Implement HTML report generation
        return "<html><body>HTML report generation not yet implemented</body></html>"
    
    def _export_pdf_report(self, report: ComplianceReport) -> str:
        """Export report as PDF."""
        # TODO: Implement PDF report generation
        return "PDF report generation not yet implemented"

# Global compliance framework instance
_compliance_framework: Optional[ComplianceFramework] = None

def get_compliance_framework() -> ComplianceFramework:
    """Get the global compliance framework instance."""
    global _compliance_framework
    if _compliance_framework is None:
        _compliance_framework = ComplianceFramework()
    return _compliance_framework

def validate_compliance(device: DeviceCapabilities,
                       method: SanitizationMethod,
                       compliance_level: ComplianceLevel) -> ComplianceReport:
    """Convenience function for compliance validation."""
    framework = get_compliance_framework()
    return framework.validate_method_compliance(device, method, compliance_level)

def log_sanitization_event(event_type: str, device_path: str, **kwargs):
    """Convenience function for logging sanitization events."""
    framework = get_compliance_framework()
    event_type_enum = AuditEventType[event_type.upper()]
    framework._log_audit_event(event_type_enum, device_path, **kwargs)

if __name__ == "__main__":
    # Example usage
    from .device_utils import DeviceCapabilities, DeviceType, InterfaceType, EncryptionType
    
    # Mock device for testing
    mock_device = DeviceCapabilities(
        path="/dev/nvme0n1",
        device_type=DeviceType.NVME,
        interface_type=InterfaceType.NVME,
        size_bytes=1024**4,
        sector_size=4096,
        model="Samsung 980 PRO",
        serial="S1234567890",
        firmware_version="1.0",
        max_read_speed_mbps=7000.0,
        max_write_speed_mbps=5000.0,
        random_iops=1000000,
        latency_ms=0.1,
        queue_depth=64,
        supports_crypto_erase=True,
        supports_secure_erase=True,
        supports_enhanced_secure_erase=True,
        supports_nvme_sanitize=True,
        supports_trim=True,
        supports_write_zeroes=True,
        is_encrypted=True,
        encryption_type=EncryptionType.HARDWARE_SED,
        encryption_algorithm="AES-256-XTS",
        secure_erase_time_estimate=2,
        crypto_erase_time_estimate=1,
        overwrite_time_estimate=20,
        platform_specific={}
    )
    
    # Test compliance validation
    framework = ComplianceFramework()
    
    scenarios = [
        (SanitizationMethod.CRYPTO_ERASE, ComplianceLevel.ENHANCED),
        (SanitizationMethod.OVERWRITE_SINGLE, ComplianceLevel.STANDARD),
        (SanitizationMethod.OVERWRITE_MULTI, ComplianceLevel.CLASSIFIED),
    ]
    
    for method, compliance_level in scenarios:
        print(f"\nTesting: {method.name} at {compliance_level.name} level")
        
        report = framework.validate_method_compliance(
            mock_device, method, compliance_level
        )
        
        print(f"Overall Status: {report.overall_status.name}")
        print(f"Risk Score: {report.risk_assessment['overall_risk_score']}")
        print(f"Validation Results: {len(report.validation_results)}")
        
        if report.recommendations:
            print("Recommendations:")
            for rec in report.recommendations[:3]:
                print(f"  - {rec}")
        
        # Export as JSON
        json_report = framework.export_compliance_report(report, "json")
        print(f"JSON Report Length: {len(json_report)} characters")