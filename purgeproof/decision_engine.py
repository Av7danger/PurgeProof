"""
Intelligent decision engine for optimal sanitization method selection.

This module provides sophisticated algorithms to choose the best sanitization approach
based on device capabilities, compliance requirements, time constraints, and security needs.
"""

import math
import time
import logging
from typing import Dict, List, Tuple, Optional, NamedTuple, Union
from dataclasses import dataclass
from enum import Enum, auto
from .device_utils import DeviceCapabilities, DeviceType, EncryptionType, InterfaceType

# Try to import the native Rust engine for method selection
try:
    from . import ffi_bindings  # type: ignore
    NATIVE_ENGINE_AVAILABLE = True
except ImportError:
    NATIVE_ENGINE_AVAILABLE = False

logger = logging.getLogger(__name__)

class ComplianceLevel(Enum):
    """Compliance and security level requirements."""
    BASIC = auto()          # Simple overwrite, consumer use
    STANDARD = auto()       # NIST SP 800-88 Clear
    ENHANCED = auto()       # NIST SP 800-88 Purge  
    CLASSIFIED = auto()     # High security, multiple methods
    TOP_SECRET = auto()     # Maximum security, crypto + multiple passes

class SecurityObjective(Enum):
    """Primary security objective for sanitization."""
    SPEED = auto()          # Minimize time
    SECURITY = auto()       # Maximum security
    COMPLIANCE = auto()     # Meet specific standards
    BALANCED = auto()       # Optimize for speed + security

class SanitizationMethod(Enum):
    """Available sanitization methods."""
    CRYPTO_ERASE = auto()       # Cryptographic key destruction
    NVME_SANITIZE = auto()      # NVMe sanitize command
    SECURE_ERASE = auto()       # ATA/SCSI secure erase
    TRIM_DISCARD = auto()       # TRIM/discard for SSDs
    OVERWRITE_SINGLE = auto()   # Single-pass overwrite
    OVERWRITE_MULTI = auto()    # Multi-pass overwrite (DoD 5220.22-M)
    HYBRID_CRYPTO = auto()      # Crypto erase + verification
    HYBRID_SECURE = auto()      # Secure erase + overwrite
    
    def __str__(self):
        return self.name.replace('_', ' ').title()

@dataclass
class MethodScore:
    """Scoring result for a sanitization method."""
    method: SanitizationMethod
    overall_score: float
    time_score: float
    security_score: float
    compliance_score: float
    compatibility_score: float
    estimated_duration_minutes: float
    security_level: str
    compliance_standards: List[str]
    risk_factors: List[str]
    optimization_notes: List[str]

@dataclass
class SelectionCriteria:
    """Criteria for method selection."""
    compliance_level: ComplianceLevel
    security_objective: SecurityObjective
    max_time_minutes: Optional[float] = None
    min_security_level: Optional[str] = None
    required_standards: Optional[List[str]] = None
    allow_hardware_methods: bool = True
    allow_multi_pass: bool = True
    verify_completion: bool = True
    preserve_data_patterns: bool = False
    target_residual_data: float = 0.001  # Percentage allowable
    
    def __post_init__(self):
        if self.required_standards is None:
            self.required_standards = []

@dataclass
class DeviceContext:
    """Device context for method selection."""
    capabilities: DeviceCapabilities
    current_usage: float = 0.0  # Percentage of device in use
    is_system_drive: bool = False
    contains_sensitive_data: bool = True
    data_classification: str = "unclassified"
    encryption_status: str = "unknown"
    previous_sanitizations: int = 0

class MethodSelectionEngine:
    """Intelligent method selection with performance optimization."""
    
    def __init__(self):
        self.compliance_requirements = self._load_compliance_requirements()
        self.method_characteristics = self._load_method_characteristics()
        self.performance_cache = {}
        
    def select_optimal_method(self, device_context: DeviceContext, 
                            criteria: SelectionCriteria) -> MethodScore:
        """
        Select the optimal sanitization method for given device and criteria.
        
        Args:
            device_context: Device information and context
            criteria: Selection criteria and constraints
            
        Returns:
            Best method with detailed scoring
        """
        if NATIVE_ENGINE_AVAILABLE:
            try:
                return self._select_with_native_engine(device_context, criteria)
            except Exception as e:
                logger.warning(f"Native selection failed, using Python fallback: {e}")
        
        return self._select_with_python_engine(device_context, criteria)
    
    def _select_with_native_engine(self, device_context: DeviceContext, 
                                 criteria: SelectionCriteria) -> MethodScore:
        """Use native Rust engine for method selection."""
        # Convert Python objects to native format
        device_dict = self._device_context_to_dict(device_context)
        criteria_dict = self._criteria_to_dict(criteria)
        
        # Call native selection function
        result = ffi_bindings.select_optimal_method(device_dict, criteria_dict)
        
        # Convert result back to Python format
        return self._result_from_native_format(result)
    
    def _select_with_python_engine(self, device_context: DeviceContext, 
                                 criteria: SelectionCriteria) -> MethodScore:
        """Python implementation of method selection."""
        logger.info(f"Selecting method for {device_context.capabilities.path}")
        
        # Get all applicable methods
        applicable_methods = self._get_applicable_methods(device_context.capabilities)
        
        if not applicable_methods:
            logger.warning("No applicable methods found, falling back to single overwrite")
            applicable_methods = [SanitizationMethod.OVERWRITE_SINGLE]
        
        # Score each method
        method_scores = []
        for method in applicable_methods:
            score = self._score_method(method, device_context, criteria)
            if score:
                method_scores.append(score)
        
        if not method_scores:
            # Emergency fallback
            return self._create_fallback_score(device_context, criteria)
        
        # Select best method
        best_method = max(method_scores, key=lambda x: x.overall_score)
        
        logger.info(f"Selected method: {best_method.method} (score: {best_method.overall_score:.2f})")
        return best_method
    
    def _get_applicable_methods(self, capabilities: DeviceCapabilities) -> List[SanitizationMethod]:
        """Get methods applicable to the device."""
        methods = []
        
        # Crypto erase (NVMe with encryption)
        if capabilities.supports_crypto_erase and capabilities.is_encrypted:
            methods.append(SanitizationMethod.CRYPTO_ERASE)
        
        # NVMe sanitize
        if capabilities.supports_nvme_sanitize:
            methods.append(SanitizationMethod.NVME_SANITIZE)
        
        # Secure erase
        if capabilities.supports_secure_erase:
            methods.append(SanitizationMethod.SECURE_ERASE)
        
        # TRIM/discard for SSDs
        if capabilities.supports_trim:
            methods.append(SanitizationMethod.TRIM_DISCARD)
        
        # Overwrite methods (always available)
        methods.extend([
            SanitizationMethod.OVERWRITE_SINGLE,
            SanitizationMethod.OVERWRITE_MULTI
        ])
        
        # Hybrid methods
        if capabilities.supports_crypto_erase:
            methods.append(SanitizationMethod.HYBRID_CRYPTO)
        if capabilities.supports_secure_erase:
            methods.append(SanitizationMethod.HYBRID_SECURE)
        
        return methods
    
    def _score_method(self, method: SanitizationMethod, device_context: DeviceContext, 
                     criteria: SelectionCriteria) -> Optional[MethodScore]:
        """Score a specific method against criteria."""
        try:
            capabilities = device_context.capabilities
            
            # Get method characteristics
            characteristics = self.method_characteristics.get(method, {})
            
            # Calculate time score
            estimated_time = self._estimate_execution_time(method, capabilities)
            time_score = self._calculate_time_score(estimated_time, criteria.max_time_minutes)
            
            # Calculate security score
            security_score = self._calculate_security_score(method, device_context, criteria)
            
            # Calculate compliance score
            compliance_score = self._calculate_compliance_score(method, criteria)
            
            # Calculate compatibility score
            compatibility_score = self._calculate_compatibility_score(method, capabilities)
            
            # Calculate overall score with weights
            weights = self._get_scoring_weights(criteria.security_objective)
            overall_score = (
                weights['time'] * time_score +
                weights['security'] * security_score +
                weights['compliance'] * compliance_score +
                weights['compatibility'] * compatibility_score
            )
            
            # Get additional metadata
            security_level = characteristics.get('security_level', 'medium')
            compliance_standards = characteristics.get('compliance_standards', [])
            risk_factors = self._identify_risk_factors(method, device_context)
            optimization_notes = self._generate_optimization_notes(method, capabilities)
            
            return MethodScore(
                method=method,
                overall_score=overall_score,
                time_score=time_score,
                security_score=security_score,
                compliance_score=compliance_score,
                compatibility_score=compatibility_score,
                estimated_duration_minutes=estimated_time,
                security_level=security_level,
                compliance_standards=compliance_standards,
                risk_factors=risk_factors,
                optimization_notes=optimization_notes
            )
            
        except Exception as e:
            logger.error(f"Failed to score method {method}: {e}")
            return None
    
    def _estimate_execution_time(self, method: SanitizationMethod, 
                               capabilities: DeviceCapabilities) -> float:
        """Estimate execution time in minutes."""
        size_gb = capabilities.size_bytes / (1024 ** 3)
        
        if method == SanitizationMethod.CRYPTO_ERASE:
            return 0.1  # Nearly instantaneous
        
        elif method == SanitizationMethod.NVME_SANITIZE:
            # Hardware command, typically very fast
            return max(0.5, size_gb / 1000)  # ~2 minutes for 1TB
        
        elif method == SanitizationMethod.SECURE_ERASE:
            # Hardware command, device-dependent
            if capabilities.device_type == DeviceType.NVME:
                return max(1, size_gb / 500)  # ~2 minutes for 1TB
            elif capabilities.device_type == DeviceType.SSD:
                return max(2, size_gb / 200)  # ~5 minutes for 1TB
            else:
                return max(10, size_gb / 20)  # ~50 minutes for 1TB (HDD)
        
        elif method == SanitizationMethod.TRIM_DISCARD:
            # Fast for SSDs
            return max(0.5, size_gb / 1000)
        
        elif method == SanitizationMethod.OVERWRITE_SINGLE:
            # Based on write speed
            write_speed_mbps = capabilities.max_write_speed_mbps
            size_mb = capabilities.size_bytes / (1024 ** 2)
            return max(1, size_mb / write_speed_mbps / 60)
        
        elif method == SanitizationMethod.OVERWRITE_MULTI:
            # Multiple passes (typically 3)
            single_pass_time = self._estimate_execution_time(
                SanitizationMethod.OVERWRITE_SINGLE, capabilities
            )
            return single_pass_time * 3
        
        elif method == SanitizationMethod.HYBRID_CRYPTO:
            # Crypto erase + verification
            return 0.1 + max(0.5, size_gb / 2000)  # Verification time
        
        elif method == SanitizationMethod.HYBRID_SECURE:
            # Secure erase + single overwrite
            secure_time = self._estimate_execution_time(
                SanitizationMethod.SECURE_ERASE, capabilities
            )
            overwrite_time = self._estimate_execution_time(
                SanitizationMethod.OVERWRITE_SINGLE, capabilities
            )
            return secure_time + overwrite_time
        
        else:
            # Default fallback
            return max(5, size_gb / 10)
    
    def _calculate_time_score(self, estimated_time: float, max_time: Optional[float]) -> float:
        """Calculate time efficiency score (0-1)."""
        if max_time is None:
            # No time constraint, score based on absolute speed
            if estimated_time <= 1:
                return 1.0
            elif estimated_time <= 5:
                return 0.9
            elif estimated_time <= 15:
                return 0.7
            elif estimated_time <= 60:
                return 0.5
            else:
                return 0.3
        else:
            # Score based on meeting time constraint
            if estimated_time <= max_time * 0.5:
                return 1.0
            elif estimated_time <= max_time * 0.8:
                return 0.8
            elif estimated_time <= max_time:
                return 0.6
            elif estimated_time <= max_time * 1.5:
                return 0.3
            else:
                return 0.1
    
    def _calculate_security_score(self, method: SanitizationMethod, 
                                device_context: DeviceContext, 
                                criteria: SelectionCriteria) -> float:
        """Calculate security effectiveness score (0-1)."""
        characteristics = self.method_characteristics.get(method, {})
        base_security = characteristics.get('security_rating', 0.5)
        
        # Adjust for device type
        if device_context.capabilities.device_type == DeviceType.SSD:
            if method in [SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.SECURE_ERASE]:
                base_security += 0.2  # More effective on SSDs
            elif method == SanitizationMethod.OVERWRITE_SINGLE:
                base_security -= 0.1  # Less effective on SSDs due to wear leveling
        
        # Adjust for encryption
        if device_context.capabilities.is_encrypted:
            if method == SanitizationMethod.CRYPTO_ERASE:
                base_security += 0.3  # Highly effective for encrypted devices
        
        # Adjust for compliance level
        if criteria.compliance_level == ComplianceLevel.TOP_SECRET:
            if method not in [SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.HYBRID_CRYPTO,
                            SanitizationMethod.OVERWRITE_MULTI]:
                base_security -= 0.3
        
        return min(1.0, max(0.0, base_security))
    
    def _calculate_compliance_score(self, method: SanitizationMethod, 
                                  criteria: SelectionCriteria) -> float:
        """Calculate compliance standards score (0-1)."""
        characteristics = self.method_characteristics.get(method, {})
        method_standards = set(characteristics.get('compliance_standards', []))
        required_standards = set(criteria.required_standards or [])
        
        # Get compliance requirements for level
        level_requirements = self.compliance_requirements.get(criteria.compliance_level, {})
        level_standards = set(level_requirements.get('standards', []))
        
        # Combine required standards
        all_required = required_standards.union(level_standards)
        
        if not all_required:
            return 1.0  # No specific requirements
        
        # Calculate coverage
        coverage = len(method_standards.intersection(all_required)) / len(all_required)
        
        # Bonus for exceeding requirements
        if len(method_standards) > len(all_required):
            coverage += 0.1
        
        return min(1.0, coverage)
    
    def _calculate_compatibility_score(self, method: SanitizationMethod, 
                                     capabilities: DeviceCapabilities) -> float:
        """Calculate device compatibility score (0-1)."""
        # Check basic compatibility
        if method == SanitizationMethod.CRYPTO_ERASE and not capabilities.supports_crypto_erase:
            return 0.0
        if method == SanitizationMethod.NVME_SANITIZE and not capabilities.supports_nvme_sanitize:
            return 0.0
        if method == SanitizationMethod.SECURE_ERASE and not capabilities.supports_secure_erase:
            return 0.0
        if method == SanitizationMethod.TRIM_DISCARD and not capabilities.supports_trim:
            return 0.0
        
        # Base compatibility score
        score = 1.0
        
        # Adjust for device type optimization
        if capabilities.device_type == DeviceType.NVME:
            if method in [SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.NVME_SANITIZE]:
                score += 0.2  # Optimized for NVMe
            elif method == SanitizationMethod.OVERWRITE_SINGLE:
                score -= 0.1  # Not optimal for NVMe
        
        elif capabilities.device_type == DeviceType.SSD:
            if method in [SanitizationMethod.SECURE_ERASE, SanitizationMethod.TRIM_DISCARD]:
                score += 0.1  # Good for SSDs
            elif method == SanitizationMethod.OVERWRITE_MULTI:
                score -= 0.2  # May cause unnecessary wear
        
        elif capabilities.device_type == DeviceType.HDD:
            if method in [SanitizationMethod.OVERWRITE_SINGLE, SanitizationMethod.OVERWRITE_MULTI]:
                score += 0.1  # Traditional methods work well
            elif method == SanitizationMethod.TRIM_DISCARD:
                score = 0.0  # Not applicable
        
        return min(1.0, max(0.0, score))
    
    def _get_scoring_weights(self, objective: SecurityObjective) -> Dict[str, float]:
        """Get scoring weights based on security objective."""
        if objective == SecurityObjective.SPEED:
            return {'time': 0.5, 'security': 0.2, 'compliance': 0.1, 'compatibility': 0.2}
        elif objective == SecurityObjective.SECURITY:
            return {'time': 0.1, 'security': 0.5, 'compliance': 0.3, 'compatibility': 0.1}
        elif objective == SecurityObjective.COMPLIANCE:
            return {'time': 0.1, 'security': 0.3, 'compliance': 0.5, 'compatibility': 0.1}
        else:  # BALANCED
            return {'time': 0.3, 'security': 0.3, 'compliance': 0.2, 'compatibility': 0.2}
    
    def _identify_risk_factors(self, method: SanitizationMethod, 
                             device_context: DeviceContext) -> List[str]:
        """Identify potential risk factors for the method."""
        risks = []
        
        capabilities = device_context.capabilities
        
        # SSD-specific risks
        if capabilities.device_type in [DeviceType.SSD, DeviceType.NVME]:
            if method in [SanitizationMethod.OVERWRITE_SINGLE, SanitizationMethod.OVERWRITE_MULTI]:
                risks.append("Wear leveling may prevent complete overwrite")
                risks.append("Over-provisioned areas may retain data")
        
        # Encryption-related risks
        if capabilities.is_encrypted:
            if method not in [SanitizationMethod.CRYPTO_ERASE, SanitizationMethod.HYBRID_CRYPTO]:
                risks.append("Encryption keys may remain recoverable")
        
        # Time-related risks
        estimated_time = self._estimate_execution_time(method, capabilities)
        if estimated_time > 60:
            risks.append("Long execution time increases interruption risk")
        
        # Hardware dependency risks
        if method in [SanitizationMethod.SECURE_ERASE, SanitizationMethod.NVME_SANITIZE]:
            risks.append("Relies on firmware implementation quality")
            risks.append("May not sanitize bad blocks or spare areas")
        
        # System drive risks
        if device_context.is_system_drive:
            risks.append("System drive sanitization requires special handling")
        
        return risks
    
    def _generate_optimization_notes(self, method: SanitizationMethod, 
                                   capabilities: DeviceCapabilities) -> List[str]:
        """Generate optimization recommendations."""
        notes = []
        
        # Performance optimizations
        if method in [SanitizationMethod.OVERWRITE_SINGLE, SanitizationMethod.OVERWRITE_MULTI]:
            optimal_chunk = self._get_optimal_chunk_size(capabilities)
            notes.append(f"Use {optimal_chunk // 1024} KB chunks for optimal performance")
            
            if capabilities.device_type == DeviceType.NVME:
                notes.append("Consider parallel writes to multiple queues")
            
            if capabilities.max_write_speed_mbps > 1000:
                notes.append("Enable write caching for better throughput")
        
        # Method-specific optimizations
        if method == SanitizationMethod.CRYPTO_ERASE:
            notes.append("Verify key destruction completion")
            notes.append("Consider additional verification for critical data")
        
        if method == SanitizationMethod.SECURE_ERASE:
            notes.append("Check estimated completion time from device")
            notes.append("Monitor for command completion")
        
        if method == SanitizationMethod.NVME_SANITIZE:
            notes.append("Use crypto erase action if device supports it")
            notes.append("Check sanitize capabilities before execution")
        
        # Device-specific optimizations
        if capabilities.device_type == DeviceType.SSD:
            notes.append("Issue TRIM command before sanitization")
            notes.append("Consider manufacturer-specific tools")
        
        return notes
    
    def _get_optimal_chunk_size(self, capabilities: DeviceCapabilities) -> int:
        """Get optimal chunk size for overwrite operations."""
        if capabilities.device_type == DeviceType.NVME:
            return 4 * 1024 * 1024  # 4MB
        elif capabilities.device_type == DeviceType.SSD:
            return 2 * 1024 * 1024  # 2MB
        else:
            return 1024 * 1024  # 1MB
    
    def _load_compliance_requirements(self) -> Dict:
        """Load compliance requirements for different levels."""
        return {
            ComplianceLevel.BASIC: {
                'standards': [],
                'min_passes': 1,
                'verification_required': False,
            },
            ComplianceLevel.STANDARD: {
                'standards': ['NIST SP 800-88 Clear'],
                'min_passes': 1,
                'verification_required': True,
            },
            ComplianceLevel.ENHANCED: {
                'standards': ['NIST SP 800-88 Purge', 'Common Criteria'],
                'min_passes': 1,
                'verification_required': True,
            },
            ComplianceLevel.CLASSIFIED: {
                'standards': ['NIST SP 800-88 Purge', 'DoD 5220.22-M', 'Common Criteria EAL4+'],
                'min_passes': 3,
                'verification_required': True,
            },
            ComplianceLevel.TOP_SECRET: {
                'standards': ['NSA/CSS Policy Manual', 'DoD 5220.22-M', 'Common Criteria EAL5+'],
                'min_passes': 3,
                'verification_required': True,
            },
        }
    
    def _load_method_characteristics(self) -> Dict:
        """Load characteristics for each sanitization method."""
        return {
            SanitizationMethod.CRYPTO_ERASE: {
                'security_rating': 0.95,
                'compliance_standards': ['NIST SP 800-88 Purge', 'Common Criteria'],
                'security_level': 'very_high',
                'reliability': 0.98,
            },
            SanitizationMethod.NVME_SANITIZE: {
                'security_rating': 0.90,
                'compliance_standards': ['NIST SP 800-88 Purge'],
                'security_level': 'high',
                'reliability': 0.95,
            },
            SanitizationMethod.SECURE_ERASE: {
                'security_rating': 0.85,
                'compliance_standards': ['NIST SP 800-88 Purge'],
                'security_level': 'high',
                'reliability': 0.90,
            },
            SanitizationMethod.TRIM_DISCARD: {
                'security_rating': 0.70,
                'compliance_standards': ['NIST SP 800-88 Clear'],
                'security_level': 'medium',
                'reliability': 0.85,
            },
            SanitizationMethod.OVERWRITE_SINGLE: {
                'security_rating': 0.75,
                'compliance_standards': ['NIST SP 800-88 Clear'],
                'security_level': 'medium',
                'reliability': 0.99,
            },
            SanitizationMethod.OVERWRITE_MULTI: {
                'security_rating': 0.90,
                'compliance_standards': ['NIST SP 800-88 Purge', 'DoD 5220.22-M'],
                'security_level': 'high',
                'reliability': 0.99,
            },
            SanitizationMethod.HYBRID_CRYPTO: {
                'security_rating': 0.98,
                'compliance_standards': ['NIST SP 800-88 Purge', 'Common Criteria EAL4+'],
                'security_level': 'very_high',
                'reliability': 0.99,
            },
            SanitizationMethod.HYBRID_SECURE: {
                'security_rating': 0.95,
                'compliance_standards': ['NIST SP 800-88 Purge', 'DoD 5220.22-M'],
                'security_level': 'very_high',
                'reliability': 0.99,
            },
        }
    
    def _create_fallback_score(self, device_context: DeviceContext, 
                             criteria: SelectionCriteria) -> MethodScore:
        """Create a fallback score when no methods are available."""
        logger.warning("Creating fallback score - single overwrite")
        
        estimated_time = self._estimate_execution_time(
            SanitizationMethod.OVERWRITE_SINGLE, device_context.capabilities
        )
        
        return MethodScore(
            method=SanitizationMethod.OVERWRITE_SINGLE,
            overall_score=0.5,
            time_score=0.5,
            security_score=0.7,
            compliance_score=0.3,
            compatibility_score=1.0,
            estimated_duration_minutes=estimated_time,
            security_level='medium',
            compliance_standards=['NIST SP 800-88 Clear'],
            risk_factors=['Fallback method - limited security'],
            optimization_notes=['Consider device-specific tools for better security']
        )
    
    def _device_context_to_dict(self, device_context: DeviceContext) -> Dict:
        """Convert DeviceContext to dictionary for native engine."""
        return {
            'capabilities': device_context.capabilities.to_dict(),
            'current_usage': device_context.current_usage,
            'is_system_drive': device_context.is_system_drive,
            'contains_sensitive_data': device_context.contains_sensitive_data,
            'data_classification': device_context.data_classification,
            'encryption_status': device_context.encryption_status,
            'previous_sanitizations': device_context.previous_sanitizations,
        }
    
    def _criteria_to_dict(self, criteria: SelectionCriteria) -> Dict:
        """Convert SelectionCriteria to dictionary for native engine."""
        return {
            'compliance_level': criteria.compliance_level.name,
            'security_objective': criteria.security_objective.name,
            'max_time_minutes': criteria.max_time_minutes,
            'min_security_level': criteria.min_security_level,
            'required_standards': criteria.required_standards,
            'allow_hardware_methods': criteria.allow_hardware_methods,
            'allow_multi_pass': criteria.allow_multi_pass,
            'verify_completion': criteria.verify_completion,
            'preserve_data_patterns': criteria.preserve_data_patterns,
            'target_residual_data': criteria.target_residual_data,
        }
    
    def _result_from_native_format(self, result: Dict) -> MethodScore:
        """Convert native engine result to MethodScore."""
        method_map = {name: method for method in SanitizationMethod for name in [method.name]}
        
        return MethodScore(
            method=method_map.get(result.get('method', ''), SanitizationMethod.OVERWRITE_SINGLE),
            overall_score=result.get('overall_score', 0.5),
            time_score=result.get('time_score', 0.5),
            security_score=result.get('security_score', 0.5),
            compliance_score=result.get('compliance_score', 0.5),
            compatibility_score=result.get('compatibility_score', 0.5),
            estimated_duration_minutes=result.get('estimated_duration_minutes', 60.0),
            security_level=result.get('security_level', 'medium'),
            compliance_standards=result.get('compliance_standards', []),
            risk_factors=result.get('risk_factors', []),
            optimization_notes=result.get('optimization_notes', [])
        )

class ComplianceValidator:
    """Validate sanitization methods against compliance requirements."""
    
    def __init__(self):
        self.standards_db = self._load_standards_database()
    
    def validate_method_compliance(self, method: SanitizationMethod, 
                                 required_standards: List[str]) -> Tuple[bool, List[str]]:
        """
        Validate if method meets compliance requirements.
        
        Args:
            method: Sanitization method to validate
            required_standards: List of required compliance standards
            
        Returns:
            (is_compliant, list_of_issues)
        """
        issues = []
        
        for standard in required_standards:
            if not self._check_standard_compliance(method, standard):
                issues.append(f"Method {method} does not meet {standard} requirements")
        
        return len(issues) == 0, issues
    
    def _check_standard_compliance(self, method: SanitizationMethod, standard: str) -> bool:
        """Check if method complies with specific standard."""
        standard_info = self.standards_db.get(standard.upper(), {})
        approved_methods = standard_info.get('approved_methods', [])
        
        return method.name in approved_methods
    
    def _load_standards_database(self) -> Dict:
        """Load compliance standards database."""
        return {
            'NIST SP 800-88 CLEAR': {
                'approved_methods': ['OVERWRITE_SINGLE', 'TRIM_DISCARD'],
                'requirements': ['Single overwrite with any pattern'],
            },
            'NIST SP 800-88 PURGE': {
                'approved_methods': ['CRYPTO_ERASE', 'NVME_SANITIZE', 'SECURE_ERASE', 
                                   'OVERWRITE_MULTI', 'HYBRID_CRYPTO', 'HYBRID_SECURE'],
                'requirements': ['Hardware sanitize commands or multiple overwrites'],
            },
            'DOD 5220.22-M': {
                'approved_methods': ['OVERWRITE_MULTI', 'HYBRID_SECURE'],
                'requirements': ['Three-pass overwrite with specific patterns'],
            },
            'COMMON CRITERIA': {
                'approved_methods': ['CRYPTO_ERASE', 'NVME_SANITIZE', 'HYBRID_CRYPTO'],
                'requirements': ['Hardware-based sanitization with verification'],
            },
        }

# Global decision engine instance
_decision_engine = MethodSelectionEngine()

def select_sanitization_method(device_capabilities: DeviceCapabilities,
                             compliance_level: ComplianceLevel = ComplianceLevel.STANDARD,
                             security_objective: SecurityObjective = SecurityObjective.BALANCED,
                             max_time_minutes: Optional[float] = None) -> MethodScore:
    """
    Convenience function for method selection.
    
    Args:
        device_capabilities: Device to sanitize
        compliance_level: Required compliance level
        security_objective: Primary objective
        max_time_minutes: Maximum time constraint
        
    Returns:
        Optimal method with scoring details
    """
    device_context = DeviceContext(capabilities=device_capabilities)
    criteria = SelectionCriteria(
        compliance_level=compliance_level,
        security_objective=security_objective,
        max_time_minutes=max_time_minutes
    )
    
    return _decision_engine.select_optimal_method(device_context, criteria)

if __name__ == "__main__":
    # Example usage
    from .device_utils import DeviceCapabilities, DeviceType
    
    # Mock device for testing
    mock_device = DeviceCapabilities(
        path="/dev/nvme0n1",
        device_type=DeviceType.NVME,
        interface_type=InterfaceType.NVME,
        size_bytes=1024**4,  # 1TB
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
    
    # Test different scenarios
    scenarios = [
        (ComplianceLevel.BASIC, SecurityObjective.SPEED, 5),
        (ComplianceLevel.ENHANCED, SecurityObjective.SECURITY, None),
        (ComplianceLevel.CLASSIFIED, SecurityObjective.COMPLIANCE, 30),
    ]
    
    for compliance, objective, max_time in scenarios:
        result = select_sanitization_method(
            mock_device, compliance, objective, max_time
        )
        
        print(f"\nScenario: {compliance.name}, {objective.name}, {max_time}min")
        print(f"Selected: {result.method} (score: {result.overall_score:.2f})")
        print(f"Time: {result.estimated_duration_minutes:.1f}min")
        print(f"Security: {result.security_level}")
        print(f"Standards: {', '.join(result.compliance_standards)}")
        if result.risk_factors:
            print(f"Risks: {'; '.join(result.risk_factors)}")