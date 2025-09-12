"""
Statistical Sampling Verification System for PurgeProof.

This module provides cryptographic verification through statistical sampling,
ensuring sanitization effectiveness while minimizing verification time.
"""

import os
import time
import random
import hashlib
import logging
import asyncio
from typing import Dict, List, Optional, Tuple, Any, Iterator, NamedTuple
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from datetime import datetime, timezone
import struct
import math
import statistics
from concurrent.futures import ThreadPoolExecutor

from .device_utils import DeviceCapabilities, DeviceType
from .decision_engine import SanitizationMethod
from .compliance import AuditEventType, log_sanitization_event

logger = logging.getLogger(__name__)

class SamplingStrategy(Enum):
    """Sampling strategies for verification."""
    RANDOM_UNIFORM = auto()
    STRATIFIED = auto()
    SYSTEMATIC = auto()
    CLUSTER = auto()
    ADAPTIVE = auto()

class VerificationLevel(Enum):
    """Verification confidence levels."""
    BASIC = auto()      # 95% confidence, 5% error margin
    STANDARD = auto()   # 99% confidence, 1% error margin
    ENHANCED = auto()   # 99.9% confidence, 0.1% error margin
    CRITICAL = auto()   # 99.99% confidence, 0.01% error margin

class PatternType(Enum):
    """Expected patterns after sanitization."""
    ZEROS = auto()
    ONES = auto()
    RANDOM = auto()
    CUSTOM = auto()
    CRYPTO_NULL = auto()
    DOD_PATTERN = auto()

@dataclass
class SampleLocation:
    """Physical location of a sample on the device."""
    offset: int
    size: int
    sector: int
    track: Optional[int] = None
    cylinder: Optional[int] = None
    lba: Optional[int] = None
    
    def __post_init__(self):
        if self.lba is None:
            self.lba = self.offset // 512  # Default sector size

@dataclass
class SampleResult:
    """Result of sampling a specific location."""
    location: SampleLocation
    expected_pattern: PatternType
    actual_data: bytes
    matches_expected: bool
    confidence_score: float
    verification_time: float
    hash_value: str
    
    def __post_init__(self):
        if not self.hash_value:
            self.hash_value = hashlib.sha256(self.actual_data).hexdigest()

@dataclass
class VerificationReport:
    """Comprehensive verification report."""
    device_path: str
    verification_id: str
    started_at: datetime
    completed_at: Optional[datetime]
    sanitization_method: SanitizationMethod
    sampling_strategy: SamplingStrategy
    verification_level: VerificationLevel
    total_samples: int
    samples_taken: int
    samples_passed: int
    samples_failed: int
    overall_success_rate: float
    confidence_interval: Tuple[float, float]
    statistical_significance: float
    sample_results: List[SampleResult]
    performance_metrics: Dict[str, Any]
    violations: List[str]
    recommendations: List[str]
    
    def __post_init__(self):
        if self.completed_at is None:
            self.completed_at = datetime.now(timezone.utc)

class SamplingCalculator:
    """Statistical calculator for sampling parameters."""
    
    @staticmethod
    def calculate_sample_size(device_size_bytes: int,
                            confidence_level: float = 0.99,
                            margin_of_error: float = 0.01,
                            population_proportion: float = 0.5) -> int:
        """
        Calculate required sample size for statistical significance.
        
        Uses the formula: n = (Z²×p×(1-p)) / E²
        Where:
        - Z = Z-score for confidence level
        - p = estimated population proportion
        - E = margin of error
        """
        # Z-scores for common confidence levels
        z_scores = {
            0.90: 1.645,
            0.95: 1.96,
            0.99: 2.576,
            0.999: 3.291,
            0.9999: 3.891
        }
        
        z_score = z_scores.get(confidence_level, 2.576)
        
        # Calculate base sample size
        numerator = (z_score ** 2) * population_proportion * (1 - population_proportion)
        denominator = margin_of_error ** 2
        
        base_sample_size = int(math.ceil(numerator / denominator))
        
        # Adjust for device size - larger devices need more samples
        device_size_gb = device_size_bytes / (1024**3)
        size_multiplier = math.log10(max(device_size_gb, 1)) / 2
        
        adjusted_sample_size = int(base_sample_size * (1 + size_multiplier))
        
        # Ensure minimum and maximum bounds
        min_samples = max(100, int(device_size_gb * 10))  # At least 10 samples per GB
        max_samples = min(100000, int(device_size_bytes / 4096))  # Max 1 sample per 4KB
        
        return max(min_samples, min(adjusted_sample_size, max_samples))
    
    @staticmethod
    def calculate_confidence_interval(sample_rate: float, 
                                    sample_size: int,
                                    confidence_level: float = 0.99) -> Tuple[float, float]:
        """Calculate confidence interval for sample success rate."""
        if sample_size == 0:
            return (0.0, 0.0)
        
        z_scores = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576, 0.999: 3.291}
        z_score = z_scores.get(confidence_level, 2.576)
        
        # Standard error for proportion
        std_error = math.sqrt((sample_rate * (1 - sample_rate)) / sample_size)
        
        # Margin of error
        margin_of_error = z_score * std_error
        
        lower_bound = max(0.0, sample_rate - margin_of_error)
        upper_bound = min(1.0, sample_rate + margin_of_error)
        
        return (lower_bound, upper_bound)

class SamplingEngine:
    """Core sampling verification engine."""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.calculator = SamplingCalculator()
    
    async def verify_sanitization(self,
                                device: DeviceCapabilities,
                                method: SanitizationMethod,
                                verification_level: VerificationLevel = VerificationLevel.STANDARD,
                                sampling_strategy: SamplingStrategy = SamplingStrategy.STRATIFIED,
                                custom_pattern: Optional[bytes] = None) -> VerificationReport:
        """
        Perform comprehensive sampling verification of sanitization.
        
        Args:
            device: Device capabilities and information
            method: Sanitization method that was used
            verification_level: Required verification confidence level
            sampling_strategy: Sampling strategy to use
            custom_pattern: Custom pattern for verification (if applicable)
            
        Returns:
            Comprehensive verification report
        """
        verification_id = f"VER-{int(time.time())}-{os.urandom(4).hex()}"
        started_at = datetime.now(timezone.utc)
        
        logger.info(f"Starting verification {verification_id} for {device.path}")
        
        # Log verification start
        log_sanitization_event(
            "VERIFICATION_START",
            device.path,
            event_data={
                'verification_id': verification_id,
                'method': method.name,
                'verification_level': verification_level.name,
                'sampling_strategy': sampling_strategy.name,
            }
        )
        
        # Calculate sampling parameters
        confidence_level, margin_of_error = self._get_verification_parameters(verification_level)
        
        total_samples = self.calculator.calculate_sample_size(
            device.size_bytes,
            confidence_level,
            margin_of_error
        )
        
        logger.info(f"Calculated {total_samples} samples needed for {confidence_level*100}% confidence")
        
        # Generate sample locations
        sample_locations = self._generate_sample_locations(
            device, total_samples, sampling_strategy
        )
        
        # Determine expected pattern
        expected_pattern = self._determine_expected_pattern(method, custom_pattern)
        
        # Perform sampling verification
        performance_start = time.time()
        sample_results = await self._perform_sampling(
            device, sample_locations, expected_pattern
        )
        performance_time = time.time() - performance_start
        
        # Analyze results
        samples_passed = sum(1 for result in sample_results if result.matches_expected)
        samples_failed = len(sample_results) - samples_passed
        success_rate = samples_passed / len(sample_results) if sample_results else 0.0
        
        # Calculate confidence interval
        confidence_interval = self.calculator.calculate_confidence_interval(
            success_rate, len(sample_results), confidence_level
        )
        
        # Calculate statistical significance
        statistical_significance = self._calculate_statistical_significance(
            samples_passed, len(sample_results), confidence_level
        )
        
        # Generate violations and recommendations
        violations, recommendations = self._analyze_verification_results(
            sample_results, success_rate, confidence_interval, verification_level
        )
        
        # Create verification report
        report = VerificationReport(
            device_path=device.path,
            verification_id=verification_id,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            sanitization_method=method,
            sampling_strategy=sampling_strategy,
            verification_level=verification_level,
            total_samples=total_samples,
            samples_taken=len(sample_results),
            samples_passed=samples_passed,
            samples_failed=samples_failed,
            overall_success_rate=success_rate,
            confidence_interval=confidence_interval,
            statistical_significance=statistical_significance,
            sample_results=sample_results,
            performance_metrics={
                'total_time_seconds': performance_time,
                'samples_per_second': len(sample_results) / performance_time if performance_time > 0 else 0,
                'average_sample_time': performance_time / len(sample_results) if sample_results else 0,
                'data_read_mb': sum(result.location.size for result in sample_results) / (1024*1024),
            },
            violations=violations,
            recommendations=recommendations
        )
        
        # Log verification completion
        log_sanitization_event(
            "VERIFICATION_COMPLETE",
            device.path,
            event_data={
                'verification_id': verification_id,
                'success_rate': success_rate,
                'samples_taken': len(sample_results),
                'violations': len(violations),
                'performance_time': performance_time,
            }
        )
        
        logger.info(f"Verification {verification_id} completed: {success_rate*100:.2f}% success rate")
        return report
    
    def _get_verification_parameters(self, level: VerificationLevel) -> Tuple[float, float]:
        """Get confidence level and margin of error for verification level."""
        mapping = {
            VerificationLevel.BASIC: (0.95, 0.05),
            VerificationLevel.STANDARD: (0.99, 0.01),
            VerificationLevel.ENHANCED: (0.999, 0.001),
            VerificationLevel.CRITICAL: (0.9999, 0.0001),
        }
        return mapping.get(level, (0.99, 0.01))
    
    def _generate_sample_locations(self,
                                 device: DeviceCapabilities,
                                 total_samples: int,
                                 strategy: SamplingStrategy) -> List[SampleLocation]:
        """Generate sample locations based on sampling strategy."""
        locations = []
        sample_size = 4096  # Default sample size (4KB)
        
        if strategy == SamplingStrategy.RANDOM_UNIFORM:
            locations = self._generate_random_uniform_samples(
                device.size_bytes, total_samples, sample_size
            )
        
        elif strategy == SamplingStrategy.STRATIFIED:
            locations = self._generate_stratified_samples(
                device.size_bytes, total_samples, sample_size
            )
        
        elif strategy == SamplingStrategy.SYSTEMATIC:
            locations = self._generate_systematic_samples(
                device.size_bytes, total_samples, sample_size
            )
        
        elif strategy == SamplingStrategy.CLUSTER:
            locations = self._generate_cluster_samples(
                device.size_bytes, total_samples, sample_size
            )
        
        elif strategy == SamplingStrategy.ADAPTIVE:
            locations = self._generate_adaptive_samples(
                device, total_samples, sample_size
            )
        
        else:
            # Default to stratified sampling
            locations = self._generate_stratified_samples(
                device.size_bytes, total_samples, sample_size
            )
        
        return locations
    
    def _generate_random_uniform_samples(self,
                                       device_size: int,
                                       count: int,
                                       sample_size: int) -> List[SampleLocation]:
        """Generate uniformly random sample locations."""
        locations = []
        max_offset = device_size - sample_size
        
        for _ in range(count):
            offset = random.randint(0, max_offset)
            # Align to sector boundary
            offset = (offset // 512) * 512
            
            locations.append(SampleLocation(
                offset=offset,
                size=sample_size,
                sector=offset // 512
            ))
        
        return locations
    
    def _generate_stratified_samples(self,
                                   device_size: int,
                                   count: int,
                                   sample_size: int) -> List[SampleLocation]:
        """Generate stratified sample locations."""
        locations = []
        
        # Divide device into strata (regions)
        num_strata = min(count, 100)  # Maximum 100 strata
        stratum_size = device_size // num_strata
        samples_per_stratum = count // num_strata
        remaining_samples = count % num_strata
        
        for stratum in range(num_strata):
            stratum_start = stratum * stratum_size
            stratum_end = min(stratum_start + stratum_size, device_size)
            
            # Calculate samples for this stratum
            stratum_samples = samples_per_stratum
            if stratum < remaining_samples:
                stratum_samples += 1
            
            # Generate random samples within this stratum
            for _ in range(stratum_samples):
                max_offset = stratum_end - sample_size
                if max_offset <= stratum_start:
                    offset = stratum_start
                else:
                    offset = random.randint(stratum_start, max_offset)
                
                # Align to sector boundary
                offset = (offset // 512) * 512
                
                locations.append(SampleLocation(
                    offset=offset,
                    size=sample_size,
                    sector=offset // 512
                ))
        
        return locations
    
    def _generate_systematic_samples(self,
                                   device_size: int,
                                   count: int,
                                   sample_size: int) -> List[SampleLocation]:
        """Generate systematic sample locations."""
        locations = []
        
        # Calculate sampling interval
        interval = device_size // count
        
        # Random starting point within first interval
        start_offset = random.randint(0, interval - 1)
        start_offset = (start_offset // 512) * 512  # Align to sector
        
        for i in range(count):
            offset = start_offset + (i * interval)
            if offset + sample_size > device_size:
                offset = device_size - sample_size
            
            # Align to sector boundary
            offset = (offset // 512) * 512
            
            locations.append(SampleLocation(
                offset=offset,
                size=sample_size,
                sector=offset // 512
            ))
        
        return locations
    
    def _generate_cluster_samples(self,
                                device_size: int,
                                count: int,
                                sample_size: int) -> List[SampleLocation]:
        """Generate cluster sample locations."""
        locations = []
        
        # Create clusters (groups of nearby samples)
        num_clusters = max(1, count // 10)  # ~10 samples per cluster
        samples_per_cluster = count // num_clusters
        
        for cluster in range(num_clusters):
            # Random cluster center
            cluster_center = random.randint(0, device_size - (samples_per_cluster * sample_size))
            cluster_center = (cluster_center // 512) * 512
            
            # Generate samples around cluster center
            for i in range(samples_per_cluster):
                offset = cluster_center + (i * sample_size * 2)
                if offset + sample_size > device_size:
                    offset = device_size - sample_size
                
                # Align to sector boundary
                offset = (offset // 512) * 512
                
                locations.append(SampleLocation(
                    offset=offset,
                    size=sample_size,
                    sector=offset // 512
                ))
        
        return locations
    
    def _generate_adaptive_samples(self,
                                 device: DeviceCapabilities,
                                 count: int,
                                 sample_size: int) -> List[SampleLocation]:
        """Generate adaptive sample locations based on device characteristics."""
        # Start with stratified sampling as base
        locations = self._generate_stratified_samples(
            device.size_bytes, count // 2, sample_size
        )
        
        # Add targeted samples for critical areas
        critical_areas = []
        
        # Beginning of device (boot sectors, partition tables)
        critical_areas.extend(range(0, min(1024*1024, device.size_bytes), 512))
        
        # End of device (backup partition tables)
        end_start = max(0, device.size_bytes - 1024*1024)
        critical_areas.extend(range(end_start, device.size_bytes, 512))
        
        # Add random samples from critical areas
        remaining_count = count - len(locations)
        if critical_areas and remaining_count > 0:
            critical_samples = min(remaining_count, len(critical_areas))
            selected_offsets = random.sample(critical_areas, critical_samples)
            
            for offset in selected_offsets:
                if offset + sample_size <= device.size_bytes:
                    locations.append(SampleLocation(
                        offset=offset,
                        size=sample_size,
                        sector=offset // 512
                    ))
        
        return locations[:count]  # Ensure we don't exceed requested count
    
    def _determine_expected_pattern(self,
                                  method: SanitizationMethod,
                                  custom_pattern: Optional[bytes] = None) -> PatternType:
        """Determine expected pattern based on sanitization method."""
        if custom_pattern:
            return PatternType.CUSTOM
        
        mapping = {
            SanitizationMethod.OVERWRITE_SINGLE: PatternType.ZEROS,
            SanitizationMethod.OVERWRITE_MULTI: PatternType.DOD_PATTERN,
            SanitizationMethod.CRYPTO_ERASE: PatternType.CRYPTO_NULL,
            SanitizationMethod.SECURE_ERASE: PatternType.ZEROS,
            SanitizationMethod.NVME_SANITIZE: PatternType.ZEROS,
            SanitizationMethod.TRIM_DISCARD: PatternType.ZEROS,
            SanitizationMethod.HYBRID_CRYPTO: PatternType.CRYPTO_NULL,
        }
        
        return mapping.get(method, PatternType.ZEROS)
    
    async def _perform_sampling(self,
                              device: DeviceCapabilities,
                              sample_locations: List[SampleLocation],
                              expected_pattern: PatternType) -> List[SampleResult]:
        """Perform actual sampling verification."""
        results = []
        
        # Use thread pool for I/O operations
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            tasks = []
            
            for location in sample_locations:
                task = asyncio.get_event_loop().run_in_executor(
                    executor,
                    self._sample_location,
                    device.path,
                    location,
                    expected_pattern
                )
                tasks.append(task)
            
            # Wait for all sampling operations to complete
            sample_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and collect valid results
            for result in sample_results:
                if isinstance(result, SampleResult):
                    results.append(result)
                elif isinstance(result, Exception):
                    logger.warning(f"Sampling error: {result}")
        
        return results
    
    def _sample_location(self,
                        device_path: str,
                        location: SampleLocation,
                        expected_pattern: PatternType) -> SampleResult:
        """Sample a specific location on the device."""
        start_time = time.time()
        
        try:
            # Read data from device
            with open(device_path, 'rb') as device_file:
                device_file.seek(location.offset)
                actual_data = device_file.read(location.size)
            
            # Check if data matches expected pattern
            matches_expected = self._verify_pattern(actual_data, expected_pattern)
            
            # Calculate confidence score based on pattern match
            confidence_score = self._calculate_confidence_score(actual_data, expected_pattern)
            
            verification_time = time.time() - start_time
            
            return SampleResult(
                location=location,
                expected_pattern=expected_pattern,
                actual_data=actual_data,
                matches_expected=matches_expected,
                confidence_score=confidence_score,
                verification_time=verification_time,
                hash_value=""  # Will be auto-calculated
            )
        
        except Exception as e:
            logger.error(f"Failed to sample location {location.offset}: {e}")
            # Return a failed result
            return SampleResult(
                location=location,
                expected_pattern=expected_pattern,
                actual_data=b"",
                matches_expected=False,
                confidence_score=0.0,
                verification_time=time.time() - start_time,
                hash_value="error"
            )
    
    def _verify_pattern(self, data: bytes, expected_pattern: PatternType) -> bool:
        """Verify if data matches expected pattern."""
        if not data:
            return False
        
        if expected_pattern == PatternType.ZEROS:
            return all(byte == 0 for byte in data)
        
        elif expected_pattern == PatternType.ONES:
            return all(byte == 255 for byte in data)
        
        elif expected_pattern == PatternType.DOD_PATTERN:
            # DoD 5220.22-M uses alternating patterns in final pass
            # We expect the final pass to be random or zeros
            return not self._contains_recognizable_patterns(data)
        
        elif expected_pattern == PatternType.CRYPTO_NULL:
            # After crypto erase, data should appear random or be inaccessible
            return not self._contains_recognizable_patterns(data)
        
        elif expected_pattern == PatternType.RANDOM:
            # Data should appear random (high entropy)
            return self._is_high_entropy(data)
        
        else:
            # Default: check for null bytes
            return all(byte == 0 for byte in data)
    
    def _calculate_confidence_score(self, data: bytes, expected_pattern: PatternType) -> float:
        """Calculate confidence score for pattern match."""
        if not data:
            return 0.0
        
        if expected_pattern == PatternType.ZEROS:
            zero_ratio = sum(1 for byte in data if byte == 0) / len(data)
            return zero_ratio
        
        elif expected_pattern == PatternType.ONES:
            ones_ratio = sum(1 for byte in data if byte == 255) / len(data)
            return ones_ratio
        
        elif expected_pattern in [PatternType.DOD_PATTERN, PatternType.CRYPTO_NULL, PatternType.RANDOM]:
            # For these patterns, higher entropy indicates better sanitization
            entropy = self._calculate_entropy(data)
            return min(1.0, entropy / 8.0)  # Normalize to 0-1 scale
        
        else:
            # Default pattern matching
            return 1.0 if self._verify_pattern(data, expected_pattern) else 0.0
    
    def _contains_recognizable_patterns(self, data: bytes) -> bool:
        """Check if data contains recognizable patterns (indicating poor sanitization)."""
        # Check for runs of identical bytes
        for i in range(len(data) - 16):
            if len(set(data[i:i+16])) == 1:  # 16 consecutive identical bytes
                return True
        
        # Check for simple patterns
        patterns = [
            b'\x00' * 16,  # Null bytes
            b'\xFF' * 16,  # All ones
            b'\xAA' * 16,  # Alternating pattern
            b'\x55' * 16,  # Alternating pattern
        ]
        
        for pattern in patterns:
            if pattern in data:
                return True
        
        return False
    
    def _is_high_entropy(self, data: bytes) -> bool:
        """Check if data has high entropy (appears random)."""
        entropy = self._calculate_entropy(data)
        return entropy > 7.0  # Close to maximum entropy of 8.0
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_statistical_significance(self,
                                          successes: int,
                                          total: int,
                                          confidence_level: float) -> float:
        """Calculate statistical significance of verification results."""
        if total == 0:
            return 0.0
        
        success_rate = successes / total
        
        # Chi-square goodness of fit test
        expected_rate = 1.0  # We expect 100% success
        chi_square = ((successes - total * expected_rate) ** 2) / (total * expected_rate)
        
        # Convert to p-value approximation
        # This is a simplified calculation - in practice, you'd use a proper statistical library
        p_value = math.exp(-chi_square / 2)
        
        # Return significance level (1 - p_value)
        return min(1.0, 1.0 - p_value)
    
    def _analyze_verification_results(self,
                                    sample_results: List[SampleResult],
                                    success_rate: float,
                                    confidence_interval: Tuple[float, float],
                                    verification_level: VerificationLevel) -> Tuple[List[str], List[str]]:
        """Analyze verification results and generate violations/recommendations."""
        violations = []
        recommendations = []
        
        # Check overall success rate
        if success_rate < 0.95:
            violations.append(f"Verification success rate {success_rate*100:.2f}% below 95% threshold")
        
        if success_rate < 0.99 and verification_level in [VerificationLevel.ENHANCED, VerificationLevel.CRITICAL]:
            violations.append(f"Success rate {success_rate*100:.2f}% insufficient for {verification_level.name} level")
        
        # Check confidence interval
        lower_bound, upper_bound = confidence_interval
        if lower_bound < 0.90:
            violations.append(f"Lower confidence bound {lower_bound*100:.2f}% below acceptable threshold")
        
        # Analyze failed samples
        failed_samples = [result for result in sample_results if not result.matches_expected]
        if failed_samples:
            # Check for patterns in failures
            failure_locations = [result.location.offset for result in failed_samples]
            
            if len(set(failure_locations)) < len(failure_locations) * 0.8:
                violations.append("Verification failures show clustering, indicating incomplete sanitization")
            
            # Check confidence scores of failed samples
            low_confidence_failures = [
                result for result in failed_samples if result.confidence_score < 0.5
            ]
            
            if low_confidence_failures:
                violations.append(f"{len(low_confidence_failures)} samples show partial sanitization patterns")
        
        # Generate recommendations
        if violations:
            recommendations.append("Re-run sanitization with more aggressive method")
            recommendations.append("Increase verification sample size for better coverage")
        
        if success_rate > 0.99:
            recommendations.append("Sanitization verification passed with high confidence")
        elif success_rate > 0.95:
            recommendations.append("Sanitization appears successful but consider additional verification")
        else:
            recommendations.append("Sanitization verification failed - investigate device or method issues")
        
        return violations, recommendations

# Convenience functions
def verify_device_sanitization(device: DeviceCapabilities,
                             method: SanitizationMethod,
                             verification_level: VerificationLevel = VerificationLevel.STANDARD) -> VerificationReport:
    """Convenience function for device sanitization verification."""
    engine = SamplingEngine()
    return asyncio.run(engine.verify_sanitization(device, method, verification_level))

def quick_verification(device_path: str,
                      method: SanitizationMethod,
                      sample_count: int = 100) -> bool:
    """Quick verification with limited sampling."""
    # This is a simplified version for basic checks
    try:
        sample_size = 4096
        device_size = Path(device_path).stat().st_size
        
        # Generate random sample locations
        samples_passed = 0
        
        for _ in range(sample_count):
            offset = random.randint(0, device_size - sample_size)
            offset = (offset // 512) * 512  # Align to sector
            
            with open(device_path, 'rb') as f:
                f.seek(offset)
                data = f.read(sample_size)
                
                # Simple check for null bytes
                if all(byte == 0 for byte in data):
                    samples_passed += 1
        
        success_rate = samples_passed / sample_count
        return success_rate > 0.95
        
    except Exception as e:
        logger.error(f"Quick verification failed: {e}")
        return False

if __name__ == "__main__":
    # Example usage and testing
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
    
    # Test sampling calculations
    calculator = SamplingCalculator()
    
    device_sizes = [500 * 1024**3, 1 * 1024**4, 8 * 1024**4]  # 500GB, 1TB, 8TB
    
    for size in device_sizes:
        for level in VerificationLevel:
            confidence, margin = {
                VerificationLevel.BASIC: (0.95, 0.05),
                VerificationLevel.STANDARD: (0.99, 0.01),
                VerificationLevel.ENHANCED: (0.999, 0.001),
                VerificationLevel.CRITICAL: (0.9999, 0.0001),
            }[level]
            
            sample_size = calculator.calculate_sample_size(size, confidence, margin)
            
            print(f"Device: {size/(1024**3):.0f}GB, Level: {level.name}")
            print(f"  Required samples: {sample_size:,}")
            print(f"  Confidence: {confidence*100}%, Margin: {margin*100}%")
            print()
    
    # Test pattern verification
    engine = SamplingEngine()
    
    test_data = [
        (b'\x00' * 1024, PatternType.ZEROS, True),
        (b'\xFF' * 1024, PatternType.ONES, True),
        (b'\x00' * 512 + b'\xFF' * 512, PatternType.ZEROS, False),
        (os.urandom(1024), PatternType.RANDOM, True),
    ]
    
    print("Pattern verification tests:")
    for data, pattern, expected in test_data:
        result = engine._verify_pattern(data, pattern)
        confidence = engine._calculate_confidence_score(data, pattern)
        
        print(f"  Pattern: {pattern.name}, Expected: {expected}, Got: {result}")
        print(f"    Confidence: {confidence:.3f}")
        print(f"    Entropy: {engine._calculate_entropy(data):.3f}")
        print()