# PurgeProof API Documentation

## Overview

PurgeProof is an enterprise-grade data sanitization tool featuring a hybrid Rust + Python architecture designed for maximum performance while maintaining NIST SP 800-88 compliance and enterprise auditability.

## Architecture

### Hybrid Design
- **Native Rust Engine**: High-performance core for device operations, cryptographic functions, and low-level sanitization
- **Python Orchestration Layer**: Enterprise features including job management, compliance validation, and user interfaces
- **FFI Bridge**: PyO3-based integration providing seamless interoperability between Rust and Python components

### Core Components
1. **Rust Engine Core** (`engine/`)
2. **Python Orchestration Layer** (`purgeproof/`)
3. **CLI Interface** (`purgeproof/cli.py`)
4. **GUI Interface** (`purgeproof/gui.py`)
5. **Testing Framework** (`tests/`)

## Installation

### Prerequisites
- Python 3.8 or later
- Rust toolchain (cargo, rustc)
- Operating System: Windows 10+, Linux (kernel 4.0+), or macOS 10.14+

### Quick Installation
```bash
# Clone the repository
git clone https://github.com/Av7danger/PurgeProof.git
cd PurgeProof

# Install with pip
pip install -e .

# Or run setup script
python setup.py
```

### Development Installation
```bash
# Install with development dependencies
pip install -e .[dev]

# Build native engine
cd engine
cargo build --release

# Run tests
pytest tests/ -v
```

## Quick Start

### CLI Usage
```bash
# List available devices
purgeproof list

# Analyze a device
purgeproof analyze /dev/sdb

# Sanitize with standard compliance
purgeproof sanitize /dev/sdb --compliance standard --verify

# Launch GUI interface
purgeproof --gui
```

### GUI Usage
```bash
# Launch graphical interface
purgeproof --gui
```

### Python API Usage
```python
import asyncio
from purgeproof import scan_devices, sanitize, ComplianceLevel, SecurityObjective

async def sanitize_device():
    # Scan for devices
    devices = scan_devices()
    
    # Select first device
    device = devices[0]
    
    # Sanitize with compliance
    result = await sanitize(
        device.path,
        compliance_level=ComplianceLevel.STANDARD,
        security_objective=SecurityObjective.SECURITY,
        verify=True
    )
    
    print(f"Sanitization completed: {result.success}")
    print(f"Method used: {result.method}")
    print(f"Duration: {result.duration_minutes:.1f} minutes")

# Run sanitization
asyncio.run(sanitize_device())
```

## API Reference

### Core Functions

#### `scan_devices() -> List[DeviceCapabilities]`
Scans the system for available storage devices.

**Returns:** List of `DeviceCapabilities` objects containing device information.

**Example:**
```python
devices = scan_devices()
for device in devices:
    print(f"Device: {device.path} ({device.model})")
    print(f"Size: {device.size_bytes / (1024**3):.1f} GB")
    print(f"Supports crypto erase: {device.supports_crypto_erase}")
```

#### `sanitize(device_path, compliance_level, security_objective, **kwargs) -> SanitizationResult`
Performs sanitization on a specified device.

**Parameters:**
- `device_path` (str): Path to the device to sanitize
- `compliance_level` (ComplianceLevel): Required compliance level
- `security_objective` (SecurityObjective): Primary security objective
- `method` (SanitizationMethod, optional): Force specific sanitization method
- `verify` (bool, optional): Perform verification after sanitization
- `passes` (int, optional): Number of overwrite passes for multi-pass methods

**Returns:** `SanitizationResult` object with operation details.

#### `get_stats() -> Dict[str, Any]`
Retrieves system statistics and status information.

**Returns:** Dictionary containing job statistics, performance metrics, and system status.

### Data Classes

#### `DeviceCapabilities`
Represents the capabilities and characteristics of a storage device.

**Attributes:**
- `path` (str): Device path
- `model` (str): Device model
- `serial` (str): Serial number
- `size_bytes` (int): Device size in bytes
- `device_type` (DeviceType): Type of device (SSD, HDD, etc.)
- `interface_type` (InterfaceType): Interface type (SATA, NVMe, etc.)
- `supports_crypto_erase` (bool): Crypto erase capability
- `supports_secure_erase` (bool): Secure erase capability
- `supports_nvme_sanitize` (bool): NVMe sanitize capability
- `supports_trim` (bool): TRIM/discard capability
- `is_encrypted` (bool): Device encryption status
- `encryption_type` (EncryptionType): Type of encryption
- `encryption_algorithm` (str): Encryption algorithm
- `sector_size` (int): Sector size in bytes
- `max_read_speed_mbps` (float): Maximum read speed
- `max_write_speed_mbps` (float): Maximum write speed
- `random_iops` (int): Random IOPS performance
- `latency_ms` (float): Average latency
- Various time estimates for different methods

#### `SanitizationResult`
Contains the results of a sanitization operation.

**Attributes:**
- `success` (bool): Operation success status
- `method` (SanitizationMethod): Method used
- `duration_minutes` (float): Operation duration
- `bytes_processed` (int): Total bytes processed
- `verification_result` (VerificationResult): Verification results
- `compliance_report` (ComplianceReport): Compliance validation
- `error_message` (str): Error message if failed

### Enumerations

#### `ComplianceLevel`
Defines compliance requirement levels:
- `BASIC`: Basic sanitization requirements
- `STANDARD`: Standard compliance (NIST SP 800-88 baseline)
- `STANDARD`: Standard compliance verification
- `COMPREHENSIVE`: Comprehensive verification with detailed analysis
- `CLASSIFIED`: Classified data requirements
- `TOP_SECRET`: Top secret data requirements

#### `SecurityObjective`
Defines primary security objectives:
- `SPEED`: Optimize for fastest completion
- `SECURITY`: Optimize for maximum security
- `COMPLIANCE`: Optimize for compliance requirements
- `BALANCED`: Balance between speed, security, and compliance

#### `SanitizationMethod`
Available sanitization methods:
- `CRYPTO_ERASE`: Cryptographic erase (fastest for encrypted devices)
- `SECURE_ERASE`: Hardware secure erase
- `NVME_SANITIZE`: NVMe sanitize command
- `TRIM_DISCARD`: TRIM/discard operations
- `OVERWRITE_SINGLE`: Single-pass overwrite
- `OVERWRITE_MULTI`: Multi-pass overwrite
- `HYBRID_CRYPTO`: Hybrid cryptographic method

## Advanced Usage

### Orchestration Layer

The orchestration layer provides enterprise-grade job management and monitoring capabilities.

```python
from purgeproof import get_orchestrator

orchestrator = get_orchestrator()

# Submit a sanitization job
job_id = orchestrator.submit_sanitization_job(
    device_path="/dev/sdb",
    compliance_level=ComplianceLevel.ENHANCED,
    security_objective=SecurityObjective.SECURITY
)

# Monitor job progress
while True:
    status = orchestrator.get_job_status(job_id)
    print(f"Progress: {status['progress']}% - {status['status']}")
    
    if status['status'] in ['completed', 'failed', 'cancelled']:
        break
    
    time.sleep(1)
```

### Compliance Framework

The compliance framework provides comprehensive validation against industry standards.

```python
from purgeproof.compliance import get_compliance_framework, ComplianceStandard

compliance = get_compliance_framework()

# Validate method compliance
report = compliance.validate_method_compliance(
    device, 
    SanitizationMethod.CRYPTO_ERASE,
    ComplianceLevel.ENHANCED
)

print(f"Compliance Status: {report.overall_status}")
print(f"Standards Met: {len(report.standards_met)}")
print(f"Risk Score: {report.risk_assessment['overall_risk_score']}")

# Export compliance report
json_report = compliance.export_compliance_report(report, "json")
pdf_report = compliance.export_compliance_report(report, "pdf")
```

### Sampling Verification

The sampling verification system provides statistical validation of sanitization effectiveness.

```python
from purgeproof.sampling_verification import SamplingEngine, VerificationLevel

sampling_engine = SamplingEngine()

# Perform verification with different sampling strategies
verification_report = await sampling_engine.verify_sanitization(
    device,
    SanitizationMethod.CRYPTO_ERASE,
    VerificationLevel.ENHANCED
)

print(f"Samples Taken: {verification_report.samples_taken}")
print(f"Success Rate: {verification_report.overall_success_rate * 100:.2f}%")
print(f"Confidence Interval: {verification_report.confidence_interval}")
```

### Decision Engine

The decision engine provides intelligent method selection based on device capabilities and requirements.

```python
from purgeproof.decision_engine import MethodSelectionEngine, SelectionCriteria, DeviceContext

selector = MethodSelectionEngine()

# Create selection criteria
criteria = SelectionCriteria(
    compliance_level=ComplianceLevel.ENHANCED,
    security_objective=SecurityObjective.BALANCED,
    time_constraint_minutes=60,
    risk_tolerance=0.1
)

# Get device context
device_context = DeviceContext(capabilities=device)

# Select optimal method
recommendation = selector.select_optimal_method(device_context, criteria)

print(f"Recommended Method: {recommendation.method}")
print(f"Score: {recommendation.overall_score}/100")
print(f"Estimated Duration: {recommendation.estimated_duration_minutes} minutes")
```

## Error Handling

PurgeProof provides comprehensive error handling with detailed error codes and messages.

```python
from purgeproof.exceptions import (
    PurgeProofError,
    DeviceNotFoundError,
    UnsupportedMethodError,
    ComplianceValidationError,
    VerificationFailedError
)

try:
    result = await sanitize("/dev/nonexistent", ComplianceLevel.STANDARD, SecurityObjective.SPEED)
except DeviceNotFoundError as e:
    print(f"Device not found: {e}")
except UnsupportedMethodError as e:
    print(f"Method not supported: {e}")
except ComplianceValidationError as e:
    print(f"Compliance validation failed: {e}")
except VerificationFailedError as e:
    print(f"Verification failed: {e}")
except PurgeProofError as e:
    print(f"General error: {e}")
```

## Performance Tuning

### Hardware Acceleration

PurgeProof automatically detects and utilizes hardware acceleration features:

- **AES-NI**: Hardware-accelerated cryptographic operations
- **NVMe Controller Plugins**: Device-specific optimizations
- **Parallel Processing**: Multi-threaded operations for large devices

### Configuration Options

```python
from purgeproof import configure_performance

# Configure performance settings
configure_performance(
    worker_threads=8,  # Number of worker threads
    buffer_size_mb=64,  # I/O buffer size
    enable_hardware_acceleration=True,
    compression_level=6  # For encrypted backups
)
```

### Benchmarking

```python
from purgeproof.benchmarks import run_performance_benchmark

# Run comprehensive performance benchmark
results = run_performance_benchmark(device)

print(f"Sequential Read: {results.sequential_read_mbps} MB/s")
print(f"Sequential Write: {results.sequential_write_mbps} MB/s")
print(f"Random Read IOPS: {results.random_read_iops}")
print(f"Random Write IOPS: {results.random_write_iops}")
```

## Security Considerations

### Privileged Access
Many sanitization operations require administrative/root privileges. Ensure PurgeProof is run with appropriate permissions.

### Data Protection
- All intermediate data is secured with AES-256 encryption
- Memory is securely cleared after operations
- Temporary files are encrypted and securely deleted

### Audit Trails
PurgeProof maintains comprehensive audit trails for compliance purposes:

```python
from purgeproof.audit import get_audit_manager

audit_manager = get_audit_manager()

# Retrieve audit trail for a specific operation
audit_trail = audit_manager.get_audit_trail(job_id)

for event in audit_trail.events:
    print(f"[{event.timestamp}] {event.action}: {event.details}")
```

## Troubleshooting

### Common Issues

#### Device Access Permissions
```bash
# Linux: Run with sudo
sudo purgeproof sanitize /dev/sdb

# Windows: Run as Administrator
# Right-click PowerShell and "Run as Administrator"
purgeproof sanitize \\.\PhysicalDrive1
```

#### Native Engine Build Failures
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Update Rust
rustup update

# Clean build
cd engine
cargo clean
cargo build --release
```

#### Memory Issues with Large Devices
```python
# Configure smaller buffer sizes for limited memory systems
configure_performance(buffer_size_mb=16)
```

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Or set environment variable
# export PURGEPROOF_LOG_LEVEL=DEBUG
```

### Performance Monitoring

```python
from purgeproof.monitoring import get_performance_monitor

monitor = get_performance_monitor()

# Monitor real-time performance during operations
with monitor.track_operation("sanitization") as tracker:
    result = await sanitize(device_path, compliance_level, security_objective)
    
    print(f"Peak Memory Usage: {tracker.peak_memory_mb} MB")
    print(f"Average CPU Usage: {tracker.avg_cpu_percent}%")
    print(f"I/O Operations: {tracker.io_operations}")
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and contribution instructions.

## License

PurgeProof is released under the MIT License. See [LICENSE](LICENSE) for details.

## Support

- **Documentation**: [https://purgeproof.readthedocs.io](https://purgeproof.readthedocs.io)
- **Issues**: [https://github.com/your-org/purgeproof/issues](https://github.com/your-org/purgeproof/issues)
- **Security**: For security-related issues, email security@purgeproof.org