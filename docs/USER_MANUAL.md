# PurgeProof Enterprise User Manual

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [User Interface Guide](#user-interface-guide)
4. [Device Management](#device-management)
5. [Sanitization Operations](#sanitization-operations)
6. [Certificate Management](#certificate-management)
7. [Compliance and Reporting](#compliance-and-reporting)
8. [Administrative Functions](#administrative-functions)
9. [Troubleshooting](#troubleshooting)
10. [Best Practices](#best-practices)

## Introduction

PurgeProof Enterprise is a comprehensive data sanitization solution designed to securely erase sensitive information from storage devices in compliance with industry standards including NIST SP 800-88 Rev.1 and DoD 5220.22-M.

### Key Features

- **Multi-Standard Compliance**: Support for NIST, DoD, and custom sanitization standards
- **Certificate Generation**: Automated digital certificates with verification codes
- **Audit Trail**: Comprehensive logging and tamper-evident audit chains
- **Enterprise Integration**: Active Directory, LDAP, and database integration
- **Professional Interface**: Both GUI and CLI interfaces for different use cases
- **Bootable Environment**: Air-gapped sanitization capabilities

### System Requirements

- Windows 10/11 Professional or Enterprise, or Ubuntu 20.04+ LTS
- 4GB RAM minimum (8GB recommended)
- 10GB available disk space
- USB 3.0 ports for device access
- Network connectivity for enterprise features

### Security Notice

PurgeProof Enterprise handles sensitive security operations. Always:

- Verify device identification before sanitization
- Follow organizational policies and procedures
- Maintain proper audit documentation
- Use air-gapped environments for classified data

## Getting Started

### Initial Login

1. **Access the Application**
   - GUI: Click the PurgeProof Enterprise desktop icon
   - CLI: Open terminal and run `purgeproof-cli`
   - Web Interface: Navigate to `https://server:8443`

2. **Authentication**
   - Enter your username and password
   - For LDAP/Active Directory users, use domain credentials
   - First-time users should contact their administrator

3. **Dashboard Overview**
   - View recent activities and system status
   - Check compliance status and pending tasks
   - Access quick actions for common operations

### User Roles and Permissions

#### Administrator
- Full system access and configuration
- User management and role assignment
- System monitoring and maintenance
- Audit log access and reporting

#### Operator
- Device sanitization operations
- Certificate generation and verification
- Limited audit log viewing
- Standard reporting functions

#### Auditor
- Read-only access to audit logs
- Certificate verification
- Compliance report generation
- No operational capabilities

### First-Time Setup

1. **Profile Configuration**
   - Update personal information
   - Set notification preferences
   - Configure default sanitization methods
   - Review security settings

2. **System Orientation**
   - Familiarize with the interface
   - Review available sanitization standards
   - Understand certificate requirements
   - Practice with test devices

## User Interface Guide

### GUI Application

#### Main Dashboard

The main dashboard provides an overview of system status and quick access to primary functions:

**Status Panel**:
- Active sessions and operations
- System health indicators
- Recent activity summary
- Compliance status overview

**Quick Actions**:
- Start new sanitization operation
- Generate certificate for completed operation
- View recent audit events
- Access help and documentation

**Navigation Menu**:
- Devices: Detection and management
- Operations: Sanitization controls
- Certificates: Generation and verification
- Audit: Logging and reporting
- Settings: Configuration and preferences

#### Device Management Interface

**Device Detection**:
- Automatic detection of connected devices
- Manual refresh for new connections
- Device information display
- Safety checks and warnings

**Device Information Panel**:
- Device model and serial number
- Capacity and interface type
- Current status and health
- Previous sanitization history

**Safety Controls**:
- System drive protection
- Confirmation dialogs
- Device verification requirements
- Emergency stop functionality

#### Operations Interface

**Sanitization Configuration**:
- Standard selection (NIST, DoD, Custom)
- Pass configuration and verification
- Progress monitoring and reporting
- Quality assurance checks

**Real-Time Monitoring**:
- Progress bars and status indicators
- Time estimates and performance metrics
- Error detection and handling
- Detailed operation logs

### Command Line Interface

#### Basic Commands

```bash
# List available devices
purgeproof-cli devices list

# Start sanitization operation
purgeproof-cli sanitize /dev/sdb --standard nist_sp_800_88 --operator "John Doe"

# Generate certificate
purgeproof-cli certificates generate /dev/sdb "NIST SP 800-88" --operator "John Doe"

# Verify certificate
purgeproof-cli certificates verify CERT-20241223-001

# View audit logs
purgeproof-cli audit list --since "2024-12-01"
```

#### Advanced Operations

```bash
# Batch sanitization
purgeproof-cli batch process devices.csv --standard dod_5220_22

# Custom sanitization patterns
purgeproof-cli sanitize /dev/sdc --custom-passes 7 --pattern random

# Export compliance report
purgeproof-cli reports generate --type compliance --format pdf --output report.pdf

# System diagnostics
purgeproof-cli system check --full
```

### Web Interface

#### Browser Access

1. **Navigation**: Open web browser and navigate to the PurgeProof server
2. **Security**: Accept security certificate (or install enterprise certificate)
3. **Login**: Enter credentials on the login page
4. **Dashboard**: Access the web-based dashboard

#### Remote Operations

- Monitor sanitization operations remotely
- Generate and download certificates
- View audit logs and reports
- Manage user accounts (administrators only)

## Device Management

### Device Detection

#### Automatic Detection

PurgeProof Enterprise automatically detects connected storage devices:

1. **USB Devices**: Detected upon connection
2. **SATA/PATA**: Detected during system scan
3. **NVMe**: Modern NVMe drives supported
4. **Network Storage**: iSCSI and network-attached devices

#### Manual Detection

```bash
# Force device scan
purgeproof-cli devices scan

# Detect specific device type
purgeproof-cli devices scan --type usb
purgeproof-cli devices scan --type sata
```

#### Device Information

For each detected device, the system displays:

- **Model and Manufacturer**: Device identification
- **Serial Number**: Unique device identifier
- **Capacity**: Total storage capacity
- **Interface**: Connection type (USB 3.0, SATA III, etc.)
- **Health Status**: SMART data and health indicators
- **Previous Operations**: Sanitization history

### Device Safety

#### Protection Mechanisms

**System Drive Protection**:
- Automatic detection of system/boot drives
- Multiple confirmation requirements
- Administrative override capabilities
- Audit logging of all attempts

**Device Verification**:
- Serial number verification
- Capacity confirmation
- Model validation
- User acknowledgment requirements

#### Safety Procedures

1. **Pre-Operation Verification**
   - Confirm device identity
   - Verify device is not system drive
   - Check for important data
   - Document authorization

2. **Operation Monitoring**
   - Real-time progress tracking
   - Error detection and handling
   - Performance monitoring
   - Quality assurance checks

3. **Post-Operation Validation**
   - Verification pass completion
   - Data sampling and verification
   - Certificate generation
   - Audit log entry

## Sanitization Operations

### Sanitization Standards

#### NIST SP 800-88 Rev.1

**Overview**: Federal standard for media sanitization

**Methods**:
- **Clear**: Logical overwrite of data
- **Purge**: Cryptographic erase or enhanced overwrite
- **Destroy**: Physical destruction of media

**Implementation**:
- Single pass cryptographically secure random data
- Verification pass to confirm completion
- Optional additional passes for enhanced security

```bash
# Standard NIST sanitization
purgeproof-cli sanitize /dev/sdb --standard nist_sp_800_88 --method purge
```

#### DoD 5220.22-M

**Overview**: Department of Defense standard

**Method**:
- Pass 1: Write zeros (00000000)
- Pass 2: Write ones (11111111)  
- Pass 3: Write random data
- Verification pass

**Implementation**:
```bash
# DoD standard sanitization
purgeproof-cli sanitize /dev/sdb --standard dod_5220_22
```

#### Custom Standards

**Configurable Options**:
- Number of passes (1-35)
- Data patterns (zeros, ones, random, custom)
- Verification requirements
- Performance optimization

```bash
# Custom 7-pass sanitization
purgeproof-cli sanitize /dev/sdb --custom-passes 7 --pattern random
```

### Operation Workflow

#### Pre-Sanitization

1. **Device Selection**
   - Connect device to system
   - Verify device in application
   - Confirm device identity
   - Check authorization

2. **Method Selection**
   - Choose sanitization standard
   - Configure operation parameters
   - Set operator information
   - Review settings

3. **Safety Verification**
   - Confirm device is not system drive
   - Verify no important data present
   - Document business justification
   - Obtain necessary approvals

#### During Sanitization

**Real-Time Monitoring**:
- Progress percentage and time estimates
- Current pass and operation phase
- Performance metrics (speed, throughput)
- Error detection and recovery

**Quality Controls**:
- Continuous verification of operation
- Temperature and health monitoring
- Power supply stability checks
- Data integrity validation

#### Post-Sanitization

1. **Verification**
   - Automatic verification pass
   - Data sampling and analysis
   - Confirmation of complete erasure
   - Quality assurance validation

2. **Documentation**
   - Automatic audit log entries
   - Operation summary report
   - Certificate generation preparation
   - Compliance documentation

### Batch Operations

#### Multiple Device Processing

```bash
# Create device list file
echo "/dev/sdb,NIST SP 800-88,John Doe" > devices.csv
echo "/dev/sdc,DoD 5220.22-M,John Doe" >> devices.csv

# Process batch
purgeproof-cli batch process devices.csv
```

#### Automated Workflows

```bash
# Schedule batch operation
purgeproof-cli batch schedule devices.csv --start-time "2024-12-24 02:00:00"

# Monitor batch progress
purgeproof-cli batch status BATCH-20241223-001
```

## Certificate Management

### Certificate Generation

#### Automatic Generation

Certificates are automatically generated upon successful sanitization completion:

**Certificate Contents**:
- Device identification (model, serial, capacity)
- Sanitization method and standard used
- Operation timestamp and duration
- Operator identification
- Verification code for authenticity
- Digital signature for integrity

#### Manual Generation

```bash
# Generate certificate for completed operation
purgeproof-cli certificates generate /dev/sdb "NIST SP 800-88" --operator "John Doe"

# Generate certificate with custom details
purgeproof-cli certificates generate /dev/sdb "Custom 7-Pass" \
  --operator "Jane Smith" \
  --notes "High-security classification"
```

### Certificate Formats

#### PDF Certificates

**Professional Format**:
- Company letterhead and branding
- Detailed device and operation information
- QR code for verification
- Digital signature integration
- Print-ready formatting

**Contents**:
- Certificate number and verification code
- Device details (model, serial, capacity)
- Sanitization method and compliance standard
- Operation date, time, and duration
- Operator name and authorization
- Verification hash and digital signature

#### XML Export

```xml
<?xml version="1.0" encoding="UTF-8"?>
<SanitizationCertificate>
  <CertificateID>CERT-20241223-001</CertificateID>
  <VerificationCode>PVP-AB12-CD34</VerificationCode>
  <Device>
    <Model>Samsung SSD 860</Model>
    <SerialNumber>S3YZNB0K123456</SerialNumber>
    <Capacity>500GB</Capacity>
  </Device>
  <Operation>
    <Standard>NIST SP 800-88 Rev.1</Standard>
    <Method>Purge</Method>
    <StartTime>2024-12-23T10:15:30Z</StartTime>
    <Duration>PT45M</Duration>
    <Operator>John Doe</Operator>
  </Operation>
  <Verification>
    <Hash>sha256:abc123...</Hash>
    <Signature>RSA-2048:def456...</Signature>
  </Verification>
</SanitizationCertificate>
```

#### JSON Export

```json
{
  "certificate_id": "CERT-20241223-001",
  "verification_code": "PVP-AB12-CD34",
  "device": {
    "model": "Samsung SSD 860",
    "serial_number": "S3YZNB0K123456",
    "capacity": "500GB",
    "interface": "SATA III"
  },
  "operation": {
    "standard": "NIST SP 800-88 Rev.1",
    "method": "Purge",
    "start_time": "2024-12-23T10:15:30Z",
    "duration": "PT45M",
    "operator": "John Doe",
    "compliance_validated": true
  },
  "verification": {
    "hash": "sha256:abc123...",
    "signature": "RSA-2048:def456...",
    "timestamp": "2024-12-23T11:00:30Z"
  }
}
```

### Certificate Verification

#### Online Verification

```bash
# Verify certificate by ID
purgeproof-cli certificates verify CERT-20241223-001

# Verify certificate by verification code
purgeproof-cli certificates verify --code PVP-AB12-CD34

# Verify certificate file
purgeproof-cli certificates verify --file certificate.pdf
```

#### Offline Verification

For air-gapped environments:

1. **Export Verification Data**
   ```bash
   purgeproof-cli certificates export-verification-data --output verification.dat
   ```

2. **Verify Using Exported Data**
   ```bash
   purgeproof-cli certificates verify --offline --data verification.dat --cert CERT-20241223-001
   ```

#### Third-Party Verification

**Public Key Distribution**:
- Share public verification key with auditors
- Provide verification instructions
- Distribute verification software tools
- Document verification procedures

## Compliance and Reporting

### Compliance Standards

#### NIST SP 800-88 Rev.1 Compliance

**Requirements Met**:
- Approved sanitization methods
- Verification procedures
- Documentation requirements
- Audit trail maintenance

**Compliance Validation**:
```bash
# Generate NIST compliance report
purgeproof-cli reports compliance --standard nist_sp_800_88 --period "2024-Q4"
```

#### DoD 5220.22-M Compliance

**Requirements Met**:
- Three-pass overwrite method
- Verification pass completion
- Chain of custody documentation
- Security classification handling

#### Industry Standards

**HIPAA Compliance** (Healthcare):
- Patient data protection
- Audit trail requirements
- Access control documentation
- Incident reporting

**SOX Compliance** (Financial):
- Financial data sanitization
- Control documentation
- Audit requirements
- Risk assessments

### Audit Reporting

#### Standard Reports

**Daily Activity Report**:
```bash
purgeproof-cli reports activity --date 2024-12-23 --format pdf
```

**Monthly Compliance Report**:
```bash
purgeproof-cli reports compliance --month 2024-12 --standard all
```

**Annual Audit Report**:
```bash
purgeproof-cli reports audit --year 2024 --detailed
```

#### Custom Reports

**Device-Specific Reports**:
```bash
# Report for specific device
purgeproof-cli reports device --serial S3YZNB0K123456

# Report for device type
purgeproof-cli reports device-type --type "USB Flash Drive"
```

**Operator Reports**:
```bash
# Report for specific operator
purgeproof-cli reports operator --name "John Doe" --period "2024-Q4"

# Performance metrics
purgeproof-cli reports performance --operator "John Doe"
```

### Export Formats

#### PDF Reports

Professional formatted reports with:
- Executive summary
- Detailed activity logs
- Compliance attestations
- Charts and graphs
- Digital signatures

#### Excel/CSV Export

```bash
# Export to Excel
purgeproof-cli reports export --format xlsx --output report.xlsx

# Export to CSV
purgeproof-cli reports export --format csv --output data.csv
```

#### XML/JSON Export

```bash
# Export to XML
purgeproof-cli reports export --format xml --output report.xml

# Export to JSON
purgeproof-cli reports export --format json --output report.json
```

## Administrative Functions

### User Management

#### Creating Users

```bash
# Create new user
purgeproof-admin create-user --name "Jane Smith" --username jsmith --role operator

# Create administrator
purgeproof-admin create-user --name "Admin User" --username admin --role administrator

# LDAP user mapping
purgeproof-admin map-ldap-user --username jsmith --ldap-dn "CN=Jane Smith,CN=Users,DC=company,DC=com"
```

#### Managing Permissions

```bash
# Assign role
purgeproof-admin assign-role --username jsmith --role operator

# Grant specific permission
purgeproof-admin grant-permission --username jsmith --permission "certificate.verify"

# Revoke permission
purgeproof-admin revoke-permission --username jsmith --permission "audit.export"
```

#### User Status Management

```bash
# Disable user account
purgeproof-admin disable-user --username jsmith

# Enable user account
purgeproof-admin enable-user --username jsmith

# Reset user password
purgeproof-admin reset-password --username jsmith
```

### System Configuration

#### General Settings

```bash
# Configure compliance standards
purgeproof-config --compliance nist_sp_800_88,dod_5220_22

# Set audit retention
purgeproof-config --audit-retention-days 2555

# Configure certificate validity
purgeproof-config --certificate-validity-days 365
```

#### Security Settings

```bash
# Enable two-factor authentication
purgeproof-config --enable-2fa

# Configure session timeout
purgeproof-config --session-timeout 3600

# Set password policy
purgeproof-config --password-policy complex
```

#### Integration Configuration

```bash
# Configure LDAP integration
purgeproof-config --ldap-server ldap://dc.company.com
purgeproof-config --ldap-base-dn "DC=company,DC=com"

# Configure SIEM integration
purgeproof-config --siem-server siem.company.com
purgeproof-config --siem-port 514
```

### System Monitoring

#### Health Checks

```bash
# System health overview
purgeproof-admin health-check

# Detailed system diagnostics
purgeproof-admin diagnostics --full

# Performance metrics
purgeproof-admin metrics --period 24h
```

#### Log Management

```bash
# View application logs
purgeproof-admin logs application --lines 100

# View audit logs
purgeproof-admin logs audit --since "2024-12-01"

# Archive old logs
purgeproof-admin logs archive --older-than 90d
```

### Backup and Maintenance

#### Backup Operations

```bash
# Create system backup
purgeproof-admin backup create --output /backup/purgeproof/

# Restore from backup
purgeproof-admin backup restore --file /backup/purgeproof/backup_20241223.tar.gz

# Schedule automatic backups
purgeproof-admin backup schedule --frequency daily --time "02:00"
```

#### System Maintenance

```bash
# Update system
purgeproof-admin update --check

# Apply updates
purgeproof-admin update --apply

# Database maintenance
purgeproof-admin database vacuum
purgeproof-admin database reindex
```

## Troubleshooting

### Common Issues

#### Device Detection Problems

**Symptom**: Devices not appearing in list

**Solutions**:
1. Check USB/SATA connections
2. Run manual device scan
3. Verify device drivers
4. Check permissions and privileges

```bash
# Manual device scan
purgeproof-cli devices scan --force

# Check system device list
lsblk  # Linux
wmic diskdrive list  # Windows
```

#### Operation Failures

**Symptom**: Sanitization operation fails or stops

**Solutions**:
1. Check device health and connectivity
2. Verify adequate power supply
3. Check for disk errors
4. Review operation logs

```bash
# Check device health
purgeproof-cli devices health /dev/sdb

# Review operation logs
purgeproof-cli logs operation --device /dev/sdb
```

#### Certificate Generation Issues

**Symptom**: Certificates cannot be generated

**Solutions**:
1. Verify operation completion
2. Check certificate storage permissions
3. Ensure digital signing keys are available
4. Validate system time synchronization

```bash
# Check certificate storage
ls -la /var/lib/purgeproof/certificates/

# Verify signing keys
purgeproof-admin verify-signing-keys

# Test certificate generation
purgeproof-cli certificates test-generation
```

### Error Codes

#### System Errors

- **ERR-001**: Device not found or disconnected
- **ERR-002**: Insufficient privileges for operation
- **ERR-003**: Device is system drive (protected)
- **ERR-004**: Operation interrupted by user
- **ERR-005**: Hardware failure detected

#### Authentication Errors

- **AUTH-001**: Invalid username or password
- **AUTH-002**: Account disabled or locked
- **AUTH-003**: LDAP server unreachable
- **AUTH-004**: Insufficient permissions for operation
- **AUTH-005**: Session expired

#### Certificate Errors

- **CERT-001**: Digital signing key not found
- **CERT-002**: Certificate storage not accessible
- **CERT-003**: Invalid verification code
- **CERT-004**: Certificate already exists
- **CERT-005**: Certificate verification failed

### Diagnostic Tools

#### System Diagnostics

```bash
# Run full system diagnostics
purgeproof-admin diagnostics --comprehensive

# Test database connectivity
purgeproof-admin test-database

# Verify certificate system
purgeproof-admin test-certificates

# Check LDAP connectivity
purgeproof-admin test-ldap
```

#### Log Analysis

```bash
# Search logs for errors
purgeproof-admin logs search --pattern "ERROR" --since "24h"

# Export logs for support
purgeproof-admin logs export --support-package

# Analyze performance metrics
purgeproof-admin metrics analyze --period "7d"
```

### Getting Support

#### Information to Collect

Before contacting support, collect:

1. **System Information**
   - Operating system and version
   - PurgeProof Enterprise version
   - Hardware specifications
   - Network configuration

2. **Error Details**
   - Exact error messages
   - Steps to reproduce
   - Recent system changes
   - Log excerpts

3. **Support Package**
   ```bash
   purgeproof-admin support-package create
   ```

#### Contact Information

**Enterprise Support**:
- Email: enterprise-support@purgeproof.com
- Portal: https://support.purgeproof.com
- Phone: 1-800-PURGEPROOF

**Emergency Support**:
- Critical Issues: critical@purgeproof.com
- 24/7 Hotline: 1-800-PURGE-911

## Best Practices

### Security Best Practices

#### Access Control

1. **Principle of Least Privilege**
   - Grant minimum necessary permissions
   - Regularly review and audit access
   - Use role-based access control
   - Implement time-limited access for temporary users

2. **Authentication Security**
   - Use strong, unique passwords
   - Enable two-factor authentication
   - Integrate with enterprise identity systems
   - Monitor authentication events

3. **Physical Security**
   - Secure access to sanitization workstations
   - Implement device chain of custody
   - Use air-gapped systems for classified data
   - Control physical access to certificates

#### Operational Security

1. **Device Verification**
   - Always verify device identity before sanitization
   - Document authorization for each operation
   - Use multiple confirmation steps for system drives
   - Maintain chain of custody documentation

2. **Audit Trail Integrity**
   - Protect audit logs from modification
   - Implement tamper-evident logging
   - Regular integrity verification
   - Secure backup of audit data

### Operational Best Practices

#### Pre-Operation Procedures

1. **Device Preparation**
   - Verify device identity and authorization
   - Check for data backup requirements
   - Document business justification
   - Confirm compliance requirements

2. **Environment Preparation**
   - Ensure stable power supply
   - Verify adequate time allocation
   - Prepare certification documentation
   - Set up monitoring and alerts

#### During Operations

1. **Monitoring**
   - Continuously monitor operation progress
   - Watch for error conditions
   - Verify power and connectivity stability
   - Document any anomalies

2. **Quality Assurance**
   - Verify correct sanitization method
   - Monitor verification pass completion
   - Check for hardware errors
   - Validate operation parameters

#### Post-Operation Procedures

1. **Verification**
   - Confirm complete data erasure
   - Validate certificate generation
   - Document operation results
   - Update asset management systems

2. **Documentation**
   - Generate and store certificates
   - Update audit records
   - Archive operation logs
   - Notify stakeholders of completion

### Compliance Best Practices

#### Documentation Management

1. **Certificate Management**
   - Store certificates in secure, tamper-evident storage
   - Implement digital signing for integrity
   - Maintain offline backup copies
   - Provide easy verification methods

2. **Audit Documentation**
   - Maintain complete audit trails
   - Implement proper retention policies
   - Ensure audit log integrity
   - Provide auditor access tools

#### Regulatory Compliance

1. **Standards Adherence**
   - Follow approved sanitization methods
   - Maintain current certification
   - Document compliance procedures
   - Regular compliance assessments

2. **Reporting Requirements**
   - Generate regular compliance reports
   - Maintain incident documentation
   - Provide audit support
   - Track compliance metrics

### Performance Optimization

#### Hardware Optimization

1. **System Configuration**
   - Use dedicated sanitization workstations
   - Implement high-speed storage interfaces
   - Ensure adequate cooling
   - Use quality power supplies

2. **Device Management**
   - Group similar devices for batch processing
   - Schedule operations during off-peak hours
   - Monitor device health indicators
   - Plan for device lifecycle management

#### Process Optimization

1. **Workflow Efficiency**
   - Standardize operational procedures
   - Implement batch processing capabilities
   - Automate routine tasks
   - Train operators thoroughly

2. **Resource Management**
   - Monitor system performance
   - Optimize database operations
   - Implement efficient logging
   - Plan for capacity growth

---

**Document Version**: 1.0  
**Last Updated**: December 23, 2024  
**Next Review**: March 23, 2025  
**Document Owner**: PurgeProof Enterprise Documentation Team