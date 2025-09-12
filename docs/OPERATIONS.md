# PurgeProof Operational Runbook

## Table of Contents

1. [System Overview](#system-overview)
2. [Pre-Deployment Checklist](#pre-deployment-checklist)
3. [Installation and Configuration](#installation-and-configuration)
4. [Daily Operations](#daily-operations)
5. [Monitoring and Alerting](#monitoring-and-alerting)
6. [Maintenance Procedures](#maintenance-procedures)
7. [Troubleshooting](#troubleshooting)
8. [Security Procedures](#security-procedures)
9. [Compliance and Auditing](#compliance-and-auditing)
10. [Emergency Procedures](#emergency-procedures)

## System Overview

### Purpose
PurgeProof is an enterprise-grade data sanitization tool designed to securely wipe storage devices while maintaining compliance with industry standards including NIST SP 800-88 Rev.1, DoD 5220.22-M, and Common Criteria EAL4+.

### Architecture Components
- **Native Rust Engine**: High-performance sanitization core
- **Python Orchestration Layer**: Job management and enterprise features
- **CLI Interface**: Command-line operations
- **GUI Interface**: Graphical user interface for operators
- **Compliance Framework**: Automated compliance validation
- **Verification System**: Statistical sampling verification

### Supported Platforms
- Windows 10/11, Windows Server 2019/2022
- Linux (RHEL 7+, Ubuntu 18.04+, CentOS 7+)
- macOS 10.14+

## Pre-Deployment Checklist

### Hardware Requirements

| Component | Minimum | Recommended | Enterprise |
|-----------|---------|-------------|------------|
| CPU | 2 cores, 2.0 GHz | 4 cores, 3.0 GHz | 8+ cores, 3.5 GHz |
| RAM | 4 GB | 8 GB | 16+ GB |
| Storage | 1 GB free | 5 GB free | 20+ GB free |
| Network | 100 Mbps | 1 Gbps | 10+ Gbps |

### Software Prerequisites
- [ ] Python 3.8+ installed
- [ ] Rust toolchain (if building from source)
- [ ] Administrative/root privileges
- [ ] Antivirus exclusions configured
- [ ] Network access for updates (optional)

### Security Considerations
- [ ] Dedicated sanitization workstation (recommended)
- [ ] Air-gapped environment (for classified operations)
- [ ] Secure storage for compliance reports
- [ ] Audit logging configured
- [ ] Access control policies defined

### Network Configuration
- [ ] Firewall rules configured (if needed)
- [ ] Proxy settings configured (if applicable)
- [ ] Certificate validation configured
- [ ] Time synchronization (NTP) configured

## Installation and Configuration

### Standard Installation

1. **Download and Extract**
   ```bash
   # Download from secure repository
   wget https://releases.purgeproof.org/v2.1.0/purgeproof-2.1.0.tar.gz
   tar -xzf purgeproof-2.1.0.tar.gz
   cd purgeproof-2.1.0
   ```

2. **Run Setup Script**
   ```bash
   # Standard installation
   python setup.py
   
   # Development installation (includes testing tools)
   python setup.py --dev
   ```

3. **Verify Installation**
   ```bash
   # Test CLI interface
   purgeproof --version
   purgeproof list
   
   # Test GUI interface
   purgeproof --gui
   
   # Run system tests
   python -m pytest tests/ -v
   ```

### Enterprise Deployment

1. **Create Service Account**
   ```bash
   # Linux
   sudo useradd -r -s /bin/false purgeproof
   sudo usermod -aG disk purgeproof
   
   # Windows
   # Create dedicated service account with appropriate privileges
   ```

2. **Install as System Service**
   ```bash
   # Linux - systemd service
   sudo cp scripts/purgeproof.service /etc/systemd/system/
   sudo systemctl enable purgeproof
   sudo systemctl start purgeproof
   
   # Windows - Windows Service
   # Use scripts/install-service.ps1
   ```

3. **Configure Logging**
   ```bash
   # Create log directory
   sudo mkdir -p /var/log/purgeproof
   sudo chown purgeproof:purgeproof /var/log/purgeproof
   
   # Configure log rotation
   sudo cp scripts/purgeproof.logrotate /etc/logrotate.d/
   ```

### Configuration Files

#### Main Configuration (`/etc/purgeproof/config.yaml`)
```yaml
# PurgeProof Configuration
system:
  log_level: INFO
  max_concurrent_jobs: 4
  temp_directory: /tmp/purgeproof
  
engine:
  worker_threads: 8
  buffer_size_mb: 64
  enable_hardware_acceleration: true
  
compliance:
  default_level: STANDARD
  audit_retention_days: 2555  # 7 years
  require_dual_approval: false
  
verification:
  default_sampling_rate: 0.1
  confidence_level: 0.95
  enable_cryptographic_verification: true
  
security:
  require_authentication: true
  session_timeout_minutes: 30
  audit_all_operations: true
```

#### Logging Configuration (`/etc/purgeproof/logging.yaml`)
```yaml
version: 1
formatters:
  default:
    format: '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
  audit:
    format: '%(asctime)s - AUDIT - %(message)s'

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: default
  
  file:
    class: logging.handlers.RotatingFileHandler
    filename: /var/log/purgeproof/purgeproof.log
    maxBytes: 10485760  # 10MB
    backupCount: 5
    formatter: default
  
  audit:
    class: logging.handlers.RotatingFileHandler
    filename: /var/log/purgeproof/audit.log
    maxBytes: 10485760
    backupCount: 10
    formatter: audit

loggers:
  purgeproof:
    level: INFO
    handlers: [console, file]
  purgeproof.audit:
    level: INFO
    handlers: [audit]
    propagate: false

root:
  level: WARNING
  handlers: [console]
```

## Daily Operations

### Starting Operations

1. **System Startup Checklist**
   - [ ] Verify system services are running
   - [ ] Check system resource availability
   - [ ] Validate storage device connectivity
   - [ ] Review pending maintenance notifications
   - [ ] Confirm backup systems are operational

2. **Pre-Operation Device Check**
   ```bash
   # Scan for available devices
   purgeproof list
   
   # Verify device access permissions
   purgeproof analyze /dev/sdb --compliance standard
   ```

### Standard Sanitization Workflow

1. **Device Preparation**
   ```bash
   # Identify device for sanitization
   purgeproof list
   
   # Analyze device capabilities and recommendations
   purgeproof analyze /dev/sdb --compliance enhanced
   ```

2. **Execute Sanitization**
   ```bash
   # Standard sanitization with verification
   purgeproof sanitize /dev/sdb \
     --compliance enhanced \
     --objective balanced \
     --verify \
     --compliance-report full
   ```

3. **Verification and Documentation**
   ```bash
   # Generate additional reports if needed
   purgeproof export-report --job-id <job_id> --format pdf
   
   # Archive compliance documentation
   cp compliance_report_*.json /secure/archive/
   ```

### Batch Operations

For multiple devices, use the batch processing capability:

```bash
# Create batch job file
cat > batch_job.json << EOF
{
  "devices": ["/dev/sdb", "/dev/sdc", "/dev/sdd"],
  "compliance_level": "ENHANCED",
  "security_objective": "BALANCED",
  "verify": true,
  "compliance_report": true
}
EOF

# Execute batch operation
purgeproof batch --config batch_job.json
```

### GUI Operations

1. **Launch GUI Interface**
   ```bash
   purgeproof --gui
   ```

2. **Standard GUI Workflow**
   - Select device from the device list
   - Review device information and recommendations
   - Configure sanitization settings
   - Start sanitization operation
   - Monitor progress in real-time
   - Export compliance reports

## Monitoring and Alerting

### System Health Monitoring

1. **Service Status**
   ```bash
   # Check service status
   systemctl status purgeproof
   
   # View recent logs
   journalctl -u purgeproof -f
   
   # Check resource usage
   top -p $(pgrep purgeproof)
   ```

2. **Performance Metrics**
   ```bash
   # Get system statistics
   purgeproof status
   
   # Monitor active operations
   watch -n 5 'purgeproof status'
   ```

### Log Monitoring

Key log files to monitor:
- `/var/log/purgeproof/purgeproof.log` - General operations
- `/var/log/purgeproof/audit.log` - Audit trail
- `/var/log/purgeproof/error.log` - Error messages
- `/var/log/purgeproof/performance.log` - Performance metrics

### Alert Conditions

Set up monitoring alerts for:
- Failed sanitization operations
- Compliance validation failures
- Verification failures
- High error rates
- System resource exhaustion
- Security audit events

### Example Monitoring Script

```bash
#!/bin/bash
# PurgeProof Health Check Script

LOG_FILE="/var/log/purgeproof/health-check.log"
ERROR_THRESHOLD=5
FAILED_JOBS_THRESHOLD=3

# Check service status
if ! systemctl is-active --quiet purgeproof; then
    echo "CRITICAL: PurgeProof service is not running" | tee -a $LOG_FILE
    exit 2
fi

# Check error rate
ERROR_COUNT=$(grep -c "ERROR" /var/log/purgeproof/purgeproof.log | tail -100)
if [ $ERROR_COUNT -gt $ERROR_THRESHOLD ]; then
    echo "WARNING: High error rate detected ($ERROR_COUNT errors)" | tee -a $LOG_FILE
fi

# Check failed jobs
FAILED_JOBS=$(purgeproof status | grep "Failed Jobs" | awk '{print $3}')
if [ $FAILED_JOBS -gt $FAILED_JOBS_THRESHOLD ]; then
    echo "WARNING: Multiple failed jobs detected ($FAILED_JOBS failures)" | tee -a $LOG_FILE
fi

echo "Health check completed at $(date)" >> $LOG_FILE
```

## Maintenance Procedures

### Daily Maintenance

1. **Log Review**
   ```bash
   # Review error logs
   grep "ERROR\|CRITICAL" /var/log/purgeproof/*.log
   
   # Check audit trail
   tail -100 /var/log/purgeproof/audit.log
   ```

2. **System Cleanup**
   ```bash
   # Clean temporary files
   find /tmp/purgeproof -mtime +1 -delete
   
   # Rotate logs if needed
   logrotate /etc/logrotate.d/purgeproof
   ```

### Weekly Maintenance

1. **Performance Review**
   ```bash
   # Generate performance report
   purgeproof report --type performance --period weekly
   
   # Review system resource usage
   sar -u -r -d 1 1
   ```

2. **Security Updates**
   ```bash
   # Check for updates
   purgeproof check-updates
   
   # Update if available (test environment first)
   # purgeproof update --version 2.1.1
   ```

### Monthly Maintenance

1. **Compliance Audit**
   ```bash
   # Generate compliance summary
   purgeproof audit --period monthly
   
   # Review audit trail completeness
   purgeproof verify-audit-trail
   ```

2. **System Optimization**
   ```bash
   # Analyze performance trends
   purgeproof analyze-performance --period monthly
   
   # Optimize configuration if needed
   purgeproof optimize-config
   ```

### Quarterly Maintenance

1. **Full System Review**
   - Review all configuration files
   - Update documentation
   - Test disaster recovery procedures
   - Security assessment
   - Compliance certification review

2. **Version Updates**
   - Plan and test major version updates
   - Update training materials
   - Review and update procedures

## Troubleshooting

### Common Issues and Solutions

#### Issue: Device Not Detected
**Symptoms:** Device doesn't appear in device list
**Solutions:**
1. Check device connections
2. Verify permissions: `ls -la /dev/sd*`
3. Refresh device list: `purgeproof list --refresh`
4. Check system logs: `dmesg | tail -20`

#### Issue: Sanitization Fails to Start
**Symptoms:** Operation fails immediately
**Solutions:**
1. Verify device is not mounted: `umount /dev/sdb*`
2. Check device permissions
3. Ensure sufficient resources available
4. Review error logs for specific error codes

#### Issue: Slow Performance
**Symptoms:** Operations take longer than expected
**Solutions:**
1. Check system resource usage
2. Verify hardware acceleration is enabled
3. Adjust buffer sizes: `purgeproof config --buffer-size 128`
4. Check for competing I/O operations

#### Issue: Verification Failures
**Symptoms:** Sanitization completes but verification fails
**Solutions:**
1. Increase sampling rate
2. Check device integrity
3. Retry with different method
4. Review device error logs

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Set debug level
export PURGEPROOF_LOG_LEVEL=DEBUG

# Run with verbose output
purgeproof sanitize /dev/sdb --verbose

# Check debug logs
tail -f /var/log/purgeproof/debug.log
```

### Performance Debugging

```bash
# Profile system performance
purgeproof profile --device /dev/sdb --duration 60

# Monitor I/O patterns
iostat -x 1 10

# Check memory usage
free -m
top -p $(pgrep purgeproof)
```

## Security Procedures

### Access Control

1. **User Authentication**
   - Implement strong authentication mechanisms
   - Use multi-factor authentication for administrative access
   - Regular password rotation policies
   - Account lockout policies

2. **Role-Based Access Control**
   - Operator: Can perform sanitization operations
   - Supervisor: Can approve sensitive operations
   - Administrator: Full system access
   - Auditor: Read-only access to logs and reports

### Audit Trail Management

1. **Audit Log Security**
   ```bash
   # Secure audit logs
   chmod 640 /var/log/purgeproof/audit.log
   chown purgeproof:audit /var/log/purgeproof/audit.log
   
   # Enable log integrity checking
   purgeproof enable-log-signing
   ```

2. **Audit Review Process**
   - Daily review of security events
   - Weekly comprehensive audit review
   - Monthly audit trail verification
   - Quarterly compliance assessment

### Secure Configuration

1. **Encryption Settings**
   ```yaml
   security:
     encrypt_temporary_files: true
     secure_memory_allocation: true
     clear_memory_on_exit: true
     use_hardware_rng: true
   ```

2. **Network Security**
   - Disable unnecessary network services
   - Use TLS for all network communications
   - Implement certificate pinning
   - Regular security assessments

## Compliance and Auditing

### NIST SP 800-88 Compliance

1. **Documentation Requirements**
   - Maintain device inventory
   - Document sanitization procedures
   - Keep detailed audit trails
   - Generate compliance reports

2. **Verification Requirements**
   - Statistical sampling verification
   - Cryptographic verification where applicable
   - Independent verification for classified data
   - Documentation of verification results

### DoD 5220.22-M Compliance

1. **Multi-Pass Requirements**
   - Three-pass minimum for classified data
   - Verification after each pass
   - Pattern verification
   - Final verification

2. **Documentation**
   - Chain of custody forms
   - Detailed operation logs
   - Verification certificates
   - Destruction certificates

### Common Criteria EAL4+ Compliance

1. **Security Functional Requirements**
   - Cryptographic operation validation
   - Audit trail protection
   - Access control verification
   - Security management

2. **Assurance Requirements**
   - Design documentation
   - Implementation guidance
   - Test documentation
   - Vulnerability assessment

### Audit Procedures

1. **Internal Audits**
   ```bash
   # Generate audit report
   purgeproof audit-report --period quarterly
   
   # Verify compliance status
   purgeproof verify-compliance --standard nist-sp-800-88
   
   # Export audit data
   purgeproof export-audit --format xml
   ```

2. **External Audits**
   - Prepare documentation packages
   - Provide system access for auditors
   - Document audit findings
   - Implement corrective actions

## Emergency Procedures

### System Failure Recovery

1. **Service Recovery**
   ```bash
   # Stop failed service
   systemctl stop purgeproof
   
   # Check logs for errors
   journalctl -u purgeproof --since "1 hour ago"
   
   # Restart service
   systemctl start purgeproof
   
   # Verify recovery
   purgeproof status
   ```

2. **Data Recovery**
   ```bash
   # Restore from backup
   systemctl stop purgeproof
   cp /backup/purgeproof/config/* /etc/purgeproof/
   systemctl start purgeproof
   ```

### Security Incident Response

1. **Immediate Actions**
   - Isolate affected systems
   - Preserve evidence
   - Document incident details
   - Notify security team

2. **Investigation Procedures**
   - Collect system logs
   - Analyze audit trails
   - Interview operators
   - Document findings

3. **Recovery Actions**
   - Implement security patches
   - Update configurations
   - Review access controls
   - Update procedures

### Business Continuity

1. **Backup Systems**
   - Maintain redundant systems
   - Regular backup verification
   - Documented recovery procedures
   - Alternative processing locations

2. **Communication Plans**
   - Stakeholder notification procedures
   - Status update protocols
   - Media response guidelines
   - Customer communication plans

### Contact Information

- **Technical Support**: support@purgeproof.org
- **Security Incidents**: security@purgeproof.org
- **Emergency Hotline**: +1-800-PURGE-911
- **Documentation**: https://docs.purgeproof.org

## Appendices

### A. Error Code Reference
[Detailed error codes and solutions]

### B. Configuration Templates
[Sample configuration files for different environments]

### C. Integration Examples
[Examples for integrating with enterprise systems]

### D. Compliance Checklists
[Detailed checklists for various compliance standards]