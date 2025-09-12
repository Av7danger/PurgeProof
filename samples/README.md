# Samples Directory Structure

This directory contains placeholder files and examples for the PurgeProof Evidence Pack. Replace placeholder content with actual artifacts generated during testing.

## Directory Structure

```
samples/
├── README.md                           # This file
├── device_info/                        # Device detection and analysis
│   ├── device_list_20250912_143022.json
│   ├── device_capabilities_WD1234567890_20250912_143022.json
│   └── smart_recommendations_WD1234567890_20250912_143022.json
├── certs/                             # Sanitization certificates
│   ├── sanitization_WD1234567890_crypto_erase_20250912_143215.json
│   ├── sanitization_WD1234567890_crypto_erase_20250912_143215.pdf
│   └── purgeproof_public.pem
├── logs/                              # Operation and verification logs
│   ├── sanitization_WD1234567890_crypto_erase_20250912_143215.log
│   └── verification_WD1234567890_crypto_erase_20250912_143301.log
├── screenshots/                       # Visual evidence
│   ├── cli_device_list_20250912_143022.png
│   ├── gui_sanitization_WD1234567890_20250912_143145.png
│   └── certificate_display_WD1234567890_crypto_20250912_143301.png
├── verification/                      # Third-party verification
│   ├── cert_verification_WD1234567890_crypto_erase_20250912_143301.txt
│   ├── hash_verification_WD1234567890_crypto_erase_20250912_143315.txt
│   └── compliance_check_WD1234567890_crypto_erase_20250912_143320.json
├── forensics/                         # Forensic testing results
│   ├── recovery_attempt_WD1234567890_crypto_erase_20250912_143400.md
│   ├── sector_analysis_WD1234567890_crypto_erase_20250912_143430.txt
│   └── tools_output_WD1234567890_crypto_erase_20250912_143445.log
└── audit/                            # Chain of custody and integrity
    ├── operator_log.csv
    ├── chain_of_custody_WD1234567890_20250912_143022.md
    ├── evidence_pack_sha256.txt
    └── evidence_manifest_20250912_150000.json
```

## Placeholder File Contents

### device_info/device_list_20250912_143022.json
```json
{
  "scan_timestamp": "2025-09-12T14:30:22Z",
  "devices": [
    {
      "path": "/dev/sdb",
      "serial": "WD1234567890",
      "model": "WD Blue SSD 1TB",
      "size_bytes": 1000204886016,
      "device_type": "SSD",
      "capabilities": ["secure_erase", "crypto_erase", "trim"],
      "encryption_status": "hardware_encrypted"
    }
  ],
  "total_devices": 1
}
```

### certs/sanitization_WD1234567890_crypto_erase_20250912_143215.json
```json
{
  "certificate_version": "1.0",
  "device_serial": "WD1234567890",
  "method": "crypto_erase",
  "timestamp": "2025-09-12T14:32:15Z",
  "operator": "OPERATOR_001",
  "compliance_level": "enhanced",
  "signature": "PLACEHOLDER_SIGNATURE_HASH",
  "verification": {
    "entropy_score": 7.98,
    "pattern_detection": "none",
    "recovery_attempts": "failed"
  }
}
```

### logs/sanitization_WD1234567890_crypto_erase_20250912_143215.log
```
[2025-09-12T14:30:22Z] INFO: Starting sanitization process
[2025-09-12T14:30:23Z] INFO: Device detected: /dev/sdb (WD1234567890)
[2025-09-12T14:30:24Z] INFO: Method selected: crypto_erase
[2025-09-12T14:32:15Z] INFO: Sanitization completed successfully
[2025-09-12T14:32:16Z] INFO: Certificate generated
```

### verification/cert_verification_WD1234567890_crypto_erase_20250912_143301.txt
```
Certificate Verification Results:
✓ Certificate signature valid
✓ Certificate not expired  
✓ Device identification matches
✓ Method execution verified
✓ Compliance standards met: NIST SP 800-88 Rev.1

Certificate Status: VALID
```

### forensics/recovery_attempt_WD1234567890_crypto_erase_20250912_143400.md
```markdown
# Forensic Recovery Attempt Report

**Device**: WD1234567890
**Method**: crypto_erase
**Test Date**: 2025-09-12T14:34:00Z

## Recovery Results
- **Files Recovered**: 0
- **Readable Content**: None
- **Data Patterns**: Random/None

## Conclusion
Sanitization effective - no data recovery possible
```

### audit/operator_log.csv
```csv
timestamp,operator_id,action,device_serial,method,status,notes
2025-09-12T14:30:22Z,OPERATOR_001,device_scan,WD1234567890,N/A,completed,"Initial detection"
2025-09-12T14:32:15Z,OPERATOR_001,sanitization,WD1234567890,crypto_erase,success,"Sanitization completed"
```

## Usage Instructions

1. **Setup**: Create the directory structure as shown above
2. **Replace Placeholders**: Use actual PurgeProof commands to generate real artifacts
3. **Validate**: Run verification commands to ensure artifact integrity
4. **Archive**: Create compressed evidence pack for submission

## Important Notes

- Replace all placeholder timestamps with actual execution times
- Update device serials with real hardware identifiers  
- Ensure all file paths match the naming convention in EVIDENCE_PACK_TEMPLATE.md
- Validate that artifacts contain actual data, not placeholder content
- Test the complete evidence generation workflow before final submission

## Security Considerations

- Remove any sensitive information before sharing
- Use anonymized device identifiers for public submissions
- Validate that logs don't contain system-specific information
- Ensure screenshots don't reveal confidential data