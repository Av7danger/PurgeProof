# PurgeProof Enterprise API Documentation

## Overview

The PurgeProof Enterprise API provides programmatic access to data sanitization operations, certificate management, audit logging, and compliance reporting. This RESTful API enables enterprise integration with existing IT infrastructure and automated workflows.

## Authentication

### API Key Authentication

```http
GET /api/v1/devices
Authorization: Bearer <api_key>
Content-Type: application/json
```

### OAuth 2.0 Authentication

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=<client_id>&client_secret=<client_secret>
```

### Session-Based Authentication

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "operator",
  "password": "secure_password"
}
```

## Base URL

- Production: `https://purgeproof.company.com/api/v1`
- Development: `https://dev-purgeproof.company.com/api/v1`

## Common Headers

```http
Authorization: Bearer <token>
Content-Type: application/json
Accept: application/json
X-API-Version: 1.0
```

## Error Handling

### Standard Error Response

```json
{
  "error": {
    "code": "DEVICE_NOT_FOUND",
    "message": "Device with ID 'sdb' not found",
    "details": {
      "device_id": "sdb",
      "timestamp": "2024-12-23T10:15:30Z"
    }
  }
}
```

### HTTP Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict
- `500 Internal Server Error` - Server error

## Device Management

### List Devices

```http
GET /api/v1/devices
```

**Response:**
```json
{
  "devices": [
    {
      "id": "sdb",
      "model": "Samsung SSD 860",
      "serial_number": "S3YZNB0K123456",
      "capacity": 500000000000,
      "interface": "SATA III",
      "status": "available",
      "health": "good",
      "last_sanitized": "2024-12-20T14:30:00Z"
    }
  ],
  "total": 1,
  "timestamp": "2024-12-23T10:15:30Z"
}
```

### Get Device Details

```http
GET /api/v1/devices/{device_id}
```

**Response:**
```json
{
  "device": {
    "id": "sdb",
    "model": "Samsung SSD 860",
    "serial_number": "S3YZNB0K123456",
    "capacity": 500000000000,
    "interface": "SATA III",
    "firmware": "RVT02B6Q",
    "status": "available",
    "health": {
      "status": "good",
      "temperature": 35,
      "power_cycles": 1250,
      "power_on_hours": 8760
    },
    "history": [
      {
        "operation_id": "OP-20241220-001",
        "timestamp": "2024-12-20T14:30:00Z",
        "method": "NIST SP 800-88",
        "operator": "John Doe",
        "success": true
      }
    ]
  }
}
```

### Scan for New Devices

```http
POST /api/v1/devices/scan
```

**Request:**
```json
{
  "force_scan": true,
  "include_system_drives": false
}
```

**Response:**
```json
{
  "scan_id": "SCAN-20241223-001",
  "devices_found": 2,
  "new_devices": [
    {
      "id": "sdc",
      "model": "Sandisk Ultra USB 3.0",
      "serial_number": "4C530000123456789ABC",
      "capacity": 64000000000,
      "interface": "USB 3.0"
    }
  ]
}
```

## Sanitization Operations

### Start Sanitization

```http
POST /api/v1/operations/sanitize
```

**Request:**
```json
{
  "device_id": "sdb",
  "standard": "nist_sp_800_88",
  "method": "purge",
  "operator": "John Doe",
  "compliance_requirements": ["NIST SP 800-88"],
  "options": {
    "verification_required": true,
    "generate_certificate": true,
    "custom_passes": null
  }
}
```

**Response:**
```json
{
  "operation": {
    "id": "OP-20241223-001",
    "device_id": "sdb",
    "status": "running",
    "standard": "nist_sp_800_88",
    "method": "purge",
    "operator": "John Doe",
    "started_at": "2024-12-23T10:15:30Z",
    "estimated_completion": "2024-12-23T11:00:30Z",
    "progress": {
      "current_pass": 1,
      "total_passes": 2,
      "percentage": 15.5,
      "speed_mbps": 125.3
    }
  }
}
```

### Get Operation Status

```http
GET /api/v1/operations/{operation_id}
```

**Response:**
```json
{
  "operation": {
    "id": "OP-20241223-001",
    "device_id": "sdb",
    "status": "completed",
    "standard": "nist_sp_800_88",
    "method": "purge",
    "operator": "John Doe",
    "started_at": "2024-12-23T10:15:30Z",
    "completed_at": "2024-12-23T11:00:30Z",
    "duration": "PT45M",
    "result": {
      "success": true,
      "passes_completed": 2,
      "verification_status": "passed",
      "certificate_id": "CERT-20241223-001"
    }
  }
}
```

### List Operations

```http
GET /api/v1/operations?status=completed&limit=10&offset=0
```

**Response:**
```json
{
  "operations": [
    {
      "id": "OP-20241223-001",
      "device_id": "sdb",
      "status": "completed",
      "operator": "John Doe",
      "started_at": "2024-12-23T10:15:30Z",
      "completed_at": "2024-12-23T11:00:30Z",
      "success": true
    }
  ],
  "pagination": {
    "total": 150,
    "limit": 10,
    "offset": 0,
    "has_more": true
  }
}
```

### Cancel Operation

```http
POST /api/v1/operations/{operation_id}/cancel
```

**Request:**
```json
{
  "reason": "User requested cancellation",
  "force": false
}
```

**Response:**
```json
{
  "operation": {
    "id": "OP-20241223-001",
    "status": "cancelled",
    "cancelled_at": "2024-12-23T10:30:15Z",
    "cancellation_reason": "User requested cancellation"
  }
}
```

## Certificate Management

### Generate Certificate

```http
POST /api/v1/certificates
```

**Request:**
```json
{
  "operation_id": "OP-20241223-001",
  "format": "pdf",
  "include_qr_code": true,
  "digital_signature": true
}
```

**Response:**
```json
{
  "certificate": {
    "id": "CERT-20241223-001",
    "verification_code": "PVP-AB12-CD34",
    "operation_id": "OP-20241223-001",
    "created_at": "2024-12-23T11:05:00Z",
    "format": "pdf",
    "size_bytes": 245760,
    "download_url": "/api/v1/certificates/CERT-20241223-001/download"
  }
}
```

### List Certificates

```http
GET /api/v1/certificates?device_id=sdb&limit=20
```

**Response:**
```json
{
  "certificates": [
    {
      "id": "CERT-20241223-001",
      "verification_code": "PVP-AB12-CD34",
      "device_id": "sdb",
      "operator": "John Doe",
      "created_at": "2024-12-23T11:05:00Z",
      "valid": true
    }
  ],
  "pagination": {
    "total": 5,
    "limit": 20,
    "offset": 0
  }
}
```

### Get Certificate Details

```http
GET /api/v1/certificates/{certificate_id}
```

**Response:**
```json
{
  "certificate": {
    "id": "CERT-20241223-001",
    "verification_code": "PVP-AB12-CD34",
    "operation_id": "OP-20241223-001",
    "device": {
      "id": "sdb",
      "model": "Samsung SSD 860",
      "serial_number": "S3YZNB0K123456",
      "capacity": 500000000000
    },
    "sanitization": {
      "standard": "NIST SP 800-88 Rev.1",
      "method": "Purge",
      "started_at": "2024-12-23T10:15:30Z",
      "completed_at": "2024-12-23T11:00:30Z",
      "operator": "John Doe"
    },
    "verification": {
      "hash": "sha256:abc123def456...",
      "signature": "RSA-2048:789xyz...",
      "valid": true
    },
    "created_at": "2024-12-23T11:05:00Z"
  }
}
```

### Download Certificate

```http
GET /api/v1/certificates/{certificate_id}/download
Accept: application/pdf
```

### Verify Certificate

```http
POST /api/v1/certificates/verify
```

**Request:**
```json
{
  "certificate_id": "CERT-20241223-001",
  "verification_code": "PVP-AB12-CD34"
}
```

**Response:**
```json
{
  "verification": {
    "valid": true,
    "certificate_id": "CERT-20241223-001",
    "issued_at": "2024-12-23T11:05:00Z",
    "device_verified": true,
    "signature_verified": true,
    "compliance_verified": true
  }
}
```

## Audit and Logging

### Get Audit Events

```http
GET /api/v1/audit/events?start_date=2024-12-01&end_date=2024-12-23&event_type=sanitization
```

**Response:**
```json
{
  "events": [
    {
      "id": "AUDIT-20241223-001",
      "timestamp": "2024-12-23T10:15:30Z",
      "event_type": "sanitization_started",
      "operator": "John Doe",
      "device_id": "sdb",
      "details": {
        "operation_id": "OP-20241223-001",
        "standard": "nist_sp_800_88",
        "method": "purge"
      },
      "hash_chain": "sha256:abc123...",
      "previous_hash": "sha256:def456..."
    }
  ],
  "pagination": {
    "total": 1250,
    "limit": 50,
    "offset": 0
  }
}
```

### Create Audit Event

```http
POST /api/v1/audit/events
```

**Request:**
```json
{
  "event_type": "user_action",
  "operator": "John Doe",
  "details": {
    "action": "certificate_downloaded",
    "certificate_id": "CERT-20241223-001",
    "ip_address": "192.168.1.100"
  }
}
```

**Response:**
```json
{
  "event": {
    "id": "AUDIT-20241223-002",
    "timestamp": "2024-12-23T11:10:00Z",
    "event_type": "user_action",
    "operator": "John Doe",
    "hash_chain": "sha256:ghi789..."
  }
}
```

### Verify Audit Integrity

```http
POST /api/v1/audit/verify-integrity
```

**Request:**
```json
{
  "start_date": "2024-12-01",
  "end_date": "2024-12-23"
}
```

**Response:**
```json
{
  "integrity": {
    "valid": true,
    "events_checked": 1250,
    "hash_chain_valid": true,
    "tampering_detected": false,
    "verification_timestamp": "2024-12-23T11:15:00Z"
  }
}
```

## Compliance and Reporting

### Generate Compliance Report

```http
POST /api/v1/reports/compliance
```

**Request:**
```json
{
  "standard": "nist_sp_800_88",
  "start_date": "2024-12-01",
  "end_date": "2024-12-23",
  "format": "pdf",
  "include_certificates": true
}
```

**Response:**
```json
{
  "report": {
    "id": "RPT-20241223-001",
    "type": "compliance",
    "standard": "nist_sp_800_88",
    "period": {
      "start": "2024-12-01",
      "end": "2024-12-23"
    },
    "generated_at": "2024-12-23T11:20:00Z",
    "format": "pdf",
    "size_bytes": 1048576,
    "download_url": "/api/v1/reports/RPT-20241223-001/download"
  }
}
```

### Get Report Status

```http
GET /api/v1/reports/{report_id}
```

**Response:**
```json
{
  "report": {
    "id": "RPT-20241223-001",
    "type": "compliance",
    "status": "completed",
    "progress": 100,
    "generated_at": "2024-12-23T11:20:00Z",
    "expires_at": "2024-12-30T11:20:00Z"
  }
}
```

### Download Report

```http
GET /api/v1/reports/{report_id}/download
Accept: application/pdf
```

## User Management

### List Users

```http
GET /api/v1/users
```

**Response:**
```json
{
  "users": [
    {
      "id": "user_001",
      "username": "jdoe",
      "name": "John Doe",
      "email": "john.doe@company.com",
      "role": "operator",
      "status": "active",
      "last_login": "2024-12-23T09:00:00Z",
      "created_at": "2024-01-15T10:00:00Z"
    }
  ],
  "pagination": {
    "total": 25,
    "limit": 50,
    "offset": 0
  }
}
```

### Create User

```http
POST /api/v1/users
```

**Request:**
```json
{
  "username": "jsmith",
  "name": "Jane Smith",
  "email": "jane.smith@company.com",
  "role": "operator",
  "password": "SecurePassword123!",
  "ldap_dn": "CN=Jane Smith,CN=Users,DC=company,DC=com"
}
```

**Response:**
```json
{
  "user": {
    "id": "user_002",
    "username": "jsmith",
    "name": "Jane Smith",
    "email": "jane.smith@company.com",
    "role": "operator",
    "status": "active",
    "created_at": "2024-12-23T11:25:00Z"
  }
}
```

### Update User

```http
PUT /api/v1/users/{user_id}
```

**Request:**
```json
{
  "name": "Jane A. Smith",
  "email": "jane.a.smith@company.com",
  "role": "administrator"
}
```

### Delete User

```http
DELETE /api/v1/users/{user_id}
```

**Response:**
```json
{
  "message": "User deleted successfully",
  "user_id": "user_002",
  "deleted_at": "2024-12-23T11:30:00Z"
}
```

## System Information

### Get System Status

```http
GET /api/v1/system/status
```

**Response:**
```json
{
  "system": {
    "status": "healthy",
    "version": "2.0.0",
    "uptime": "PT48H15M30S",
    "services": {
      "database": "healthy",
      "certificate_store": "healthy",
      "audit_logger": "healthy",
      "device_manager": "healthy"
    },
    "performance": {
      "cpu_usage": 15.2,
      "memory_usage": 45.8,
      "disk_usage": 25.3,
      "active_operations": 2
    }
  }
}
```

### Get System Health

```http
GET /api/v1/system/health
```

**Response:**
```json
{
  "health": {
    "overall": "healthy",
    "checks": [
      {
        "name": "database_connectivity",
        "status": "pass",
        "response_time_ms": 12
      },
      {
        "name": "certificate_storage",
        "status": "pass",
        "free_space_gb": 850
      },
      {
        "name": "audit_log_integrity",
        "status": "pass",
        "last_verified": "2024-12-23T11:00:00Z"
      }
    ],
    "timestamp": "2024-12-23T11:35:00Z"
  }
}
```

### Get System Metrics

```http
GET /api/v1/system/metrics?period=24h
```

**Response:**
```json
{
  "metrics": {
    "period": "24h",
    "operations": {
      "total": 25,
      "successful": 24,
      "failed": 1,
      "success_rate": 96.0
    },
    "certificates": {
      "generated": 24,
      "verified": 18
    },
    "performance": {
      "avg_operation_time": "PT42M30S",
      "avg_throughput_mbps": 128.5
    },
    "audit": {
      "events_logged": 150,
      "integrity_checks": 4
    }
  }
}
```

## WebSocket API

### Real-Time Operation Updates

```javascript
const ws = new WebSocket('wss://purgeproof.company.com/api/v1/ws/operations');

ws.onopen = function() {
  // Subscribe to operation updates
  ws.send(JSON.stringify({
    action: 'subscribe',
    operation_id: 'OP-20241223-001'
  }));
};

ws.onmessage = function(event) {
  const update = JSON.parse(event.data);
  console.log('Operation update:', update);
};
```

**Update Message Format:**
```json
{
  "type": "operation_update",
  "operation_id": "OP-20241223-001",
  "status": "running",
  "progress": {
    "percentage": 45.2,
    "current_pass": 1,
    "speed_mbps": 125.3,
    "eta": "2024-12-23T10:45:00Z"
  },
  "timestamp": "2024-12-23T10:30:00Z"
}
```

### System Events

```javascript
// Subscribe to system events
ws.send(JSON.stringify({
  action: 'subscribe',
  channel: 'system_events'
}));
```

**Event Message Format:**
```json
{
  "type": "system_event",
  "event": "device_connected",
  "details": {
    "device_id": "sdc",
    "model": "Kingston USB 3.0",
    "capacity": 32000000000
  },
  "timestamp": "2024-12-23T10:35:00Z"
}
```

## Rate Limiting

### API Rate Limits

- **Standard Users**: 100 requests per minute
- **Operators**: 500 requests per minute  
- **Administrators**: 1000 requests per minute

### Rate Limit Headers

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1703340000
```

### Rate Limit Response

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 60 seconds.",
    "retry_after": 60
  }
}
```

## SDK Examples

### Python SDK

```python
import purgeproof_enterprise

# Initialize client
client = purgeproof_enterprise.Client(
    base_url="https://purgeproof.company.com/api/v1",
    api_key="your_api_key"
)

# List devices
devices = client.devices.list()

# Start sanitization
operation = client.operations.sanitize(
    device_id="sdb",
    standard="nist_sp_800_88",
    operator="John Doe"
)

# Monitor progress
while operation.status == "running":
    operation.refresh()
    print(f"Progress: {operation.progress.percentage}%")
    time.sleep(10)

# Generate certificate
if operation.status == "completed":
    certificate = client.certificates.create(
        operation_id=operation.id,
        format="pdf"
    )
    certificate.download("certificate.pdf")
```

### JavaScript SDK

```javascript
const PurgeProof = require('purgeproof-enterprise-sdk');

const client = new PurgeProof({
  baseURL: 'https://purgeproof.company.com/api/v1',
  apiKey: 'your_api_key'
});

// Start sanitization
const operation = await client.operations.sanitize({
  deviceId: 'sdb',
  standard: 'nist_sp_800_88',
  operator: 'John Doe'
});

// Listen for real-time updates
client.subscribe('operation_update', operation.id, (update) => {
  console.log(`Progress: ${update.progress.percentage}%`);
});

// Generate certificate when complete
operation.onComplete(async () => {
  const certificate = await client.certificates.create({
    operationId: operation.id,
    format: 'pdf'
  });
  
  await certificate.download('./certificate.pdf');
});
```

### curl Examples

```bash
# List devices
curl -H "Authorization: Bearer $API_KEY" \
     "https://purgeproof.company.com/api/v1/devices"

# Start sanitization
curl -X POST \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"device_id":"sdb","standard":"nist_sp_800_88","operator":"John Doe"}' \
     "https://purgeproof.company.com/api/v1/operations/sanitize"

# Check operation status
curl -H "Authorization: Bearer $API_KEY" \
     "https://purgeproof.company.com/api/v1/operations/OP-20241223-001"

# Download certificate
curl -H "Authorization: Bearer $API_KEY" \
     -H "Accept: application/pdf" \
     "https://purgeproof.company.com/api/v1/certificates/CERT-20241223-001/download" \
     --output certificate.pdf
```

## API Versioning

### Version Strategy

- API versions are specified in the URL path (`/api/v1/`)
- Current version: `v1`
- Backward compatibility maintained for 2 major versions
- Deprecation notices provided 6 months before removal

### Version Headers

```http
X-API-Version: 1.0
X-Deprecated-Features: none
X-Supported-Versions: 1.0, 1.1
```

---

**API Version**: 1.0  
**Last Updated**: December 23, 2024  
**Next Review**: March 23, 2025  
**Document Owner**: PurgeProof Enterprise API Team