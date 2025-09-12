# PurgeProof Quick Start Guide

## Installation and Setup

### 1. Quick Installation

```bash
# Clone repository
git clone https://github.com/Av7danger/PurgeProof.git
cd PurgeProof

# Install with pip (recommended)
pip install -e .

# Or install with specific features
pip install -e .[gui]  # With GUI support
pip install -e .[dev]  # With development tools
```

### 2. Alternative Installation

```bash
# Install dependencies manually
pip install -r requirements.txt

# Run setup script
python setup.py

# Build Rust engine (if needed)
cd engine
cargo build --release
```

### 3. Platform Requirements

**Windows:**
- Run as Administrator for full device access
- Python 3.8+ with pip

**Linux:**
- Install system utilities: `sudo apt install hdparm nvme-cli smartmontools`
- Run with sudo for device access

**macOS:**
**macOS:**

- Basic diskutil support (in development)

## Quick Start

### Using PurgeProof (Recommended)

```bash
# Auto-detect best interface
purgeproof

# Force specific interface
purgeproof --cli          # Command line
purgeproof --tkinter      # Simple GUI
purgeproof --pyqt         # Modern GUI

# Check available interfaces
purgeproof --check
```

### Direct CLI Usage

```bash
# List storage devices
purgeproof list-devices

# Sanitize a device (DESTRUCTIVE!)
purgeproof sanitize --device "/dev/sdb" --method "crypto-erase"

# Verify sanitization
purgeproof verify --device "/dev/sdb" --level "standard"

# Generate certificate
purgeproof certificate --device "/dev/sdb" --format "pdf"
```

## GUI Usage

1. **Device Selection:**

   - Click "Refresh Devices" to scan for storage devices
   - Select target device from dropdown

2. **Configure Options:**

   - Choose sanitization method (auto-recommended)
   - Set verification level (standard recommended)
   - Enable/disable certificate generation

3. **Safety Checks:**

   - Review device information carefully
   - Ensure you have proper authorization
   - Confirm all data will be permanently destroyed

4. **Execute Sanitization:**
   - Click "Sanitize Device"
   - Follow confirmation prompts
   - Monitor progress and wait for completion

## Security Features

### NIST SP 800-88 Rev.1 Compliance
- **Clear:** Logical sanitization (file system overwrite)
- **Purge:** Cryptographic erase, firmware secure erase, overwrite
- **Destroy:** Physical destruction (guidance provided)

### Digital Certificates
- Tamper-proof JSON and PDF certificates
- RSA/ECDSA digital signatures
- QR codes for mobile verification
- Blockchain-ready hash chains

### Verification Engine
- Statistical entropy analysis
- Pattern detection algorithms
- Compliance assessment reporting
- Multiple verification levels

## Advanced Usage

### Configuration Files

```bash
# Create custom configuration
mkdir ~/.purgeproof
cp config/default.yaml ~/.purgeproof/config.yaml
```

### Enterprise Deployment

```bash
# Batch sanitization
purgeproof batch --config "enterprise.yaml"

# Audit reporting
purgeproof audit --output "audit-report.json"
```

## Safety Guidelines

⚠️ **CRITICAL WARNINGS:**

1. **Data Destruction:** All data will be permanently lost
2. **Device Authorization:** Ensure you own or have permission to sanitize the device
3. **System Devices:** Never sanitize system drives or boot devices
4. **Backup Verification:** Confirm all important data is backed up
5. **Legal Compliance:** Follow local data protection regulations

## Troubleshooting

### Common Issues

**"WMI not available" on Windows:**

```bash
pip install pywin32 wmi
```

**Permission denied errors:**

- Windows: Run as Administrator
- Linux: Use sudo
- macOS: Grant Full Disk Access permission

**Device not detected:**

- Check device connections
- Verify device is not mounted/in use
- Try refreshing device list
- Check platform-specific tools are installed

**Sanitization fails:**

- Unmount all file systems on the device
- Close any applications using the device
- Check device health with SMART tools
- Try different sanitization method

### Getting Help

1. **Documentation:** Check `/docs` directory for detailed guides
2. **Logs:** Review application logs in `~/.purgeproof/logs/`
3. **Issues:** Report bugs on GitHub repository
4. **Support:** Contact enterprise support for commercial licenses

## File Structure Reference

```text
PurgeProof/
├── purgeproof/             # Core application package
│   ├── core/              # Core sanitization engine
│   ├── gui/               # GUI interfaces
│   ├── cli.py             # Command-line interface
│   └── __init__.py        # Package initialization
├── engine/                # Rust engine components
├── tests/                 # Test suite
├── docs/                  # Documentation
├── config/                # Configuration templates
├── pyproject.toml         # Project configuration
└── requirements.txt       # Python dependencies
```

## Legal and Compliance

This tool is designed for legitimate data sanitization purposes. Users are responsible for:

- Obtaining proper authorization before use
- Compliance with local laws and regulations
- Following organizational data handling policies
- Proper disposal of sanitized media

## Support

For technical support, feature requests, or security vulnerabilities:

- [GitHub Issues](https://github.com/your-org/purgeproof/issues)
- Security Contact: <security@purgeproof.com>
- [Documentation](https://docs.purgeproof.com)
