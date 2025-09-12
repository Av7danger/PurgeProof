# PurgeProof Quick Start Guide

## Installation and Setup

### 1. Install Dependencies

```bash
# Install core dependencies
pip install cryptography psutil pyserial reportlab qrcode Pillow click colorama

# Optional: Install PyQt6 for modern GUI
pip install PyQt6 PyQt6-tools

# Windows-specific dependencies (optional, for enhanced device detection)
pip install pywin32 wmi
```

### 2. Platform Requirements

**Windows:**
- Run as Administrator for full device access
- PowerShell execution policy may need adjustment

**Linux:**
- Install system utilities: `sudo apt install hdparm nvme-cli gparted smartmontools`
- Run with sudo for device access

**Android (via ADB):**
- Install ADB tools and enable developer mode

## Quick Start

### Using the Launcher (Recommended)

```bash
# Auto-detect best interface
python launcher.py

# Force specific interface
python launcher.py --cli          # Command line
python launcher.py --tkinter      # Simple GUI
python launcher.py --pyqt         # Modern GUI

# Check available interfaces
python launcher.py --check
```

### Direct CLI Usage

```bash
# List storage devices
python launcher.py --cli list-devices

# Sanitize a device (DESTRUCTIVE!)
python launcher.py --cli sanitize --device "/dev/sdb" --method "crypto-erase"

# Verify sanitization
python launcher.py --cli verify --device "/dev/sdb" --level "standard"

# Generate certificate
python launcher.py --cli certificate --device "/dev/sdb" --format "pdf"
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
python launcher.py --cli batch --config "enterprise.yaml"

# Audit reporting
python launcher.py --cli audit --output "audit-report.json"
```

### Bootable ISO Creation
```bash
# Build bootable sanitization environment
cd bootable
./build-iso.sh
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

```
PurgeProof/
├── launcher.py              # Main launcher script
├── wipeit/                  # Core application package
│   ├── core/               # Core sanitization engine
│   ├── gui/                # GUI interfaces
│   ├── cli.py              # Command-line interface
│   └── requirements.txt    # Python dependencies
├── bootable/               # Bootable ISO components
├── tests/                  # Test suite
├── docs/                   # Documentation
└── config/                 # Configuration templates
```

## Legal and Compliance

This tool is designed for legitimate data sanitization purposes. Users are responsible for:
- Obtaining proper authorization before use
- Compliance with local laws and regulations
- Following organizational data handling policies
- Proper disposal of sanitized media

## Support

For technical support, feature requests, or security vulnerabilities:
- GitHub Issues: https://github.com/your-org/purgeproof/issues
- Security Contact: security@purgeproof.com
- Documentation: https://docs.purgeproof.com
