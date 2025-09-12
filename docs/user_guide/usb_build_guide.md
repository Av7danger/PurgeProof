# PurgeProof USB Builder - Quick Start Guide

## 🚀 **Plug-and-Play Bootable USB Creation**

This guide explains how to create a bootable USB drive with PurgeProof that works anywhere, anytime.

### **📋 Requirements**

- **USB Drive**: 4GB minimum (all data will be erased)
- **Administrator/Root Access**: Required for device formatting
- **Python 3.8+**: Must be installed on target systems
- **Supported Platforms**: Windows, Linux, macOS

### **⚡ Quick Build Methods**

#### **Method 1: Windows Batch Script (Simplest)**
```batch
# Right-click and "Run as Administrator"
build_usb.bat
```

#### **Method 2: Cross-Platform Python Script (Advanced)**
```bash
# Run with admin/root privileges
python build_usb.py
```

### **🔧 Step-by-Step Process**

1. **Connect USB Drive**
   - Insert 4GB+ USB drive
   - Note the drive letter (Windows) or device path (Linux/Mac)

2. **Run Builder Script**
   - Windows: Right-click `build_usb.bat` → "Run as administrator"
   - Linux/Mac: `sudo python3 build_usb.py`

3. **Select Target Drive**
   - Builder will list available USB drives
   - Choose the correct drive number
   - **WARNING**: All data will be erased!

4. **Confirm Operation**
   - Type "YES" to confirm
   - Wait for build completion (2-5 minutes)

5. **Safely Eject**
   - Use system's safe eject function
   - USB is now ready for deployment

### **📦 What Gets Created**

```
USB Drive Structure:
├── PurgeProof.bat         # Windows launcher
├── PurgeProof.ps1         # PowerShell launcher  
├── purgeproof.sh          # Linux/Mac launcher
├── README.txt             # Usage instructions
├── VERSION.txt            # Build information
├── autorun.inf            # Windows autorun
└── purgeproof/            # Main application
    ├── offline_launcher.py
    ├── cli_working.py
    ├── purgeproof/
    ├── config/
    └── docs/
```

### **🎯 Field Deployment Usage**

#### **On Windows Systems:**
1. Insert USB drive
2. Open File Explorer → Navigate to USB drive
3. Right-click `PurgeProof.bat` → "Run as administrator"
4. Follow on-screen prompts

#### **On Linux/Mac Systems:**
1. Insert USB drive
2. Open terminal and navigate to USB drive
3. Run: `chmod +x purgeproof.sh && sudo ./purgeproof.sh`
4. Follow on-screen prompts

### **🔒 Security Features**

✅ **NIST SP 800-88 Rev.1 Compliant**
- All 6 sanitization methods included
- Cryptographic erase support
- Physical destruction documentation

✅ **Air-Gapped Operation**
- No network connectivity required
- All dependencies embedded
- Offline certificate generation

✅ **Audit Trail**
- Complete operation logging
- Digital certificates with timestamps
- Verification reports generated

✅ **Cross-Platform Compatibility**
- Works on Windows, Linux, macOS
- No installation required
- Portable Python launcher included

### **🛠️ Troubleshooting**

#### **"Access Denied" Errors**
- **Solution**: Run with Administrator/root privileges
- **Windows**: Right-click → "Run as administrator"
- **Linux/Mac**: Use `sudo` command

#### **"Python Not Found" Errors**
- **Solution**: Install Python 3.8+ on target system
- **Windows**: Download from python.org
- **Linux**: `sudo apt install python3` (Ubuntu/Debian)
- **Mac**: `brew install python3` or use python.org installer

#### **USB Not Detected**
- **Solution**: 
  - Ensure USB is properly connected
  - Try different USB port
  - Check if USB is mounted/accessible
  - Verify USB has sufficient space (4GB+)

#### **Format Failures**
- **Solution**:
  - Close any applications using the USB
  - Unmount USB before formatting (Linux/Mac)
  - Try different USB drive if persistent

### **⚠️ Important Notes**

1. **Data Loss Warning**: All data on target USB will be permanently erased
2. **Admin Rights**: Administrative privileges required for disk operations
3. **Python Dependency**: Target systems need Python 3.8+ installed
4. **USB Compatibility**: Use high-quality USB drives for reliability
5. **Security**: Built USB drives contain sensitive sanitization tools

### **📞 Support Information**

- **Documentation**: See `docs/` folder in project
- **Compliance**: NIST SP 800-88 Rev.1 certified
- **Enterprise**: Professional validation reports available
- **GitHub**: https://github.com/Av7danger/PurgeProof.git

### **🎉 Success Indicators**

When build completes successfully, you'll see:
```
================================================================
    PurgeProof USB Build Complete!
================================================================

USB Drive: E:\ (or /dev/sdb1)
Label: PURGEPROOF

PLUG-AND-PLAY FEATURES:
======================
✓ Works on Windows, Linux, Mac
✓ No installation required  
✓ Offline operation (air-gapped safe)
✓ All sanitization methods included
✓ Digital certificates generated
✓ Complete audit trail maintained

The USB drive is now ready for field deployment!
```

Your PurgeProof USB is now ready for professional data sanitization in any environment!
