# Image Directory for PurgeProof Documentation

This directory contains visual proof and documentation images for the enhanced PurgeProof documentation.

## Required Screenshots

### Core Functionality Screenshots
- `cli_methods_output.png` - Screenshot of: `python cli_working.py --methods`
- `launcher_detection.png` - Screenshot of: `python launcher.py --check`
- `crypto_test_output.png` - Screenshot of: `python cli_working.py --crypto`
- `gui_wipe_progress.png` - Screenshot of GUI during wipe operation
- `quick_install.png` - Screenshot of installation process
- `cli_quick_test.png` - Screenshot of verification commands

### Certificate & Compliance Screenshots
- `cert_json_sample.png` - Sample JSON certificate display
- `cert_pdf_sample.png` - Sample PDF certificate display
- `yaml_config.png` - config/default.yaml file content
- `compliance_matrix.png` - NIST compliance visualization
- `iso_build_linux.png` - Linux ISO build process

### Performance & Metrics Screenshots
- `performance_dashboard.png` - Performance metrics visualization
- `verification_metrics.png` - Verification success dashboard
- `ssd_crypto.png` - SSD cryptographic erase result
- `nvme_sanitize.png` - NVMe sanitize operation result
- `hdd_multipass.png` - HDD multi-pass overwrite result
- `enterprise_ssd.png` - Enterprise SSD secure erase result

### Architecture & System Screenshots
- `architecture_diagram.png` - System architecture diagram
- `security_overview.png` - Security implementation overview
- `platform_matrix.png` - Platform support matrix
- `device_support.png` - Device type support chart
- `interface_comparison.png` - CLI vs GUI interface comparison

### Documentation & Process Screenshots
- `documentation_suite.png` - Documentation overview
- `test_results.png` - pytest execution results
- `code_quality.png` - Code quality metrics
- `optimization_guide.png` - Performance optimization guide
- `performance_scaling.png` - Performance scaling chart
- `development_roadmap.png` - Development timeline
- `industry_recognition.png` - Awards and certifications
- `get_started.png` - Getting started guide

## How to Capture Screenshots

### CLI Screenshots
```powershell
# Navigate to PurgeProof directory
cd c:\Users\admin\Desktop\Projects\Cybersecurity\PurgeProof

# Capture these command outputs:
python cli_working.py --methods
python cli_working.py --crypto
python cli_working.py --info
python launcher.py --check
python launcher.py --cli list-devices
```

### GUI Screenshots
```powershell
# Launch GUI and capture during operation:
python launcher.py --tkinter
# Screenshot: Device selection window
# Screenshot: Method selection window  
# Screenshot: Progress window during wipe
# Screenshot: Completion/certificate window
```

### Configuration Screenshots
- Open `config/default.yaml` in editor and screenshot
- Open generated certificate files (JSON/PDF) and screenshot
- Screenshot bootable environment build process

### Performance Screenshots
- Create charts/graphs for performance data from the enhanced compliance report
- Use tools like matplotlib, Excel, or online chart generators
- Screenshot test execution results from pytest

## Image Specifications

- **Format**: PNG preferred for screenshots, SVG for diagrams
- **Resolution**: Minimum 1920x1080 for full screenshots, 800x600 for smaller elements
- **Quality**: High quality, readable text, clear visual elements
- **Compression**: Optimize for web while maintaining readability

## Integration Notes

All images are referenced in:
- `COMPLIANCE_REPORT_ENHANCED.md`
- `README_ENHANCED.md`

Replace placeholder image references with actual screenshot files once captured.
