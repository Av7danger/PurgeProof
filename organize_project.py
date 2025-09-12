import os
import shutil
from pathlib import Path

def create_directories():
    """Create necessary directories for organization."""
    dirs = [
        'docs/user_guide',
        'docs/developer_guide',
        'docs/compliance',
        'docs/enterprise',
        'docs/images',
        'scripts',
        'tests/unit',
        'tests/integration',
        'config',
        'wipeit/cli',
        'wipeit/core',
        'wipeit/utils'
    ]
    
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)

def move_files():
    """Move files to their appropriate locations."""
    # Documentation files
    doc_mapping = {
        'QUICKSTART.md': 'docs/user_guide/quickstart.md',
        'README.md': 'docs/user_guide/index.md',
        'README_ENHANCED.md': 'docs/user_guide/advanced_usage.md',
        'README_FINAL.md': 'docs/user_guide/overview.md',
        'USB_BUILD_GUIDE.md': 'docs/user_guide/usb_build_guide.md',
        'CONTRIBUTING.md': 'docs/developer_guide/contributing.md',
        'COMPLIANCE_REPORT.md': 'docs/compliance/report.md',
        'COMPLIANCE_REPORT_ENHANCED.md': 'docs/compliance/enhanced_report.md',
        'COMPLIANCE_SUMMARY.md': 'docs/compliance/summary.md',
        'DOCUMENTATION_ENHANCEMENT_SUMMARY.md': 'docs/developer_guide/documentation_enhancements.md',
        'ENTERPRISE_TEMPLATE_DELIVERY.md': 'docs/enterprise/template_delivery.md',
        'ENTERPRISE_VALIDATION_REPORT.md': 'docs/enterprise/validation_report.md',
        'PROJECT_SUMMARY.md': 'docs/developer_guide/project_summary.md',
        'STATUS_COMPLETE.md': 'docs/developer_guide/status_report.md',
        'SYSTEM_CHECK_COMPLETE.md': 'docs/developer_guide/system_check.md'
    }
    
    # Script files
    script_mapping = {
        'build_usb.py': 'scripts/build_usb.py',
        'build_usb.bat': 'scripts/build_usb.bat',
        'generate_documentation_charts.py': 'scripts/generate_docs.py',
        'install.py': 'scripts/install.py',
        'launcher.py': 'scripts/launcher.py',
        'offline_launcher.py': 'scripts/offline_launcher.py',
        'perf_test.py': 'tests/performance/test_perf.py',
        'cli_working.py': 'wipeit/cli/main.py',
        'test_cli.py': 'tests/integration/test_cli.py',
        'test_minimal.py': 'tests/unit/test_minimal.py',
        'test_system.py': 'tests/integration/test_system.py',
        'usb_demo.py': 'examples/usb_demo.py'
    }
    
    # Move documentation files
    for src, dst in doc_mapping.items():
        if os.path.exists(src):
            shutil.move(src, dst)
            print(f"Moved {src} to {dst}")
    
    # Move script files
    os.makedirs('tests/performance', exist_ok=True)
    os.makedirs('examples', exist_ok=True)
    
    for src, dst in script_mapping.items():
        if os.path.exists(src):
            shutil.move(src, dst)
            print(f"Moved {src} to {dst}")

def create_new_readme():
    """Create a new, clean README.md."""
    readme_content = """# WipeIt - Secure Data Wiping Utility

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A secure and verifiable data wiping utility for complete data erasure.

## Features

- Secure data wiping using multiple algorithms
- Verification of wiped data
- Support for various storage devices
- Command-line interface
- Enterprise features

## Quick Start

```bash
# Install WipeIt
pip install -e .

# Run WipeIt
wipeit --help
```

## Documentation

For detailed documentation, please see:

- [User Guide](docs/user_guide/index.md)
- [Developer Guide](docs/developer_guide/index.md)
- [Compliance Information](docs/compliance/report.md)
- [Enterprise Features](docs/enterprise/)

## Contributing

Contributions are welcome! Please see our [Contributing Guide](docs/developer_guide/contributing.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
"""
    
    with open('README.md', 'w', encoding='utf-8') as f:
        f.write(readme_content)
    
    print("Created new README.md")

def main():
    print("Starting project reorganization...")
    create_directories()
    move_files()
    create_new_readme()
    print("Reorganization complete!")

if __name__ == "__main__":
    main()
