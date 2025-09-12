"""
Test requirements and setup for PurgeProof Enterprise Test Suite

This file defines optional dependencies and provides setup instructions
for comprehensive testing capabilities.
"""

# Core testing dependencies (optional)
OPTIONAL_DEPENDENCIES = {
    'pytest': {
        'purpose': 'Advanced test runner with fixtures and plugins',
        'install': 'pip install pytest',
        'fallback': 'Basic Python test execution'
    },
    'pytest-cov': {
        'purpose': 'Code coverage reporting',
        'install': 'pip install pytest-cov',
        'fallback': 'No coverage reporting'
    },
    'mock': {
        'purpose': 'Mock object framework for testing',
        'install': 'pip install mock',
        'fallback': 'unittest.mock (Python 3.3+)'
    },
    'yaml': {
        'purpose': 'YAML configuration file support',
        'install': 'pip install PyYAML',
        'fallback': 'Mock YAML handling'
    },
    'cryptography': {
        'purpose': 'Digital signature and certificate validation',
        'install': 'pip install cryptography',
        'fallback': 'Mock cryptographic operations'
    },
    'reportlab': {
        'purpose': 'PDF certificate generation',
        'install': 'pip install reportlab',
        'fallback': 'Mock PDF generation'
    },
    'tkinter': {
        'purpose': 'GUI testing framework',
        'install': 'Built into Python (usually)',
        'fallback': 'Headless GUI simulation'
    }
}

def check_dependencies():
    """Check which optional dependencies are available"""
    available = {}
    missing = {}
    
    for dep_name, dep_info in OPTIONAL_DEPENDENCIES.items():
        try:
            if dep_name == 'tkinter':
                import tkinter
            else:
                __import__(dep_name)
            available[dep_name] = dep_info
        except ImportError:
            missing[dep_name] = dep_info
    
    return available, missing

def print_dependency_status():
    """Print status of test dependencies"""
    available, missing = check_dependencies()
    
    print("PurgeProof Test Suite Dependency Status")
    print("=" * 40)
    
    if available:
        print("\n✅ Available Dependencies:")
        for dep_name, dep_info in available.items():
            print(f"  • {dep_name}: {dep_info['purpose']}")
    
    if missing:
        print("\n⚠️  Missing Dependencies (optional):")
        for dep_name, dep_info in missing.items():
            print(f"  • {dep_name}: {dep_info['purpose']}")
            print(f"    Install: {dep_info['install']}")
            print(f"    Fallback: {dep_info['fallback']}")
            print()
    
    print("\nNote: All dependencies are optional. Tests will run with fallback")
    print("implementations if dependencies are missing.")
    
    return len(missing) == 0

def setup_test_environment():
    """Setup test environment with available dependencies"""
    import sys
    import os
    from pathlib import Path
    
    # Add project root to Python path
    test_dir = Path(__file__).parent
    project_root = test_dir.parent
    
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # Set environment variables for testing
    os.environ['PURGEPROOF_TEST_MODE'] = '1'
    os.environ['PURGEPROOF_LOG_LEVEL'] = 'DEBUG'
    
    # Check dependencies
    all_available = print_dependency_status()
    
    return all_available

if __name__ == "__main__":
    """Run dependency check when executed directly"""
    setup_test_environment()