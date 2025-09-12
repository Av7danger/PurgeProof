"""
PurgeProof Peak Performance - Production Build System
Complete build pipeline for maximum performance deployment
"""

import subprocess
import sys
import os
from pathlib import Path
import shutil

def build_rust_acceleration():
    """Build Rust acceleration engine with peak optimizations"""
    print("🚀 Building Rust acceleration engine with peak optimizations...")
    
    engine_dir = Path("engine")
    if not engine_dir.exists():
        print("❌ Rust engine directory not found")
        return False
    
    # Set environment variables for maximum optimization
    env = os.environ.copy()
    env.update({
        'RUSTFLAGS': '-C target-cpu=native -C opt-level=3 -C lto=fat -C codegen-units=1 -C target-feature=+avx2,+aes',
        'CARGO_BUILD_RELEASE': '1'
    })
    
    try:
        # Build with production optimizations
        result = subprocess.run([
            'cargo', 'build', '--release',
            '--features', 'simd,hardware-crypto,cross-platform'
        ], cwd=engine_dir, env=env, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Rust engine built successfully with peak optimizations")
            return True
        else:
            print(f"❌ Rust build failed: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("❌ Cargo not found. Please install Rust toolchain.")
        return False
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False

def install_python_dependencies():
    """Install optimized Python dependencies"""
    print("🐍 Installing optimized Python dependencies...")
    
    # Core dependencies for peak performance
    dependencies = [
        'numpy>=1.21.0',        # Optimized numerical operations
        'psutil>=5.8.0',        # System information
        'cryptography>=3.4.0',  # Hardware crypto acceleration
        'maturin>=0.13.0',      # Rust-Python integration
        'pybind11>=2.8.0',      # C++ bindings if needed
        'scipy>=1.7.0',         # Scientific computing
        'numba>=0.56.0',        # JIT compilation for Python
    ]
    
    for dep in dependencies:
        try:
            result = subprocess.run([
                sys.executable, '-m', 'pip', 'install', '--upgrade', dep
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ Installed {dep}")
            else:
                print(f"⚠️ Warning: Failed to install {dep}")
                
        except Exception as e:
            print(f"❌ Error installing {dep}: {e}")

def create_distribution():
    """Create optimized distribution package"""
    print("📦 Creating optimized distribution package...")
    
    dist_dir = Path("dist")
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    dist_dir.mkdir()
    
    # Copy core files
    core_files = [
        "wipeit/",
        "engine/target/release/",
        "README.md",
        "setup.py",
        "requirements.txt"
    ]
    
    for file_path in core_files:
        src = Path(file_path)
        if src.exists():
            if src.is_dir():
                shutil.copytree(src, dist_dir / src.name)
            else:
                shutil.copy2(src, dist_dir)
            print(f"✅ Copied {file_path}")
        else:
            print(f"⚠️ Warning: {file_path} not found")
    
    print("✅ Distribution package created")

def run_performance_tests():
    """Run comprehensive performance tests"""
    print("🧪 Running performance validation tests...")
    
    test_commands = [
        # Test Python import
        [sys.executable, '-c', 'import wipeit.core.wipe_engine_peak; print("✅ Peak engine import successful")'],
        
        # Test Rust acceleration (if available)
        [sys.executable, '-c', '''
try:
    import purgeproof_engine
    print("✅ Rust acceleration available")
    caps = purgeproof_engine.get_performance_profile()
    print(f"Hardware features: {caps}")
except ImportError:
    print("⚠️ Rust acceleration not available")
'''],
        
        # System capability test
        [sys.executable, '-c', '''
from wipeit.core.wipe_engine_peak import PeakWipeEngine
engine = PeakWipeEngine()
caps = engine.get_system_capabilities()
print(f"✅ System capabilities: {caps}")
''']
    ]
    
    for cmd in test_commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print(result.stdout.strip())
            else:
                print(f"❌ Test failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print("⚠️ Test timed out")
        except Exception as e:
            print(f"❌ Test error: {e}")

def create_deployment_script():
    """Create deployment script for production systems"""
    print("🚀 Creating deployment script...")
    
    deployment_script = '''#!/bin/bash
# PurgeProof Peak Performance Deployment Script

echo "🚀 Deploying PurgeProof Peak Performance System"

# Check system requirements
echo "Checking system requirements..."

# Check for Rust toolchain
if command -v rustc >/dev/null 2>&1; then
    echo "✅ Rust toolchain found: $(rustc --version)"
else
    echo "⚠️ Rust toolchain not found - installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
fi

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2)
echo "✅ Python version: $python_version"

# Install dependencies
echo "Installing Python dependencies..."
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Build Rust acceleration
echo "Building Rust acceleration engine..."
cd engine
cargo build --release --features simd,hardware-crypto,cross-platform
cd ..

# Run performance validation
echo "Running performance validation..."
python3 -c "from wipeit.core.wipe_engine_peak import PeakWipeEngine; engine = PeakWipeEngine(); print('✅ Peak engine ready')"

echo "🎉 PurgeProof Peak Performance deployment complete!"
echo "Run 'python3 -m wipeit --help' for usage information"
'''
    
    with open("deploy_peak.sh", 'w') as f:
        f.write(deployment_script)
    
    os.chmod("deploy_peak.sh", 0o755)
    print("✅ Deployment script created: deploy_peak.sh")

def main():
    """Main build and deployment process"""
    print("🎯 PurgeProof Peak Performance Build System")
    print("=" * 50)
    
    # Phase 1: Build Rust acceleration
    if not build_rust_acceleration():
        print("⚠️ Continuing without Rust acceleration")
    
    # Phase 2: Install Python dependencies
    install_python_dependencies()
    
    # Phase 3: Run performance tests
    run_performance_tests()
    
    # Phase 4: Create distribution
    create_distribution()
    
    # Phase 5: Create deployment script
    create_deployment_script()
    
    print("\n🎉 Peak Performance build completed!")
    print("\nNext steps:")
    print("1. Run './deploy_peak.sh' on target systems")
    print("2. Test with: python3 -c 'from wipeit.core.wipe_engine_peak import peak_overwrite'")
    print("3. Benchmark: python3 -m wipeit benchmark")

if __name__ == "__main__":
    main()