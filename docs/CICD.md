# CI/CD Pipeline Configuration for PurgeProof

## Overview

This document describes the Continuous Integration/Continuous Deployment (CI/CD) pipeline for PurgeProof, designed to ensure high-quality releases across multiple platforms while maintaining security and compliance standards.

## Pipeline Architecture

### Multi-Platform Support

- **Linux**: Ubuntu 20.04+, RHEL 8+, CentOS 8+
- **Windows**: Windows 10/11, Windows Server 2019/2022
- **macOS**: macOS 10.14+

### Build Stages

1. **Source Code Validation**
2. **Dependency Resolution**
3. **Native Engine Compilation**
4. **Python Package Building**
5. **Automated Testing**
6. **Security Scanning**
7. **Compliance Validation**
8. **Packaging and Distribution**
9. **Deployment**

## GitHub Actions Workflow

### Main CI/CD Pipeline (`.github/workflows/ci-cd.yml`)

```yaml
name: PurgeProof CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always
  PYTHON_VERSION: '3.8'

jobs:
  # Code Quality and Security
  code-quality:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ env.PYTHON_VERSION }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install black isort mypy pylint bandit safety
    
    - name: Code formatting check
      run: |
        black --check --diff .
        isort --check-only --diff .
    
    - name: Type checking
      run: mypy purgeproof/
    
    - name: Linting
      run: pylint purgeproof/
    
    - name: Security scanning
      run: |
        bandit -r purgeproof/
        safety check
    
    - name: License scanning
      uses: fossa-contrib/fossa-action@v2
      with:
        api-key: ${{ secrets.FOSSA_API_KEY }}

  # Rust Engine Build and Test
  rust-build:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        rust: [stable, beta]
    runs-on: ${{ matrix.os }}
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust
      uses: actions-rs/toolchain@v1
      with:
        toolchain: ${{ matrix.rust }}
        components: rustfmt, clippy
        override: true
    
    - name: Cache Rust dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          engine/target
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
    
    - name: Rust formatting check
      run: cargo fmt --all -- --check
      working-directory: engine
    
    - name: Rust linting
      run: cargo clippy --all-targets --all-features -- -D warnings
      working-directory: engine
    
    - name: Build Rust engine
      run: cargo build --release --all-features
      working-directory: engine
    
    - name: Run Rust tests
      run: cargo test --release --all-features
      working-directory: engine
    
    - name: Security audit
      run: |
        cargo install cargo-audit
        cargo audit
      working-directory: engine
    
    - name: Upload Rust artifacts
      uses: actions/upload-artifact@v3
      with:
        name: rust-engine-${{ matrix.os }}
        path: engine/target/release/

  # Python Package Build and Test
  python-build:
    needs: rust-build
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: ['3.8', '3.9', '3.10', '3.11']
    runs-on: ${{ matrix.os }}
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Download Rust artifacts
      uses: actions/download-artifact@v3
      with:
        name: rust-engine-${{ matrix.os }}
        path: engine/target/release/
    
    - name: Install Python dependencies
      run: |
        python -m pip install --upgrade pip
        pip install build wheel pytest pytest-asyncio pytest-cov
        pip install -e .
    
    - name: Build Python package
      run: python -m build
    
    - name: Install package
      run: pip install dist/*.whl
    
    - name: Run Python tests
      run: |
        pytest tests/ -v --cov=purgeproof --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella
    
    - name: Upload Python artifacts
      uses: actions/upload-artifact@v3
      with:
        name: python-package-${{ matrix.os }}-py${{ matrix.python-version }}
        path: dist/

  # Integration Tests
  integration-tests:
    needs: [rust-build, python-build]
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
    runs-on: ${{ matrix.os }}
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: ${{ env.PYTHON_VERSION }}
    
    - name: Download artifacts
      uses: actions/download-artifact@v3
      with:
        name: python-package-${{ matrix.os }}-py${{ env.PYTHON_VERSION }}
        path: dist/
    
    - name: Install package
      run: pip install dist/*.whl
    
    - name: Run integration tests
      run: pytest tests/integration/ -v --tb=short
    
    - name: Run compliance tests
      run: pytest tests/compliance/ -v --tb=short
    
    - name: Run performance benchmarks
      run: pytest tests/benchmarks/ -v --benchmark-only

  # Security and Compliance Validation
  security-compliance:
    needs: [code-quality, rust-build, python-build]
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Run SAST with Semgrep
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/secrets
          p/python
          p/rust
    
    - name: Run container security scan
      uses: aquasec/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload security scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'
    
    - name: Compliance validation
      run: |
        python scripts/validate_compliance.py --standard nist-sp-800-88
        python scripts/validate_compliance.py --standard dod-5220-22-m

  # Package and Release
  package-release:
    if: startsWith(github.ref, 'refs/tags/v')
    needs: [integration-tests, security-compliance]
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Download all artifacts
      uses: actions/download-artifact@v3
    
    - name: Create release packages
      run: |
        mkdir -p release/
        # Package for different platforms
        python scripts/create_release_packages.py
    
    - name: Generate checksums
      run: |
        cd release/
        sha256sum * > checksums.txt
        gpg --armor --detach-sig checksums.txt
    
    - name: Create GitHub Release
      uses: softprops/action-gh-release@v1
      with:
        files: release/*
        generate_release_notes: true
        draft: false
        prerelease: ${{ contains(github.ref, 'beta') || contains(github.ref, 'alpha') }}
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Publish to PyPI
      uses: pypa/gh-action-pypi-publish@release/v1
      with:
        user: __token__
        password: ${{ secrets.PYPI_API_TOKEN }}
        packages_dir: dist/

  # Deploy to staging
  deploy-staging:
    if: github.ref == 'refs/heads/develop'
    needs: [integration-tests, security-compliance]
    runs-on: ubuntu-latest
    environment: staging
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Deploy to staging environment
      run: |
        # Deploy to staging servers
        python scripts/deploy_staging.py
      env:
        STAGING_SSH_KEY: ${{ secrets.STAGING_SSH_KEY }}
        STAGING_HOSTS: ${{ secrets.STAGING_HOSTS }}
    
    - name: Run staging tests
      run: |
        python scripts/test_staging_deployment.py
    
    - name: Notify team
      uses: 8398a7/action-slack@v3
      with:
        status: ${{ job.status }}
        channel: '#purgeproof-ci'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}

  # Deploy to production
  deploy-production:
    if: startsWith(github.ref, 'refs/tags/v') && !contains(github.ref, 'beta') && !contains(github.ref, 'alpha')
    needs: package-release
    runs-on: ubuntu-latest
    environment: production
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Deploy to production
      run: |
        # Deploy to production servers
        python scripts/deploy_production.py
      env:
        PRODUCTION_SSH_KEY: ${{ secrets.PRODUCTION_SSH_KEY }}
        PRODUCTION_HOSTS: ${{ secrets.PRODUCTION_HOSTS }}
    
    - name: Run production smoke tests
      run: |
        python scripts/test_production_deployment.py
    
    - name: Update documentation
      run: |
        python scripts/update_docs.py --version ${{ github.ref_name }}
    
    - name: Notify stakeholders
      uses: 8398a7/action-slack@v3
      with:
        status: success
        channel: '#purgeproof-releases'
        webhook_url: ${{ secrets.SLACK_WEBHOOK }}
        text: "🚀 PurgeProof ${{ github.ref_name }} has been deployed to production!"
```

### Nightly Build Pipeline (`.github/workflows/nightly.yml`)

```yaml
name: Nightly Build and Test

on:
  schedule:
    - cron: '0 2 * * *'  # Run at 2 AM UTC daily
  workflow_dispatch:

jobs:
  nightly-comprehensive-test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        rust: [stable, beta, nightly]
        python: ['3.8', '3.9', '3.10', '3.11', '3.12']
    runs-on: ${{ matrix.os }}
    continue-on-error: ${{ matrix.rust == 'nightly' }}
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Install Rust ${{ matrix.rust }}
      uses: actions-rs/toolchain@v1
      with:
        toolchain: ${{ matrix.rust }}
        override: true
    
    - name: Set up Python ${{ matrix.python }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python }}
    
    - name: Run comprehensive tests
      run: |
        # Build and test with all feature combinations
        python scripts/run_comprehensive_tests.py
    
    - name: Performance regression tests
      run: |
        python scripts/performance_regression_tests.py
    
    - name: Memory leak detection
      run: |
        python scripts/memory_leak_tests.py
    
    - name: Generate nightly report
      run: |
        python scripts/generate_nightly_report.py
    
    - name: Upload test results
      uses: actions/upload-artifact@v3
      with:
        name: nightly-results-${{ matrix.os }}-rust${{ matrix.rust }}-py${{ matrix.python }}
        path: test-results/
```

## Build Scripts

### Cross-Platform Build Script (`scripts/build.py`)

```python
#!/usr/bin/env python3
"""
Cross-platform build script for PurgeProof.
Handles building both Rust engine and Python package.
"""

import os
import sys
import subprocess
import platform
import argparse
from pathlib import Path

def build_rust_engine(target=None, release=True):
    """Build the Rust engine with specified target."""
    print("Building Rust engine...")
    
    os.chdir("engine")
    
    cmd = ["cargo", "build"]
    
    if release:
        cmd.append("--release")
    
    if target:
        cmd.extend(["--target", target])
    
    cmd.append("--all-features")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Rust build failed: {result.stderr}")
        return False
    
    print("✓ Rust engine built successfully")
    return True

def build_python_package():
    """Build the Python package."""
    print("Building Python package...")
    
    os.chdir("..")  # Back to root
    
    # Build wheel
    result = subprocess.run([sys.executable, "-m", "build"], 
                          capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Python build failed: {result.stderr}")
        return False
    
    print("✓ Python package built successfully")
    return True

def run_tests():
    """Run test suite."""
    print("Running test suite...")
    
    result = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"],
                          capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Tests failed: {result.stderr}")
        return False
    
    print("✓ All tests passed")
    return True

def create_distribution():
    """Create platform-specific distribution."""
    system = platform.system()
    arch = platform.machine()
    
    print(f"Creating distribution for {system}-{arch}...")
    
    dist_dir = Path(f"dist/{system}-{arch}")
    dist_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy built artifacts
    if system == "Windows":
        engine_file = "engine/target/release/purgeproof_engine.dll"
    elif system == "Darwin":
        engine_file = "engine/target/release/libpurgeproof_engine.dylib"
    else:
        engine_file = "engine/target/release/libpurgeproof_engine.so"
    
    if Path(engine_file).exists():
        subprocess.run(["cp", engine_file, dist_dir])
    
    # Copy Python package
    for wheel in Path("dist").glob("*.whl"):
        subprocess.run(["cp", str(wheel), dist_dir])
    
    print(f"✓ Distribution created in {dist_dir}")

def main():
    parser = argparse.ArgumentParser(description="Build PurgeProof")
    parser.add_argument("--target", help="Rust target triple")
    parser.add_argument("--debug", action="store_true", help="Debug build")
    parser.add_argument("--no-tests", action="store_true", help="Skip tests")
    parser.add_argument("--no-python", action="store_true", help="Skip Python build")
    
    args = parser.parse_args()
    
    # Build Rust engine
    if not build_rust_engine(target=args.target, release=not args.debug):
        return 1
    
    # Build Python package
    if not args.no_python and not build_python_package():
        return 1
    
    # Run tests
    if not args.no_tests and not run_tests():
        return 1
    
    # Create distribution
    create_distribution()
    
    print("🎉 Build completed successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

### Release Script (`scripts/release.py`)

```python
#!/usr/bin/env python3
"""
Release automation script for PurgeProof.
Handles version bumping, tagging, and release preparation.
"""

import re
import sys
import subprocess
import json
from pathlib import Path
from datetime import datetime

class ReleaseManager:
    def __init__(self):
        self.root_dir = Path(__file__).parent.parent
        self.version_files = [
            "engine/Cargo.toml",
            "purgeproof/__init__.py",
            "setup.py"
        ]
    
    def get_current_version(self):
        """Get current version from Cargo.toml."""
        cargo_toml = self.root_dir / "engine/Cargo.toml"
        content = cargo_toml.read_text()
        
        match = re.search(r'version = "([^"]+)"', content)
        if match:
            return match.group(1)
        
        raise ValueError("Could not find version in Cargo.toml")
    
    def bump_version(self, version_type="patch"):
        """Bump version number."""
        current = self.get_current_version()
        major, minor, patch = map(int, current.split('.'))
        
        if version_type == "major":
            major += 1
            minor = 0
            patch = 0
        elif version_type == "minor":
            minor += 1
            patch = 0
        elif version_type == "patch":
            patch += 1
        
        new_version = f"{major}.{minor}.{patch}"
        
        # Update all version files
        for file_path in self.version_files:
            self.update_version_in_file(file_path, new_version)
        
        return new_version
    
    def update_version_in_file(self, file_path, new_version):
        """Update version in a specific file."""
        full_path = self.root_dir / file_path
        content = full_path.read_text()
        
        if file_path.endswith(".toml"):
            content = re.sub(r'version = "[^"]+"', f'version = "{new_version}"', content)
        elif file_path.endswith(".py"):
            content = re.sub(r'__version__ = "[^"]+"', f'__version__ = "{new_version}"', content)
            content = re.sub(r'version="[^"]+"', f'version="{new_version}"', content)
        
        full_path.write_text(content)
        print(f"Updated version in {file_path}")
    
    def generate_changelog(self, version):
        """Generate changelog for the release."""
        changelog_file = self.root_dir / "CHANGELOG.md"
        
        # Get commits since last tag
        try:
            result = subprocess.run(
                ["git", "log", "--oneline", "--pretty=format:- %s", 
                 f"$(git describe --tags --abbrev=0)..HEAD"],
                capture_output=True, text=True, shell=True
            )
            commits = result.stdout.strip()
        except:
            commits = "- Initial release"
        
        # Read existing changelog
        if changelog_file.exists():
            existing = changelog_file.read_text()
        else:
            existing = "# Changelog\n\nAll notable changes to this project will be documented in this file.\n\n"
        
        # Add new entry
        date = datetime.now().strftime("%Y-%m-%d")
        new_entry = f"""## [{version}] - {date}

{commits}

"""
        
        # Insert after header
        lines = existing.split('\n')
        header_end = 2
        for i, line in enumerate(lines):
            if line.startswith('## '):
                header_end = i
                break
        
        new_content = '\n'.join(lines[:header_end]) + '\n' + new_entry + '\n'.join(lines[header_end:])
        changelog_file.write_text(new_content)
        
        print(f"Updated changelog for version {version}")
    
    def create_release_tag(self, version):
        """Create git tag for the release."""
        tag_name = f"v{version}"
        
        # Add all version files
        for file_path in self.version_files:
            subprocess.run(["git", "add", str(file_path)])
        
        subprocess.run(["git", "add", "CHANGELOG.md"])
        
        # Commit changes
        subprocess.run(["git", "commit", "-m", f"Release version {version}"])
        
        # Create tag
        subprocess.run(["git", "tag", "-a", tag_name, "-m", f"Release {version}"])
        
        print(f"Created release tag {tag_name}")
        
        return tag_name

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage PurgeProof releases")
    parser.add_argument("--version-type", choices=["major", "minor", "patch"], 
                       default="patch", help="Type of version bump")
    parser.add_argument("--dry-run", action="store_true", 
                       help="Show what would be done without making changes")
    
    args = parser.parse_args()
    
    manager = ReleaseManager()
    
    current_version = manager.get_current_version()
    print(f"Current version: {current_version}")
    
    if args.dry_run:
        print(f"Would bump {args.version_type} version")
        return 0
    
    # Bump version
    new_version = manager.bump_version(args.version_type)
    print(f"Bumped version to: {new_version}")
    
    # Generate changelog
    manager.generate_changelog(new_version)
    
    # Create release tag
    tag_name = manager.create_release_tag(new_version)
    
    print(f"🎉 Release {new_version} prepared!")
    print(f"Push with: git push origin main {tag_name}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
```

## Docker Configuration

### Multi-Stage Dockerfile

```dockerfile
# Build stage for Rust engine
FROM rust:1.70 as rust-builder

WORKDIR /app/engine
COPY engine/ .

RUN cargo build --release --all-features

# Build stage for Python package
FROM python:3.11-slim as python-builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy Python code
COPY purgeproof/ purgeproof/
COPY setup.py .
COPY requirements.txt .

# Copy Rust artifacts
COPY --from=rust-builder /app/engine/target/release/ engine/target/release/

# Build Python package
RUN pip install build
RUN python -m build

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

# Copy built package
COPY --from=python-builder /app/dist/*.whl /tmp/

# Install PurgeProof
RUN pip install /tmp/*.whl && rm /tmp/*.whl

# Create non-root user
RUN useradd -r -s /bin/false purgeproof

# Set up volumes
VOLUME ["/data", "/logs"]

# Expose any needed ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import purgeproof; print('OK')" || exit 1

USER purgeproof

ENTRYPOINT ["purgeproof"]
CMD ["--help"]
```

### Docker Compose for Development

```yaml
version: '3.8'

services:
  purgeproof-dev:
    build:
      context: .
      dockerfile: Dockerfile.dev
    volumes:
      - .:/app
      - cargo-cache:/usr/local/cargo/registry
      - target-cache:/app/engine/target
    environment:
      - RUST_LOG=debug
      - PURGEPROOF_LOG_LEVEL=DEBUG
    privileged: true  # Required for device access
    devices:
      - /dev:/dev  # Mount all devices
    command: ["--gui"]

  purgeproof-test:
    build:
      context: .
      dockerfile: Dockerfile
    command: ["python", "-m", "pytest", "tests/", "-v"]
    volumes:
      - ./test-results:/app/test-results

volumes:
  cargo-cache:
  target-cache:
```

## Deployment Automation

### Production Deployment Script

```python
#!/usr/bin/env python3
"""
Production deployment script for PurgeProof.
Handles rolling updates across multiple servers.
"""

import subprocess
import sys
import time
import json
from pathlib import Path

class ProductionDeployer:
    def __init__(self, config_file="deployment.json"):
        self.config = self.load_config(config_file)
        self.servers = self.config["production_servers"]
    
    def load_config(self, config_file):
        """Load deployment configuration."""
        with open(config_file) as f:
            return json.load(f)
    
    def deploy_to_server(self, server):
        """Deploy to a single server."""
        print(f"Deploying to {server['hostname']}...")
        
        # Copy files
        subprocess.run([
            "scp", "-r", "dist/", f"{server['user']}@{server['hostname']}:/tmp/"
        ])
        
        # Execute deployment commands
        commands = [
            "sudo systemctl stop purgeproof",
            "sudo pip install --upgrade /tmp/dist/*.whl",
            "sudo systemctl start purgeproof",
            "sudo systemctl enable purgeproof"
        ]
        
        for cmd in commands:
            result = subprocess.run([
                "ssh", f"{server['user']}@{server['hostname']}", cmd
            ])
            
            if result.returncode != 0:
                raise Exception(f"Command failed on {server['hostname']}: {cmd}")
        
        # Health check
        time.sleep(10)
        health_result = subprocess.run([
            "ssh", f"{server['user']}@{server['hostname']}", 
            "purgeproof status"
        ])
        
        if health_result.returncode != 0:
            raise Exception(f"Health check failed on {server['hostname']}")
        
        print(f"✓ Successfully deployed to {server['hostname']}")
    
    def rolling_deployment(self):
        """Perform rolling deployment across all servers."""
        for server in self.servers:
            try:
                self.deploy_to_server(server)
                time.sleep(30)  # Wait between deployments
            except Exception as e:
                print(f"❌ Deployment failed for {server['hostname']}: {e}")
                return False
        
        print("🎉 Rolling deployment completed successfully!")
        return True

def main():
    deployer = ProductionDeployer()
    success = deployer.rolling_deployment()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
```

This comprehensive CI/CD pipeline provides:

- **Multi-platform support** for Linux, Windows, and macOS
- **Hybrid architecture builds** combining Rust engine and Python packaging
- **Security-first approach** with automated vulnerability scanning
- **Compliance validation** ensuring enterprise standards
- **Rolling deployments** for zero-downtime updates
- **Comprehensive testing** across multiple Python and Rust versions

The pipeline ensures high-quality, secure releases while maintaining compliance with enterprise standards.

1. **Automated Quality Assurance**: Code formatting, linting, security scanning
2. **Multi-Platform Building**: Support for Linux, Windows, and macOS
3. **Comprehensive Testing**: Unit tests, integration tests, compliance validation
4. **Security Integration**: SAST, dependency scanning, compliance checks
5. **Automated Deployment**: Staging and production deployment automation
6. **Release Management**: Version bumping, changelog generation, tagging
7. **Monitoring Integration**: Health checks, notifications, reporting

The pipeline ensures high-quality, secure releases while maintaining compliance with enterprise standards.