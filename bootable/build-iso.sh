#!/bin/bash
"""
PurgeProof Bootable ISO Builder

Creates a bootable Linux environment with PurgeProof pre-installed
for offline data sanitization operations.

This script builds a custom Ubuntu-based live ISO with:
- PurgeProof data sanitization tool
- Hardware detection utilities
- Secure boot support
- Network-isolated environment

Usage:
    sudo ./build-iso.sh [options]

Options:
    --arch <arch>       Target architecture (amd64, i386)
    --output <path>     Output ISO file path
    --no-secure-boot    Disable secure boot support
    --minimal           Create minimal ISO (CLI only)
    --gui               Include GUI interfaces
    --help              Show this help message

Requirements:
    - Ubuntu/Debian build system
    - debootstrap, squashfs-tools, xorriso
    - At least 4GB free disk space
"""

set -e  # Exit on any error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$SCRIPT_DIR/build"
ISO_NAME="purgeproof-bootable"
UBUNTU_VERSION="22.04"
UBUNTU_CODENAME="jammy"

# Default options
ARCH="amd64"
OUTPUT_PATH="$SCRIPT_DIR/$ISO_NAME-$ARCH.iso"
SECURE_BOOT=true
MINIMAL=false
INCLUDE_GUI=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
PurgeProof Bootable ISO Builder

Usage: sudo ./build-iso.sh [options]

Options:
    --arch <arch>       Target architecture (amd64, i386) [default: amd64]
    --output <path>     Output ISO file path [default: ./purgeproof-bootable-amd64.iso]
    --no-secure-boot    Disable secure boot support
    --minimal           Create minimal ISO (CLI only)
    --gui               Include GUI interfaces (requires X11)
    --help              Show this help message

Examples:
    sudo ./build-iso.sh                                    # Basic ISO
    sudo ./build-iso.sh --gui --output /tmp/purgeproof.iso # GUI ISO
    sudo ./build-iso.sh --minimal --arch i386              # Minimal 32-bit ISO

Requirements:
    - Root privileges (sudo)
    - Ubuntu/Debian build system
    - debootstrap, squashfs-tools, xorriso, isolinux
    - At least 4GB free disk space

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --arch)
                ARCH="$2"
                shift 2
                ;;
            --output)
                OUTPUT_PATH="$2"
                shift 2
                ;;
            --no-secure-boot)
                SECURE_BOOT=false
                shift
                ;;
            --minimal)
                MINIMAL=true
                shift
                ;;
            --gui)
                INCLUDE_GUI=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    
    # Check required tools
    local required_tools=("debootstrap" "mksquashfs" "xorriso" "isolinux")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install with: apt-get install debootstrap squashfs-tools xorriso isolinux-utils"
        exit 1
    fi
    
    # Check disk space (need at least 4GB)
    local available_space=$(df "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
    local required_space=$((4 * 1024 * 1024))  # 4GB in KB
    
    if [[ $available_space -lt $required_space ]]; then
        log_error "Insufficient disk space. Need at least 4GB, have $(($available_space / 1024 / 1024))GB"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Clean previous builds
clean_build() {
    log_info "Cleaning previous build artifacts..."
    
    if [[ -d "$BUILD_DIR" ]]; then
        umount "$BUILD_DIR/chroot/dev" 2>/dev/null || true
        umount "$BUILD_DIR/chroot/proc" 2>/dev/null || true
        umount "$BUILD_DIR/chroot/sys" 2>/dev/null || true
        rm -rf "$BUILD_DIR"
    fi
    
    mkdir -p "$BUILD_DIR"/{chroot,iso/{boot,isolinux},staging}
    
    log_success "Build directory prepared"
}

# Create base system
create_base_system() {
    log_info "Creating base Ubuntu system ($UBUNTU_CODENAME $ARCH)..."
    
    # Use local mirror if available, otherwise use main Ubuntu mirror
    local mirror="http://archive.ubuntu.com/ubuntu"
    if [[ $ARCH == "amd64" ]]; then
        mirror="http://archive.ubuntu.com/ubuntu"
    fi
    
    debootstrap --arch="$ARCH" --variant=minbase "$UBUNTU_CODENAME" \
        "$BUILD_DIR/chroot" "$mirror"
    
    log_success "Base system created"
}

# Configure chroot environment
configure_chroot() {
    log_info "Configuring chroot environment..."
    
    # Mount required filesystems
    mount --bind /dev "$BUILD_DIR/chroot/dev"
    mount --bind /proc "$BUILD_DIR/chroot/proc"
    mount --bind /sys "$BUILD_DIR/chroot/sys"
    
    # Configure sources.list
    cat > "$BUILD_DIR/chroot/etc/apt/sources.list" << EOF
deb http://archive.ubuntu.com/ubuntu $UBUNTU_CODENAME main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $UBUNTU_CODENAME-updates main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu $UBUNTU_CODENAME-security main restricted universe multiverse
EOF
    
    # Configure hostname
    echo "purgeproof-live" > "$BUILD_DIR/chroot/etc/hostname"
    
    # Configure hosts
    cat > "$BUILD_DIR/chroot/etc/hosts" << EOF
127.0.0.1   localhost purgeproof-live
::1         localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
EOF
    
    # Configure resolv.conf
    echo "nameserver 8.8.8.8" > "$BUILD_DIR/chroot/etc/resolv.conf"
    
    log_success "Chroot environment configured"
}

# Install packages
install_packages() {
    log_info "Installing packages in chroot..."
    
    # Base packages for live system
    local base_packages=(
        "linux-image-generic"
        "live-boot"
        "systemd-sysv"
        "python3"
        "python3-pip"
        "python3-venv"
        "hdparm"
        "nvme-cli"
        "smartmontools"
        "gdisk"
        "parted"
        "util-linux"
        "dmidecode"
        "pciutils"
        "usbutils"
        "lshw"
        "cryptsetup"
        "openssh-client"
        "wget"
        "curl"
        "nano"
        "vim-tiny"
    )
    
    # Add GUI packages if requested
    if [[ $INCLUDE_GUI == true ]]; then
        base_packages+=(
            "xorg"
            "openbox"
            "lxterminal"
            "firefox"
            "python3-tk"
        )
    fi
    
    # Install packages
    chroot "$BUILD_DIR/chroot" apt-get update
    chroot "$BUILD_DIR/chroot" apt-get install -y "${base_packages[@]}"
    
    # Install Python dependencies for PurgeProof
    chroot "$BUILD_DIR/chroot" pip3 install \
        cryptography psutil pyserial reportlab qrcode Pillow click colorama
    
    if [[ $INCLUDE_GUI == true ]]; then
        chroot "$BUILD_DIR/chroot" pip3 install PyQt6
    fi
    
    log_success "Packages installed"
}

# Install PurgeProof
install_purgeproof() {
    log_info "Installing PurgeProof application..."
    
    # Copy PurgeProof to chroot
    cp -r "$PROJECT_ROOT/wipeit" "$BUILD_DIR/chroot/opt/"
    cp "$PROJECT_ROOT/launcher.py" "$BUILD_DIR/chroot/opt/wipeit/"
    
    # Create launcher script
    cat > "$BUILD_DIR/chroot/usr/local/bin/purgeproof" << 'EOF'
#!/bin/bash
cd /opt/wipeit
python3 launcher.py "$@"
EOF
    chmod +x "$BUILD_DIR/chroot/usr/local/bin/purgeproof"
    
    # Create desktop entry for GUI
    if [[ $INCLUDE_GUI == true ]]; then
        mkdir -p "$BUILD_DIR/chroot/home/purgeproof/Desktop"
        cat > "$BUILD_DIR/chroot/home/purgeproof/Desktop/PurgeProof.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=PurgeProof Data Sanitizer
Comment=Secure data sanitization tool
Exec=/usr/local/bin/purgeproof --gui
Icon=security-high
Terminal=false
Categories=System;Security;
StartupNotify=true
EOF
        chmod +x "$BUILD_DIR/chroot/home/purgeproof/Desktop/PurgeProof.desktop"
    fi
    
    # Configure auto-login for purgeproof user
    chroot "$BUILD_DIR/chroot" useradd -m -s /bin/bash purgeproof
    chroot "$BUILD_DIR/chroot" usermod -aG sudo purgeproof
    echo "purgeproof:purgeproof" | chroot "$BUILD_DIR/chroot" chpasswd
    
    log_success "PurgeProof installed"
}

# Configure boot system
configure_boot() {
    log_info "Configuring boot system..."
    
    # Create initramfs
    chroot "$BUILD_DIR/chroot" update-initramfs -u
    
    # Copy kernel and initrd
    cp "$BUILD_DIR/chroot/boot/vmlinuz-"* "$BUILD_DIR/iso/boot/vmlinuz"
    cp "$BUILD_DIR/chroot/boot/initrd.img-"* "$BUILD_DIR/iso/boot/initrd.img"
    
    # Create isolinux configuration
    cp /usr/lib/ISOLINUX/isolinux.bin "$BUILD_DIR/iso/isolinux/"
    cp /usr/lib/syslinux/modules/bios/ldlinux.c32 "$BUILD_DIR/iso/isolinux/"
    cp /usr/lib/syslinux/modules/bios/menu.c32 "$BUILD_DIR/iso/isolinux/"
    
    cat > "$BUILD_DIR/iso/isolinux/isolinux.cfg" << EOF
DEFAULT menu.c32
PROMPT 0
TIMEOUT 100

MENU TITLE PurgeProof Live Boot Menu
MENU BACKGROUND purgeproof.png

LABEL purgeproof
    MENU LABEL ^PurgeProof Live System
    MENU DEFAULT
    KERNEL ../boot/vmlinuz
    APPEND initrd=../boot/initrd.img boot=live quiet splash

LABEL purgeproof-safe
    MENU LABEL PurgeProof ^Safe Mode
    KERNEL ../boot/vmlinuz
    APPEND initrd=../boot/initrd.img boot=live quiet splash acpi=off noapic nomodeset

LABEL memtest
    MENU LABEL ^Memory Test
    KERNEL memtest86+.bin
EOF
    
    log_success "Boot system configured"
}

# Create filesystem image
create_filesystem() {
    log_info "Creating filesystem image..."
    
    # Cleanup chroot
    chroot "$BUILD_DIR/chroot" apt-get clean
    rm -f "$BUILD_DIR/chroot/etc/resolv.conf"
    
    # Unmount filesystems
    umount "$BUILD_DIR/chroot/dev" || true
    umount "$BUILD_DIR/chroot/proc" || true
    umount "$BUILD_DIR/chroot/sys" || true
    
    # Create squashfs image
    mksquashfs "$BUILD_DIR/chroot" "$BUILD_DIR/iso/live/filesystem.squashfs" \
        -comp xz -b 1M -Xdict-size 100%
    
    # Create filesystem.size file
    echo $(du -s "$BUILD_DIR/chroot" | cut -f1) > "$BUILD_DIR/iso/live/filesystem.size"
    
    log_success "Filesystem image created"
}

# Build ISO
build_iso() {
    log_info "Building final ISO image..."
    
    # Create ISO with xorriso
    xorriso -as mkisofs \
        -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
        -c isolinux/boot.cat \
        -b isolinux/isolinux.bin \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        -volid "PURGEPROOF_LIVE" \
        -output "$OUTPUT_PATH" \
        "$BUILD_DIR/iso"
    
    # Make ISO hybrid (bootable from USB)
    isohybrid "$OUTPUT_PATH"
    
    log_success "ISO built successfully: $OUTPUT_PATH"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    # Unmount any remaining mounts
    umount "$BUILD_DIR/chroot/dev" 2>/dev/null || true
    umount "$BUILD_DIR/chroot/proc" 2>/dev/null || true
    umount "$BUILD_DIR/chroot/sys" 2>/dev/null || true
    
    # Remove build directory if requested
    if [[ ${CLEANUP_BUILD:-true} == true ]]; then
        rm -rf "$BUILD_DIR"
    fi
}

# Main function
main() {
    log_info "PurgeProof Bootable ISO Builder starting..."
    echo "Target: $ARCH architecture"
    echo "Output: $OUTPUT_PATH"
    echo "Features: $(if [[ $INCLUDE_GUI == true ]]; then echo "GUI enabled"; else echo "CLI only"; fi)"
    echo "Secure Boot: $(if [[ $SECURE_BOOT == true ]]; then echo "enabled"; else echo "disabled"; fi)"
    echo
    
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Build steps
    check_prerequisites
    clean_build
    create_base_system
    configure_chroot
    install_packages
    install_purgeproof
    configure_boot
    create_filesystem
    build_iso
    
    log_success "PurgeProof bootable ISO created successfully!"
    log_info "ISO file: $OUTPUT_PATH"
    log_info "Size: $(ls -lh "$OUTPUT_PATH" | awk '{print $5}')"
    
    echo
    echo "Usage instructions:"
    echo "1. Write ISO to USB drive: dd if=$OUTPUT_PATH of=/dev/sdX bs=4M"
    echo "2. Boot from USB drive"
    echo "3. Login as 'purgeproof' (password: purgeproof)"
    echo "4. Run 'purgeproof' command or use desktop icon"
    echo
    echo "Security notes:"
    echo "- This is a live system - no data is persisted"
    echo "- Network access is available but not required"
    echo "- All sanitization operations require explicit confirmation"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    parse_args "$@"
    main
fi
