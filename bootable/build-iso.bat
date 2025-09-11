@echo off
REM PurgeProof Bootable ISO Builder for Windows
REM 
REM This script creates a Windows PE (WinPE) based bootable environment
REM with PurgeProof pre-installed for offline data sanitization.
REM 
REM Requirements:
REM   - Windows Assessment and Deployment Kit (ADK)
REM   - Windows PE add-on for ADK
REM   - Administrative privileges
REM 
REM Usage:
REM   build-iso.bat [options]
REM 
REM Options:
REM   /arch:<arch>        Target architecture (x64, x86, arm64)
REM   /output:<path>      Output ISO file path
REM   /minimal           Create minimal ISO (CLI only)
REM   /gui               Include GUI interfaces
REM   /help              Show this help message

setlocal enabledelayedexpansion

:: Configuration
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%..\"
set "BUILD_DIR=%SCRIPT_DIR%build"
set "ISO_NAME=purgeproof-winpe"
set "WINPE_ARCH=amd64"
set "OUTPUT_PATH=%SCRIPT_DIR%\%ISO_NAME%-%WINPE_ARCH%.iso"
set "MINIMAL=false"
set "INCLUDE_GUI=false"

:: Colors (using PowerShell for colored output)
set "RED=[31m"
set "GREEN=[32m"
set "YELLOW=[33m"
set "BLUE=[34m"
set "NC=[0m"

:: Logging functions
goto :main

:log_info
    powershell -Command "Write-Host '[INFO] %~1' -ForegroundColor Blue"
    goto :eof

:log_success
    powershell -Command "Write-Host '[SUCCESS] %~1' -ForegroundColor Green"
    goto :eof

:log_warning
    powershell -Command "Write-Host '[WARNING] %~1' -ForegroundColor Yellow"
    goto :eof

:log_error
    powershell -Command "Write-Host '[ERROR] %~1' -ForegroundColor Red"
    goto :eof

:show_help
    echo PurgeProof Bootable ISO Builder for Windows
    echo.
    echo Usage: build-iso.bat [options]
    echo.
    echo Options:
    echo   /arch:^<arch^>        Target architecture (amd64, x86, arm64) [default: amd64]
    echo   /output:^<path^>      Output ISO file path [default: ./purgeproof-winpe-amd64.iso]
    echo   /minimal             Create minimal ISO (CLI only)
    echo   /gui                 Include GUI interfaces
    echo   /help                Show this help message
    echo.
    echo Examples:
    echo   build-iso.bat                                    # Basic ISO
    echo   build-iso.bat /gui /output:C:\temp\purgeproof.iso # GUI ISO
    echo   build-iso.bat /minimal /arch:x86                 # Minimal 32-bit ISO
    echo.
    echo Requirements:
    echo   - Administrative privileges
    echo   - Windows Assessment and Deployment Kit (ADK)
    echo   - Windows PE add-on for ADK
    echo   - At least 4GB free disk space
    echo.
    goto :eof

:parse_args
    if "%~1"=="" goto :eof
    
    if /i "%~1"=="/help" (
        call :show_help
        exit /b 0
    )
    
    if /i "%~1"=="/minimal" (
        set "MINIMAL=true"
        shift
        goto :parse_args
    )
    
    if /i "%~1"=="/gui" (
        set "INCLUDE_GUI=true"
        shift
        goto :parse_args
    )
    
    if "%~1" neq "" if "%~1:~0,6%"=="/arch:" (
        set "WINPE_ARCH=%~1:~6%"
        set "OUTPUT_PATH=%SCRIPT_DIR%\%ISO_NAME%-%WINPE_ARCH%.iso"
        shift
        goto :parse_args
    )
    
    if "%~1" neq "" if "%~1:~0,8%"=="/output:" (
        set "OUTPUT_PATH=%~1:~8%"
        shift
        goto :parse_args
    )
    
    call :log_error "Unknown option: %~1"
    call :show_help
    exit /b 1

:check_prerequisites
    call :log_info "Checking prerequisites..."
    
    :: Check if running as administrator
    net session >nul 2>&1
    if %errorlevel% neq 0 (
        call :log_error "This script must be run as Administrator"
        exit /b 1
    )
    
    :: Check for Windows ADK
    set "ADK_PATH="
    for %%i in ("C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\%WINPE_ARCH%\DISM\dism.exe") do (
        if exist "%%i" set "ADK_PATH=%%~dpi"
    )
    
    if not defined ADK_PATH (
        call :log_error "Windows Assessment and Deployment Kit (ADK) not found"
        call :log_info "Download and install from: https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install"
        exit /b 1
    )
    
    :: Check for WinPE add-on
    set "WINPE_PATH="
    for %%i in ("C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\%WINPE_ARCH%\en-us\winpe.wim") do (
        if exist "%%i" set "WINPE_PATH=%%~dpi"
    )
    
    if not defined WINPE_PATH (
        call :log_error "Windows PE add-on for ADK not found"
        call :log_info "Download and install from: https://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install"
        exit /b 1
    )
    
    :: Check disk space (need at least 4GB)
    for /f "tokens=3" %%a in ('dir "%SCRIPT_DIR%" /-c ^| findstr /C:" bytes free"') do set "FREE_BYTES=%%a"
    set /a "REQUIRED_BYTES=4294967296"
    if %FREE_BYTES% lss %REQUIRED_BYTES% (
        call :log_error "Insufficient disk space. Need at least 4GB"
        exit /b 1
    )
    
    call :log_success "Prerequisites check passed"
    goto :eof

:clean_build
    call :log_info "Cleaning previous build artifacts..."
    
    if exist "%BUILD_DIR%" (
        rmdir /s /q "%BUILD_DIR%" 2>nul
    )
    
    mkdir "%BUILD_DIR%\mount" 2>nul
    mkdir "%BUILD_DIR%\media" 2>nul
    mkdir "%BUILD_DIR%\iso" 2>nul
    
    call :log_success "Build directory prepared"
    goto :eof

:create_winpe_base
    call :log_info "Creating Windows PE base image..."
    
    :: Copy WinPE files
    call copype %WINPE_ARCH% "%BUILD_DIR%\winpe"
    
    :: Mount the WIM file
    dism /Mount-Wim /WimFile:"%BUILD_DIR%\winpe\media\sources\boot.wim" /Index:1 /MountDir:"%BUILD_DIR%\mount"
    
    call :log_success "Windows PE base image created"
    goto :eof

:install_python
    call :log_info "Installing Python in WinPE..."
    
    :: Download and install Python (embedded version)
    set "PYTHON_URL=https://www.python.org/ftp/python/3.11.0/python-3.11.0-embed-amd64.zip"
    set "PYTHON_DIR=%BUILD_DIR%\mount\python"
    
    mkdir "%PYTHON_DIR%"
    
    :: Use PowerShell to download Python
    powershell -Command "Invoke-WebRequest -Uri '%PYTHON_URL%' -OutFile '%BUILD_DIR%\python.zip'"
    
    :: Extract Python
    powershell -Command "Expand-Archive -Path '%BUILD_DIR%\python.zip' -DestinationPath '%PYTHON_DIR%'"
    
    :: Install pip
    powershell -Command "Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile '%PYTHON_DIR%\get-pip.py'"
    
    call :log_success "Python installed"
    goto :eof

:install_utilities
    call :log_info "Installing disk utilities..."
    
    :: Copy diskpart and other utilities (already available in WinPE)
    :: Add any additional utilities here
    
    :: Create utility scripts
    echo @echo off > "%BUILD_DIR%\mount\Windows\System32\list-disks.bat"
    echo echo Available disks: >> "%BUILD_DIR%\mount\Windows\System32\list-disks.bat"
    echo diskpart /s list-disk.txt >> "%BUILD_DIR%\mount\Windows\System32\list-disks.bat"
    
    echo list disk > "%BUILD_DIR%\mount\Windows\System32\list-disk.txt"
    echo exit >> "%BUILD_DIR%\mount\Windows\System32\list-disk.txt"
    
    call :log_success "Utilities installed"
    goto :eof

:install_purgeproof
    call :log_info "Installing PurgeProof application..."
    
    :: Copy PurgeProof to WinPE
    xcopy "%PROJECT_ROOT%\wipeit" "%BUILD_DIR%\mount\purgeproof\" /E /I /H /Y
    copy "%PROJECT_ROOT%\launcher.py" "%BUILD_DIR%\mount\purgeproof\"
    
    :: Create launcher batch file
    echo @echo off > "%BUILD_DIR%\mount\Windows\System32\purgeproof.bat"
    echo cd /d \purgeproof >> "%BUILD_DIR%\mount\Windows\System32\purgeproof.bat"
    echo \python\python.exe launcher.py %%* >> "%BUILD_DIR%\mount\Windows\System32\purgeproof.bat"
    
    :: Create desktop shortcut (if GUI enabled)
    if "%INCLUDE_GUI%"=="true" (
        echo [Desktop Entry] > "%BUILD_DIR%\mount\Users\Default\Desktop\PurgeProof.lnk"
        echo Name=PurgeProof Data Sanitizer >> "%BUILD_DIR%\mount\Users\Default\Desktop\PurgeProof.lnk"
        echo Exec=purgeproof.bat --gui >> "%BUILD_DIR%\mount\Users\Default\Desktop\PurgeProof.lnk"
    )
    
    :: Install Python dependencies
    "%BUILD_DIR%\mount\python\python.exe" -m pip install --target "%BUILD_DIR%\mount\python\Lib\site-packages" cryptography psutil pyserial reportlab qrcode Pillow click colorama
    
    if "%INCLUDE_GUI%"=="true" (
        "%BUILD_DIR%\mount\python\python.exe" -m pip install --target "%BUILD_DIR%\mount\python\Lib\site-packages" PyQt6
    )
    
    call :log_success "PurgeProof installed"
    goto :eof

:configure_startup
    call :log_info "Configuring startup..."
    
    :: Create startup script
    echo @echo off > "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo echo. >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo echo ================================================ >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo echo    PurgeProof Data Sanitization Environment >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo echo ================================================ >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo echo. >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo echo Type 'purgeproof' to start the application >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo echo Type 'purgeproof --help' for usage information >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo echo. >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    echo cmd.exe >> "%BUILD_DIR%\mount\Windows\System32\startnet.cmd"
    
    call :log_success "Startup configured"
    goto :eof

:build_iso
    call :log_info "Building final ISO image..."
    
    :: Commit changes to WIM
    dism /Unmount-Wim /MountDir:"%BUILD_DIR%\mount" /Commit
    
    :: Create ISO structure
    xcopy "%BUILD_DIR%\winpe\media\*" "%BUILD_DIR%\iso\" /E /I /H /Y
    
    :: Create ISO with oscdimg
    oscdimg -n -m -b"%BUILD_DIR%\iso\boot\etfsboot.com" "%BUILD_DIR%\iso" "%OUTPUT_PATH%"
    
    call :log_success "ISO built successfully: %OUTPUT_PATH%"
    goto :eof

:cleanup
    call :log_info "Cleaning up..."
    
    :: Unmount any remaining images
    dism /Cleanup-Wim >nul 2>&1
    
    :: Remove build directory if requested
    if "%CLEANUP_BUILD%"=="true" (
        rmdir /s /q "%BUILD_DIR%" 2>nul
    )
    goto :eof

:main
    :: Parse command line arguments
    call :parse_args %*
    
    call :log_info "PurgeProof Bootable ISO Builder for Windows starting..."
    echo Target: %WINPE_ARCH% architecture
    echo Output: %OUTPUT_PATH%
    echo Features: %INCLUDE_GUI% GUI, %MINIMAL% Minimal
    echo.
    
    :: Build steps
    call :check_prerequisites
    if errorlevel 1 exit /b 1
    
    call :clean_build
    if errorlevel 1 exit /b 1
    
    call :create_winpe_base
    if errorlevel 1 exit /b 1
    
    call :install_python
    if errorlevel 1 exit /b 1
    
    call :install_utilities
    if errorlevel 1 exit /b 1
    
    call :install_purgeproof
    if errorlevel 1 exit /b 1
    
    call :configure_startup
    if errorlevel 1 exit /b 1
    
    call :build_iso
    if errorlevel 1 exit /b 1
    
    call :cleanup
    
    call :log_success "PurgeProof bootable ISO created successfully!"
    call :log_info "ISO file: %OUTPUT_PATH%"
    
    echo.
    echo Usage instructions:
    echo 1. Write ISO to USB drive using Rufus or similar tool
    echo 2. Boot from USB drive
    echo 3. Wait for Windows PE to load
    echo 4. Type 'purgeproof' to start the application
    echo.
    echo Security notes:
    echo - This is a live system - no data is persisted
    echo - Network drivers may need to be added for network access
    echo - All sanitization operations require explicit confirmation

endlocal
exit /b 0
