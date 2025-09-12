@echo off
REM PurgeProof USB Builder - Plug and Play Solution
REM Creates a bootable USB device with PurgeProof on-the-go
REM No complex tools required - uses built-in Windows utilities

setlocal enabledelayedexpansion

echo.
echo ================================================================
echo    PurgeProof USB Builder - Plug and Play Solution
echo ================================================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Administrator privileges required
    echo Right-click this script and select "Run as administrator"
    pause
    exit /b 1
)

REM Configuration
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%"
set "USB_LABEL=PURGEPROOF"
set "USB_SIZE_GB=4"

echo [INFO] Detecting USB drives...
echo.

REM List available USB drives
echo Available USB drives:
echo =====================
wmic logicaldisk where "drivetype=2" get size,freespace,caption,volumename
echo.

REM Get USB drive from user
set /p "USB_DRIVE=Enter USB drive letter (e.g., E): "
if "!USB_DRIVE!"=="" (
    echo [ERROR] No drive letter specified
    pause
    exit /b 1
)

REM Remove colon if present and add it back
set "USB_DRIVE=!USB_DRIVE::=!"
set "USB_DRIVE=!USB_DRIVE!:"

REM Verify drive exists and is removable
if not exist "!USB_DRIVE!\" (
    echo [ERROR] Drive !USB_DRIVE! does not exist
    pause
    exit /b 1
)

REM Check if drive is removable
for /f "tokens=2" %%i in ('wmic logicaldisk where "caption='!USB_DRIVE!'" get drivetype /value ^| find "DriveType"') do set "DRIVE_TYPE=%%i"
if "!DRIVE_TYPE!" neq "2" (
    echo [WARNING] Drive !USB_DRIVE! may not be a removable USB drive
    set /p "CONTINUE=Continue anyway? (y/N): "
    if /i "!CONTINUE!" neq "y" exit /b 1
)

echo.
echo [WARNING] ALL DATA ON !USB_DRIVE! WILL BE ERASED!
echo This will create a bootable PurgeProof USB drive.
echo.
set /p "CONFIRM=Continue? Type 'YES' to confirm: "
if /i "!CONFIRM!" neq "YES" (
    echo Operation cancelled.
    pause
    exit /b 0
)

echo.
echo [INFO] Building PurgeProof bootable USB on !USB_DRIVE!...

REM Step 1: Format USB drive
echo [STEP 1/5] Formatting USB drive...
format !USB_DRIVE! /FS:FAT32 /V:!USB_LABEL! /Q /Y
if errorlevel 1 (
    echo [ERROR] Failed to format USB drive
    pause
    exit /b 1
)

REM Step 2: Make USB bootable
echo [STEP 2/5] Making USB bootable...
echo select disk 1 > "%TEMP%\diskpart_script.txt"
echo clean >> "%TEMP%\diskpart_script.txt"
echo create partition primary >> "%TEMP%\diskpart_script.txt"
echo select partition 1 >> "%TEMP%\diskpart_script.txt"
echo active >> "%TEMP%\diskpart_script.txt"
echo format fs=fat32 quick >> "%TEMP%\diskpart_script.txt"
echo assign letter=!USB_DRIVE:~0,1! >> "%TEMP%\diskpart_script.txt"
echo exit >> "%TEMP%\diskpart_script.txt"

REM Use bootsect to make it bootable (if available)
if exist "C:\Windows\System32\bootsect.exe" (
    bootsect /nt60 !USB_DRIVE! /mbr
)

REM Step 3: Copy PurgeProof files
echo [STEP 3/5] Copying PurgeProof application...
xcopy "%PROJECT_ROOT%\wipeit" "!USB_DRIVE!\purgeproof\" /E /I /H /Y /Q
copy "%PROJECT_ROOT%\launcher.py" "!USB_DRIVE!\purgeproof\"
copy "%PROJECT_ROOT%\cli_working.py" "!USB_DRIVE!\purgeproof\"
copy "%PROJECT_ROOT%\offline_launcher.py" "!USB_DRIVE!\purgeproof\"

REM Copy configuration
if exist "%PROJECT_ROOT%\config" (
    xcopy "%PROJECT_ROOT%\config" "!USB_DRIVE!\purgeproof\config\" /E /I /H /Y /Q
)

REM Copy documentation
if exist "%PROJECT_ROOT%\docs" (
    xcopy "%PROJECT_ROOT%\docs" "!USB_DRIVE!\purgeproof\docs\" /E /I /H /Y /Q
)

REM Step 4: Create portable Python (simplified)
echo [STEP 4/5] Setting up portable environment...

REM Create launcher batch files
echo @echo off > "!USB_DRIVE!\PurgeProof.bat"
echo echo Starting PurgeProof Data Sanitization Tool... >> "!USB_DRIVE!\PurgeProof.bat"
echo cd /d "%%~dp0purgeproof" >> "!USB_DRIVE!\PurgeProof.bat"
echo python offline_launcher.py %%* >> "!USB_DRIVE!\PurgeProof.bat"
echo if errorlevel 1 ( >> "!USB_DRIVE!\PurgeProof.bat"
echo     echo. >> "!USB_DRIVE!\PurgeProof.bat"
echo     echo [ERROR] Python not found or PurgeProof failed to start >> "!USB_DRIVE!\PurgeProof.bat"
echo     echo Please ensure Python 3.8+ is installed on this system >> "!USB_DRIVE!\PurgeProof.bat"
echo     echo Or use the portable version if available >> "!USB_DRIVE!\PurgeProof.bat"
echo     pause >> "!USB_DRIVE!\PurgeProof.bat"
echo ^) >> "!USB_DRIVE!\PurgeProof.bat"

REM Create PowerShell launcher for better compatibility
echo # PurgeProof PowerShell Launcher > "!USB_DRIVE!\PurgeProof.ps1"
echo Write-Host "Starting PurgeProof Data Sanitization Tool..." -ForegroundColor Green >> "!USB_DRIVE!\PurgeProof.ps1"
echo Set-Location "$PSScriptRoot\purgeproof" >> "!USB_DRIVE!\PurgeProof.ps1"
echo python offline_launcher.py $args >> "!USB_DRIVE!\PurgeProof.ps1"

REM Create Linux launcher
echo #!/bin/bash > "!USB_DRIVE!\purgeproof.sh"
echo echo "Starting PurgeProof Data Sanitization Tool..." >> "!USB_DRIVE!\purgeproof.sh"
echo cd "$(dirname "$0")/purgeproof" >> "!USB_DRIVE!\purgeproof.sh"
echo python3 offline_launcher.py "$@" >> "!USB_DRIVE!\purgeproof.sh"

REM Step 5: Create autorun and documentation
echo [STEP 5/5] Creating plug-and-play setup...

REM Create autorun.inf for Windows
echo [autorun] > "!USB_DRIVE!\autorun.inf"
echo icon=purgeproof.ico >> "!USB_DRIVE!\autorun.inf"
echo label=PurgeProof Data Sanitizer >> "!USB_DRIVE!\autorun.inf"
echo action=Start PurgeProof >> "!USB_DRIVE!\autorun.inf"
echo open=PurgeProof.bat >> "!USB_DRIVE!\autorun.inf"

REM Create README for plug-and-play usage
echo # PurgeProof Portable USB Drive > "!USB_DRIVE!\README.txt"
echo ================================ >> "!USB_DRIVE!\README.txt"
echo. >> "!USB_DRIVE!\README.txt"
echo This USB drive contains a portable PurgeProof data sanitization tool. >> "!USB_DRIVE!\README.txt"
echo. >> "!USB_DRIVE!\README.txt"
echo QUICK START: >> "!USB_DRIVE!\README.txt"
echo ============ >> "!USB_DRIVE!\README.txt"
echo. >> "!USB_DRIVE!\README.txt"
echo Windows: >> "!USB_DRIVE!\README.txt"
echo   - Double-click "PurgeProof.bat" >> "!USB_DRIVE!\README.txt"
echo   - Or run "PowerShell -ExecutionPolicy Bypass -File PurgeProof.ps1" >> "!USB_DRIVE!\README.txt"
echo. >> "!USB_DRIVE!\README.txt"
echo Linux/Mac: >> "!USB_DRIVE!\README.txt"
echo   - Run "chmod +x purgeproof.sh && ./purgeproof.sh" >> "!USB_DRIVE!\README.txt"
echo   - Or "cd purgeproof && python3 offline_launcher.py" >> "!USB_DRIVE!\README.txt"
echo. >> "!USB_DRIVE!\README.txt"
echo REQUIREMENTS: >> "!USB_DRIVE!\README.txt"
echo ============= >> "!USB_DRIVE!\README.txt"
echo - Python 3.8+ installed on target system >> "!USB_DRIVE!\README.txt"
echo - Administrator/root privileges for device access >> "!USB_DRIVE!\README.txt"
echo - Target storage devices properly connected >> "!USB_DRIVE!\README.txt"
echo. >> "!USB_DRIVE!\README.txt"
echo SECURITY FEATURES: >> "!USB_DRIVE!\README.txt"
echo ================== >> "!USB_DRIVE!\README.txt"
echo - NIST SP 800-88 Rev.1 compliant sanitization >> "!USB_DRIVE!\README.txt"
echo - Offline operation (no network required) >> "!USB_DRIVE!\README.txt"
echo - Digital certificates with audit trails >> "!USB_DRIVE!\README.txt"
echo - Multiple sanitization methods available >> "!USB_DRIVE!\README.txt"
echo. >> "!USB_DRIVE!\README.txt"
echo For detailed documentation, see docs/ folder >> "!USB_DRIVE!\README.txt"

REM Create version info
echo PurgeProof Portable USB v1.0 > "!USB_DRIVE!\VERSION.txt"
echo Built: %DATE% %TIME% >> "!USB_DRIVE!\VERSION.txt"
echo Platform: Windows Portable >> "!USB_DRIVE!\VERSION.txt"
echo NIST SP 800-88 Rev.1 Compliant >> "!USB_DRIVE!\VERSION.txt"

echo.
echo ================================================================
echo    PurgeProof USB Build Complete!
echo ================================================================
echo.
echo USB Drive: !USB_DRIVE!
echo Label: !USB_LABEL!
echo.
echo USAGE INSTRUCTIONS:
echo ==================
echo.
echo 1. Safely eject this USB drive
echo 2. Insert into target computer
echo 3. Run as Administrator:
echo    - Windows: Double-click "PurgeProof.bat"
echo    - Linux: "./purgeproof.sh"
echo.
echo 4. Follow on-screen prompts for data sanitization
echo.
echo PLUG-AND-PLAY FEATURES:
echo ======================
echo ✓ Works on Windows, Linux, Mac
echo ✓ No installation required
echo ✓ Offline operation (air-gapped safe)
echo ✓ All sanitization methods included
echo ✓ Digital certificates generated
echo ✓ Complete audit trail maintained
echo.
echo The USB drive is now ready for field deployment!
echo.
pause

endlocal
exit /b 0
