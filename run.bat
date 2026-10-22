@echo off
setlocal

cd /d "%~dp0" || exit /b 1

call "%~dp0generate_cert.bat"
if errorlevel 1 exit /b 1

set "RDP_HTML=%~dp0pin_portal.html"
set "RDP_NOTIFY_BAT=%~dp0send_notify.bat"

where python >nul 2>&1
if errorlevel 1 (
    echo Python was not found in PATH.
    pause
    exit /b 1
)

for /f %%P in ('python settings.py server port') do set "PORT=%%P"
if not defined PORT (
    echo Could not read server port from config.ini.
    pause
    exit /b 1
)

powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }" >nul 2>&1
if errorlevel 1 (
    start "RDP Server" /D "%~dp0" cmd /k "python server.py %PORT%"
) else (
    echo RDP server is already listening on port %PORT%.
)

powershell -NoProfile -Command "$end=(Get-Date).AddSeconds(10); do { if (Get-NetTCPConnection -LocalPort %PORT% -State Listen -ErrorAction SilentlyContinue) { exit 0 }; Start-Sleep -Milliseconds 250 } while ((Get-Date) -lt $end); exit 1" >nul 2>&1
if errorlevel 1 (
    echo RDP server did not start on port %PORT%. Check the RDP Server window.
    pause
    exit /b 1
)

echo RDP gateway is ready on port %PORT%. MSTSC and any .rdp file were not started.

exit /b 0

