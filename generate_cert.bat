@echo off
setlocal
cd /d "%~dp0" || exit /b 1

if exist "rdp.crt" goto check_key
if exist "rdp.key" goto incomplete_pair
goto generate

:check_key
if exist "rdp.key" goto already_ready
goto incomplete_pair

:already_ready
echo RDP certificate and key already exist; leaving them unchanged.
exit /b 0

:generate
where openssl >nul 2>&1
if errorlevel 1 (
    echo OpenSSL was not found in PATH.
    echo Install OpenSSL or add its bin folder to PATH, then run this file again.
    exit /b 1
)

echo Creating a 1-year self-signed RDP certificate for localhost...
openssl req -x509 -newkey rsa:2048 -nodes -keyout "%~dp0rdp.key" -out "%~dp0rdp.crt" -days 365 -subj "/CN=rdp-local" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
if errorlevel 1 goto generate_failed
if not exist "rdp.crt" goto generate_failed
if not exist "rdp.key" goto generate_failed
echo Certificate created: rdp.crt
exit /b 0

:incomplete_pair
echo Only one of rdp.crt and rdp.key exists. Refusing to overwrite either file.
echo Review or remove the incomplete certificate pair, then run this file again.
exit /b 1

:generate_failed
del /q "%~dp0rdp.key" "%~dp0rdp.crt" >nul 2>&1
echo Certificate generation failed; partial output was removed.
exit /b 1
