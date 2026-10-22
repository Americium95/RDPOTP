@echo off
if not defined RDP_NOTIFY_URL exit /b 2
if /i "%RDP_OTP_STDIN%"=="1" (
  curl --fail --silent --show-error --max-time 6 ^
    -H "Title: RDPOTP" ^
    -H "Icon: https://img.icons8.com/?size=100&id=VInVwRr6GbDx&format=png&color=00bcc2" ^
    --data-binary @- ^
    "%RDP_NOTIFY_URL%" >nul 2>&1
  if errorlevel 1 exit /b 1
  exit /b 0
)
curl ^
  -H "Title: RDPOTP" ^
  -H "Icon: https://img.icons8.com/?size=100&id=VInVwRr6GbDx&format=png&color=00bcc2" ^
  -d "로그인이 시도되었습니다." ^
  "%RDP_NOTIFY_URL%"
