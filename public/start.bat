@echo off
set HOST=%1
if "%HOST%"=="" (
  echo Usage: start.bat your-server.workers.dev
  exit /b 1
)
where node >nul 2>nul
if errorlevel 1 (
  echo Installing Node.js, please wait...
  winget install -e --id OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements
  echo.
  echo Node.js installed. CLOSE this window, open a NEW cmd and run the same command again.
  pause
  exit /b
)
if not exist "%USERPROFILE%\.securemsg" mkdir "%USERPROFILE%\.securemsg"
curl -sLo "%USERPROFILE%\.securemsg\client.js" https://%HOST%/client.js
node "%USERPROFILE%\.securemsg\client.js" wss://%HOST%
