@echo off
echo ================================================
echo  CAVE-OT: Building and starting Docker stack
echo ================================================
cd /d "%~dp0docker"
docker compose up -d --build
echo.
echo ================================================
echo  Exit code: %errorlevel%
echo ================================================
pause
