@echo off
echo ================================================
echo  CAVE-OT Complete System Manager
echo ================================================
echo.

echo 1. Checking Docker containers...
cd /d "%~dp0docker"
docker ps | findstr "caveot"
if %errorlevel% neq 0 (
    echo   WARNING: Docker containers not running!
    echo   Starting Docker stack...
    docker compose up -d
    timeout /t 10 /nobreak > nul
) else (
    echo   SUCCESS: Docker containers are running
)

echo.
echo 2. Starting File Watcher...
start "CAVE-OT File Watcher" cmd /k "cd /d "%~dp0" && python file_watcher.py"
timeout /t 2 /nobreak > nul

echo.
echo 3. Checking Dashboard...
tasklist | findstr "python" | findstr "app.py" > nul
if %errorlevel% neq 0 (
    echo   Starting Dashboard...
    start "CAVE-OT Dashboard" cmd /k "cd /d "%~dp0" && python Dashboard/app.py"
    timeout /t 5 /nobreak > nul
) else (
    echo   Dashboard is already running
)

echo.
echo 3. System Status:
echo    - Docker Engine: Running (generating simulated OT traffic)
echo    - File Watcher: Monitoring JSON files
echo    - Database Sync: Ingesting data to PostgreSQL
echo    - Dashboard: http://localhost:5000
echo.
echo 4. Quick Test Commands:
echo    - Check Docker logs: docker logs -f caveot-engine
echo    - Check database: python check_database_fixed.py
echo    - View dashboard: http://localhost:5000
echo.
echo ================================================
echo  System is running! Press any key to exit...
echo ================================================
pause > nul