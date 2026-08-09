@echo off
REM CAVE-OT CVE Model Updater
REM Fetches new/changed CVEs since the last run (NVD API + EPSS + CISA KEV),
REM merges them in, and retrains model\*.pkl. Safe to run manually or on a
REM schedule (Task Scheduler) — deliberately has NO pause below, since a
REM pause would hang forever waiting for a keypress under an unattended run.

cd /d "%~dp0"

echo ============================================================
echo CAVE-OT CVE MODEL UPDATE
echo ============================================================
echo.

python Data_Processing\update_cve_data.py %*

if errorlevel 1 (
    echo.
    echo [ERROR] Update failed — model\*.pkl left unchanged from last successful run.
    exit /b 1
)

echo.
echo ============================================================
echo UPDATE COMPLETE
echo ============================================================
