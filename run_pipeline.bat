@echo off
REM CAVE-OT Pipeline Runner for Windows
REM Runs the complete CVE mapping and risk scoring pipeline

echo ============================================================
echo CAVE-OT PIPELINE RUNNER
echo ============================================================
echo.

REM Check if model_input.json exists
if not exist model_input.json (
    echo [ERROR] model_input.json not found
    echo Please create model_input.json with device data first
    echo.
    pause
    exit /b 1
)

REM Check if models are trained
if not exist "D:\Downloads\CAVE-OT Datasets\model\ot_vectorizer.pkl" (
    echo [ERROR] Models not trained yet
    echo Please run: python model_trainer.py
    echo.
    pause
    exit /b 1
)

echo [1/2] Running CVE Mapper...
echo ------------------------------------------------------------
python cve_mapper.py
if errorlevel 1 (
    echo [ERROR] CVE Mapper failed
    pause
    exit /b 1
)

echo.
echo [2/2] Running Risk Scorer...
echo ------------------------------------------------------------
python risk_scorer.py
if errorlevel 1 (
    echo [ERROR] Risk Scorer failed
    pause
    exit /b 1
)

echo.
echo ============================================================
echo PIPELINE COMPLETE
echo ============================================================
echo Results saved to: model_input.json
echo.
pause
