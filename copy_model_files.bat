@echo off
set SRC=E:\Univeristy\Semester 7\FYP\CAVE-OT\CAVE-OT Datasets_KIRO\CAVE-OT Datasets

echo ================================================
echo  Copying trained model + policy model files in
echo  from your E: drive into both project folders
echo ================================================

echo.
echo [1/4] CAVE-OT-docker-main : model\
mkdir "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\model" 2>nul
xcopy /Y /I "%SRC%\model\*.pkl" "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\model\"

echo.
echo [2/4] CAVE-OT-docker-main : Policy_Compliance\models\
mkdir "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\Policy_Compliance\models" 2>nul
xcopy /Y /I "%SRC%\Policy_Compliance\models\*.pkl" "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\Policy_Compliance\models\"

echo.
echo [3/4] FYP_CAVE-OT--main : model\
mkdir "F:\FYP_CAVE-OT--main\FYP_CAVE-OT--main\model" 2>nul
xcopy /Y /I "%SRC%\model\*.pkl" "F:\FYP_CAVE-OT--main\FYP_CAVE-OT--main\model\"

echo.
echo [4/4] FYP_CAVE-OT--main : Policy_Compliance\models\
mkdir "F:\FYP_CAVE-OT--main\FYP_CAVE-OT--main\Policy_Compliance\models" 2>nul
xcopy /Y /I "%SRC%\Policy_Compliance\models\*.pkl" "F:\FYP_CAVE-OT--main\FYP_CAVE-OT--main\Policy_Compliance\models\"

echo.
echo ================================================
echo  Also copying the source datasets, in case you
echo  ever need to retrain
echo ================================================
mkdir "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\Datasets" 2>nul
xcopy /Y /I "%SRC%\Datasets\training_ready.csv" "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\Datasets\"
xcopy /Y /I "%SRC%\Datasets\ot_training_ready.csv" "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\Datasets\"

echo.
echo DONE.
echo.
echo Verifying:
dir "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\model"
dir "F:\CAVE-OT-docker-main\CAVE-OT-docker-main\Policy_Compliance\models"
pause
