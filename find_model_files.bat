@echo off
setlocal enabledelayedexpansion
set OUT=%~dp0find_model_files_results.txt
echo Searching for .pkl files and training datasets... > "%OUT%"
echo This may take a minute or two. >> "%OUT%"
echo. >> "%OUT%"

echo ================================================ >> "%OUT%"
echo  .pkl files anywhere on C:\Users >> "%OUT%"
echo ================================================ >> "%OUT%"
dir /s /b "C:\Users\*.pkl" 2>nul >> "%OUT%"

echo. >> "%OUT%"
echo ================================================ >> "%OUT%"
echo  .pkl files on D:, E:, F:, G: >> "%OUT%"
echo ================================================ >> "%OUT%"
for %%D in (D E F G) do (
    if exist %%D:\ (
        dir /s /b "%%D:\*.pkl" 2>nul >> "%OUT%"
    )
)

echo. >> "%OUT%"
echo ================================================ >> "%OUT%"
echo  training_ready.csv / ot_training_ready.csv anywhere on C:\Users, D:, E:, F:, G: >> "%OUT%"
echo ================================================ >> "%OUT%"
dir /s /b "C:\Users\training_ready.csv" 2>nul >> "%OUT%"
dir /s /b "C:\Users\ot_training_ready.csv" 2>nul >> "%OUT%"
for %%D in (D E F G) do (
    if exist %%D:\ (
        dir /s /b "%%D:\training_ready.csv" 2>nul >> "%OUT%"
        dir /s /b "%%D:\ot_training_ready.csv" 2>nul >> "%OUT%"
    )
)

echo. >> "%OUT%"
echo ================================================ >> "%OUT%"
echo  Any folder literally named "model" on D:, E:, F:, G: >> "%OUT%"
echo ================================================ >> "%OUT%"
for %%D in (D E F G) do (
    if exist %%D:\ (
        dir /s /b /ad "%%D:\model" 2>nul >> "%OUT%"
    )
)

echo. >> "%OUT%"
echo ================================================ >> "%OUT%"
echo  Any folder named "CAVE-OT Datasets" or containing "Datasets" on D:, E:, F:, G: >> "%OUT%"
echo ================================================ >> "%OUT%"
for %%D in (D E F G) do (
    if exist %%D:\ (
        dir /s /b /ad "%%D:\*Datasets*" 2>nul >> "%OUT%"
        dir /s /b /ad "%%D:\*CAVE-OT*" 2>nul >> "%OUT%"
    )
)

echo. >> "%OUT%"
echo DONE. >> "%OUT%"

echo Search complete. Opening results...
notepad "%OUT%"
