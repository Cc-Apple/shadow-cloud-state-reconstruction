@echo off
chcp 65001 >nul
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

set "DIR=%~dp0"
set "SCRIPT=%DIR%33b_final_reconstruction_seal_fixed.py"

echo Running 33b Final Reconstruction Seal Fixed...
python "%SCRIPT%"

if errorlevel 1 (
  echo.
  echo [FAILED]
  pause
  exit /b 1
)

echo.
echo [OK] Finished 33b Final Reconstruction Seal Fixed.
echo Output: C:\Users\Administrator\Desktop\Result\SC_Final_33b_RECONSTRUCTION_SEAL_FIXED
pause
