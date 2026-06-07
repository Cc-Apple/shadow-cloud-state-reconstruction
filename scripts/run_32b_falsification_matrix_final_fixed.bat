@echo off
chcp 65001 >nul
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

set "DIR=%~dp0"
set "SCRIPT=%DIR%32b_falsification_matrix_final_fixed.py"

echo Running 32b Falsification Matrix Final Fixed...
python "%SCRIPT%"

if errorlevel 1 (
  echo.
  echo [FAILED]
  pause
  exit /b 1
)

echo.
echo [OK] Finished 32b Falsification Matrix Final Fixed.
echo Output: C:\Users\Administrator\Desktop\Result\SC_Falsification_32b_FINAL_MATRIX_FIXED
pause
