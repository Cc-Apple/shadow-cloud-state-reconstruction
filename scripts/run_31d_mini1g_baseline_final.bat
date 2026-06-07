@echo off
chcp 65001 >nul
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

set "DIR=%~dp0"
set "SCRIPT=%DIR%31d_mini1g_baseline_final.py"

echo Running 31d MINI1G Baseline Final...
python "%SCRIPT%"

if errorlevel 1 (
  echo.
  echo [FAILED]
  pause
  exit /b 1
)

echo.
echo [OK] Finished 31d MINI1G Baseline Final.
echo Output: C:\Users\Administrator\Desktop\Result\SC_Baseline_31d_MINI1G_FINAL
pause
