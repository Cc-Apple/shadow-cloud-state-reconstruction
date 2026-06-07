@echo off
chcp 65001 >nul
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

set "DIR=%~dp0"
set "SCRIPT=%DIR%34_repo_lite_package.py"

echo Running 34 Repo Lite Package...
python "%SCRIPT%"

if errorlevel 1 (
  echo.
  echo [FAILED]
  pause
  exit /b 1
)

echo.
echo [OK] Finished 34 Repo Lite Package.
echo Output: C:\Users\Administrator\Desktop\Result\SC_Repo_34_LITE_PACKAGE
pause
