@echo off
chcp 65001 >nul
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

set "DIR=%~dp0"
set "SCRIPT=%DIR%30d_endpoint_path_owner_audit_final.py"

echo Running SC Endpoint 30d Path Owner Audit Final...
python "%SCRIPT%"

if errorlevel 1 (
  echo.
  echo [FAILED]
  pause
  exit /b 1
)

echo.
echo [OK] Finished SC Endpoint 30d.
echo Output: C:\Users\Administrator\Desktop\Result\SC_Endpoint_30d_PATH_OWNER_AUDIT_FINAL
pause
