@echo off
chcp 65001 >nul
setlocal
set "PYTHONIOENCODING=utf-8"
set "PYTHONUTF8=1"

set "DIR=%~dp0"
set "SCRIPT=%DIR%35_repo_readme_builder.py"

echo Running 35 Repo README Builder...
python "%SCRIPT%"

if errorlevel 1 (
  echo.
  echo [FAILED]
  pause
  exit /b 1
)

echo.
echo [OK] Finished 35 Repo README Builder.
echo Output: C:\Users\Administrator\Desktop\Result\SC_Repo_35_README_BUILDER
pause
