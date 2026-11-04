@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -B final\forensic_demo.py %*
) else (
  python -B final\forensic_demo.py %*
)
pause
