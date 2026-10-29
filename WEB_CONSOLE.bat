@echo off
REM Double-click to open the PID-Guard web console.
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
python web\server.py
echo.
pause
