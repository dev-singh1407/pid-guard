@echo off
REM Double-click to run the full project demonstration.
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
python demo\run_all.py
echo.
pause
