@echo off
REM Double-click to paste your own text and see the verdict live.
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
python demo\try_it.py
echo.
pause
