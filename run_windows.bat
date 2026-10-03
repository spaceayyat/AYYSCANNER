@echo off
rem Start AYYSCANNER (Windows). Double-click this file. Extra arguments are passed through.
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 run.py %*
) else (
    python run.py %*
)
if errorlevel 1 (
    echo.
    echo AYYSCANNER stopped with an error. See the message above.
    echo Python 3.10 or newer is required: https://www.python.org/downloads/
    pause
)
