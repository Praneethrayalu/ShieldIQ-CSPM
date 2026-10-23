@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem ============================================================
rem  ShieldIQ - one-click Windows check and launch
rem  No admin rights needed. No PowerShell. No system changes.
rem  Everything is logged to windows-test-log.txt
rem ============================================================
cd /d "%~dp0"
set LOG=windows-test-log.txt
echo ShieldIQ Windows check - %DATE% %TIME% > "%LOG%"

rem ---- 1. Find Python -------------------------------------------------
set PY=
where py >nul 2>&1
if %errorlevel%==0 (
    py -3 --version >nul 2>&1 && set PY=py -3
)
if not defined PY (
    where python >nul 2>&1 && set PY=python
)
if not defined PY (
    echo [FAIL] Python was not found on this PC.
    echo [FAIL] Python was not found on this PC. >> "%LOG%"
    echo        Install Python 3.10 or newer from https://www.python.org/downloads/
    echo        IMPORTANT: tick "Add python.exe to PATH" during setup.
    goto :fail
)
echo [OK] Python found: >> "%LOG%"
%PY% --version >> "%LOG%" 2>&1
if errorlevel 1 goto :fail
for /f "tokens=2" %%v in ('%PY% --version 2^>^&1') do set PYVER=%%v
echo [OK] Python %PYVER%
%PY% -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" 2>nul
if errorlevel 1 (
    echo [FAIL] Python %PYVER% is too old. ShieldIQ needs Python 3.10 or newer.
    echo [FAIL] Python %PYVER% is too old - need 3.10+ >> "%LOG%"
    echo        Get the latest from https://www.python.org/downloads/
    goto :fail
)

rem ---- 2. Create the virtual environment (once) -----------------------
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment... >> "%LOG%"
    %PY% -m venv .venv >> "%LOG%" 2>&1
    if errorlevel 1 (
        echo [FAIL] Could not create .venv - see %LOG%
        goto :fail
    )
    echo [OK] Virtual environment created
) else (
    echo [OK] Virtual environment already exists
)

set VENVPY=.venv\Scripts\python.exe

rem ---- 3. Install dependencies (skips quickly if already done) --------
echo Installing dependencies... >> "%LOG%"
"%VENVPY%" -m pip install --quiet --disable-pip-version-warning -r requirements.txt >> "%LOG%" 2>&1
if errorlevel 1 (
    echo [FAIL] pip install failed - see %LOG%  (check your internet connection)
    goto :fail
)
echo [OK] Dependencies installed

rem ---- 4. Run the test suite ------------------------------------------
echo Running tests... >> "%LOG%"
echo Running the test suite (about 25 seconds)...
"%VENVPY%" -m pytest -q >> "%LOG%" 2>&1
if errorlevel 1 (
    echo [FAIL] Some tests failed - see the end of %LOG%
    goto :fail
)
for /f "tokens=*" %%l in ('type "%LOG%" ^| findstr /R "passed"') do set LASTLINE=%%l
echo [OK] Tests: !LASTLINE!

rem ---- 5. Start the app ------------------------------------------------
echo Starting ShieldIQ... >> "%LOG%"
echo.
echo ============================================================
echo  ShieldIQ is starting at  http://127.0.0.1:5000
echo  Open that address in your browser.
echo  Demo sign-in: demo@shieldiq.local  /  ShieldIQ@2026
echo  Press Ctrl+C in this window to stop the app.
echo ============================================================
echo.
"%VENVPY%" run.py
goto :end

:fail
echo.
echo Something went wrong. Open %LOG% to see the details.
:end
echo.
pause
