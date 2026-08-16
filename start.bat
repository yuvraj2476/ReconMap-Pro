@echo off
REM ============================================================================
REM  ReconMap Pro - easy Windows launcher
REM
REM  Double-click this file (or run it from a terminal) to start the full
REM  application locally. It will:
REM    1. Create a Python virtual environment on first run
REM    2. Install backend + frontend dependencies (first run only)
REM    3. Build the React frontend (first run only)
REM    4. Start the local demo lab on http://localhost:8099
REM    5. Start the ReconMap Pro API + web UI on http://localhost:8000
REM    6. Open your browser automatically
REM
REM  Press Ctrl+C in this window to stop everything.
REM ============================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo  ============================================================
echo   ReconMap Pro - local launcher
echo  ============================================================
echo.

REM --- Check Python -----------------------------------------------------------
where python >nul 2>nul
if errorlevel 1 (
    echo  [ERROR] Python 3.11+ was not found on your PATH.
    echo          Please install it from https://www.python.org/downloads/
    echo          Ensure "Add Python to PATH" is checked during install.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [ok] Found Python %PYVER%

REM --- Check Node -------------------------------------------------------------
where npm >nul 2>nul
if errorlevel 1 (
    echo  [WARN]  Node.js / npm not found. The frontend cannot be built,
    echo          but the API and docs at http://localhost:8000/docs will work.
    echo          Install Node from https://nodejs.org/ for the full UI.
    set HAS_NODE=0
) else (
    set HAS_NODE=1
    for /f %%v in ('node --version 2^>^&1') do echo  [ok] Found Node %%v
)

REM --- Backend venv -----------------------------------------------------------
if not exist "backend\.venv" (
    echo.
    echo  [1/4] Creating Python virtual environment...
    pushd backend
    python -m venv .venv
    if errorlevel 1 (
        echo  [ERROR] Failed to create virtual environment.
        popd
        pause
        exit /b 1
    )
    call .venv\Scripts\activate.bat
    echo  [2/4] Installing backend dependencies - this takes a minute...
    python -m pip install --upgrade pip >nul
    pip install -r requirements.txt
    if errorlevel 1 (
        echo  [ERROR] Backend dependency install failed.
        popd
        pause
        exit /b 1
    )
    popd
) else (
    echo.
    echo  [1/4] Using existing backend virtual environment.
    pushd backend
    call .venv\Scripts\activate.bat
    popd
)

REM --- Frontend build ---------------------------------------------------------
if "!HAS_NODE!"=="1" (
    if not exist "frontend\node_modules" (
        echo  [3/4] Installing frontend dependencies...
        pushd frontend
        call npm install
        popd
    )
    if not exist "frontend\dist\index.html" (
        echo  [4/4] Building React frontend...
        pushd frontend
        call npm run build
        popd
    ) else (
        echo  [3/4] Using existing frontend build.
    )
) else (
    echo  [3/4] Skipping frontend - Node.js not installed.
)

REM --- Configure environment --------------------------------------------------
set RECONMAP_ALLOW_PRIVATE_NETWORKS=true
set RECONMAP_LAB_EXTRA_PORTS=8099
set RECONMAP_DATABASE_URL=sqlite+aiosqlite:///./reconmap.db
set RECONMAP_REPORT_DIR=./reports
set RECONMAP_CORS_ORIGINS=http://localhost:8000,http://localhost:5173
set PYTHONUNBUFFERED=1

REM --- Start the demo lab in a new window -------------------------------------
echo.
echo  Starting local demo lab on http://localhost:8099 ...
start "ReconMap Lab" cmd /k "cd /d "%~dp0lab" && python server.py"

REM --- Give the lab a moment to come up ---------------------------------------
timeout /t 2 /nobreak >nul

REM --- Open the browser after a short delay -----------------------------------
start "" cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:8000"

REM --- Start the API + web UI -------------------------------------------------
echo.
echo  ============================================================
echo   ReconMap Pro is starting ...
echo.
echo     Web UI:        http://localhost:8000
echo     API docs:      http://localhost:8000/docs
echo     Demo lab:      http://localhost:8099
echo.
echo   In the UI, click "New scan" and target:  lab.local
echo   (the local demo lab is an authorized target)
echo.
echo   Press Ctrl+C in this window to stop the server.
echo   (Also close the "ReconMap Lab" window to stop the lab.)
echo  ============================================================
echo.

cd /d "%~dp0backend"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

endlocal
