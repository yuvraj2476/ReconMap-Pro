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

REM --- Check Python -----------------------------------------------------------
where python >nul 2>nul
if errorlevel 1 (
    echo   [!] [ERROR] Python 3.11+ was not found on your PATH.
    echo               Please install it from https://www.python.org/downloads/
    echo               Ensure "Add Python to PATH" is checked during install.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v

echo.
python -c "print('   ____________________________________________________________________\n    ____                     __  __               ____             \n   |  _ \\ ___  ___ ___  _ __ |  \\/  | __ _ _ __   |  _ \\ _ __ ___  \n   | |_) / _ \\/ __/ _ \\| \'_ \\| |\\/| |/ _` | \'_ \\  | |_) | \'__/ _ \\\n   |  _ <  __/ (_| (_) | | | | |  | | (_| | |_) | |  __/| |  | (_) |\n   |_| \\_\\___|\\___|\\___/|_| |_|_|  |_|\\__,_| .__/  |_|   |_|   \\___/ \n                                           |_|                     \n                       -= Attack-Surface Intelligence =-\          \n   ____________________________________________________________________\n')"
echo   [+] Python %PYVER% found.


REM --- Check Node -------------------------------------------------------------
where npm >nul 2>nul
if errorlevel 1 (
    echo   [!] [WARN]  Node.js / npm not found. The frontend cannot be built,
    echo               but the API and docs at http://localhost:8000/docs will work.
    echo               Install Node from https://nodejs.org/ for the full UI.
    set HAS_NODE=0
) else (
    set HAS_NODE=1
    for /f %%v in ('node --version 2^>^&1') do echo   [+] Node %%v found.
)

REM --- Backend venv -----------------------------------------------------------
if not exist "backend\.venv" (
    echo.
    echo   [1/4] Creating Python virtual environment...
    pushd backend
    python -m venv .venv
    if errorlevel 1 (
        echo   [!] [ERROR] Failed to create virtual environment.
        popd
        pause
        exit /b 1
    )
    echo   [2/4] Installing backend dependencies - this takes a minute...
    .venv\Scripts\python.exe -m pip install --upgrade pip >nul
    .venv\Scripts\pip.exe install -r requirements.txt
    if errorlevel 1 (
        echo   [!] [ERROR] Backend dependency install failed.
        popd
        pause
        exit /b 1
    )
    popd
) else (
    echo.
    echo   [1/4] Using existing backend virtual environment.
)

REM --- Frontend build ---------------------------------------------------------
if "!HAS_NODE!"=="1" (
    if not exist "frontend\node_modules" (
        echo   [2/4] Installing frontend dependencies...
        pushd frontend
        call npm install
        popd
    )
    if not exist "frontend\dist\index.html" (
        echo   [3/4] Building React frontend...
        pushd frontend
        call npm run build
        popd
    ) else (
        echo   [3/4] Using existing frontend build.
    )
) else (
    echo   [2/4] Skipping frontend - Node.js not installed.
)

REM --- Configure environment --------------------------------------------------
set RECONMAP_ALLOW_PRIVATE_NETWORKS=false
set RECONMAP_DATABASE_URL=sqlite+aiosqlite:///./reconmap.db
set RECONMAP_REPORT_DIR=./reports
set RECONMAP_CORS_ORIGINS=http://localhost:8000,http://localhost:5173
set PYTHONUNBUFFERED=1

REM --- Open the browser after a short delay -----------------------------------
start "" cmd /c "timeout /t 4 /nobreak >nul && start http://localhost:8000"

REM --- Start the API + web UI -------------------------------------------------
echo.
echo   ====================================================================
echo    ReconMap Pro is starting ...
echo.
echo      [+] Web UI:        http://localhost:8000
echo      [+] API docs:      http://localhost:8000/docs
echo.
echo    Press Ctrl+C in this window to stop the server.
echo   ====================================================================
echo.

cd /d "%~dp0backend"
.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000

endlocal
