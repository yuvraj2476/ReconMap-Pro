@echo off
REM ============================================================================
REM  ReconMap Pro - quick command-line scan launcher (Windows)
REM
REM  Usage:
REM     scan.bat lab.local                 (scan the local demo lab)
REM     scan.bat example.com --passive     (passive-only scan)
REM
REM  The first argument is the authorized target domain. Any extra arguments
REM  are forwarded directly to the CLI (see: scan.bat --help).
REM ============================================================================

setlocal
cd /d "%~dp0\backend"

if not exist ".venv\Scripts\activate.bat" (
    echo [setup] Creating virtual environment and installing dependencies...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    python -m pip install --upgrade pip >nul
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

set RECONMAP_ALLOW_PRIVATE_NETWORKS=false
set RECONMAP_DATABASE_URL=sqlite+aiosqlite:///./reconmap.db
set RECONMAP_REPORT_DIR=./reports

if "%~1"=="" (
    echo Usage: scan.bat ^<target-domain^> [extra cli args...]
    echo.
    echo Examples:
    echo   scan.bat example.com
    echo   scan.bat example.com --passive
    echo   scan.bat example.com --active-subdomains
    echo.
    python -m app.cli --help
    exit /b 0
)

python -m app.cli scan %*

endlocal
