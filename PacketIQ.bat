@echo off
REM ============================================================
REM  PacketIQ - double-click launcher (Windows)
REM
REM  Double-click this file. First run sets everything up
REM  (about a minute); afterwards it starts instantly and opens
REM  the web app in your browser. Close this window to stop.
REM ============================================================
setlocal
cd /d "%~dp0"

echo.
echo   PacketIQ - AI PCAP Forensics ^& SOC Intelligence (Web App)
echo.

REM 1) Find Python
where py >nul 2>&1 && (set "PY=py -3") || (set "PY=python")
%PY% --version >nul 2>&1
if errorlevel 1 (
  echo Python 3.9+ is required. Install it from https://www.python.org/downloads/
  echo Then double-click this file again.
  pause
  exit /b 1
)

REM 2) Create venv on first run
if not exist ".venv\" (
  echo First-time setup: creating an isolated environment...
  %PY% -m venv .venv
)
set "VENV_PY=.venv\Scripts\python.exe"

REM 3) Install on first run
"%VENV_PY%" -c "import packetiq, fastapi, scapy" >nul 2>&1
if errorlevel 1 (
  echo Installing PacketIQ and dependencies ^(one-time, ~1-2 minutes^)...
  "%VENV_PY%" -m pip install -q --upgrade pip
  "%VENV_PY%" -m pip install -q -e .
  if errorlevel 1 (
    echo Install failed. Check your internet connection and try again.
    pause
    exit /b 1
  )
)

REM 4) .env from template
if not exist ".env" copy ".env.example" ".env" >nul 2>&1

REM 5) Demo capture
if not exist "samples\demo_attack.pcap" "%VENV_PY%" samples\generate_sample.py >nul 2>&1

echo.
echo Ready! Opening PacketIQ at http://localhost:8080
echo A demo capture is at samples\demo_attack.pcap - drag it into the upload box.
echo Keep this window open while you use the app. Close it to stop.
echo.

"%VENV_PY%" -m packetiq.cli webapp --port 8080
pause
