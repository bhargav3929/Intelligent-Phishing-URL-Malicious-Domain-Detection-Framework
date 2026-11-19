@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo [PhishRadar] Creating virtual environment...
    python -m venv .venv || (echo Python 3.10+ is required & pause & exit /b 1)
)
call ".venv\Scripts\activate.bat"
echo [PhishRadar] Installing dependencies...
python -m pip install -q -r requirements.txt || (echo Install failed & pause & exit /b 1)
if not exist ".env" if exist ".env.example" copy /y ".env.example" ".env" >nul
start "" cmd /c "timeout /t 3 /nobreak >nul & start http://127.0.0.1:8003"
echo [PhishRadar] Starting on http://127.0.0.1:8003  (Ctrl+C to stop)
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8003
endlocal
