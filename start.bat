@echo off
echo.
echo =======================================
echo   PANOPTES — Starting Full Stack
echo =======================================
echo.

:: Kill any existing backend on 8000
for /f "tokens=5" %%a in ('netstat -aon ^| find ":8000" 2^>nul') do (
    taskkill /F /PID %%a >nul 2>&1
)

:: Start Backend
echo [1/2] Starting Backend (FastAPI + OPA)...
set PYTHONPATH=.
set STREAM_INTERVAL_SECONDS=4
set ANOMALY_INJECTION_RATE=0.35
start "PANOPTES Backend" cmd /k ".\venv\Scripts\python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000"

:: Wait for backend
echo     Waiting for backend to start...
timeout /t 15 /nobreak >nul

:: Start Frontend
echo [2/2] Starting Frontend (React + Vite)...
start "PANOPTES Frontend" cmd /k "cd frontend && npm run dev"

echo.
echo =======================================
echo   PANOPTES Running!
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:5173
echo   API Docs: http://localhost:8000/docs
echo =======================================
echo.
pause
