@echo off
echo === PANOPTES Quick Start ===
echo.

if not exist "venv" (
    echo Run setup.ps1 first!
    pause
    exit /b 1
)

echo Starting backend...
start "PANOPTES Backend" cmd /k "venv\Scripts\activate && python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000"

timeout /t 5 /nobreak >nul

echo Starting frontend...
start "PANOPTES Frontend" cmd /k "cd frontend && npm run dev"

timeout /t 4 /nobreak >nul

echo.
echo Dashboard: http://localhost:5173
echo API Docs:  http://localhost:8000/docs
echo.
start http://localhost:5173
