# PANOPTES - Windows Setup Script
# Run this once before starting the application
# Usage: .\setup.ps1

Write-Host ""
Write-Host "=== PANOPTES Setup ===" -ForegroundColor Cyan
Write-Host "Quantum-Safe Insider Threat Detection Platform" -ForegroundColor Gray
Write-Host ""

$ProjectRoot = $PSScriptRoot

# ── Python virtual environment ───────────────────────────────────────────────
Write-Host "[1/5] Creating Python virtual environment..." -ForegroundColor Yellow
python -m venv "$ProjectRoot\venv"
if (-not $?) { Write-Host "ERROR: Python not found. Install Python 3.11+" -ForegroundColor Red; exit 1 }

$pip = "$ProjectRoot\venv\Scripts\pip.exe"
$python = "$ProjectRoot\venv\Scripts\python.exe"

# ── Install requirements ──────────────────────────────────────────────────────
Write-Host "[2/5] Installing Python dependencies..." -ForegroundColor Yellow
& $pip install --upgrade pip -q
& $pip install -r "$ProjectRoot\backend\requirements.txt"

# Try liboqs-python (real PQC)
Write-Host "      Attempting liboqs-python (real ML-KEM/ML-DSA)..." -ForegroundColor Gray
& $pip install oqs 2>$null
if ($?) {
    Write-Host "      [+] liboqs-python installed - real NIST PQC active" -ForegroundColor Green
} else {
    Write-Host "      [!] liboqs not available - using cryptography fallback" -ForegroundColor Yellow
    Write-Host "        (Still works - Ed25519 + X25519 used instead)" -ForegroundColor Gray
}

# ── Download OPA binary ───────────────────────────────────────────────────────
Write-Host "[3/5] Downloading OPA binary..." -ForegroundColor Yellow
$opaPath = "$ProjectRoot\opa.exe"
if (Test-Path $opaPath) {
    Write-Host "      [+] OPA already present at $opaPath" -ForegroundColor Green
} else {
    $opaUrl = "https://github.com/open-policy-agent/opa/releases/download/v0.68.0/opa_windows_amd64.exe"
    try {
        Invoke-WebRequest -Uri $opaUrl -OutFile $opaPath -UseBasicParsing
        Write-Host "      [+] OPA downloaded to $opaPath" -ForegroundColor Green
    } catch {
        Write-Host "      [!] Could not download OPA (no internet?). Inline policy fallback will be used." -ForegroundColor Yellow
    }
}

# ── Frontend dependencies ─────────────────────────────────────────────────────
Write-Host "[4/5] Installing frontend dependencies..." -ForegroundColor Yellow
Push-Location "$ProjectRoot\frontend"
npm install --silent
if ($?) { Write-Host "      [+] npm packages installed" -ForegroundColor Green }
Pop-Location

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[5/5] Setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "=== To start PANOPTES ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Terminal 1 (Backend):" -ForegroundColor White
Write-Host "  .\venv\Scripts\activate" -ForegroundColor Gray
Write-Host "  cd backend" -ForegroundColor Gray  
Write-Host "  python -m uvicorn main:app --host 0.0.0.0 --port 8000" -ForegroundColor Gray
Write-Host ""
Write-Host "Terminal 2 (Frontend):" -ForegroundColor White
Write-Host "  cd frontend" -ForegroundColor Gray
Write-Host "  npm run dev" -ForegroundColor Gray
Write-Host ""
Write-Host "Dashboard: http://localhost:5173" -ForegroundColor Cyan
Write-Host "API Docs:  http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""
