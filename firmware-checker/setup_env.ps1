# Firmware Checker - Environment Setup Script
# Run this with: . .\setup_env.ps1

$line = "=" * 80
Write-Host $line -ForegroundColor Cyan
Write-Host "Firmware Checker - Environment Setup" -ForegroundColor Yellow
Write-Host $line -ForegroundColor Cyan
Write-Host ""

# Check if .env file exists
if (-not (Test-Path ".env")) {
    Write-Host "[WARNING] No .env file found!" -ForegroundColor Red
    Write-Host "Creating .env from .env.example..." -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host ""
    Write-Host "[ACTION REQUIRED] Please edit .env and set your SECRET_KEY" -ForegroundColor Yellow
    Write-Host "Run: python generate_secret_key.py" -ForegroundColor Cyan
    Write-Host ""
}

# Load environment variables from .env file
if (Test-Path ".env") {
    Write-Host "Loading environment variables from .env file..." -ForegroundColor Green
    Get-Content ".env" | ForEach-Object {
        if ($_ -match '^([^=#]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            
            # Skip empty values
            if ($value) {
                [Environment]::SetEnvironmentVariable($key, $value, "Process")
                Write-Host "  [OK] $key" -ForegroundColor Green
            }
        }
    }
    Write-Host ""
}

# Verify SECRET_KEY is set
$secretKey = [Environment]::GetEnvironmentVariable("SECRET_KEY", "Process")
if (-not $secretKey -or $secretKey -eq "your-secret-key-here") {
    $errorLine = "=" * 80
    Write-Host $errorLine -ForegroundColor Red
    Write-Host "[CRITICAL] SECRET_KEY not configured!" -ForegroundColor Red
    Write-Host $errorLine -ForegroundColor Red
    Write-Host ""
    Write-Host "Generate a secure key with:" -ForegroundColor Yellow
    Write-Host "  python generate_secret_key.py" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Then update your .env file with the generated key." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "[OK] SECRET_KEY is configured" -ForegroundColor Green
    Write-Host ""
}

# Check Python and dependencies
Write-Host "Checking Python environment..." -ForegroundColor Green
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  [OK] $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Python not found!" -ForegroundColor Red
}

Write-Host ""
$endLine = "=" * 80
Write-Host $endLine -ForegroundColor Cyan
Write-Host "Environment setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "To start the application, run:" -ForegroundColor Yellow
Write-Host "  python app.py" -ForegroundColor Cyan
Write-Host $endLine -ForegroundColor Cyan
