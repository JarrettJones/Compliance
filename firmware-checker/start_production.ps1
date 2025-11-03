# Start Production Server with Environment Variables
# This script loads .env and starts the Waitress production server

Write-Host "Loading environment variables..." -ForegroundColor Cyan
. .\setup_env.ps1

Write-Host ""
Write-Host "Starting production server..." -ForegroundColor Green
python run_production.py
