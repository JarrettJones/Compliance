# Uninstall Flask App Windows Service
# Run this script as Administrator

$serviceName = "FirmwareCheckerApp"
$nssmPath = "C:\nssm\nssm.exe"

# Check if NSSM is installed
if (-not (Test-Path $nssmPath)) {
    Write-Host "NSSM not found at $nssmPath" -ForegroundColor Red
    exit 1
}

# Check if service exists
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if (-not $existingService) {
    Write-Host "Service '$serviceName' does not exist." -ForegroundColor Yellow
    exit 0
}

Write-Host "Stopping service '$serviceName'..." -ForegroundColor Yellow
& $nssmPath stop $serviceName
Start-Sleep -Seconds 2

Write-Host "Removing service '$serviceName'..." -ForegroundColor Yellow
& $nssmPath remove $serviceName confirm

Write-Host "Service removed successfully!" -ForegroundColor Green
