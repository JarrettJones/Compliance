# Install Flask App as Windows Service using NSSM
# Run this script as Administrator

$serviceName = "FirmwareCheckerApp"
$appPath = "C:\Users\jarrettjones\Compliance\firmware-checker"
$pythonExe = "python.exe"  # Adjust if you have a specific Python path
$appScript = "app.py"
$nssmPath = "C:\nssm\nssm.exe"  # Adjust to where you download NSSM

# Check if NSSM is installed
if (-not (Test-Path $nssmPath)) {
    Write-Host "NSSM not found at $nssmPath" -ForegroundColor Red
    Write-Host "Please download NSSM from https://nssm.cc/download" -ForegroundColor Yellow
    Write-Host "Extract it and update the `$nssmPath variable in this script" -ForegroundColor Yellow
    exit 1
}

# Check if service already exists
$existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "Service '$serviceName' already exists. Removing it first..." -ForegroundColor Yellow
    & $nssmPath stop $serviceName
    & $nssmPath remove $serviceName confirm
    Start-Sleep -Seconds 2
}

# Install the service
Write-Host "Installing service '$serviceName'..." -ForegroundColor Green
& $nssmPath install $serviceName $pythonExe "$appPath\$appScript"

# Configure the service
Write-Host "Configuring service..." -ForegroundColor Green
& $nssmPath set $serviceName AppDirectory $appPath
& $nssmPath set $serviceName DisplayName "Firmware Checker Application"
& $nssmPath set $serviceName Description "Flask web application for firmware checking"
& $nssmPath set $serviceName Start SERVICE_AUTO_START

# Set up logging
& $nssmPath set $serviceName AppStdout "$appPath\logs\service_stdout.log"
& $nssmPath set $serviceName AppStderr "$appPath\logs\service_stderr.log"

# Rotate logs
& $nssmPath set $serviceName AppRotateFiles 1
& $nssmPath set $serviceName AppRotateOnline 1
& $nssmPath set $serviceName AppRotateBytes 10485760  # 10MB

# Set environment variables if needed
& $nssmPath set $serviceName AppEnvironmentExtra "FLASK_ENV=production"

# Start the service
Write-Host "Starting service..." -ForegroundColor Green
& $nssmPath start $serviceName

# Check status
Start-Sleep -Seconds 3
$service = Get-Service -Name $serviceName
Write-Host "`nService Status: $($service.Status)" -ForegroundColor Cyan

if ($service.Status -eq "Running") {
    Write-Host "`nService installed and started successfully!" -ForegroundColor Green
    Write-Host "The Flask app will now start automatically on server boot." -ForegroundColor Green
    Write-Host "`nUseful commands:" -ForegroundColor Yellow
    Write-Host "  View service status: Get-Service $serviceName" -ForegroundColor White
    Write-Host "  Stop service: Stop-Service $serviceName" -ForegroundColor White
    Write-Host "  Start service: Start-Service $serviceName" -ForegroundColor White
    Write-Host "  View logs: Get-Content $appPath\logs\service_stdout.log -Tail 50" -ForegroundColor White
} else {
    Write-Host "`nService installation failed or service not running." -ForegroundColor Red
    Write-Host "Check the logs at: $appPath\logs\" -ForegroundColor Yellow
}
