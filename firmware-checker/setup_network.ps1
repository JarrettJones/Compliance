# Network Configuration Script for Firmware Checker
# Run this on your test server as Administrator

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Firmware Checker - Network Configuration" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

Write-Host "[OK] Running as Administrator" -ForegroundColor Green
Write-Host ""

# Step 1: Get server IP addresses
Write-Host "Step 1: Network Configuration" -ForegroundColor Cyan
Write-Host "-" * 80
$ipAddresses = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' }
Write-Host "Available network interfaces:" -ForegroundColor Yellow
foreach ($ip in $ipAddresses) {
    $adapter = Get-NetAdapter | Where-Object { $_.ifIndex -eq $ip.InterfaceIndex }
    Write-Host "  - $($ip.IPAddress) ($($adapter.InterfaceDescription))" -ForegroundColor Green
}
Write-Host ""

# Recommend primary IP
$primaryIP = ($ipAddresses | Select-Object -First 1).IPAddress
Write-Host "Primary IP Address: $primaryIP" -ForegroundColor Green
Write-Host ""

# Step 2: Check if port 5000 is in use
Write-Host "Step 2: Port Availability Check" -ForegroundColor Cyan
Write-Host "-" * 80
$port = 5000
$portCheck = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue

if ($portCheck) {
    Write-Host "[WARNING] Port $port is already in use!" -ForegroundColor Yellow
    Write-Host "Process using port: $($portCheck.OwningProcess)" -ForegroundColor Yellow
    $process = Get-Process -Id $portCheck.OwningProcess -ErrorAction SilentlyContinue
    if ($process) {
        Write-Host "Process name: $($process.ProcessName)" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "If this is the Firmware Checker, you're good to go!" -ForegroundColor Green
} else {
    Write-Host "[OK] Port $port is available" -ForegroundColor Green
}
Write-Host ""

# Step 3: Configure Windows Firewall
Write-Host "Step 3: Firewall Configuration" -ForegroundColor Cyan
Write-Host "-" * 80

# Check if rule already exists
$existingRule = Get-NetFirewallRule -DisplayName "Firmware Checker" -ErrorAction SilentlyContinue

if ($existingRule) {
    Write-Host "[INFO] Firewall rule already exists" -ForegroundColor Yellow
    Write-Host "Removing old rule..." -ForegroundColor Yellow
    Remove-NetFirewallRule -DisplayName "Firmware Checker"
}

# Create new firewall rule
try {
    New-NetFirewallRule `
        -DisplayName "Firmware Checker" `
        -Description "Allow inbound HTTP traffic to Firmware Checker web application" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort $port `
        -Action Allow `
        -Profile Domain,Private `
        -Enabled True | Out-Null
    
    Write-Host "[OK] Firewall rule created successfully!" -ForegroundColor Green
    Write-Host "    Rule Name: Firmware Checker" -ForegroundColor White
    Write-Host "    Port: $port" -ForegroundColor White
    Write-Host "    Profiles: Domain, Private" -ForegroundColor White
} catch {
    Write-Host "[ERROR] Failed to create firewall rule: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Step 4: Verify firewall rule
Write-Host "Step 4: Verify Firewall Rule" -ForegroundColor Cyan
Write-Host "-" * 80
$rule = Get-NetFirewallRule -DisplayName "Firmware Checker" -ErrorAction SilentlyContinue
if ($rule) {
    Write-Host "[OK] Firewall rule is active" -ForegroundColor Green
    Write-Host "    Enabled: $($rule.Enabled)" -ForegroundColor White
    Write-Host "    Direction: $($rule.Direction)" -ForegroundColor White
    Write-Host "    Action: $($rule.Action)" -ForegroundColor White
} else {
    Write-Host "[ERROR] Firewall rule not found!" -ForegroundColor Red
}
Write-Host ""

# Step 5: Display access URLs
Write-Host "Step 5: Access URLs" -ForegroundColor Cyan
Write-Host "-" * 80
Write-Host "The Firmware Checker is accessible at:" -ForegroundColor Yellow
Write-Host ""
Write-Host "From this server:" -ForegroundColor White
Write-Host "  http://localhost:$port" -ForegroundColor Cyan
Write-Host ""
Write-Host "From other computers on the network:" -ForegroundColor White
foreach ($ip in $ipAddresses) {
    Write-Host "  http://$($ip.IPAddress):$port" -ForegroundColor Cyan
}
Write-Host ""

# Step 6: Test connectivity
Write-Host "Step 6: Connectivity Test" -ForegroundColor Cyan
Write-Host "-" * 80
Write-Host "Testing if server is responding..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:$port" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    Write-Host "[OK] Server is responding!" -ForegroundColor Green
    Write-Host "    Status: $($response.StatusCode)" -ForegroundColor White
} catch {
    Write-Host "[WARNING] Server is not responding" -ForegroundColor Yellow
    Write-Host "Make sure the server is running with: .\start_production.ps1" -ForegroundColor Yellow
}
Write-Host ""

# Step 7: Summary
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Configuration Complete!" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Ensure the server is running: .\start_production.ps1" -ForegroundColor White
Write-Host "2. Share this URL with your team:" -ForegroundColor White
Write-Host "   http://$primaryIP:$port" -ForegroundColor Cyan
Write-Host "3. Users can access from any browser on your network" -ForegroundColor White
Write-Host ""
Write-Host "To test from another computer:" -ForegroundColor Yellow
Write-Host "  Open browser and navigate to: http://$primaryIP:$port" -ForegroundColor Cyan
Write-Host ""
# Optional: Create a shortcut or bookmark info
Write-Host "Tip: Create a bookmark or shortcut for easy access!" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
