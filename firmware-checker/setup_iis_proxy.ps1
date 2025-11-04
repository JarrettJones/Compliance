# IIS Reverse Proxy Setup for Firmware Checker
# This configures IIS to serve the app at http://hostname/firmware-checker
# Run as Administrator

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "IIS Reverse Proxy Setup for Firmware Checker" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}

# Step 1: Check if IIS is installed
Write-Host "Step 1: Checking IIS Installation" -ForegroundColor Cyan
Write-Host "-" * 80

$iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -ErrorAction SilentlyContinue

if ($iisFeature -and $iisFeature.State -eq "Enabled") {
    Write-Host "[OK] IIS is installed" -ForegroundColor Green
} else {
    Write-Host "[INFO] IIS is not installed. Installing..." -ForegroundColor Yellow
    Write-Host "This may take several minutes..." -ForegroundColor Yellow
    
    try {
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole -All -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -All -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-CommonHttpFeatures -All -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors -All -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationDevelopment -All -NoRestart
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole -All -NoRestart
        
        Write-Host "[OK] IIS installed successfully!" -ForegroundColor Green
        Write-Host "[WARNING] You may need to restart the computer" -ForegroundColor Yellow
    } catch {
        Write-Host "[ERROR] Failed to install IIS: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}
Write-Host ""

# Step 2: Install URL Rewrite and ARR modules
Write-Host "Step 2: Checking IIS Modules" -ForegroundColor Cyan
Write-Host "-" * 80
Write-Host "[INFO] You need to manually install:" -ForegroundColor Yellow
Write-Host "  1. URL Rewrite Module: https://www.iis.net/downloads/microsoft/url-rewrite" -ForegroundColor Cyan
Write-Host "  2. Application Request Routing (ARR): https://www.iis.net/downloads/microsoft/application-request-routing" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key after installing these modules..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# Step 3: Get hostname
Write-Host "Step 3: Server Information" -ForegroundColor Cyan
Write-Host "-" * 80
$hostname = $env:COMPUTERNAME
Write-Host "Server Hostname: $hostname" -ForegroundColor Green
Write-Host "Access URL will be: http://$hostname/firmware-checker" -ForegroundColor Cyan
Write-Host ""

# Step 4: Create web.config for reverse proxy
Write-Host "Step 4: Creating IIS Configuration" -ForegroundColor Cyan
Write-Host "-" * 80

$iisPath = "C:\inetpub\wwwroot\firmware-checker"
$webConfigPath = "$iisPath\web.config"

# Create directory if it doesn't exist
if (-not (Test-Path $iisPath)) {
    New-Item -ItemType Directory -Path $iisPath -Force | Out-Null
    Write-Host "[OK] Created directory: $iisPath" -ForegroundColor Green
}

# Create web.config for reverse proxy
$webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="ReverseProxyInboundRule" stopProcessing="true">
                    <match url="(.*)" />
                    <action type="Rewrite" url="http://localhost:5000/{R:1}" />
                    <serverVariables>
                        <set name="HTTP_X_FORWARDED_PROTO" value="http" />
                        <set name="HTTP_X_FORWARDED_HOST" value="{HTTP_HOST}" />
                        <set name="HTTP_X_ORIGINAL_URL" value="/firmware-checker/{R:1}" />
                    </serverVariables>
                </rule>
            </rules>
        </rewrite>
        <httpErrors errorMode="Detailed" />
    </system.webServer>
</configuration>
"@

Set-Content -Path $webConfigPath -Value $webConfig -Force
Write-Host "[OK] Created web.config at: $webConfigPath" -ForegroundColor Green
Write-Host ""

# Step 5: Create IIS Application
Write-Host "Step 5: Configuring IIS Application" -ForegroundColor Cyan
Write-Host "-" * 80

Import-Module WebAdministration -ErrorAction SilentlyContinue

# Remove existing application if it exists
if (Test-Path "IIS:\Sites\Default Web Site\firmware-checker") {
    Remove-WebApplication -Site "Default Web Site" -Name "firmware-checker"
    Write-Host "[INFO] Removed existing application" -ForegroundColor Yellow
}

# Create new application
try {
    New-WebApplication -Site "Default Web Site" -Name "firmware-checker" -PhysicalPath $iisPath | Out-Null
    Write-Host "[OK] Created IIS application: firmware-checker" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to create IIS application: $($_.Exception.Message)" -ForegroundColor Red
}
Write-Host ""

# Step 6: Configure ARR (Application Request Routing)
Write-Host "Step 6: Enabling ARR Proxy" -ForegroundColor Cyan
Write-Host "-" * 80
Write-Host "[INFO] Enabling proxy in ARR..." -ForegroundColor Yellow

try {
    Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" -Filter "system.webServer/proxy" -Name "enabled" -Value $true
    Write-Host "[OK] ARR proxy enabled" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Could not enable ARR proxy automatically" -ForegroundColor Yellow
    Write-Host "Manual step: Open IIS Manager > Server > Application Request Routing Cache > Server Proxy Settings > Enable proxy" -ForegroundColor Yellow
}
Write-Host ""

# Step 7: Configure Firewall for HTTP (port 80)
Write-Host "Step 7: Configuring Firewall for HTTP" -ForegroundColor Cyan
Write-Host "-" * 80

$existingRule = Get-NetFirewallRule -DisplayName "World Wide Web Services (HTTP Traffic-In)" -ErrorAction SilentlyContinue
if ($existingRule) {
    Write-Host "[OK] HTTP firewall rule already exists" -ForegroundColor Green
} else {
    try {
        New-NetFirewallRule `
            -DisplayName "World Wide Web Services (HTTP Traffic-In)" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 80 `
            -Action Allow `
            -Profile Domain,Private `
            -Enabled True | Out-Null
        Write-Host "[OK] Created HTTP firewall rule" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Could not create firewall rule: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
Write-Host ""

# Step 8: Summary
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "IIS Configuration Complete!" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Access URLs:" -ForegroundColor Yellow
Write-Host "  http://$hostname/firmware-checker" -ForegroundColor Cyan
Write-Host "  http://localhost/firmware-checker" -ForegroundColor Cyan
Write-Host ""
Write-Host "Important:" -ForegroundColor Yellow
Write-Host "1. Make sure Waitress server is running on port 5000" -ForegroundColor White
Write-Host "   Run: .\start_production.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. If you installed URL Rewrite/ARR, restart IIS:" -ForegroundColor White
Write-Host "   iisreset" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Test the URL in a browser:" -ForegroundColor White
Write-Host "   http://$hostname/firmware-checker" -ForegroundColor Cyan
Write-Host ""
Write-Host "Troubleshooting:" -ForegroundColor Yellow
Write-Host "- Verify Waitress is running: Get-Process python" -ForegroundColor White
Write-Host "- Check IIS logs: C:\inetpub\logs\LogFiles\" -ForegroundColor White
Write-Host "- Verify URL Rewrite module is installed in IIS Manager" -ForegroundColor White
Write-Host "=" * 80 -ForegroundColor Cyan
