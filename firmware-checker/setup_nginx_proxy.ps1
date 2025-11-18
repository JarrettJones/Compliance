# nginx Setup Script for Firmware Checker
# Configures nginx to serve at http://hostname/firmware-checker

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "nginx Configuration for Firmware Checker" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Step 1: Find nginx installation
Write-Host "Step 1: Locating nginx Installation" -ForegroundColor Cyan
Write-Host "-" * 80

$nginxPaths = @(
    "C:\nginx",
    "C:\nginx-1.25.3",
    "C:\nginx-1.24.0",
    "C:\Program Files\nginx",
    "C:\tools\nginx"
)

$nginxPath = $null
foreach ($path in $nginxPaths) {
    if (Test-Path "$path\nginx.exe") {
        $nginxPath = $path
        break
    }
}

if (-not $nginxPath) {
    Write-Host "[ERROR] nginx installation not found!" -ForegroundColor Red
    Write-Host "Checked locations:" -ForegroundColor Yellow
    foreach ($path in $nginxPaths) {
        Write-Host "  - $path" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Please specify your nginx installation path:" -ForegroundColor Yellow
    $nginxPath = Read-Host "Enter path (e.g., C:\nginx)"
    
    if (-not (Test-Path "$nginxPath\nginx.exe")) {
        Write-Host "[ERROR] nginx.exe not found at: $nginxPath" -ForegroundColor Red
        exit 1
    }
}

Write-Host "[OK] Found nginx at: $nginxPath" -ForegroundColor Green
Write-Host ""

# Step 2: Backup existing configuration
Write-Host "Step 2: Backing Up Existing Configuration" -ForegroundColor Cyan
Write-Host "-" * 80

$nginxConf = "$nginxPath\conf\nginx.conf"
$backupConf = "$nginxPath\conf\nginx.conf.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

if (Test-Path $nginxConf) {
    Copy-Item $nginxConf $backupConf
    Write-Host "[OK] Backed up to: $backupConf" -ForegroundColor Green
} else {
    Write-Host "[WARNING] No existing nginx.conf found" -ForegroundColor Yellow
}
Write-Host ""

# Step 3: Create new configuration
Write-Host "Step 3: Creating nginx Configuration" -ForegroundColor Cyan
Write-Host "-" * 80

$hostname = $env:COMPUTERNAME.ToLower()

$nginxConfig = @"
# nginx configuration for Firmware Checker
# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

worker_processes auto;

events {
    worker_connections 1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    
    sendfile        on;
    keepalive_timeout  65;
    
    # Logging
    access_log  logs/access.log;
    error_log   logs/error.log;
    
    # HTTP server - redirect to HTTPS
    server {
        listen 80;
        server_name $hostname localhost;
        
        # Redirect all HTTP to HTTPS
        return 301 https://`$host`$request_uri;
    }
    
    # HTTPS server
    server {
        listen 443 ssl;
        server_name $hostname localhost;
        
        # SSL Certificate Configuration
        # Using Microsoft-signed certificate from C:\nginx\ssl
        ssl_certificate      C:/nginx/ssl/server.crt;
        ssl_certificate_key  C:/nginx/ssl/server.key;
        
        # SSL Settings
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        
        # Root redirects to firmware-checker
        location = / {
            return 301 /firmware-checker/;
        }
        
        # Firmware Checker application
        # Keep the /firmware-checker prefix when proxying
        location /firmware-checker {
            # Rewrite to strip /firmware-checker before passing to Flask
            rewrite ^/firmware-checker(.*)$ `$1 break;
            
            # Proxy to Waitress at root (use IPv4 explicitly to avoid IPv6 issues)
            proxy_pass http://127.0.0.1:5000;
            
            # Preserve original request information
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host `$host;
            proxy_set_header X-Forwarded-Port `$server_port;
            
            # CRITICAL: Tell Flask about the /firmware-checker prefix
            # This makes url_for() generate correct URLs
            proxy_set_header X-Forwarded-Prefix /firmware-checker;
            proxy_set_header X-Script-Name /firmware-checker;
            
            # Performance optimizations
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            
            # Timeouts for long-running firmware checks
            proxy_connect_timeout 10s;
            proxy_send_timeout 120s;
            proxy_read_timeout 120s;
            
            # Disable buffering for faster responses
            proxy_buffering off;
            proxy_request_buffering off;
            
            # Enable keepalive
            keepalive_timeout 65;
        }
    }
}
"@

# Use UTF8 without BOM for nginx compatibility
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($nginxConf, $nginxConfig, $utf8NoBom)
Write-Host "[OK] Created nginx.conf" -ForegroundColor Green
Write-Host ""

# Step 4: Test nginx configuration
Write-Host "Step 4: Testing nginx Configuration" -ForegroundColor Cyan
Write-Host "-" * 80

# Change to nginx directory before testing
Push-Location $nginxPath
$testResult = & ".\nginx.exe" -t 2>&1
$testExitCode = $LASTEXITCODE
Pop-Location

if ($testExitCode -eq 0) {
    Write-Host "[OK] Configuration test passed" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Configuration test failed:" -ForegroundColor Red
    Write-Host $testResult -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Restoring backup..." -ForegroundColor Yellow
    if (Test-Path $backupConf) {
        Copy-Item $backupConf $nginxConf -Force
        Write-Host "[OK] Backup restored" -ForegroundColor Green
    }
    exit 1
}
Write-Host ""

# Step 5: Configure Windows Firewall
Write-Host "Step 5: Configuring Windows Firewall" -ForegroundColor Cyan
Write-Host "-" * 80

try {
    # HTTP port 80
    $existingRule = Get-NetFirewallRule -DisplayName "nginx HTTP" -ErrorAction SilentlyContinue
    if ($existingRule) {
        Write-Host "[INFO] HTTP firewall rule already exists" -ForegroundColor Yellow
    } else {
        New-NetFirewallRule `
            -DisplayName "nginx HTTP" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 80 `
            -Action Allow `
            -Profile Domain,Private `
            -Enabled True | Out-Null
        Write-Host "[OK] Created firewall rule for port 80 (HTTP)" -ForegroundColor Green
    }
    
    # HTTPS port 443
    $existingHttpsRule = Get-NetFirewallRule -DisplayName "nginx HTTPS" -ErrorAction SilentlyContinue
    if ($existingHttpsRule) {
        Write-Host "[INFO] HTTPS firewall rule already exists" -ForegroundColor Yellow
    } else {
        New-NetFirewallRule `
            -DisplayName "nginx HTTPS" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 443 `
            -Action Allow `
            -Profile Domain,Private `
            -Enabled True | Out-Null
        Write-Host "[OK] Created firewall rule for port 443 (HTTPS)" -ForegroundColor Green
    }
} catch {
    Write-Host "[WARNING] Could not configure firewall (may need Administrator)" -ForegroundColor Yellow
}
Write-Host ""

# Step 6: Restart nginx
Write-Host "Step 6: Restarting nginx" -ForegroundColor Cyan
Write-Host "-" * 80

# Stop nginx if running
$nginxProcess = Get-Process -Name "nginx" -ErrorAction SilentlyContinue
if ($nginxProcess) {
    Write-Host "Stopping nginx..." -ForegroundColor Yellow
    Push-Location $nginxPath
    & ".\nginx.exe" -s quit
    Pop-Location
    Start-Sleep -Seconds 2
}

# Start nginx (must run from nginx directory)
Write-Host "Starting nginx..." -ForegroundColor Yellow
Push-Location $nginxPath
Start-Process -FilePath ".\nginx.exe" -WindowStyle Hidden
Pop-Location

Start-Sleep -Seconds 2

# Verify nginx is running
$nginxProcess = Get-Process -Name "nginx" -ErrorAction SilentlyContinue
if ($nginxProcess) {
    Write-Host "[OK] nginx is running" -ForegroundColor Green
    Write-Host "    Processes: $($nginxProcess.Count)" -ForegroundColor White
} else {
    Write-Host "[ERROR] Failed to start nginx" -ForegroundColor Red
    Write-Host "Check logs at: $nginxPath\logs\error.log" -ForegroundColor Yellow
}
Write-Host ""

# Step 7: SSL Certificate Setup Instructions
Write-Host "Step 7: SSL Certificate Setup" -ForegroundColor Cyan
Write-Host "-" * 80
Write-Host ""
Write-Host "IMPORTANT: You need to configure SSL certificates for HTTPS to work!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Certificate Location: $nginxPath\conf\ssl\" -ForegroundColor Cyan
Write-Host ""
Write-Host "Steps to configure your organization's certificate:" -ForegroundColor White
Write-Host "1. Create the SSL directory if it doesn't exist:" -ForegroundColor White
Write-Host "   New-Item -ItemType Directory -Path '$nginxPath\conf\ssl' -Force" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Export your certificate from certlm.msc:" -ForegroundColor White
Write-Host "   a. Open certlm.msc (Certificate Manager)" -ForegroundColor Gray
Write-Host "   b. Navigate to Personal > Certificates" -ForegroundColor Gray
Write-Host "   c. Find your server certificate (CN=$hostname)" -ForegroundColor Gray
Write-Host "   d. Right-click > All Tasks > Export" -ForegroundColor Gray
Write-Host "   e. Export with private key as PFX" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Convert PFX to PEM format for nginx:" -ForegroundColor White
Write-Host "   # Extract certificate" -ForegroundColor Gray
Write-Host "   openssl pkcs12 -in certificate.pfx -clcerts -nokeys -out server.crt" -ForegroundColor Cyan
Write-Host ""
Write-Host "   # Extract private key" -ForegroundColor Gray
Write-Host "   openssl pkcs12 -in certificate.pfx -nocerts -nodes -out server.key" -ForegroundColor Cyan
Write-Host ""
Write-Host "4. Copy the files to nginx:" -ForegroundColor White
Write-Host "   Copy-Item server.crt '$nginxPath\conf\ssl\server.crt'" -ForegroundColor Cyan
Write-Host "   Copy-Item server.key '$nginxPath\conf\ssl\server.key'" -ForegroundColor Cyan
Write-Host ""
Write-Host "5. Reload nginx:" -ForegroundColor White
Write-Host "   cd $nginxPath; .\nginx.exe -s reload" -ForegroundColor Cyan
Write-Host ""
Write-Host "NOTE: If you don't have OpenSSL, download from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Yellow
Write-Host ""

# Step 8: Summary
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "nginx Configuration Complete!" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Access URLs:" -ForegroundColor Yellow
Write-Host "  HTTP:  http://$hostname/firmware-checker (redirects to HTTPS)" -ForegroundColor Cyan
Write-Host "  HTTPS: https://$hostname/firmware-checker" -ForegroundColor Cyan
Write-Host ""
Write-Host "Important:" -ForegroundColor Yellow
Write-Host "1. Configure SSL certificates (see Step 7 above)" -ForegroundColor White
Write-Host ""
Write-Host "2. Make sure Waitress is running on port 5000:" -ForegroundColor White
Write-Host "   .\start_production.ps1" -ForegroundColor Cyan
Write-Host ""
Write-Host "3. Test the URL after configuring certificates:" -ForegroundColor White
Write-Host "   Start-Process https://localhost/firmware-checker" -ForegroundColor Cyan
Write-Host ""
Write-Host "nginx Commands:" -ForegroundColor Yellow
Write-Host "  Start:   cd $nginxPath; .\nginx.exe" -ForegroundColor White
Write-Host "  Stop:    cd $nginxPath; .\nginx.exe -s quit" -ForegroundColor White
Write-Host "  Reload:  cd $nginxPath; .\nginx.exe -s reload" -ForegroundColor White
Write-Host "  Test:    cd $nginxPath; .\nginx.exe -t" -ForegroundColor White
Write-Host ""
Write-Host "Logs:" -ForegroundColor Yellow
Write-Host "  Access: $nginxPath\logs\access.log" -ForegroundColor White
Write-Host "  Error:  $nginxPath\logs\error.log" -ForegroundColor White
Write-Host ""
Write-Host "Configuration file: $nginxConf" -ForegroundColor Yellow
Write-Host "Backup: $backupConf" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
