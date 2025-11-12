# Self-Signed SSL Certificate Setup for Firmware Checker
# Generates certificate and configures nginx for HTTPS

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "SSL Certificate Setup for Firmware Checker" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Configuration
$hostname = $env:COMPUTERNAME.ToLower()
$nginxPath = "C:\nginx"
$sslPath = "$nginxPath\conf\ssl"
$certName = "firmware-checker"

# Step 1: Create SSL directory
Write-Host "Step 1: Creating SSL Directory" -ForegroundColor Cyan
Write-Host "-" * 80

if (-not (Test-Path $nginxPath)) {
    Write-Host "[ERROR] nginx not found at: $nginxPath" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Path $sslPath -Force | Out-Null
Write-Host "[OK] SSL directory: $sslPath" -ForegroundColor Green
Write-Host ""

# Step 2: Generate self-signed certificate
Write-Host "Step 2: Generating Self-Signed Certificate" -ForegroundColor Cyan
Write-Host "-" * 80

# Remove old certificate if exists
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq "Firmware Checker SSL" } | Remove-Item -ErrorAction SilentlyContinue

# Create new certificate
$cert = New-SelfSignedCertificate `
    -DnsName $hostname, "localhost", "127.0.0.1" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(5) `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -KeyAlgorithm RSA `
    -HashAlgorithm SHA256 `
    -FriendlyName "Firmware Checker SSL"

Write-Host "[OK] Certificate created" -ForegroundColor Green
Write-Host "    Subject: $($cert.Subject)" -ForegroundColor White
Write-Host "    Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
Write-Host "    Valid Until: $($cert.NotAfter)" -ForegroundColor White
Write-Host ""

# Step 3: Export certificate to PFX
Write-Host "Step 3: Exporting Certificate" -ForegroundColor Cyan
Write-Host "-" * 80

$certPassword = ConvertTo-SecureString -String "firmware-checker-2025" -Force -AsPlainText
$pfxPath = "$sslPath\$certName.pfx"

Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$($cert.Thumbprint)" `
    -FilePath $pfxPath `
    -Password $certPassword | Out-Null

Write-Host "[OK] Exported to: $pfxPath" -ForegroundColor Green
Write-Host ""

# Step 4: Convert to PEM format (nginx requires PEM)
Write-Host "Step 4: Converting to PEM Format" -ForegroundColor Cyan
Write-Host "-" * 80

# Check if OpenSSL is available
$opensslPaths = @(
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "C:\Program Files\OpenSSL\bin\openssl.exe",
    "C:\OpenSSL-Win64\bin\openssl.exe",
    "openssl.exe"  # Check PATH
)

$opensslPath = $null
foreach ($path in $opensslPaths) {
    $resolvedPath = $null
    if ($path -eq "openssl.exe") {
        $resolvedPath = (Get-Command openssl -ErrorAction SilentlyContinue).Source
    } elseif (Test-Path $path) {
        $resolvedPath = $path
    }
    
    if ($resolvedPath) {
        $opensslPath = $resolvedPath
        break
    }
}

if ($opensslPath) {
    Write-Host "[OK] Found OpenSSL: $opensslPath" -ForegroundColor Green
    
    # Convert PFX to PEM certificate
    $certPemPath = "$sslPath\$certName.crt"
    & $opensslPath pkcs12 -in $pfxPath -out $certPemPath -clcerts -nokeys -password pass:firmware-checker-2025 2>&1 | Out-Null
    
    # Convert PFX to PEM private key
    $keyPemPath = "$sslPath\$certName.key"
    & $opensslPath pkcs12 -in $pfxPath -out $keyPemPath -nocerts -nodes -password pass:firmware-checker-2025 2>&1 | Out-Null
    
    if ((Test-Path $certPemPath) -and (Test-Path $keyPemPath)) {
        Write-Host "[OK] Created PEM files:" -ForegroundColor Green
        Write-Host "    Certificate: $certPemPath" -ForegroundColor White
        Write-Host "    Private Key: $keyPemPath" -ForegroundColor White
    } else {
        Write-Host "[ERROR] Failed to create PEM files" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[WARNING] OpenSSL not found - using PowerShell export" -ForegroundColor Yellow
    
    # Alternative: Export using PowerShell (creates Base64 encoded cert)
    $certPemPath = "$sslPath\$certName.crt"
    $keyPemPath = "$sslPath\$certName.key"
    
    # Export certificate
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certPem = "-----BEGIN CERTIFICATE-----`n"
    $certPem += [Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $certPem += "`n-----END CERTIFICATE-----"
    [System.IO.File]::WriteAllText($certPemPath, $certPem)
    
    # Export private key (requires more complex handling)
    Write-Host "[INFO] Private key export requires OpenSSL or manual steps" -ForegroundColor Yellow
    Write-Host "       Please install OpenSSL and re-run this script" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "       Git for Windows includes OpenSSL:" -ForegroundColor Yellow
    Write-Host "       https://git-scm.com/download/win" -ForegroundColor Cyan
    exit 1
}
Write-Host ""

# Step 5: Update nginx configuration
Write-Host "Step 5: Updating nginx Configuration" -ForegroundColor Cyan
Write-Host "-" * 80

$nginxConf = "$nginxPath\conf\nginx.conf"
$backupConf = "$nginxPath\conf\nginx.conf.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

# Backup existing config
if (Test-Path $nginxConf) {
    Copy-Item $nginxConf $backupConf
    Write-Host "[OK] Backed up config to: $backupConf" -ForegroundColor Green
}

# Create new HTTPS configuration
$nginxConfig = @"
# nginx configuration for Firmware Checker with SSL
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
    
    # HTTP Server - Redirect to HTTPS
    server {
        listen 80;
        server_name $hostname localhost;
        
        # Redirect all HTTP to HTTPS
        return 301 https://`$host`$request_uri;
    }
    
    # HTTPS Server
    server {
        listen 443 ssl;
        server_name $hostname localhost;
        
        # SSL Certificate
        ssl_certificate      ssl/$certName.crt;
        ssl_certificate_key  ssl/$certName.key;
        
        # SSL Configuration
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        
        # Root redirects to firmware-checker
        location = / {
            return 301 /firmware-checker/;
        }
        
        # Redirect /firmware-checker to /firmware-checker/ (with trailing slash)
        location = /firmware-checker {
            return 301 /firmware-checker/;
        }
        
        # Firmware Checker application
        location /firmware-checker/ {
            # Strip /firmware-checker prefix and pass the rest to Flask
            rewrite ^/firmware-checker/(.*)$ /`$1 break;
            
            # Proxy to Waitress at root (use IPv4 explicitly to avoid IPv6 issues)
            proxy_pass http://127.0.0.1:5000;
            
            # Preserve original request information
            proxy_set_header Host `$host;
            proxy_set_header X-Real-IP `$remote_addr;
            proxy_set_header X-Forwarded-For `$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto `$scheme;
            proxy_set_header X-Forwarded-Host `$host;
            proxy_set_header X-Forwarded-Port `$server_port;
            
            # CRITICAL: Tell Flask about the /firmware-checker prefix
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
Write-Host "[OK] Updated nginx.conf" -ForegroundColor Green
Write-Host ""

# Step 6: Test nginx configuration
Write-Host "Step 6: Testing nginx Configuration" -ForegroundColor Cyan
Write-Host "-" * 80

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

# Step 7: Restart nginx
Write-Host "Step 7: Restarting nginx" -ForegroundColor Cyan
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

# Start nginx
Write-Host "Starting nginx with SSL..." -ForegroundColor Yellow
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

# Step 8: Configure Windows Firewall
Write-Host "Step 8: Configuring Windows Firewall" -ForegroundColor Cyan
Write-Host "-" * 80

try {
    # Port 80
    $existingRule80 = Get-NetFirewallRule -DisplayName "nginx HTTP" -ErrorAction SilentlyContinue
    if (-not $existingRule80) {
        New-NetFirewallRule `
            -DisplayName "nginx HTTP" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 80 `
            -Action Allow `
            -Profile Domain,Private `
            -Enabled True | Out-Null
        Write-Host "[OK] Created firewall rule for port 80" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Firewall rule for port 80 already exists" -ForegroundColor Yellow
    }
    
    # Port 443
    $existingRule443 = Get-NetFirewallRule -DisplayName "nginx HTTPS" -ErrorAction SilentlyContinue
    if (-not $existingRule443) {
        New-NetFirewallRule `
            -DisplayName "nginx HTTPS" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort 443 `
            -Action Allow `
            -Profile Domain,Private `
            -Enabled True | Out-Null
        Write-Host "[OK] Created firewall rule for port 443" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Firewall rule for port 443 already exists" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[WARNING] Could not configure firewall (may need Administrator)" -ForegroundColor Yellow
}
Write-Host ""

# Summary
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "SSL Configuration Complete!" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Access URLs:" -ForegroundColor Yellow
Write-Host "  https://$hostname/firmware-checker" -ForegroundColor Cyan
Write-Host "  https://localhost/firmware-checker" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT - First-Time Access:" -ForegroundColor Yellow
Write-Host "1. Your browser will show a security warning (self-signed certificate)" -ForegroundColor White
Write-Host "2. Click 'Advanced' or 'Details'" -ForegroundColor White
Write-Host "3. Click 'Proceed to $hostname (unsafe)' or 'Accept the Risk'" -ForegroundColor White
Write-Host ""
Write-Host "Optional - Install Certificate to Avoid Warnings:" -ForegroundColor Yellow
Write-Host "1. Run: certmgr.msc" -ForegroundColor White
Write-Host "2. Navigate to: Personal > Certificates" -ForegroundColor White
Write-Host "3. Find: Firmware Checker SSL" -ForegroundColor White
Write-Host "4. Export and import to: Trusted Root Certification Authorities" -ForegroundColor White
Write-Host ""
Write-Host "Certificate Details:" -ForegroundColor Yellow
Write-Host "  Location: $sslPath" -ForegroundColor White
Write-Host "  Certificate: $certName.crt" -ForegroundColor White
Write-Host "  Private Key: $certName.key" -ForegroundColor White
Write-Host "  Valid Until: $($cert.NotAfter.ToString('yyyy-MM-dd'))" -ForegroundColor White
Write-Host ""
Write-Host "nginx Configuration:" -ForegroundColor Yellow
Write-Host "  Config: $nginxConf" -ForegroundColor White
Write-Host "  Backup: $backupConf" -ForegroundColor White
Write-Host "=" * 80 -ForegroundColor Cyan
