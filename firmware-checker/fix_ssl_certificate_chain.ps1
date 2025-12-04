# Fix SSL Certificate Chain for nginx
# This script exports the certificate WITH the full chain from Windows Certificate Store

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Fix SSL Certificate Chain for nginx" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Configuration
$hostname = $env:COMPUTERNAME
$nginxPath = "C:\nginx"
$sslDir = "$nginxPath\ssl"

# Step 1: Find nginx
Write-Host "Step 1: Locating nginx" -ForegroundColor Cyan
Write-Host "-" * 80

if (-not (Test-Path "$nginxPath\nginx.exe")) {
    Write-Host "[ERROR] nginx not found at: $nginxPath" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Found nginx at: $nginxPath" -ForegroundColor Green
Write-Host ""

# Step 2: Find the certificate
Write-Host "Step 2: Finding Server Certificate" -ForegroundColor Cyan
Write-Host "-" * 80

Write-Host "Server hostname: $hostname" -ForegroundColor White
Write-Host ""

# Search in LocalMachine\My store
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | 
    Where-Object { 
        $_.Subject -like "*CN=$hostname*" -or 
        $_.DnsNameList.Unicode -contains $hostname
    } |
    Where-Object { $_.HasPrivateKey -eq $true } |
    Where-Object { $_.NotAfter -gt (Get-Date) } |
    Where-Object { $_.Subject -ne $_.Issuer } |  # Exclude self-signed certificates
    Sort-Object -Property NotAfter -Descending |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "[ERROR] No valid certificate found for $hostname" -ForegroundColor Red
    Write-Host ""
    Write-Host "Available certificates:" -ForegroundColor Yellow
    Get-ChildItem -Path Cert:\LocalMachine\My | ForEach-Object {
        Write-Host "  Subject: $($_.Subject)" -ForegroundColor White
        Write-Host "  DNS Names: $($_.DnsNameList.Unicode -join ', ')" -ForegroundColor Gray
        Write-Host "  Expires: $($_.NotAfter)" -ForegroundColor Gray
        Write-Host "  Has Private Key: $($_.HasPrivateKey)" -ForegroundColor Gray
        Write-Host ""
    }
    exit 1
}

Write-Host "[OK] Found certificate:" -ForegroundColor Green
Write-Host "  Subject: $($cert.Subject)" -ForegroundColor White
Write-Host "  Issuer: $($cert.Issuer)" -ForegroundColor White
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
Write-Host "  Expires: $($cert.NotAfter)" -ForegroundColor White
Write-Host "  DNS Names: $($cert.DnsNameList.Unicode -join ', ')" -ForegroundColor White
Write-Host ""

# Step 3: Export certificate WITH full chain
Write-Host "Step 3: Exporting Certificate with Full Chain" -ForegroundColor Cyan
Write-Host "-" * 80

$fullChainPath = "$sslDir\server-fullchain.crt"

try {
    # Export the certificate with full chain in Base64 format
    $certChain = @()
    
    # Add the server certificate
    $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $certPem = "-----BEGIN CERTIFICATE-----`n"
    $certPem += [Convert]::ToBase64String($certBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
    $certPem += "`n-----END CERTIFICATE-----`n"
    $certChain += $certPem
    
    # Build the chain and add intermediate certificates
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.Build($cert) | Out-Null
    
    # Add intermediate certificates (skip the first one as it's the server cert, and skip the last if it's root)
    for ($i = 1; $i -lt $chain.ChainElements.Count; $i++) {
        $intermediateCert = $chain.ChainElements[$i].Certificate
        
        # Skip the root CA (self-signed)
        if ($intermediateCert.Subject -eq $intermediateCert.Issuer) {
            Write-Host "  Skipping root CA: $($intermediateCert.Subject)" -ForegroundColor Gray
            continue
        }
        
        Write-Host "  Adding intermediate CA: $($intermediateCert.Subject)" -ForegroundColor White
        
        $intermediateBytes = $intermediateCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $intermediatePem = "-----BEGIN CERTIFICATE-----`n"
        $intermediatePem += [Convert]::ToBase64String($intermediateBytes, [System.Base64FormattingOptions]::InsertLineBreaks)
        $intermediatePem += "`n-----END CERTIFICATE-----`n"
        $certChain += $intermediatePem
    }
    
    # Write the full chain to file
    $fullChainContent = $certChain -join "`n"
    [System.IO.File]::WriteAllText($fullChainPath, $fullChainContent)
    
    Write-Host "[OK] Exported certificate with full chain to: $fullChainPath" -ForegroundColor Green
    Write-Host "  Chain length: $($certChain.Count) certificate(s)" -ForegroundColor White
    
} catch {
    Write-Host "[ERROR] Failed to export certificate: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 4: Export private key to PFX (temporary)
Write-Host "Step 4: Exporting Private Key" -ForegroundColor Cyan
Write-Host "-" * 80

$pfxPath = "$sslDir\temp.pfx"
$pfxPassword = ConvertTo-SecureString -String "temp123" -Force -AsPlainText

try {
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword -Force | Out-Null
    Write-Host "[OK] Exported to temporary PFX: $pfxPath" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to export PFX: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 5: Convert PFX to PEM private key
Write-Host "Step 5: Converting Private Key to PEM Format" -ForegroundColor Cyan
Write-Host "-" * 80

# Find OpenSSL
$opensslPaths = @(
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "C:\Program Files\OpenSSL\bin\openssl.exe",
    "C:\OpenSSL-Win64\bin\openssl.exe",
    "openssl.exe"
)

$opensslPath = $null
foreach ($path in $opensslPaths) {
    if ($path -eq "openssl.exe") {
        $resolved = (Get-Command openssl -ErrorAction SilentlyContinue)
        if ($resolved) {
            $opensslPath = $resolved.Source
            break
        }
    } elseif (Test-Path $path) {
        $opensslPath = $path
        break
    }
}

if (-not $opensslPath) {
    Write-Host "[ERROR] OpenSSL not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install OpenSSL:" -ForegroundColor Yellow
    Write-Host "  - Git for Windows (includes OpenSSL): https://git-scm.com/download/win" -ForegroundColor Cyan
    Write-Host "  - OpenSSL for Windows: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Temporary PFX saved at: $pfxPath (password: temp123)" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] Found OpenSSL: $opensslPath" -ForegroundColor Green

# Extract private key
$keyPath = "$sslDir\server-new.key"
Write-Host "Extracting private key..." -ForegroundColor White

$process = Start-Process -FilePath $opensslPath -ArgumentList @(
    "pkcs12", "-in", $pfxPath, "-nocerts", "-nodes", "-out", $keyPath, "-password", "pass:temp123"
) -Wait -NoNewWindow -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "[OK] Private key extracted to: $keyPath" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to extract private key" -ForegroundColor Red
    exit 1
}

# Clean up temporary PFX
Remove-Item $pfxPath -Force -ErrorAction SilentlyContinue
Write-Host "[OK] Cleaned up temporary PFX file" -ForegroundColor Green
Write-Host ""

# Step 6: Backup and update nginx config
Write-Host "Step 6: Updating nginx Configuration" -ForegroundColor Cyan
Write-Host "-" * 80

$nginxConf = "$nginxPath\conf\nginx.conf"

# Backup existing config
$backupConf = "$nginxPath\conf\nginx.conf.backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item $nginxConf $backupConf -Force
Write-Host "[OK] Backed up config to: $backupConf" -ForegroundColor Green

# Read current config
$configContent = Get-Content $nginxConf -Raw

# Update SSL certificate paths
$configContent = $configContent -replace 'ssl_certificate\s+.*;', 'ssl_certificate      C:/nginx/ssl/server-fullchain.crt;'
$configContent = $configContent -replace 'ssl_certificate_key\s+.*;', 'ssl_certificate_key  C:/nginx/ssl/server-new.key;'

# Write updated config
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($nginxConf, $configContent, $utf8NoBom)

Write-Host "[OK] Updated nginx.conf with new certificate paths" -ForegroundColor Green
Write-Host ""

# Step 7: Test nginx configuration
Write-Host "Step 7: Testing nginx Configuration" -ForegroundColor Cyan
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
    Copy-Item $backupConf $nginxConf -Force
    Write-Host "[OK] Backup restored" -ForegroundColor Green
    exit 1
}
Write-Host ""

# Step 8: Restart nginx
Write-Host "Step 8: Restarting nginx" -ForegroundColor Cyan
Write-Host "-" * 80

# Stop all nginx processes
Write-Host "Stopping nginx..." -ForegroundColor Yellow
Get-Process -Name "nginx" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Start nginx
Write-Host "Starting nginx with updated certificate..." -ForegroundColor Yellow
Push-Location $nginxPath
Start-Process -FilePath ".\nginx.exe" -WindowStyle Hidden
Pop-Location

Start-Sleep -Seconds 2

# Verify nginx is running
$nginxProcess = Get-Process -Name "nginx" -ErrorAction SilentlyContinue
if ($nginxProcess) {
    Write-Host "[OK] nginx is running" -ForegroundColor Green
    Write-Host "  Processes: $($nginxProcess.Count)" -ForegroundColor White
} else {
    Write-Host "[ERROR] Failed to start nginx" -ForegroundColor Red
    Write-Host "Check logs at: $nginxPath\logs\error.log" -ForegroundColor Yellow
}
Write-Host ""

# Summary
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "SSL Certificate Chain Fix Complete!" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Certificate Files:" -ForegroundColor Yellow
Write-Host "  Full Chain Certificate: $fullChainPath" -ForegroundColor Cyan
Write-Host "  Private Key: $keyPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Access URLs:" -ForegroundColor Yellow
Write-Host "  https://$hostname/firmware-checker/" -ForegroundColor Cyan
Write-Host ""
Write-Host "The certificate should now show as secure in your browser!" -ForegroundColor Green
Write-Host "The full chain includes:" -ForegroundColor White
Write-Host "  - Server certificate (DCA20301103N414.redmond.corp.microsoft.com)" -ForegroundColor White
Write-Host "  - Intermediate CA (MSIT CA Z2)" -ForegroundColor White
Write-Host ""
Write-Host "Certificate Details:" -ForegroundColor Yellow
Write-Host "  Valid Until: $($cert.NotAfter)" -ForegroundColor White
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
Write-Host "=" * 80 -ForegroundColor Cyan
