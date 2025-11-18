# Export Certificate from Windows Certificate Store for nginx
# This script exports your organization's certificate and converts it to nginx-compatible format

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Export Certificate for nginx" -ForegroundColor Yellow
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# Find nginx installation
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
    exit 1
}

Write-Host "[OK] Found nginx at: $nginxPath" -ForegroundColor Green
Write-Host ""

# Create SSL directory
$sslDir = "$nginxPath\conf\ssl"
if (-not (Test-Path $sslDir)) {
    New-Item -ItemType Directory -Path $sslDir -Force | Out-Null
    Write-Host "[OK] Created SSL directory: $sslDir" -ForegroundColor Green
} else {
    Write-Host "[OK] SSL directory exists: $sslDir" -ForegroundColor Green
}
Write-Host ""

# Step 1: Find the certificate
Write-Host "Step 1: Finding Server Certificate" -ForegroundColor Cyan
Write-Host "-" * 80

$hostname = $env:COMPUTERNAME
Write-Host "Server hostname: $hostname" -ForegroundColor White
Write-Host ""

# Search in LocalMachine\My store (Personal certificates)
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | 
    Where-Object { 
        $_.Subject -like "*CN=$hostname*" -or 
        $_.Subject -like "*CN=*.$env:USERDNSDOMAIN*" 
    } |
    Where-Object { $_.HasPrivateKey -eq $true } |
    Where-Object { $_.NotAfter -gt (Get-Date) } |
    Sort-Object -Property NotAfter -Descending |
    Select-Object -First 1

if (-not $cert) {
    Write-Host "[ERROR] No valid certificate found in LocalMachine\My store" -ForegroundColor Red
    Write-Host ""
    Write-Host "Looking for certificates with:" -ForegroundColor Yellow
    Write-Host "  - Subject containing: $hostname" -ForegroundColor White
    Write-Host "  - Has private key" -ForegroundColor White
    Write-Host "  - Not expired" -ForegroundColor White
    Write-Host ""
    Write-Host "Available certificates:" -ForegroundColor Yellow
    Get-ChildItem -Path Cert:\LocalMachine\My | ForEach-Object {
        Write-Host "  Subject: $($_.Subject)" -ForegroundColor White
        Write-Host "  Thumbprint: $($_.Thumbprint)" -ForegroundColor Gray
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
Write-Host ""

# Step 2: Export to PFX
Write-Host "Step 2: Exporting to PFX" -ForegroundColor Cyan
Write-Host "-" * 80

$pfxPath = "$sslDir\temp_cert.pfx"
$pfxPassword = ConvertTo-SecureString -String "temp123" -Force -AsPlainText

try {
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword -Force | Out-Null
    Write-Host "[OK] Exported to: $pfxPath" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to export PFX: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Step 3: Check for OpenSSL
Write-Host "Step 3: Converting to nginx Format (PEM)" -ForegroundColor Cyan
Write-Host "-" * 80

$opensslPaths = @(
    "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    "C:\OpenSSL-Win64\bin\openssl.exe",
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "openssl.exe"  # Check if in PATH
)

$opensslPath = $null
foreach ($path in $opensslPaths) {
    if (Get-Command $path -ErrorAction SilentlyContinue) {
        $opensslPath = $path
        break
    }
}

if (-not $opensslPath) {
    Write-Host "[WARNING] OpenSSL not found!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "PFX file created at: $pfxPath" -ForegroundColor Cyan
    Write-Host "Password: temp123" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To complete the conversion, either:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Option 1: Install OpenSSL and run these commands:" -ForegroundColor White
    Write-Host "  Download from: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Then run:" -ForegroundColor White
    Write-Host "  openssl pkcs12 -in '$pfxPath' -clcerts -nokeys -out '$sslDir\server.crt' -password pass:temp123" -ForegroundColor Cyan
    Write-Host "  openssl pkcs12 -in '$pfxPath' -nocerts -nodes -out '$sslDir\server.key' -password pass:temp123" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Option 2: Use an online converter (less secure):" -ForegroundColor White
    Write-Host "  Upload $pfxPath to https://www.sslshopper.com/ssl-converter.html" -ForegroundColor Cyan
    Write-Host "  Convert to: PEM (separate certificate and key)" -ForegroundColor Cyan
    Write-Host "  Save as: $sslDir\server.crt and $sslDir\server.key" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

Write-Host "[OK] Found OpenSSL at: $opensslPath" -ForegroundColor Green
Write-Host ""

# Extract certificate
$certPath = "$sslDir\server.crt"
Write-Host "Extracting certificate..." -ForegroundColor White
$process = Start-Process -FilePath $opensslPath -ArgumentList @(
    "pkcs12", "-in", $pfxPath, "-clcerts", "-nokeys", "-out", $certPath, "-password", "pass:temp123"
) -Wait -NoNewWindow -PassThru

if ($process.ExitCode -eq 0) {
    Write-Host "[OK] Certificate extracted to: $certPath" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Failed to extract certificate" -ForegroundColor Red
    exit 1
}

# Extract private key
$keyPath = "$sslDir\server.key"
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
Write-Host ""

# Clean up temporary PFX
Remove-Item $pfxPath -Force
Write-Host "[OK] Cleaned up temporary PFX file" -ForegroundColor Green
Write-Host ""

# Step 4: Set permissions on private key
Write-Host "Step 4: Setting Permissions" -ForegroundColor Cyan
Write-Host "-" * 80

try {
    # Get the current ACL
    $acl = Get-Acl $keyPath
    
    # Disable inheritance and copy existing permissions
    $acl.SetAccessRuleProtection($true, $true)
    
    # Remove all access rules except for Administrators and SYSTEM
    $acl.Access | ForEach-Object {
        if ($_.IdentityReference -notlike "*Administrators*" -and 
            $_.IdentityReference -notlike "*SYSTEM*") {
            $acl.RemoveAccessRule($_) | Out-Null
        }
    }
    
    # Apply the modified ACL
    Set-Acl -Path $keyPath -AclObject $acl
    
    Write-Host "[OK] Secured private key file permissions" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Could not set permissions: $($_.Exception.Message)" -ForegroundColor Yellow
}
Write-Host ""

# Step 5: Summary
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Certificate Export Complete!" -ForegroundColor Green
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""
Write-Host "Certificate Files:" -ForegroundColor Yellow
Write-Host "  Certificate: $certPath" -ForegroundColor Cyan
Write-Host "  Private Key: $keyPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Reload nginx to use the new certificate:" -ForegroundColor White
Write-Host "   cd $nginxPath" -ForegroundColor Cyan
Write-Host "   .\nginx.exe -t  # Test configuration" -ForegroundColor Cyan
Write-Host "   .\nginx.exe -s reload  # Reload with new certificate" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. Test HTTPS access:" -ForegroundColor White
Write-Host "   Start-Process https://$hostname/firmware-checker" -ForegroundColor Cyan
Write-Host ""
Write-Host "Certificate Details:" -ForegroundColor Yellow
Write-Host "  Valid Until: $($cert.NotAfter)" -ForegroundColor White
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
Write-Host "=" * 80 -ForegroundColor Cyan
