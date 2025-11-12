# Install CA-Signed SSL Certificate for Firmware Checker
# Run this script after downloading your certificate from SSLAdmin

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SSL Certificate Installation Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Certificate details
$certThumbprint = "A8A8C64E7AD375981BCE879DE6F42A42E4297515"
$serverName = "dca20301103n414.redmond.corp.microsoft.com"
$nginxPath = "C:\nginx-1.24.0"
$certDir = "$nginxPath\ssl"

Write-Host "Certificate Details:" -ForegroundColor Yellow
Write-Host "  Subject: $serverName"
Write-Host "  Thumbprint: $certThumbprint"
Write-Host "  Expires: 12 November 2026"
Write-Host ""

# Check if nginx directory exists
if (-not (Test-Path $nginxPath)) {
    Write-Host "ERROR: nginx directory not found at $nginxPath" -ForegroundColor Red
    exit 1
}

# Create ssl directory if it doesn't exist
if (-not (Test-Path $certDir)) {
    Write-Host "Creating SSL directory..." -ForegroundColor Green
    New-Item -ItemType Directory -Path $certDir -Force | Out-Null
}

Write-Host "Please download the certificate files from SSLAdmin:" -ForegroundColor Yellow
Write-Host "  1. Full Certificate Chain (.p7b)" -ForegroundColor White
Write-Host "  2. Base64 Encoded (.cer)" -ForegroundColor White
Write-Host ""
Write-Host "Recommended: Download the Full Certificate Chain (.p7b)" -ForegroundColor Green
Write-Host ""

# Prompt for certificate file location
Write-Host "Enter the path to your downloaded certificate file:" -ForegroundColor Cyan
Write-Host "(Drag and drop the file here, or paste the full path)" -ForegroundColor Gray
$certFile = Read-Host "Certificate file path"

# Clean up the path (remove quotes if present)
$certFile = $certFile.Trim('"')

if (-not (Test-Path $certFile)) {
    Write-Host "ERROR: Certificate file not found: $certFile" -ForegroundColor Red
    exit 1
}

$certExtension = [System.IO.Path]::GetExtension($certFile).ToLower()
Write-Host ""
Write-Host "Processing certificate file: $certFile" -ForegroundColor Green

# Import the certificate to Windows Certificate Store first
Write-Host ""
Write-Host "Step 1: Importing certificate to Windows Certificate Store..." -ForegroundColor Cyan

try {
    if ($certExtension -eq ".p7b") {
        # Import P7B (PKCS#7) certificate chain
        Write-Host "Importing certificate chain from P7B file..." -ForegroundColor Yellow
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $cert.Import($certFile)
        
        foreach ($c in $cert) {
            if ($c.Subject -like "*$serverName*") {
                $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
                $certStore.Open("ReadWrite")
                $certStore.Add($c)
                $certStore.Close()
                Write-Host "✓ Imported server certificate" -ForegroundColor Green
                $serverCert = $c
            }
        }
    } elseif ($certExtension -eq ".cer") {
        # Import CER file
        Write-Host "Importing certificate from CER file..." -ForegroundColor Yellow
        Import-Certificate -FilePath $certFile -CertStoreLocation Cert:\LocalMachine\My
        Write-Host "✓ Imported certificate" -ForegroundColor Green
    } else {
        Write-Host "ERROR: Unsupported certificate format. Please use .p7b or .cer" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "ERROR importing certificate: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Step 2: Retrieving certificate from Windows Store..." -ForegroundColor Cyan

# Get the certificate from the store using thumbprint
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $certThumbprint }

if (-not $cert) {
    Write-Host "ERROR: Certificate with thumbprint $certThumbprint not found in certificate store" -ForegroundColor Red
    Write-Host "Available certificates:" -ForegroundColor Yellow
    Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject, Thumbprint, NotAfter
    exit 1
}

Write-Host "✓ Found certificate: $($cert.Subject)" -ForegroundColor Green
Write-Host ""

Write-Host "Step 3: Exporting certificate and private key for nginx..." -ForegroundColor Cyan

# Export certificate with private key (PFX)
$pfxPath = "$certDir\server.pfx"
$pfxPassword = ConvertTo-SecureString -String "temp123" -Force -AsPlainText

try {
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword | Out-Null
    Write-Host "✓ Exported PFX file" -ForegroundColor Green
} catch {
    Write-Host "ERROR exporting PFX: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Step 4: Converting to PEM format for nginx..." -ForegroundColor Cyan

# Convert PFX to PEM using OpenSSL (nginx format)
$opensslPath = "C:\Program Files\Git\usr\bin\openssl.exe"

if (-not (Test-Path $opensslPath)) {
    # Try alternate location
    $opensslPath = "C:\Program Files\OpenSSL\bin\openssl.exe"
}

if (-not (Test-Path $opensslPath)) {
    Write-Host "ERROR: OpenSSL not found. Please install OpenSSL or Git for Windows" -ForegroundColor Red
    Write-Host "Git for Windows includes OpenSSL and can be downloaded from: https://git-scm.com/download/win" -ForegroundColor Yellow
    exit 1
}

# Extract certificate (public key)
$certPemPath = "$certDir\server.crt"
& $opensslPath pkcs12 -in $pfxPath -clcerts -nokeys -out $certPemPath -password pass:temp123 -passin pass:temp123

# Extract private key
$keyPemPath = "$certDir\server.key"
& $opensslPath pkcs12 -in $pfxPath -nocerts -out "$certDir\server_encrypted.key" -password pass:temp123 -passin pass:temp123 -passout pass:temp123

# Decrypt private key (remove password for nginx)
& $opensslPath rsa -in "$certDir\server_encrypted.key" -out $keyPemPath -passin pass:temp123

# Clean up temporary files
Remove-Item "$certDir\server_encrypted.key" -Force
Remove-Item $pfxPath -Force

Write-Host "✓ Converted to PEM format" -ForegroundColor Green
Write-Host ""

Write-Host "Step 5: Verifying certificate files..." -ForegroundColor Cyan

if ((Test-Path $certPemPath) -and (Test-Path $keyPemPath)) {
    Write-Host "✓ Certificate file: $certPemPath" -ForegroundColor Green
    Write-Host "✓ Private key file: $keyPemPath" -ForegroundColor Green
    
    # Display certificate details
    Write-Host ""
    Write-Host "Certificate Information:" -ForegroundColor Yellow
    $certInfo = & $opensslPath x509 -in $certPemPath -noout -subject -issuer -dates
    Write-Host $certInfo
} else {
    Write-Host "ERROR: Certificate conversion failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Certificate Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Restart nginx: cd C:\nginx-1.24.0; .\nginx.exe -s reload" -ForegroundColor White
Write-Host "  2. Test HTTPS: https://$serverName/firmware-checker" -ForegroundColor White
Write-Host ""
Write-Host "Files created:" -ForegroundColor Cyan
Write-Host "  Certificate: $certPemPath" -ForegroundColor White
Write-Host "  Private Key: $keyPemPath" -ForegroundColor White
Write-Host ""
