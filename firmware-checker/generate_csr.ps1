# Generate CSR for SSL Certificate Request
# This script creates a private key and CSR for certificate signing

$serverName = "dca20301103n414.redmond.corp.microsoft.com"
$shortName = "dca20301103n414"
$outputDir = "C:\nginx\ssl"
$opensslPath = "C:\Program Files\Git\usr\bin\openssl.exe"

# Create output directory if it doesn't exist
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Set file paths
$keyPath = Join-Path $outputDir "$shortName-private.key"
$csrPath = Join-Path $outputDir "$shortName.csr"

Write-Host "Generating new private key and CSR..." -ForegroundColor Cyan

# Generate private key (2048-bit RSA)
Write-Host "Creating private key: $keyPath" -ForegroundColor Yellow
& $opensslPath genrsa -out $keyPath 2048

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to generate private key" -ForegroundColor Red
    exit 1
}

# Create CSR config file
$configPath = Join-Path $outputDir "csr.conf"
$configContent = @"
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = $serverName

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $serverName
DNS.2 = $shortName
"@

$configContent | Out-File -FilePath $configPath -Encoding ascii

# Generate CSR
Write-Host "Creating CSR: $csrPath" -ForegroundColor Yellow
& $opensslPath req -new -key $keyPath -out $csrPath -config $configPath

if ($LASTEXITCODE -ne 0) {
    Write-Host "[ERROR] Failed to generate CSR" -ForegroundColor Red
    exit 1
}

# Display CSR content for submission
Write-Host "`n[SUCCESS] CSR and private key generated successfully!" -ForegroundColor Green
Write-Host "`nPrivate Key: $keyPath" -ForegroundColor Cyan
Write-Host "CSR File: $csrPath" -ForegroundColor Cyan

Write-Host "`n" + ("=" * 80) -ForegroundColor Yellow
Write-Host "CSR CONTENT (Submit this to SSLAdmin):" -ForegroundColor Yellow
Write-Host ("=" * 80) -ForegroundColor Yellow
Get-Content $csrPath
Write-Host ("=" * 80) -ForegroundColor Yellow

Write-Host "`nIMPORTANT: Keep the private key file secure!" -ForegroundColor Red
Write-Host "File: $keyPath" -ForegroundColor Red

# Verify CSR
Write-Host "`nVerifying CSR..." -ForegroundColor Cyan
& $opensslPath req -in $csrPath -noout -text | Select-String -Pattern "Subject:|DNS:"
