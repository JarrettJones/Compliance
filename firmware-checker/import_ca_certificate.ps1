# Import CA-signed certificate into Windows Certificate Store
# This pairs the new certificate with the existing private key

param(
    [string]$CertificatePath = "C:\nginx\ssl\dca20301103n414.redmond.corp.microsoft.com.cer"
)

Write-Host "Importing CA-signed Certificate" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan

# Check if certificate file exists
if (-not (Test-Path $CertificatePath)) {
    Write-Host "[ERROR] Certificate file not found: $CertificatePath" -ForegroundColor Red
    Write-Host "Please provide the path to your .cer or .p7b file" -ForegroundColor Yellow
    exit 1
}

Write-Host "Certificate file: $CertificatePath" -ForegroundColor White

# Import certificate into LocalMachine\My store
try {
    Write-Host "`nImporting certificate into LocalMachine\My store..." -ForegroundColor Yellow
    
    $cert = Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\LocalMachine\My
    
    Write-Host "[SUCCESS] Certificate imported!" -ForegroundColor Green
    Write-Host "`nCertificate Details:" -ForegroundColor Cyan
    Write-Host "  Subject:      $($cert.Subject)" -ForegroundColor White
    Write-Host "  Issuer:       $($cert.Issuer)" -ForegroundColor White
    Write-Host "  Thumbprint:   $($cert.Thumbprint)" -ForegroundColor White
    Write-Host "  NotAfter:     $($cert.NotAfter)" -ForegroundColor White
    Write-Host "  HasPrivateKey: $($cert.HasPrivateKey)" -ForegroundColor $(if ($cert.HasPrivateKey) { "Green" } else { "Red" })
    
    if (-not $cert.HasPrivateKey) {
        Write-Host "`n[WARNING] Certificate does not have a private key associated!" -ForegroundColor Red
        Write-Host "This means the CSR was created on a different computer or the private key was lost." -ForegroundColor Yellow
        Write-Host "You may need to generate a new CSR and request a new certificate." -ForegroundColor Yellow
    } else {
        Write-Host "`n[SUCCESS] Private key is associated with this certificate!" -ForegroundColor Green
        
        # Export the certificate with private key to PFX
        $pfxPath = "C:\nginx\ssl\server.pfx"
        $tempPassword = ConvertTo-SecureString -String "temp123" -Force -AsPlainText
        
        Write-Host "`nExporting certificate with private key to PFX..." -ForegroundColor Yellow
        Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $tempPassword | Out-Null
        
        # Use OpenSSL to convert PFX to PEM format for nginx
        $opensslPath = "C:\Program Files\Git\usr\bin\openssl.exe"
        $certPath = "C:\nginx\ssl\server.crt"
        $keyPath = "C:\nginx\ssl\server.key"
        
        if (Test-Path $opensslPath) {
            Write-Host "Converting to nginx format (PEM)..." -ForegroundColor Yellow
            
            # Extract certificate
            & $opensslPath pkcs12 -in $pfxPath -out $certPath -nokeys -password "pass:temp123" 2>$null
            
            # Extract private key
            & $opensslPath pkcs12 -in $pfxPath -out $keyPath -nocerts -nodes -password "pass:temp123" 2>$null
            
            Write-Host "[SUCCESS] Certificate and key exported for nginx!" -ForegroundColor Green
            Write-Host "  Certificate: $certPath" -ForegroundColor White
            Write-Host "  Private Key: $keyPath" -ForegroundColor White
            
            # Clean up PFX
            Remove-Item $pfxPath -Force
            
            Write-Host "`nYou can now run setup_nginx_proxy.ps1 to configure nginx with SSL" -ForegroundColor Cyan
        } else {
            Write-Host "[WARNING] OpenSSL not found, manual conversion needed" -ForegroundColor Yellow
        }
    }
    
} catch {
    Write-Host "[ERROR] Failed to import certificate: $_" -ForegroundColor Red
    exit 1
}
