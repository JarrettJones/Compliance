# Accessing Firmware Checker by Hostname

You have three options for URL structure:

## Option 1: Hostname with Port (Easiest - No Extra Setup)

**URL:** `http://your-hostname:5000`

**Setup:** Nothing! This works immediately.

**Find your hostname:**
```powershell
$env:COMPUTERNAME
```

Example: If hostname is `LAB-SERVER-01`:
```
http://LAB-SERVER-01:5000
```

**Pros:**
- ✅ Works immediately
- ✅ No additional configuration
- ✅ Simple to set up

**Cons:**
- ❌ Port number in URL (`:5000`)

---

## Option 2: Hostname with Path via IIS (Recommended)

**URL:** `http://your-hostname/firmware-checker`

**Setup:** Use IIS as a reverse proxy

### Installation Steps:

1. **Install IIS and modules:**
   ```powershell
   # Run as Administrator
   .\setup_iis_proxy.ps1
   ```

2. **Download required modules:**
   - [URL Rewrite Module](https://www.iis.net/downloads/microsoft/url-rewrite)
   - [Application Request Routing](https://www.iis.net/downloads/microsoft/application-request-routing)

3. **Restart IIS:**
   ```powershell
   iisreset
   ```

4. **Start Waitress (must be running):**
   ```powershell
   .\start_production.ps1
   ```

5. **Access:**
   ```
   http://your-hostname/firmware-checker
   ```

**How it works:**
- IIS listens on port 80 (default HTTP)
- Forwards requests to `http://localhost:5000` (Waitress)
- URL Rewrite makes path `/firmware-checker` work
- Users see clean URL without port number

**Pros:**
- ✅ Clean URL (no port number)
- ✅ Standard HTTP port 80
- ✅ Can add HTTPS later

**Cons:**
- ❌ Requires IIS installation
- ❌ More complex setup
- ❌ Two services to manage (IIS + Waitress)

---

## Option 3: Custom DNS Name (Advanced)

**URL:** `http://firmware-checker/` or `http://firmware-checker.yourdomain.com/`

**Setup:** Requires DNS configuration

### For Simple Internal Name:

1. **Add to each client's hosts file** (`C:\Windows\System32\drivers\etc\hosts`):
   ```
   192.168.1.100  firmware-checker
   ```

2. **Access:**
   ```
   http://firmware-checker:5000
   ```

### For Corporate DNS:

1. **Add DNS A record in your domain controller:**
   ```
   firmware-checker.yourdomain.com -> 192.168.1.100
   ```

2. **Access:**
   ```
   http://firmware-checker.yourdomain.com:5000
   ```

Or combine with IIS (Option 2) for:
```
http://firmware-checker.yourdomain.com/
```

---

## Comparison Table

| Option | URL Example | Setup Difficulty | Port Required? | Best For |
|--------|-------------|-----------------|----------------|----------|
| **Option 1** | `http://LAB-SERVER:5000` | ⭐ Easy | Yes (`:5000`) | Quick deployment |
| **Option 2** | `http://LAB-SERVER/firmware-checker` | ⭐⭐⭐ Medium | No | Production use |
| **Option 3** | `http://firmware-checker:5000` | ⭐⭐ Medium | Yes | Custom branding |

---

## Recommended Approach

For internal lab deployment, I recommend **Option 1** (hostname with port):

```powershell
# Get your hostname
$hostname = $env:COMPUTERNAME
Write-Host "Access your Firmware Checker at:"
Write-Host "http://$hostname:5000" -ForegroundColor Cyan
```

**Why?**
- Works immediately
- No additional setup
- Easy to troubleshoot
- Port 5000 is not a security issue for internal use

**Share this with your team:**
```
http://YOUR-SERVER-HOSTNAME:5000
```

---

## If You Want Clean URLs (Option 2)

If you really want `http://hostname/firmware-checker` without the port:

1. Run `.\setup_iis_proxy.ps1` as Administrator
2. Download and install URL Rewrite + ARR modules
3. Restart IIS: `iisreset`
4. Keep Waitress running: `.\start_production.ps1`
5. Access: `http://hostname/firmware-checker`

Both Waitress and IIS must be running for this to work.

---

## Troubleshooting

**"Can't resolve hostname"**
- Use IP address instead: `http://192.168.1.100:5000`
- Check both computers are on same network/domain

**"Hostname works on server but not on client"**
- Verify DNS/hostname resolution: `nslookup your-hostname`
- Try using IP address to confirm connectivity
- Check if client is on same domain/network

**"IIS shows error"**
- Verify Waitress is running: `Get-Process python`
- Check IIS can reach localhost:5000
- Review IIS logs: `C:\inetpub\logs\LogFiles\`

**"Path works but CSS/JS broken"**
- Flask might need to know it's behind a proxy
- See advanced configuration in DEPLOYMENT.md
