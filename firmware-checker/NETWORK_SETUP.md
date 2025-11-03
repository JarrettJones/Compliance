# Firmware Checker - Network Troubleshooting Guide

## Making Your Server Accessible to the Network

### On Your Test Server (Run as Administrator):

```powershell
# Navigate to the application directory
cd C:\FirmwareChecker

# Run the network setup script
.\setup_network.ps1
```

This script will:
- ✅ Show your server's IP address
- ✅ Create Windows Firewall rule for port 5000
- ✅ Verify the server is running
- ✅ Provide access URLs for your team

---

## Manual Configuration (if needed)

### 1. Get Your Server's IP Address

```powershell
ipconfig | findstr IPv4
```

Look for your network adapter (usually "Ethernet" or "Wi-Fi")
Example: `192.168.1.100`

### 2. Configure Windows Firewall

```powershell
# Run as Administrator
New-NetFirewallRule `
    -DisplayName "Firmware Checker" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5000 `
    -Action Allow `
    -Profile Domain,Private
```

### 3. Verify Server is Running

Check that Waitress is listening on 0.0.0.0:5000:

```powershell
netstat -ano | findstr :5000
```

You should see: `0.0.0.0:5000` or `[::]:5000` (not 127.0.0.1:5000)

### 4. Test from Server

```powershell
# Test local access
Start-Process "http://localhost:5000"
```

### 5. Share URL with Team

Replace with your actual IP:
```
http://your-server-ip:5000
```

Example:
```
http://192.168.1.100:5000
```

---

## Troubleshooting Common Issues

### Issue: "Can't connect from other computers"

**Check 1: Verify firewall rule**
```powershell
Get-NetFirewallRule -DisplayName "Firmware Checker"
```

Should show: `Enabled: True`, `Action: Allow`

**Check 2: Verify server is listening on all interfaces**
```powershell
netstat -ano | findstr :5000
```

Should show `0.0.0.0:5000` (not `127.0.0.1:5000`)

If it shows `127.0.0.1:5000`, check your `.env` file:
```
HOST=0.0.0.0  # Should be 0.0.0.0, not 127.0.0.1
PORT=5000
```

**Check 3: Test from the server itself**
```powershell
# This should work
Invoke-WebRequest -Uri "http://localhost:5000" -UseBasicParsing
```

**Check 4: Test with server IP from the server**
```powershell
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1).IPAddress
Invoke-WebRequest -Uri "http://$ip:5000" -UseBasicParsing
```

**Check 5: Test from client computer**
```powershell
# On client computer (replace with your server IP)
Test-NetConnection -ComputerName 192.168.1.100 -Port 5000
```

Should show: `TcpTestSucceeded : True`

---

### Issue: "Port already in use"

Check what's using the port:
```powershell
Get-NetTCPConnection -LocalPort 5000
```

Stop the conflicting process or change the port in `.env`:
```
PORT=5001  # Or any other available port
```

Then update firewall rule for the new port.

---

### Issue: "Firewall rule not working"

**Check Windows Firewall status:**
```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled
```

**Check if rule is in correct profile:**
```powershell
Get-NetFirewallRule -DisplayName "Firmware Checker" | Format-List *
```

**Try adding to all profiles:**
```powershell
Remove-NetFirewallRule -DisplayName "Firmware Checker"
New-NetFirewallRule `
    -DisplayName "Firmware Checker" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5000 `
    -Action Allow `
    -Profile Domain,Private,Public
```

---

### Issue: "Connection times out"

**Check network connectivity:**
```powershell
# From client computer, ping the server
ping server-ip

# Test if port is reachable
Test-NetConnection -ComputerName server-ip -Port 5000
```

**Possible causes:**
- Server firewall blocking (see above)
- Network firewall/router blocking port 5000
- Wrong IP address (check both computers are on same network)
- VPN or network isolation

---

## Network Profiles Explained

**Domain:** Corporate domain-joined networks (most restrictive, most secure)
**Private:** Home/work networks (trusted networks)
**Public:** Coffee shops, airports (least trusted)

For internal lab deployment, use Domain + Private profiles.

---

## Security Considerations for Network Access

Since this is internal lab deployment:

✅ **Configured:**
- Strong SECRET_KEY
- Production server (Waitress)
- Debug mode disabled

⚠️ **Optional (for enhanced security):**
- Limit firewall rule to specific IP ranges
- Use VPN for remote access
- Implement HTTPS (requires certificate)

**To restrict to specific IP range:**
```powershell
New-NetFirewallRule `
    -DisplayName "Firmware Checker" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5000 `
    -Action Allow `
    -RemoteAddress 192.168.1.0/24 `
    -Profile Domain,Private
```

---

## Testing Checklist

From your test server:
- [ ] `http://localhost:5000` works
- [ ] `http://server-ip:5000` works

From another computer on the network:
- [ ] `ping server-ip` succeeds
- [ ] `Test-NetConnection -ComputerName server-ip -Port 5000` succeeds
- [ ] `http://server-ip:5000` opens in browser

---

## Quick Commands Reference

**Start server:**
```powershell
cd C:\FirmwareChecker
& .\start_production.ps1
```

**Stop server:**
```
Ctrl+C in the terminal
```

**Check if running:**
```powershell
Get-Process python
```

**Get server IP:**
```powershell
ipconfig | findstr IPv4
```

**Test connectivity:**
```powershell
Test-NetConnection -ComputerName server-ip -Port 5000
```

**View firewall rules:**
```powershell
Get-NetFirewallRule -DisplayName "Firmware Checker" | Format-List *
```

---

## Support

If you continue to have issues:
1. Verify server is running on correct port
2. Check both server and client are on same network
3. Temporarily disable firewall to test (re-enable after!)
4. Check corporate network policies (some block custom ports)
