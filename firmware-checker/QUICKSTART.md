# Quick Start Guide - Test Server Deployment

## On Your Test Server

### 1. Copy Files
Transfer the `firmware-checker` folder to your test server:
```
C:\FirmwareChecker\
```

### 2. Install Dependencies
```powershell
cd C:\FirmwareChecker
pip install -r requirements.txt
```

### 3. Configure Environment
```powershell
# Generate secret key
python generate_secret_key.py

# Create .env from template
Copy-Item .env.example .env

# Edit .env and paste your SECRET_KEY
notepad .env
```

### 4. Start Production Server
```powershell
cd C:\FirmwareChecker
& .\start_production.ps1
```

That's it! Access at: `http://your-server-ip:5000`

---

## Commands Reference

### Start Server (Production)
```powershell
& .\start_production.ps1
```

### Start Server (Development/Testing)
```powershell
python app.py
```

### Stop Server
Press `Ctrl+C` in the terminal, or:
```powershell
Stop-Process -Name python -Force
```

### Check if Running
```powershell
Get-Process python
```

### View Logs
Console output shows all activity in real-time

### Test Connectivity
From another machine:
```
http://server-ip:5000
```

---

## Firewall Rule (if needed)
```powershell
New-NetFirewallRule -DisplayName "Firmware Checker" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

---

## Run as Windows Service (Optional)

For permanent deployment:

1. Download NSSM: https://nssm.cc/download
2. Install as service:

```powershell
# Set environment variables first
. .\setup_env.ps1

# Get the values
$secretKey = $env:SECRET_KEY
$pythonPath = (Get-Command python).Source
$scriptPath = "C:\FirmwareChecker\run_production.py"

# Install service
nssm install FirmwareChecker $pythonPath $scriptPath

# Set environment
nssm set FirmwareChecker AppEnvironmentExtra SECRET_KEY=$secretKey
nssm set FirmwareChecker AppEnvironmentExtra FLASK_DEBUG=False
nssm set FirmwareChecker AppEnvironmentExtra HOST=0.0.0.0
nssm set FirmwareChecker AppEnvironmentExtra PORT=5000

# Set working directory
nssm set FirmwareChecker AppDirectory C:\FirmwareChecker

# Configure logging
New-Item -ItemType Directory -Force -Path C:\FirmwareChecker\logs
nssm set FirmwareChecker AppStdout C:\FirmwareChecker\logs\service-output.log
nssm set FirmwareChecker AppStderr C:\FirmwareChecker\logs\service-error.log

# Start service
nssm start FirmwareChecker

# Auto-start on boot
nssm set FirmwareChecker Start SERVICE_AUTO_START
```

Service management:
```powershell
nssm start FirmwareChecker
nssm stop FirmwareChecker
nssm restart FirmwareChecker
nssm status FirmwareChecker
```

---

## Troubleshooting

**Port already in use:**
```powershell
netstat -ano | findstr :5000
taskkill /PID <process-id> /F
```

**Can't access from network:**
- Check firewall allows port 5000
- Verify HOST=0.0.0.0 in .env
- Test from server first: `http://localhost:5000`

**Environment variables not loaded:**
- Always use `start_production.ps1` script
- Or manually load: `. .\setup_env.ps1` before running

**Database locked:**
- Stop all Python processes
- Check file permissions on firmware_checker.db

---

## What You Get with Waitress

✅ Production-grade stability
✅ Multiple worker threads (handles concurrent checks)
✅ Better performance than Flask dev server
✅ Graceful shutdown
✅ Better timeout handling
✅ Suitable for internal production use

---

## Default Configuration

- **Port:** 5000
- **Threads:** 4
- **Host:** 0.0.0.0 (all interfaces)
- **Debug:** False (production mode)
- **Timeout:** 120 seconds (for long firmware checks)

Adjust in `.env` file if needed.
