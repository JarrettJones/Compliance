# Production Deployment Guide - Waitress

This guide walks you through deploying the Firmware Checker on your test server using Waitress, a production-ready WSGI server.

## Prerequisites

- Windows Server or Windows 10/11
- Python 3.8+ installed
- Network access from server to your RSCM devices

## Step-by-Step Deployment

### 1. Transfer Files to Test Server

Copy the entire `firmware-checker` folder to your test server, for example:
```
C:\FirmwareChecker\
```

### 2. Install Python Dependencies

Open PowerShell as Administrator on the test server:

```powershell
cd C:\FirmwareChecker
pip install -r requirements.txt
```

This installs Flask, Waitress, Paramiko, and all other dependencies.

### 3. Configure Environment

Generate a secure secret key:
```powershell
python generate_secret_key.py
```

Create your `.env` file:
```powershell
Copy-Item .env.example .env
notepad .env
```

Update the `.env` file with:
- Your generated `SECRET_KEY`
- Set `FLASK_DEBUG=False` for production
- Configure `HOST` and `PORT` (defaults are fine: 0.0.0.0:5000)

Example `.env`:
```
SECRET_KEY=your-generated-key-here
FLASK_DEBUG=False
HOST=0.0.0.0
PORT=5000
WAITRESS_THREADS=4
```

### 4. Load Environment Variables

```powershell
. .\setup_env.ps1
```

You should see confirmation that SECRET_KEY is configured.

### 5. Start Production Server

**Option A: Run directly**
```powershell
python run_production.py
```

**Option B: Run as a service (recommended for permanent deployment)**

Create a scheduled task or use NSSM (Non-Sucking Service Manager):

Download NSSM from https://nssm.cc/download

```powershell
# Install NSSM
nssm install FirmwareChecker "C:\Python313\python.exe" "C:\FirmwareChecker\run_production.py"

# Set environment variables
nssm set FirmwareChecker AppEnvironmentExtra SECRET_KEY=your-key-here
nssm set FirmwareChecker AppEnvironmentExtra FLASK_DEBUG=False

# Set working directory
nssm set FirmwareChecker AppDirectory C:\FirmwareChecker

# Start the service
nssm start FirmwareChecker
```

### 6. Verify Server is Running

Open a browser and navigate to:
```
http://localhost:5000
```

Or from another machine on the network:
```
http://your-server-ip:5000
```

You should see the Firmware Checker homepage.

### 7. Configure Firewall (if needed)

If accessing from other machines, allow port 5000:

```powershell
New-NetFirewallRule -DisplayName "Firmware Checker" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

## Production Server Features

Waitress provides:
- ✅ Multiple worker threads (default: 4)
- ✅ Better performance than Flask dev server
- ✅ Production-grade stability
- ✅ Graceful handling of concurrent requests
- ✅ Better timeout handling for long-running firmware checks

## Starting and Stopping

**Development mode (for testing):**
```powershell
python app.py
```

**Production mode:**
```powershell
. .\setup_env.ps1
python run_production.py
```

**As a Windows Service (using NSSM):**
```powershell
# Start
nssm start FirmwareChecker

# Stop
nssm stop FirmwareChecker

# Restart
nssm restart FirmwareChecker

# Check status
nssm status FirmwareChecker
```

## Monitoring and Logs

The application logs to the console. When running as a service with NSSM:
- stdout log: `C:\FirmwareChecker\logs\service-output.log`
- stderr log: `C:\FirmwareChecker\logs\service-error.log`

Configure these in NSSM:
```powershell
nssm set FirmwareChecker AppStdout C:\FirmwareChecker\logs\service-output.log
nssm set FirmwareChecker AppStderr C:\FirmwareChecker\logs\service-error.log
```

## Updating the Application

1. Stop the server/service
2. Copy new files to the server
3. Restart the server/service

```powershell
nssm stop FirmwareChecker
# Copy updated files
nssm start FirmwareChecker
```

## Troubleshooting

**Port already in use:**
```powershell
# Check what's using port 5000
netstat -ano | findstr :5000

# Kill the process (replace PID with actual process ID)
taskkill /PID <PID> /F

# Or change the port in .env
```

**Can't access from other machines:**
- Check Windows Firewall rules
- Verify HOST is set to 0.0.0.0 (not 127.0.0.1)
- Ensure network allows connections to port 5000

**Database errors:**
- Ensure the application has write permissions to the folder
- Check that `firmware_checker.db` isn't locked by another process

**Import errors:**
- Verify all dependencies are installed: `pip list`
- Reinstall if needed: `pip install -r requirements.txt --force-reinstall`

## Security Notes for Production

Since this is an internal lab tool:
- ✅ Strong SECRET_KEY configured
- ✅ Production server (Waitress)
- ✅ Debug mode disabled
- ⚠️ Consider restricting firewall to specific IP ranges
- ⚠️ Keep server patched and updated

## Performance Tuning

Adjust worker threads based on load:
```
# In .env
WAITRESS_THREADS=8  # More threads for higher concurrency
```

For very high loads, consider running multiple instances behind a load balancer.

## Backup

Important files to backup:
- `firmware_checker.db` - All your system and check data
- `.env` - Your configuration (keep secure!)
- `uploads/` - Any uploaded files

## Support

For issues or questions:
1. Check logs for error messages
2. Verify environment variables are loaded
3. Test connectivity to RSCM devices
4. Review SECURITY.md for configuration help
