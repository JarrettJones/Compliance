# Windows Service Setup Instructions

## Method 1: NSSM (Recommended)

NSSM (Non-Sucking Service Manager) is the easiest way to run your Flask app as a Windows service.

### Steps:

1. **Download NSSM:**
   - Go to https://nssm.cc/download
   - Download the latest version (e.g., nssm-2.24.zip)
   - Extract to `C:\nssm\` (or another location)

2. **Create logs directory:**
   ```powershell
   mkdir C:\Users\jarrettjones\Compliance\firmware-checker\logs
   ```

3. **Run the installation script as Administrator:**
   ```powershell
   cd C:\Users\jarrettjones\Compliance\firmware-checker
   .\install_windows_service.ps1
   ```

4. **Verify the service is running:**
   ```powershell
   Get-Service FirmwareCheckerApp
   ```

### Service Management Commands:

```powershell
# Start the service
Start-Service FirmwareCheckerApp

# Stop the service
Stop-Service FirmwareCheckerApp

# Restart the service
Restart-Service FirmwareCheckerApp

# Check service status
Get-Service FirmwareCheckerApp

# View logs
Get-Content C:\Users\jarrettjones\Compliance\firmware-checker\logs\service_stdout.log -Tail 50
Get-Content C:\Users\jarrettjones\Compliance\firmware-checker\logs\service_stderr.log -Tail 50
```

### Uninstall:

```powershell
.\uninstall_windows_service.ps1
```

---

## Method 2: Task Scheduler (Alternative)

If you can't use NSSM, you can use Windows Task Scheduler:

1. Open Task Scheduler (`taskschd.msc`)
2. Create Basic Task:
   - Name: "Firmware Checker App"
   - Trigger: At startup
   - Action: Start a program
   - Program: `python.exe`
   - Arguments: `C:\Users\jarrettjones\Compliance\firmware-checker\app.py`
   - Start in: `C:\Users\jarrettjones\Compliance\firmware-checker`
3. Additional settings:
   - Run whether user is logged on or not
   - Run with highest privileges
   - Configure for: Windows Server

---

## Method 3: Manual Windows Service (Advanced)

Use Python's `pywin32` package to create a native Windows service:

```powershell
pip install pywin32
```

Then create a service wrapper script (more complex - not recommended unless needed).

---

## Troubleshooting:

1. **Service won't start:**
   - Check logs in `logs\service_stderr.log`
   - Verify Python path is correct
   - Ensure all dependencies are installed

2. **Port already in use:**
   - Check if Flask is already running manually
   - Use `netstat -ano | findstr :5000` to find processes

3. **Permissions issues:**
   - Run installation script as Administrator
   - Ensure service account has read access to app directory

4. **After code updates:**
   ```powershell
   Restart-Service FirmwareCheckerApp
   ```

---

## Production Configuration:

Before setting up the service, update `app.py` to disable debug mode:

```python
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)  # Change to False
```

Also consider using a production WSGI server like `waitress`:

```powershell
pip install waitress
```

Then create `wsgi.py`:
```python
from waitress import serve
from app import app

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000, threads=4)
```

Update the service to run `wsgi.py` instead of `app.py`.
