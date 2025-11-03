# Compliance - Firmware Checker

A Flask-based web application for checking and tracking firmware versions across DC-SCM, OVL2, and other platform components in lab environments.

## Features

- 🔍 **Automated Firmware Checking** - Check 39+ firmware types via SSH/Redfish/WinRM
- 📊 **Firmware Recipes** - Define and compare against target firmware versions
- 🔄 **Individual Recheck** - Recheck specific firmware types without full scan
- ✅ **Selective Checking** - Choose which firmware types to check
- 🔐 **Secure Configuration** - Environment-based secrets, production WSGI server
- 📝 **System Tracking** - Track systems with automated BMC serial number registration
- 🔎 **Search & Filter** - Advanced filtering and grouping of systems

## Quick Start

See [QUICKSTART.md](firmware-checker/QUICKSTART.md) for deployment instructions.

```powershell
# 1. Install dependencies
pip install -r firmware-checker/requirements.txt

# 2. Generate secret key
python firmware-checker/generate_secret_key.py

# 3. Configure environment
Copy-Item firmware-checker/.env.example firmware-checker/.env
# Edit .env with your SECRET_KEY

# 4. Start production server
cd firmware-checker
& .\start_production.ps1
```

Access at: `http://localhost:5000`

## Documentation

- **[QUICKSTART.md](firmware-checker/QUICKSTART.md)** - Fast deployment guide
- **[DEPLOYMENT.md](firmware-checker/DEPLOYMENT.md)** - Complete deployment walkthrough
- **[SECURITY.md](firmware-checker/SECURITY.md)** - Security configuration guide
- **[README.md](firmware-checker/README.md)** - Application documentation

## Technology Stack

- **Backend:** Flask (Python 3.8+)
- **Database:** SQLite
- **Server:** Waitress WSGI (production)
- **Frontend:** Bootstrap 5, JavaScript
- **Connectivity:** Paramiko (SSH), Requests (Redfish), PyWinRM (Windows)

## Firmware Types Supported

### DC-SCM (12 types)
BMC FW, BIOS, CPLD, PDB, HMC, ME, OOB Switch, FPGA, BMC Boot Loader, BIOS Boot Loader, HMC Boot Loader, ME Boot Loader

### OVL2 (12 types)
FPGA Agilex, Cyclone V Image, Cyclone V PFMID, SOC FIP, SOC FIP PFMID, SOC Test OS, Host FPGA Driver, SOC FPGA Driver, MANA Driver, Glacier Cerberus FW, Cerberus Utility, Glacier Peak CFM

### Other Platform (6+ types)
NVMe, SAS Expander, HBA, Storage Backplane, Network Adapters, etc.

## Security Features

✅ Cryptographically secure SECRET_KEY  
✅ Environment-based configuration  
✅ Production WSGI server (Waitress)  
✅ Debug mode disabled in production  
✅ Sensitive files gitignored  
✅ Security warnings for misconfigurations  

## Requirements

- Python 3.8+
- Windows (for production) or Linux/Mac (development)
- Network access to RSCM/BMC devices
- SSH/Redfish/WinRM credentials

## License

Internal Microsoft tool for lab deployments.

## Support

For issues or questions, see documentation in the `firmware-checker/` directory.

---

**Project Structure:**
```
Compliance/
├── firmware-checker/           # Main application
│   ├── app.py                  # Flask application
│   ├── run_production.py       # Production server launcher
│   ├── firmware_modules/       # Firmware checking modules
│   ├── templates/              # HTML templates
│   ├── static/                 # CSS/JS assets
│   ├── .env.example            # Configuration template
│   └── [documentation]         # Setup guides
└── README.md                   # This file
```
