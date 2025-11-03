# Firmware Version Checker

A Flask-based web application for checking and recording firmware versions from various systems including DC-SCM, OVL2, and other platform firmwares.

## Features

- **System Management**: Add, edit, delete, and manage systems with RSCM IP and port information
- **Firmware Checking**: Check firmware versions across 39 different firmware types in 3 categories:
  - **DC-SCM** (15 types): IFWI, BMC, Inventory, PowerCapping, FanTable, SDRGenerator, IPMIAllowList, BMCTip, Manticore, CFM, TPM Module, SCM-CPLD, and more
  - **Other Platform** (6 types): HPMCpld, SOC VR Configs, E.1s storage, M.2 storage
  - **OVL2** (18 types): FPGA Agilex variants, Cyclone V variants, OVL SOC FIP variants, drivers, tools, and Glacier Cerberus components
- **Historical Tracking**: Store and view firmware check history for each system
- **Web Interface**: Responsive Bootstrap-based UI for easy management
- **Database Storage**: SQLite database for system and firmware check data

## Project Structure

```
firmware-checker/
├── app.py                     # Main Flask application
├── requirements.txt           # Python dependencies
├── README.md                 # This file
├── firmware_modules/         # Firmware checking modules
│   ├── __init__.py
│   ├── dc_scm.py            # DC-SCM firmware checker
│   ├── ovl2.py              # OVL2 firmware checker
│   └── other_platform.py    # Other platform firmware checker
├── templates/               # HTML templates
│   ├── base.html           # Base template
│   ├── index.html          # Dashboard
│   ├── systems.html        # Systems list
│   ├── add_system.html     # Add system form
│   ├── edit_system.html    # Edit system form
│   ├── system_detail.html  # System details and history
│   ├── check_firmware.html # Firmware checking interface
│   ├── firmware_types.html # Firmware types reference
│   ├── 404.html            # Error page
│   └── 500.html            # Error page
└── static/                 # Static files
    ├── css/
    │   └── style.css       # Custom CSS
    └── js/
        └── main.js         # Custom JavaScript
```

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. **Clone or download the project** to your utility server
2. **Navigate to the project directory**:
   ```bash
   cd firmware-checker
   ```

3. **Create a virtual environment** (recommended):
   ```bash
   python -m venv firmware_env
   ```

4. **Activate the virtual environment**:
   ```bash
   # On Windows
   firmware_env\Scripts\activate
   
   # On Linux/Mac
   source firmware_env/bin/activate
   ```

5. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

6. **Run the application**:
   ```bash
   python app.py
   ```

7. **Open your browser** and navigate to `http://localhost:5000`

## Configuration

### Environment Variables

You can set the following environment variables:

- `SECRET_KEY`: Flask secret key for sessions (default: 'dev-key-change-in-production')
- `DATABASE`: Database file path (default: 'firmware_checker.db')

### Database

The application uses SQLite by default. The database is automatically created when you first run the application.

## Usage

### Adding Systems

1. Navigate to the **Systems** page
2. Click **Add System**
3. Fill in the system information:
   - **System Name**: Unique identifier for the system
   - **RSCM IP Address**: IP address for RSCM connection
   - **RSCM Port**: Port number (default: 22)
   - **Description**: Optional description

### Checking Firmware

1. Go to a system's detail page
2. Click **Check Firmware**
3. Click **Start Firmware Check**
4. View the results organized by category (DC-SCM, Other Platform, OVL2)

### Viewing History

- Each system's detail page shows the complete firmware check history
- Click on firmware data to view detailed results
- Export results to JSON format

## Current Status

**⚠️ IMPORTANT**: This application is currently in **development phase**. All firmware checking functions are **placeholder implementations** that return mock data. 

### What Works Now:
- ✅ Web interface and system management
- ✅ Database structure and data storage
- ✅ Firmware type categorization
- ✅ Results display and history tracking

### What Needs Implementation:
- ❌ Actual firmware checking logic for each firmware type
- ❌ SSH/RSCM connection handling
- ❌ Real firmware version parsing and extraction
- ❌ Error handling for connection failures

## Next Steps for Implementation

To implement actual firmware checking, you'll need to:

1. **Implement SSH connections** in each firmware module
2. **Add specific commands** for each firmware type
3. **Parse output** to extract version information
4. **Handle errors** and connection issues
5. **Test with actual systems**

Each firmware module (`dc_scm.py`, `ovl2.py`, `other_platform.py`) has placeholder functions ready for implementation.

## Production Deployment

For production deployment:

1. **Set environment variables**:
   ```bash
   export SECRET_KEY="your-secure-secret-key"
   export FLASK_ENV="production"
   ```

2. **Use a production WSGI server**:
   ```bash
   # Using Gunicorn (Linux/Mac)
   gunicorn -w 4 -b 0.0.0.0:5000 app:app
   
   # Using Waitress (Windows/Cross-platform)
   waitress-serve --host=0.0.0.0 --port=5000 app:app
   ```

3. **Configure reverse proxy** (nginx, Apache) if needed

4. **Set up SSL/TLS** for secure connections

5. **Configure firewall** to allow access on your chosen port

## Firmware Types Reference

### DC-SCM (15 types)
- IFWI, BMC, Inventory, PowerCapping, FanTable
- SDRGenerator, IPMIAllowList, BMCTip
- BMCTip PCD Platform ID, BMCTip PCD Version
- Manticore, CFM PlatformID, CFMVersion ID
- TPM Module, SCM-CPLD

### Other Platform (6 types)
- HPMCpld, SOC VR Configs
- E.1s (Primary/Secondary), M.2 (Primary/Secondary)

### OVL2 (18 types)
- OVL2 overall package, FPGA Agilex variants
- Cyclone V variants, OVL SOC FIP variants
- SOC Test OS, Host/SOC FPGA drivers and tools
- FPGAsec Tool, MANA Driver, Glacier Cerberus variants

## Troubleshooting

### Common Issues

1. **Port already in use**: Change the port in `app.py` or kill the process using the port
2. **Database errors**: Delete `firmware_checker.db` to reset the database
3. **Permission errors**: Ensure the user has write permissions in the project directory
4. **Import errors**: Make sure all dependencies are installed: `pip install -r requirements.txt`

### Logs

The application logs to the console by default. For production, configure file-based logging.

## License

This project is for internal use. Modify and distribute according to your organization's policies.

## Support

For questions or issues with implementation, consult your team lead or the original developer.

---

**Version**: 1.0.0 (Development)  
**Last Updated**: October 29, 2025