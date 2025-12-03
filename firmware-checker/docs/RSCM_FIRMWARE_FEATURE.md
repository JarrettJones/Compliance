# RSCM Firmware Collection Feature

## Overview
This feature adds RSCM (Rack Secure Control Module) firmware version collection to the firmware checker system using the Redfish API.

## Implementation Details

### New Module: `firmware_modules/rscm.py`
- **Class**: `RSCMChecker`
- **Purpose**: Check RSCM firmware versions via Redfish API
- **Endpoint**: `/redfish/v1/Managers/RackManager`

### Key Features

#### 1. **RSCMChecker Class**
```python
class RSCMChecker:
    def __init__(self, username='root', password='', timeout=30)
    def check_firmware(self, rscm_ip, rscm_port=8080)
    def test_connection(self, rscm_ip, rscm_port=8080)
```

#### 2. **Firmware Data Extracted**
- **Manager Type**: `ManagerType` field (e.g., "3OU_POWER_SHELF")
- **Model**: `Model` field (e.g., "M4010")
- **Firmware Version**: `FirmwareVersion` field (e.g., "1.27.7")

#### 3. **Optional Extended Data**
If available in the RSCM response:
- **Components**: From `Oem.Microsoft.Components` array
  - Each component's Name and Version
- **FW Update List**: From `Oem.Microsoft.FWUpdateList` array
  - Each FW bank's Name and Version

#### 4. **Integration Points**

**app.py Changes:**
- Line 30: Import `RSCMChecker` from `firmware_modules.rscm`
- Line 739: Initialize `rscm_checker` with credentials
- Lines 750-752: Add RSCM check to total firmware types count
- Line 771: Add `'rscm': {'firmware_versions': {}}` to results structure
- Lines 1028-1084: RSCM firmware checking logic in `perform_firmware_check_threaded()`
- Line 1123: Include 'rscm' in firmware comparison categories

**Firmware Check Flow:**
1. DC-SCM firmware checks (Redfish)
2. OVL2 firmware checks (SSH/Redfish)
3. Other Platform firmware checks (WinRM/SSH)
4. **RSCM firmware check (Redfish)** ← NEW
5. Complete and save results

### Results Structure

The RSCM results are stored in the firmware check data with this structure:

```json
{
  "rscm": {
    "category": "RSCM",
    "status": "completed",
    "timestamp": "2025-01-22T12:34:56.789",
    "firmware_versions": {
      "Manager Type": {
        "version": "3OU_POWER_SHELF",
        "status": "success"
      },
      "Model": {
        "version": "M4010",
        "status": "success"
      },
      "Firmware Version": {
        "version": "1.27.7",
        "status": "success"
      },
      "Component: SwitchBladeFW": {
        "version": "4.3.1",
        "status": "success"
      },
      "FW Bank: PrimaryFW": {
        "version": "1.27.7",
        "status": "success"
      }
    },
    "errors": []
  }
}
```

### Error Handling

The RSCM checker includes comprehensive error handling:

1. **Connection Testing**: Validates Redfish API accessibility before checking
2. **Timeout Handling**: Configurable timeout (default 30s)
3. **SSL Verification**: Disabled for self-signed certificates (common in datacenter equipment)
4. **Failed Checks**: Returns error status with descriptive messages
5. **Missing Data**: Returns "Unknown" for missing fields rather than crashing

### Test Script: `test_rscm_checker.py`

A standalone test script is provided to validate RSCM connectivity and firmware retrieval:

**Usage:**
```bash
# Update credentials and RSCM IP in the script
python test_rscm_checker.py
```

**Test Output:**
- Connection test results
- Firmware version extraction
- Status indicators (✓/✗) for each component
- Detailed error messages if check fails

### Selective Firmware Checking

RSCM checks are:
- **Enabled by default** in full firmware checks
- **Can be excluded** in selective firmware checks
- **Counted as 1 unit** in progress tracking (not split into sub-checks)

### Progress Tracking

RSCM checks are integrated into the firmware check progress:
- Shows as "RSCM" category during execution
- Displays "RSCM Manager" as current firmware type
- Updates percentage completion in real-time
- Stores results in database immediately after completion

## API Endpoint Details

### RSCM Redfish API
- **URL**: `https://{rscm_ip}:{rscm_port}/redfish/v1/Managers/RackManager`
- **Method**: GET
- **Auth**: HTTP Basic Authentication
- **SSL**: Verify=False (self-signed certs)
- **Timeout**: Configurable (default 30s)

### Response Structure
```json
{
  "@odata.type": "#Manager.v1_16_0.Manager",
  "Id": "RackManager",
  "Name": "Manager",
  "ManagerType": "3OU_POWER_SHELF",
  "Model": "M4010",
  "FirmwareVersion": "1.27.7",
  "Status": {
    "State": "Enabled",
    "Health": "OK"
  },
  "Oem": {
    "Microsoft": {
      "Components": [
        {
          "Name": "SwitchBladeFW",
          "Version": "4.3.1"
        }
      ],
      "FWUpdateList": [
        {
          "Name": "PrimaryFW",
          "Version": "1.27.7"
        }
      ]
    }
  }
}
```

## Configuration

### RSCM Credentials
RSCM uses the same credentials as DC-SCM (BMC credentials):
- Username: Typically "root" or "admin"
- Password: Same as BMC password
- Port: Default 8080 (HTTPS)

### System Requirements
- RSCM IP must be reachable from the firmware checker server
- RSCM must support Redfish API v1.0+
- Port 8080 must be open (or alternative HTTPS port configured)

## Database Storage

RSCM firmware data is stored in the `firmware_checks` table:
- **Field**: `firmware_data` (JSON column)
- **Structure**: Same as other firmware categories
- **Indexing**: Part of overall firmware check record
- **History**: All RSCM checks are preserved with timestamps

## UI Integration

The RSCM firmware results will appear:
1. **Check Progress Page**: Shows RSCM category during live checks
2. **Check Result Page**: Displays RSCM firmware versions alongside other categories
3. **Recipe Comparison**: RSCM versions can be compared against recipe expectations

## Future Enhancements

Potential improvements for RSCM checking:
1. **Health Monitoring**: Extract status, temperature, power metrics
2. **Component Details**: Parse detailed component information from Oem.Microsoft
3. **Update Status**: Track firmware update operations via FWUpdateList
4. **eMMC Health**: Monitor RSCM storage health metrics
5. **Alert Thresholds**: Define expected RSCM firmware versions per program

## Testing Recommendations

Before deploying to production:

1. **Test RSCM Connectivity**:
   ```bash
   python test_rscm_checker.py
   ```

2. **Verify Credentials**: Ensure RSCM username/password match BMC credentials

3. **Test Full Check**: Run a complete firmware check on a system with RSCM

4. **Validate Results**: Confirm RSCM data appears in check results UI

5. **Test Selective Check**: Verify RSCM can be excluded if desired

## Troubleshooting

### Common Issues

**Connection Timeout:**
- Check RSCM IP is correct and reachable
- Verify port 8080 is open
- Increase timeout value if needed

**Authentication Failed:**
- Confirm RSCM username and password
- Try default credentials (root/P@ssw0rd)
- Check if RSCM requires different credentials than BMC

**No Data Returned:**
- Verify RSCM supports Redfish API
- Check RSCM firmware version (must support Managers endpoint)
- Review RSCM logs for API errors

**SSL Certificate Errors:**
- The checker disables SSL verification for self-signed certs
- If issues persist, check urllib3 and requests library versions

## Version History

- **v1.0** (2025-01-22): Initial RSCM firmware collection implementation
  - Basic firmware version extraction (ManagerType, Model, FirmwareVersion)
  - Connection testing and error handling
  - Integration with firmware check workflow
  - Test script for validation
