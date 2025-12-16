# Version Management Guide

## Current Version: 1.1.0 (Released: 2025-12-16)

### How to Update Version

1. **Edit `version.py`**:
   ```python
   __version__ = "1.2.0"  # Update version number
   __release_date__ = "2025-12-20"  # Update release date
   ```

2. **Add to version history comment**:
   ```python
   # Version history:
   # 1.2.0 (2025-12-20) - Description of new features
   # 1.1.0 (2025-12-16) - Added reservation system, timezone support, location hierarchy display
   # 1.0.0 (Initial)    - Initial release with firmware checking functionality
   ```

3. **Commit the change**:
   ```bash
   git add version.py
   git commit -m "Bump version to 1.2.0"
   git push origin main
   ```

### Version Numbering Scheme

We use [Semantic Versioning](https://semver.org/):
- **MAJOR.MINOR.PATCH** (e.g., 1.1.0)
- **MAJOR**: Breaking changes or major feature overhauls
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Where Version Appears

- **Footer**: Displayed on all pages at the bottom
- **Format**: "Version 1.1.0 - Released 2025-12-16"

### Recent Merge Summary

✅ **Backup created**: `main-backup-20251216-140805` branch
✅ **Merged**: reservation → main
✅ **New features in main**:
- Reservation system with calendar view
- User timezone support (Pacific Time default)
- Location hierarchy display (compact format)
- Unique location constraint
- Orphaned systems fix
- Version tracking system

### Production Deployment

On your production server:
```bash
git fetch origin
git checkout main
git pull origin main
# Restart Flask application
```

Or run the deployment script:
```bash
python deploy_reservation_branch.py
```
