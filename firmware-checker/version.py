"""
Version information for Firmware Checker application.
"""

__version__ = "1.1.0"
__release_date__ = "2025-12-16"

# Version history:
# 1.1.0 (2025-12-16) - Added reservation system, timezone support, location hierarchy display
# 1.0.0 (Initial)    - Initial release with firmware checking functionality

def get_version():
    """Return the current version string."""
    return __version__

def get_version_info():
    """Return version information as a dictionary."""
    return {
        "version": __version__,
        "release_date": __release_date__
    }
