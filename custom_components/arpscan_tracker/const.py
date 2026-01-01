"""Constants for the ARP-Scan Device Tracker integration."""

from typing import Final

DOMAIN: Final = "arpscan_tracker"

# Configuration keys
CONF_INTERFACE: Final = "interface"
CONF_NETWORK: Final = "network"
CONF_SCAN_INTERVAL: Final = "scan_interval"
CONF_CONSIDER_HOME: Final = "consider_home"
CONF_INCLUDE: Final = "include"
CONF_EXCLUDE: Final = "exclude"
CONF_TIMEOUT: Final = "timeout"
CONF_RESOLVE_HOSTNAMES: Final = "resolve_hostnames"

# Defaults
DEFAULT_SCAN_INTERVAL: Final = 15  # seconds
DEFAULT_CONSIDER_HOME: Final = 180  # seconds
DEFAULT_TIMEOUT: Final = 1.0  # seconds
DEFAULT_INTERFACE: Final = None  # Auto-detect
DEFAULT_NETWORK: Final = None  # Auto-detect from interface
DEFAULT_RESOLVE_HOSTNAMES: Final = True

# Platforms
PLATFORMS: Final = ["device_tracker"]

# Data keys
DATA_COORDINATOR: Final = "coordinator"
DATA_SCANNER: Final = "scanner"

# Entity attributes
ATTR_IP: Final = "ip"
ATTR_MAC: Final = "mac"
ATTR_VENDOR: Final = "vendor"
ATTR_HOSTNAME: Final = "hostname"
ATTR_LAST_SEEN: Final = "last_seen"
