"""Constants for the ARP-Scan Device Tracker integration."""

from datetime import timedelta
from typing import Final

DOMAIN: Final = "arpscan_tracker"

# Configuration keys
CONF_INTERFACE: Final = "interface"
CONF_NETWORK: Final = "network"
CONF_CONSIDER_HOME: Final = "consider_home"
CONF_INCLUDE: Final = "include"
CONF_EXCLUDE: Final = "exclude"
CONF_RESOLVE_HOSTNAMES: Final = "resolve_hostnames"
CONF_HOSTS: Final = "hosts"
CONF_DEVICES_ENABLED: Final = "devices_enabled"
CONF_TRACK_NEW_DEVICES: Final = "track_new_devices"

# Options removed in config entry version 1.2
LEGACY_OPTIONS: Final = ("scan_interval", "timeout")

# Defaults
DEFAULT_CONSIDER_HOME: Final = 180  # seconds
DEFAULT_RESOLVE_HOSTNAMES: Final = True
DEFAULT_DEVICES_ENABLED: Final = True
DEFAULT_TRACK_NEW_DEVICES: Final = True

SCAN_INTERVAL: Final = timedelta(seconds=15)

# Largest network scanned by broadcast; every address gets an ARP request
# (with a retry) on every sweep. 1024 addresses is a /22.
MAX_NETWORK_ADDRESSES: Final = 1024

# Platforms
PLATFORMS: Final = ["device_tracker"]

# Entity attributes
ATTR_VENDOR: Final = "vendor"
ATTR_LAST_SEEN: Final = "last_seen"
