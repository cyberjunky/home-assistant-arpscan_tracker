"""The ARP-Scan Device Tracker integration."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_CONSIDER_HOME,
    CONF_EXCLUDE,
    CONF_INCLUDE,
    CONF_INTERFACE,
    CONF_NETWORK,
    CONF_RESOLVE_HOSTNAMES,
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
    DATA_COORDINATOR,
    DATA_SCANNER,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_RESOLVE_HOSTNAMES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TIMEOUT,
    DOMAIN,
    PLATFORMS,
)
from .scanner import ArpScanner

_LOGGER = logging.getLogger(__name__)

# Legacy YAML schema for import
PLATFORM_SCHEMA = vol.Schema({
    vol.Optional("platform"): cv.string,
    vol.Optional("interval_seconds", default=DEFAULT_SCAN_INTERVAL): cv.positive_int,
    vol.Optional("consider_home", default=DEFAULT_CONSIDER_HOME): cv.positive_int,
    vol.Optional("track_new_devices", default=True): cv.boolean,
    vol.Optional("include", default=[]): vol.All(cv.ensure_list, [cv.string]),
    vol.Optional("exclude", default=[]): vol.All(cv.ensure_list, [cv.string]),
    vol.Optional("scan_options", default=""): cv.string,
})


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the ARP-Scan integration from YAML (legacy import)."""
    hass.data.setdefault(DOMAIN, {})

    # Check for legacy device_tracker platform config
    if "device_tracker" in config:
        for tracker_config in config["device_tracker"]:
            if tracker_config.get("platform") == "arpscan_tracker":
                _LOGGER.warning(
                    "YAML configuration for arpscan_tracker is deprecated. "
                    "Your configuration has been imported. Please remove the "
                    "device_tracker configuration from YAML and restart Home Assistant."
                )
                # Import the config
                hass.async_create_task(
                    hass.config_entries.flow.async_init(
                        DOMAIN,
                        context={"source": "import"},
                        data=tracker_config,
                    )
                )
                break

    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ARP-Scan Device Tracker from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Get configuration
    interface = entry.data.get(CONF_INTERFACE)
    network = entry.data.get(CONF_NETWORK)
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    timeout = entry.options.get(CONF_TIMEOUT, DEFAULT_TIMEOUT)
    resolve_hostnames = entry.options.get(CONF_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES)
    include_list = entry.options.get(CONF_INCLUDE, [])
    exclude_list = entry.options.get(CONF_EXCLUDE, [])

    # Create scanner
    scanner = ArpScanner(
        interface=interface,
        network=network,
        timeout=timeout,
        resolve_hostnames=resolve_hostnames,
    )

    async def async_update_data() -> dict[str, dict[str, Any]]:
        """Fetch data from ARP scanner."""
        try:
            devices = await scanner.async_scan()
        except Exception as err:
            _LOGGER.error("Error performing ARP scan: %s", err)
            raise UpdateFailed(f"ARP scan failed: {err}") from err

        # Filter devices based on include/exclude lists
        result: dict[str, dict[str, Any]] = {}
        for device in devices:
            ip = device["ip"]
            mac = device["mac"]

            # Apply include filter (if specified, only include listed IPs)
            if include_list:
                if ip not in include_list:
                    _LOGGER.debug("Device %s (%s) not in include list, skipping", ip, mac)
                    continue
            # Apply exclude filter (only if include is not specified)
            elif exclude_list and ip in exclude_list:
                _LOGGER.debug("Device %s (%s) in exclude list, skipping", ip, mac)
                continue

            result[mac] = device

        _LOGGER.debug("ARP scan returned %d devices after filtering", len(result))
        return result

    # Create coordinator
    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"{DOMAIN}_{interface}",
        update_method=async_update_data,
        update_interval=timedelta(seconds=scan_interval),
    )

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    # Store data
    hass.data[DOMAIN][entry.entry_id] = {
        DATA_COORDINATOR: coordinator,
        DATA_SCANNER: scanner,
    }

    # Register update listener for options changes
    entry.async_on_unload(entry.add_update_listener(async_options_update_listener))

    # Forward to platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok


async def async_options_update_listener(
    hass: HomeAssistant, entry: ConfigEntry
) -> None:
    """Handle options update."""
    # Reload the integration when options change
    await hass.config_entries.async_reload(entry.entry_id)


async def async_migrate_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Migrate old entry."""
    _LOGGER.debug(
        "Migrating config entry from version %s.%s",
        config_entry.version,
        config_entry.minor_version,
    )

    if config_entry.version == 1:
        # Current version, no migration needed
        pass

    _LOGGER.debug(
        "Migration to version %s.%s successful",
        config_entry.version,
        config_entry.minor_version,
    )
    return True
