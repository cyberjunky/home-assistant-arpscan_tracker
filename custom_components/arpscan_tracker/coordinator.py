"""Data update coordinator for the ARP-Scan Device Tracker integration."""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_EXCLUDE,
    CONF_HOSTS,
    CONF_INCLUDE,
    CONF_INTERFACE,
    CONF_NETWORK,
    CONF_RESOLVE_HOSTNAMES,
    DEFAULT_RESOLVE_HOSTNAMES,
    DOMAIN,
    SCAN_INTERVAL,
)
from .probe import ScanError
from .scanner import ArpScanner

_LOGGER = logging.getLogger(__name__)

type ArpScanConfigEntry = ConfigEntry[ArpScanCoordinator]


class ArpScanCoordinator(DataUpdateCoordinator[dict[str, dict[str, Any]]]):
    """Scans the network; data maps each found MAC to its device info."""

    config_entry: ArpScanConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ArpScanConfigEntry) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN}_{entry.data[CONF_INTERFACE]}",
            update_interval=SCAN_INTERVAL,
        )
        options = entry.options
        self.scanner = ArpScanner(
            interface=entry.data[CONF_INTERFACE],
            network=entry.data.get(CONF_NETWORK),
            resolve_hostnames=options.get(CONF_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES),
            hosts=options.get(CONF_HOSTS) or None,
        )
        self._include = set(options.get(CONF_INCLUDE, []))
        self._exclude = set(options.get(CONF_EXCLUDE, []))

    async def _async_update_data(self) -> dict[str, dict[str, Any]]:
        """Scan the network and apply the include/exclude filters."""
        try:
            devices = await self.scanner.async_scan()
        except ScanError as err:
            raise UpdateFailed(f"ARP scan failed: {err}") from err

        result: dict[str, dict[str, Any]] = {}
        for device in devices:
            ip = device["ip"]
            if self._include and ip not in self._include:
                continue
            if ip in self._exclude:
                continue
            result[str(device["mac"])] = device

        _LOGGER.debug("ARP scan found %d devices, %d after filtering", len(devices), len(result))
        return result

    async def async_shutdown(self) -> None:
        """Stop scanning and the probe worker."""
        await super().async_shutdown()
        await self.scanner.async_close()
