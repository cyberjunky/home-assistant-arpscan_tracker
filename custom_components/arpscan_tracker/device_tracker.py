"""Device tracker platform for ARP-Scan."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)
import homeassistant.util.dt as dt_util

from .const import (
    ATTR_IP,
    ATTR_LAST_SEEN,
    ATTR_MAC,
    ATTR_VENDOR,
    CONF_CONSIDER_HOME,
    CONF_INTERFACE,
    DATA_COORDINATOR,
    DEFAULT_CONSIDER_HOME,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker entities from a config entry."""
    coordinator: DataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]
    consider_home = entry.options.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME)
    interface = entry.data.get(CONF_INTERFACE, "unknown")

    # Track which devices we've already created entities for
    tracked_macs: set[str] = set()

    @callback
    def async_add_new_entities() -> None:
        """Add entities for newly discovered devices."""
        new_entities: list[ArpScanDeviceTracker] = []
        
        for mac, device_data in coordinator.data.items():
            if mac not in tracked_macs:
                tracked_macs.add(mac)
                new_entities.append(
                    ArpScanDeviceTracker(
                        coordinator=coordinator,
                        mac=mac,
                        consider_home=consider_home,
                        interface=interface,
                        entry_id=entry.entry_id,
                    )
                )
                _LOGGER.debug("Adding new device tracker for MAC %s", mac)

        if new_entities:
            async_add_entities(new_entities)

    # Add entities for initial data
    async_add_new_entities()

    # Listen for coordinator updates to add new devices
    entry.async_on_unload(
        coordinator.async_add_listener(async_add_new_entities)
    )


class ArpScanDeviceTracker(CoordinatorEntity, ScannerEntity):
    """Representation of a device tracked via ARP scan."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        mac: str,
        consider_home: int,
        interface: str,
        entry_id: str,
    ) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)
        
        self._mac = mac.lower()
        self._consider_home = consider_home
        self._interface = interface
        self._entry_id = entry_id
        self._last_seen: datetime | None = None
        
        # Get initial device data
        device_data = coordinator.data.get(self._mac, {})
        ip_address = device_data.get("ip", "unknown")
        vendor = device_data.get("vendor", "Unknown")
        hostname = device_data.get("hostname")
        
        # Format MAC for entity_id (remove colons)
        mac_clean = self._mac.replace(":", "")
        
        # Entity ID uses MAC address (e.g., device_tracker.arpscan_tracker_1c697a658c2)
        self._attr_unique_id = f"{DOMAIN}_{mac_clean}"
        
        # Display name: hostname if known, otherwise IP address
        if hostname:
            self._attr_name = hostname
        else:
            self._attr_name = ip_address
        
        # Store for later reference
        self._ip_address = ip_address
        self._hostname = hostname
        
        # Update last seen on init if device is in data
        if self._mac in coordinator.data:
            self._last_seen = dt_util.utcnow()

    @property
    def source_type(self) -> SourceType:
        """Return the source type."""
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        """Return True if the device is currently connected."""
        # Check if device is in latest scan results
        if self._mac in self.coordinator.data:
            self._last_seen = dt_util.utcnow()
            return True
        
        # Check if device was seen within consider_home window
        if self._last_seen:
            time_diff = (dt_util.utcnow() - self._last_seen).total_seconds()
            if time_diff <= self._consider_home:
                return True
        
        return False

    @property
    def mac_address(self) -> str:
        """Return the MAC address."""
        return self._mac

    @property
    def ip_address(self) -> str | None:
        """Return the IP address."""
        if self._mac in self.coordinator.data:
            return self.coordinator.data[self._mac].get("ip")
        return None

    @property
    def hostname(self) -> str | None:
        """Return the hostname from DNS lookup."""
        if self._mac in self.coordinator.data:
            return self.coordinator.data[self._mac].get("hostname")
        return self._hostname

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = {
            ATTR_MAC: self._mac,
        }
        
        if self._mac in self.coordinator.data:
            device_data = self.coordinator.data[self._mac]
            attrs[ATTR_IP] = device_data.get("ip")
            attrs[ATTR_VENDOR] = device_data.get("vendor", "Unknown")
        
        if self._last_seen:
            attrs[ATTR_LAST_SEEN] = self._last_seen.isoformat()
        
        return attrs

    @property
    def device_info(self) -> dict[str, Any]:
        """Return device info - all entities share one scanner device."""
        return {
            "identifiers": {(DOMAIN, self._interface)},
            "name": f"ARP Scanner ({self._interface})",
            "manufacturer": "ARP-Scan Tracker",
            "model": "Network Scanner",
        }

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self._mac in self.coordinator.data:
            self._last_seen = dt_util.utcnow()
        self.async_write_ha_state()
