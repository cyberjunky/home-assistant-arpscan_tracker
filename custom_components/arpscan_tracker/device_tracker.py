"""Device tracker platform for ARP-Scan."""

import logging
import re
from datetime import datetime, timedelta
from typing import Any

import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import DOMAIN as DEVICE_TRACKER_DOMAIN
from homeassistant.components.device_tracker import ScannerEntity
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    ATTR_LAST_SEEN,
    ATTR_VENDOR,
    CONF_CONSIDER_HOME,
    CONF_DEVICES_ENABLED,
    CONF_TRACK_NEW_DEVICES,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_DEVICES_ENABLED,
    DEFAULT_TRACK_NEW_DEVICES,
    DOMAIN,
)
from .coordinator import ArpScanConfigEntry, ArpScanCoordinator

_LOGGER = logging.getLogger(__name__)

# The coordinator does all updates
PARALLEL_UPDATES = 0

# Matches names produced by the old "IP address with dots replaced by
# underscores" fallback (e.g. "192_168_1_5"). Treated as unset, since an IP
# can be reassigned to a different device over time.
_IP_BASED_NAME_RE = re.compile(r"^\d{1,3}(?:_\d{1,3}){3}$")
_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")

# State attribute holding the hostname (set by ScannerEntity)
_ATTR_HOST_NAME = "host_name"


def _device_info(
    hass: HomeAssistant,
    entry: ArpScanConfigEntry,
    mac: str,
    hostname: str | None,
    fallback_name: str | None = None,
) -> DeviceInfo:
    """Describe the tracked device.

    The device is named after its hostname. Without one, an existing device
    keeps its name (it may have been named before the device went offline),
    and a new device is named after fallback_name or else its MAC address.
    """
    connections = {(dr.CONNECTION_NETWORK_MAC, mac)}
    if hostname:
        return DeviceInfo(connections=connections, name=hostname)
    connection = (dr.CONNECTION_NETWORK_MAC, mac)
    if any(
        connection in device.connections
        for device in dr.async_entries_for_config_entry(dr.async_get(hass), entry.entry_id)
    ):
        return DeviceInfo(connections=connections)
    return DeviceInfo(connections=connections, name=fallback_name or mac.replace(":", ""))


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ArpScanConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up device tracker entities from a config entry."""
    coordinator = entry.runtime_data
    consider_home = timedelta(seconds=entry.options.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME))
    devices_enabled = entry.options.get(CONF_DEVICES_ENABLED, DEFAULT_DEVICES_ENABLED)
    track_new_devices = entry.options.get(CONF_TRACK_NEW_DEVICES, DEFAULT_TRACK_NEW_DEVICES)
    ent_reg = er.async_get(hass)
    tracked_macs: set[str] = set()

    def create_entity(mac: str, fallback_name: str | None = None) -> ArpScanDeviceTracker:
        tracked_macs.add(mac)
        device = coordinator.data.get(mac, {})
        return ArpScanDeviceTracker(
            coordinator,
            mac,
            _device_info(hass, entry, mac, device.get("hostname"), fallback_name),
            consider_home,
            devices_enabled,
        )

    # Restore the devices found in previous runs, also while they are offline
    restored: list[ArpScanDeviceTracker] = []
    for reg_entry in er.async_entries_for_config_entry(ent_reg, entry.entry_id):
        mac = reg_entry.unique_id.lower()
        if reg_entry.domain != DEVICE_TRACKER_DOMAIN or not _MAC_RE.match(mac):
            continue

        # Keep the registry in line with the "Enable Found Devices" option
        if devices_enabled and reg_entry.disabled_by == er.RegistryEntryDisabler.INTEGRATION:
            ent_reg.async_update_entity(reg_entry.entity_id, disabled_by=None)
        elif not devices_enabled and reg_entry.disabled_by is None:
            ent_reg.async_update_entity(
                reg_entry.entity_id, disabled_by=er.RegistryEntryDisabler.INTEGRATION
            )

        # Older versions named the entity rather than the device
        fallback_name = reg_entry.original_name
        if fallback_name and _IP_BASED_NAME_RE.match(fallback_name):
            fallback_name = None
        restored.append(create_entity(mac, fallback_name))
    async_add_entities(restored)
    _LOGGER.debug("Restored %d device trackers", len(restored))

    @callback
    def async_add_new_entities() -> None:
        """Add entities for newly found devices."""
        if not track_new_devices:
            return
        new_entities: list[ArpScanDeviceTracker] = []
        for mac in coordinator.data:
            if mac in tracked_macs:
                continue
            # The same device can be seen on several configured interfaces;
            # its MAC is the unique ID, so only the first entry tracks it
            entity_id = ent_reg.async_get_entity_id(DEVICE_TRACKER_DOMAIN, DOMAIN, mac)
            other = ent_reg.async_get(entity_id) if entity_id else None
            if other is not None and other.config_entry_id != entry.entry_id:
                tracked_macs.add(mac)
                _LOGGER.debug("%s is already tracked by another ARP-Scan entry", mac)
                continue
            new_entities.append(create_entity(mac))
        if new_entities:
            _LOGGER.debug("Adding %d new device trackers", len(new_entities))
            async_add_entities(new_entities)

    async_add_new_entities()
    entry.async_on_unload(coordinator.async_add_listener(async_add_new_entities))


class ArpScanDeviceTracker(CoordinatorEntity[ArpScanCoordinator], RestoreEntity, ScannerEntity):
    """A device tracked via ARP scan."""

    _attr_has_entity_name = True
    _attr_name = None
    # ScannerEntity marks trackers as diagnostic, which hides them by default
    _attr_entity_category = None  # type: ignore[assignment]

    def __init__(
        self,
        coordinator: ArpScanCoordinator,
        mac: str,
        device_info: DeviceInfo,
        consider_home: timedelta,
        devices_enabled: bool,
    ) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)
        self._attr_mac_address = mac
        self._attr_device_info = device_info
        self._consider_home = consider_home
        self._devices_enabled = devices_enabled
        self._last_seen: datetime | None = None
        self._vendor: str | None = None
        self._update_from_scan()

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled when first added.

        ScannerEntity only enables entities whose MAC is already known to
        another integration, which would leave found devices disabled.
        """
        return self._devices_enabled

    @property
    def is_connected(self) -> bool:
        """Return True if the device is in the latest scan or was seen within consider_home."""
        if self.coordinator.last_update_success and self.mac_address in self.coordinator.data:
            return True
        if self._last_seen is None:
            return False
        return dt_util.utcnow() - self._last_seen <= self._consider_home

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the vendor and when the device was last seen."""
        attrs: dict[str, Any] = {}
        if self._vendor:
            attrs[ATTR_VENDOR] = self._vendor
        if self._last_seen:
            attrs[ATTR_LAST_SEEN] = self._last_seen.isoformat()
        return attrs

    def _update_from_scan(self) -> None:
        """Take over the latest successful scan result."""
        if not self.coordinator.last_update_success:
            # The data is from the last successful scan; seeing the device
            # there again says nothing about it being present now
            return
        assert self.mac_address is not None
        if (device := self.coordinator.data.get(self.mac_address)) is None:
            self._attr_ip_address = None
            return
        self._last_seen = dt_util.utcnow()
        self._attr_ip_address = device["ip"]
        self._attr_hostname = device.get("hostname") or self.hostname
        self._vendor = device.get("vendor")

    async def async_added_to_hass(self) -> None:
        """Restore when the device was last seen, then follow the scans."""
        if (last_state := await self.async_get_last_state()) is not None:
            last_seen = last_state.attributes.get(ATTR_LAST_SEEN)
            if self._last_seen is None and isinstance(last_seen, str):
                self._last_seen = dt_util.parse_datetime(last_seen)
            if self.hostname is None:
                self._attr_hostname = last_state.attributes.get(_ATTR_HOST_NAME)
            if self._vendor is None:
                self._vendor = last_state.attributes.get(ATTR_VENDOR)
        await super().async_added_to_hass()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle a new scan result."""
        self._update_from_scan()
        super()._handle_coordinator_update()
