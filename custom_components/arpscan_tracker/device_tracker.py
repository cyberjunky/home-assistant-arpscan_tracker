"""Device tracker platform for ARP-Scan."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta
from typing import Any, cast

import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import ScannerEntity, SourceType
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import (
    ATTR_IP,
    ATTR_LAST_SEEN,
    ATTR_MAC,
    ATTR_VENDOR,
    CONF_CONSIDER_HOME,
    CONF_DEVICES_ENABLED,
    CONF_INTERFACE,
    CONF_TRACK_NEW_DEVICES,
    DATA_COORDINATOR,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_DEVICES_ENABLED,
    DEFAULT_TRACK_NEW_DEVICES,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

# Matches names produced by the old "IP address with dots replaced by
# underscores" fallback (e.g. "192_168_1_5"). Treated as unset so it can be
# re-derived to a hostname or the MAC-based fallback, since an IP can be
# reassigned to a different device over time.
_IP_BASED_NAME_RE = re.compile(r"^\d{1,3}(?:_\d{1,3}){3}$")


def _is_ip_based_name(name: str) -> bool:
    """Return True if name matches the old IP-based fallback name pattern."""
    return bool(_IP_BASED_NAME_RE.match(name))


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker entities from a config entry."""
    from homeassistant.helpers import entity_registry as er

    coordinator: DataUpdateCoordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]
    consider_home = entry.options.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME)
    # Defensive check: ensure consider_home is an int (might be timedelta from corrupted config)
    if isinstance(consider_home, timedelta):
        consider_home = int(consider_home.total_seconds())
    interface = entry.data.get(CONF_INTERFACE, "unknown")
    devices_enabled = entry.options.get(CONF_DEVICES_ENABLED, DEFAULT_DEVICES_ENABLED)
    track_new_devices = entry.options.get(CONF_TRACK_NEW_DEVICES, DEFAULT_TRACK_NEW_DEVICES)

    # Track which devices we've already created entities for
    tracked_macs: set[str] = set()

    # Restore entities from entity registry (devices discovered in previous runs)
    ent_reg = er.async_get(hass)
    restored_entities: list[ArpScanDeviceTracker] = []

    registry_entries = er.async_entries_for_config_entry(ent_reg, entry.entry_id)
    _LOGGER.debug(
        "Entity registry has %d entries for config entry %s",
        len(registry_entries),
        entry.entry_id,
    )
    for entity in registry_entries:
        # ScannerEntity.unique_id always returns mac_address, so registry
        # entries will have MAC-format unique_ids (e.g. 88:a2:9e:27:00:21)
        if entity.unique_id and ":" in entity.unique_id and len(entity.unique_id) == 17:
            mac_formatted = entity.unique_id.lower()
        else:
            _LOGGER.debug(
                "Skipping registry entry with unrecognized unique_id format: %s (entity_id=%s)",
                entity.unique_id,
                entity.entity_id,
            )
            continue

        # Update enabled/disabled state in registry based on config option
        if devices_enabled and entity.disabled_by == er.RegistryEntryDisabler.INTEGRATION:
            ent_reg.async_update_entity(entity.entity_id, disabled_by=None)
            _LOGGER.info("Enabling device tracker %s (devices_enabled=True)", entity.entity_id)
        elif not devices_enabled and entity.disabled_by is None:
            ent_reg.async_update_entity(
                entity.entity_id, disabled_by=er.RegistryEntryDisabler.INTEGRATION
            )
            _LOGGER.info("Disabling device tracker %s (devices_enabled=False)", entity.entity_id)

        if mac_formatted not in tracked_macs:
            tracked_macs.add(mac_formatted)
            restored_entities.append(
                ArpScanDeviceTracker(
                    coordinator=coordinator,
                    mac=mac_formatted,
                    consider_home=consider_home,
                    interface=interface,
                    entry_id=entry.entry_id,
                    devices_enabled=devices_enabled,
                    restored_name=entity.original_name or entity.name,
                )
            )
            _LOGGER.info(
                "Restoring device tracker for MAC %s from registry (currently %s)",
                mac_formatted,
                "online" if mac_formatted in coordinator.data else "offline",
            )

    if restored_entities:
        async_add_entities(restored_entities)
        _LOGGER.info("Restored %d device tracker entities from registry", len(restored_entities))
    else:
        _LOGGER.debug("No device tracker entities to restore from registry")

    @callback
    def async_add_new_entities() -> None:
        """Add entities for newly discovered devices."""
        if not track_new_devices:
            _LOGGER.debug("Track new devices is disabled, skipping new entity creation")
            return

        new_entities: list[ArpScanDeviceTracker] = []

        _LOGGER.debug("Checking for new entities: coordinator has %d devices, %d already tracked",
                      len(coordinator.data), len(tracked_macs))

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
                        devices_enabled=devices_enabled,
                    )
                )
                _LOGGER.info("Creating NEW device tracker entity for MAC %s (IP: %s, hostname: %s)",
                            mac, device_data.get("ip"), device_data.get("hostname"))

        if new_entities:
            _LOGGER.info("Adding %d new device tracker entities", len(new_entities))
            async_add_entities(new_entities)
        else:
            _LOGGER.debug("No new entities to add this update")

    # Add entities for initial data (devices currently online but not restored)
    async_add_new_entities()

    # Listen for coordinator updates to add new devices
    entry.async_on_unload(coordinator.async_add_listener(async_add_new_entities))


class ArpScanDeviceTracker(CoordinatorEntity, RestoreEntity, ScannerEntity):
    """Representation of a device tracked via ARP scan."""

    # Override ScannerEntity's default entity_category=DIAGNOSTIC which causes
    # all entities to be disabled by default regardless of devices_enabled option
    _attr_entity_category = None


    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        mac: str,
        consider_home: int,
        interface: str,
        entry_id: str,
        devices_enabled: bool = True,
        restored_name: str | None = None,
    ) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)

        self._mac = mac.lower()
        self._consider_home = consider_home
        self._interface = interface
        self._entry_id = entry_id
        self._attr_entity_registry_enabled_default = devices_enabled
        self._last_seen: datetime | None = dt_util.utcnow() - timedelta(days=365)

        # Get initial device data
        device_data = coordinator.data.get(self._mac, {})
        ip_address = device_data.get("ip", "unknown")
        hostname = device_data.get("hostname")

        # Display name priority:
        # 1. Restored name (preserves user-set or previously discovered names).
        #    Old IP-based fallback names are treated as unset and re-derived
        #    below, since an IP can be reassigned to a different device.
        # 2. Hostname from DNS
        # 3. MAC address without colons (stable fallback, unlike an IP)
        # Vendor is kept as a state attribute only, not used in entity name/id
        vendor = device_data.get("vendor")
        if restored_name and not _is_ip_based_name(restored_name):
            self._attr_name = restored_name
        elif hostname:
            self._attr_name = hostname
        else:
            self._attr_name = self._mac.replace(":", "")

        # Store for later reference
        self._ip_address = ip_address
        self._hostname: str | None = hostname if isinstance(hostname, str) else None

        # Update last seen on init if device is in data
        if self._mac in coordinator.data:
            self._last_seen = dt_util.utcnow()

    async def async_added_to_hass(self) -> None:
        """Restore state when entity is added to hass."""
        # IMPORTANT: Restore previous state BEFORE calling super() which registers
        # the coordinator listener. This ensures _last_seen is set before any
        # coordinator updates are processed.
        if (last_state := await self.async_get_last_state()) is not None:
            # Restore last_seen from attributes
            if last_seen_str := last_state.attributes.get(ATTR_LAST_SEEN):
                try:
                    self._last_seen = dt_util.parse_datetime(last_seen_str)
                    _LOGGER.debug(
                        "Restored last_seen for %s: %s",
                        self._mac,
                        self._last_seen,
                    )
                except (ValueError, TypeError):
                    pass

            # Restore IP and hostname if not currently in coordinator data
            if self._mac not in self.coordinator.data:
                if ip := last_state.attributes.get(ATTR_IP):
                    self._ip_address = ip
                # Restore hostname as entity name if it was set. Old IP-based
                # fallback names are ignored so they re-derive to the
                # MAC-based fallback instead (see _is_ip_based_name).
                if (
                    last_state.name
                    and last_state.name != "unknown"
                    and not _is_ip_based_name(last_state.name)
                ):
                    self._attr_name = last_state.name

        # Now register with coordinator after state is restored
        await super().async_added_to_hass()

    @property
    def available(self) -> bool:
        """Return True, device trackers are always available."""
        return True

    @property
    def source_type(self) -> SourceType:
        """Return the source type."""
        return SourceType.ROUTER

    @property
    def is_connected(self) -> bool:
        """Return True if the device is currently connected."""
        # Check if device is in latest scan results
        if self._mac in self.coordinator.data:
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
            ip = self.coordinator.data[self._mac].get("ip")
            return cast(str, ip) if ip else None
        return None

    @property
    def hostname(self) -> str | None:
        """Return the hostname from DNS lookup."""
        if self._mac in self.coordinator.data:
            hostname = self.coordinator.data[self._mac].get("hostname")
            return cast(str, hostname) if hostname else None
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

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        if self._mac in self.coordinator.data:
            self._last_seen = dt_util.utcnow()
        self.async_write_ha_state()
