"""The ARP-Scan Device Tracker integration."""

import logging

import voluptuous as vol
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.device_registry import DeviceEntry

from .const import CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME, LEGACY_OPTIONS, PLATFORMS
from .coordinator import ArpScanConfigEntry, ArpScanCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ArpScanConfigEntry) -> bool:
    """Set up ARP-Scan Device Tracker from a config entry."""
    coordinator = ArpScanCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ArpScanConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def _async_update_listener(hass: HomeAssistant, entry: ArpScanConfigEntry) -> None:
    """Reload the entry when its options change."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: ArpScanConfigEntry, device: DeviceEntry
) -> bool:
    """Allow removing devices that are no longer wanted, e.g. not seen for ages.

    A device that shows up again is added back if new devices are tracked.
    """
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: ArpScanConfigEntry) -> bool:
    """Migrate old config entries."""
    if entry.version > 1:
        # Downgraded from a future version
        return False

    if entry.minor_version < 2:
        # 1.2: the scan interval and ARP timeout are no longer configurable,
        # and consider_home is always stored as seconds
        options = {k: v for k, v in entry.options.items() if k not in LEGACY_OPTIONS}
        if CONF_CONSIDER_HOME in options:
            try:
                consider_home = cv.time_period(options[CONF_CONSIDER_HOME])
            except vol.Invalid:
                options[CONF_CONSIDER_HOME] = DEFAULT_CONSIDER_HOME
            else:
                options[CONF_CONSIDER_HOME] = int(consider_home.total_seconds())
        hass.config_entries.async_update_entry(entry, options=options, minor_version=2)

    _LOGGER.debug("Migrated config entry to version %s.%s", entry.version, entry.minor_version)
    return True
