"""Diagnostics support for ARP-Scan Device Tracker."""

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from .coordinator import ArpScanConfigEntry

# Hostnames often contain people's names ("johns-iphone")
TO_REDACT = {"hostname"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ArpScanConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = entry.runtime_data
    return {
        "entry": {
            "data": dict(entry.data),
            "options": dict(entry.options),
        },
        "last_update_success": coordinator.last_update_success,
        "last_exception": repr(coordinator.last_exception) if coordinator.last_exception else None,
        "devices": async_redact_data(list(coordinator.data.values()), TO_REDACT),
        "known_devices": coordinator.scanner.known_devices,
    }
