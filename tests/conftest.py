"""Fixtures for ARP-Scan Device Tracker tests."""

from collections.abc import Generator
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant.common import MockConfigEntry

from custom_components.arpscan_tracker.const import (
    CONF_CONSIDER_HOME,
    CONF_DEVICES_ENABLED,
    CONF_EXCLUDE,
    CONF_HOSTS,
    CONF_INCLUDE,
    CONF_INTERFACE,
    CONF_NETWORK,
    CONF_RESOLVE_HOSTNAMES,
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
    CONF_TRACK_NEW_DEVICES,
    DOMAIN,
)

INTERFACE = "eth0"
NETWORK = "192.168.1.0/24"

MAC_PHONE = "aa:bb:cc:dd:ee:01"
MAC_LAPTOP = "aa:bb:cc:dd:ee:02"

ENTRY_DATA = {CONF_INTERFACE: INTERFACE, CONF_NETWORK: NETWORK}

ENTRY_OPTIONS = {
    CONF_SCAN_INTERVAL: 15,
    CONF_CONSIDER_HOME: 180,
    CONF_TIMEOUT: 1.5,
    CONF_RESOLVE_HOSTNAMES: True,
    CONF_DEVICES_ENABLED: True,
    CONF_TRACK_NEW_DEVICES: True,
    CONF_INCLUDE: [],
    CONF_EXCLUDE: [],
    CONF_HOSTS: [],
}


def scan_result() -> list[dict[str, str | None]]:
    """Return a typical ArpScanner.async_scan result."""
    return [
        {"ip": "192.168.1.10", "mac": MAC_PHONE, "vendor": "Acme", "hostname": "phone"},
        {"ip": "192.168.1.11", "mac": MAC_LAPTOP, "vendor": "Unknown", "hostname": None},
    ]


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Enable loading of the custom integration in all tests."""
    return


@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """Return a mocked config entry."""
    return MockConfigEntry(
        domain=DOMAIN,
        title=f"ARP Scan ({INTERFACE})",
        data=dict(ENTRY_DATA),
        options=dict(ENTRY_OPTIONS),
        unique_id=f"{DOMAIN}_{INTERFACE}",
    )


@pytest.fixture
def mock_scan() -> Generator[AsyncMock]:
    """Patch the ARP scan so no subprocess or raw socket is used."""
    with patch(
        "custom_components.arpscan_tracker.scanner.ArpScanner.async_scan",
        new_callable=AsyncMock,
        return_value=scan_result(),
    ) as mock:
        yield mock


@pytest.fixture
def mock_interfaces() -> Generator[None]:
    """Patch interface/network detection used by the config flow."""
    with (
        patch(
            "custom_components.arpscan_tracker.config_flow.get_available_interfaces",
            return_value=[INTERFACE, "wlan0"],
        ),
        patch(
            "custom_components.arpscan_tracker.config_flow.get_default_interface",
            return_value=INTERFACE,
        ),
        patch(
            "custom_components.arpscan_tracker.config_flow.get_interface_network",
            return_value=NETWORK,
        ),
    ):
        yield
