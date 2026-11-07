"""Tests for setting up and unloading the ARP-Scan Device Tracker integration."""

from datetime import timedelta
from unittest.mock import AsyncMock, patch

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.setup import async_setup_component
from pytest_homeassistant.common import MockConfigEntry

from custom_components.arpscan_tracker.const import (
    CONF_EXCLUDE,
    CONF_INCLUDE,
    CONF_SCAN_INTERVAL,
    DATA_COORDINATOR,
    DATA_SCANNER,
    DOMAIN,
)

from .conftest import ENTRY_DATA, ENTRY_OPTIONS, MAC_LAPTOP, MAC_PHONE, NETWORK, scan_result


async def test_setup_and_unload(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """The entry sets up a coordinator with the scan results and unloads cleanly."""
    mock_config_entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED
    entry_data = hass.data[DOMAIN][mock_config_entry.entry_id]
    coordinator = entry_data[DATA_COORDINATOR]
    assert coordinator.update_interval == timedelta(seconds=15)
    assert set(coordinator.data) == {MAC_PHONE, MAC_LAPTOP}
    assert entry_data[DATA_SCANNER].network == NETWORK
    mock_scan.assert_awaited()

    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.NOT_LOADED
    assert mock_config_entry.entry_id not in hass.data[DOMAIN]


async def test_setup_retry_on_scan_error(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """A failing first scan puts the entry into setup retry."""
    mock_scan.side_effect = OSError("boom")
    mock_config_entry.add_to_hass(hass)

    assert not await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY


async def test_include_filter(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """Only included IPs end up in the coordinator data."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=dict(ENTRY_DATA),
        options={**ENTRY_OPTIONS, CONF_INCLUDE: ["192.168.1.10"], CONF_EXCLUDE: ["192.168.1.10"]},
    )
    entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert set(hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR].data) == {MAC_PHONE}


async def test_exclude_filter_and_missing_mac(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """Excluded IPs and devices without a MAC are dropped."""
    mock_scan.return_value = [
        *scan_result(),
        {"ip": "192.168.1.12", "mac": None, "vendor": "Unknown", "hostname": None},
    ]
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=dict(ENTRY_DATA),
        options={**ENTRY_OPTIONS, CONF_EXCLUDE: ["192.168.1.11"]},
    )
    entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    assert set(hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR].data) == {MAC_PHONE}


async def test_timedelta_scan_interval(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """A scan interval stored as timedelta is converted to seconds."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=dict(ENTRY_DATA),
        options={**ENTRY_OPTIONS, CONF_SCAN_INTERVAL: timedelta(seconds=45)},
    )
    entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()

    coordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]
    assert coordinator.update_interval == timedelta(seconds=45)


async def test_options_update_reloads(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """Changing the options reloads the entry with the new settings."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    hass.config_entries.async_update_entry(
        mock_config_entry, options={**ENTRY_OPTIONS, CONF_SCAN_INTERVAL: 60}
    )
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED
    coordinator = hass.data[DOMAIN][mock_config_entry.entry_id][DATA_COORDINATOR]
    assert coordinator.update_interval == timedelta(seconds=60)


async def test_yaml_import(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """A legacy device_tracker YAML entry is imported into a config entry."""
    with (
        patch(
            "custom_components.arpscan_tracker.config_flow.get_default_interface",
            return_value="eth0",
        ),
        patch(
            "custom_components.arpscan_tracker.config_flow.get_interface_network",
            return_value=NETWORK,
        ),
    ):
        assert await async_setup_component(
            hass,
            DOMAIN,
            {"device_tracker": [{"platform": DOMAIN, "interval_seconds": 20}]},
        )
        await hass.async_block_till_done()

    entries = hass.config_entries.async_entries(DOMAIN)
    assert len(entries) == 1
    assert entries[0].options[CONF_SCAN_INTERVAL] == 20
