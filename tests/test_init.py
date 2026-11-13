"""Tests for setting up, migrating and unloading the integration."""

from unittest.mock import AsyncMock

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import STATE_HOME, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.setup import async_setup_component
from pytest_homeassistant.common import MockConfigEntry
from pytest_homeassistant.typing import WebSocketGenerator

from custom_components.arpscan_tracker.const import (
    CONF_CONSIDER_HOME,
    CONF_EXCLUDE,
    CONF_INCLUDE,
    CONF_RESOLVE_HOSTNAMES,
    DOMAIN,
    SCAN_INTERVAL,
)
from custom_components.arpscan_tracker.probe import ScanError

from .conftest import (
    ENTRY_DATA,
    ENTRY_OPTIONS,
    MAC_LAPTOP,
    MAC_PHONE,
    NETWORK,
    FakeNetwork,
    make_entry,
)


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> bool:
    entry.add_to_hass(hass)
    result = await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return result


async def test_setup_and_unload(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """The entry scans on setup and stops the probe worker on unload."""
    assert await _setup(hass, mock_config_entry)

    assert mock_config_entry.state is ConfigEntryState.LOADED
    coordinator = mock_config_entry.runtime_data
    assert coordinator.update_interval == SCAN_INTERVAL
    assert set(coordinator.data) == {MAC_PHONE, MAC_LAPTOP}
    assert coordinator.scanner.network == NETWORK

    assert await hass.config_entries.async_unload(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.NOT_LOADED
    assert fake_network.processes[0].returncode == 0


async def test_setup_retry_on_scan_error(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A failing first scan retries setup and doesn't leave the worker running."""
    fake_network.error = "Permission denied"

    assert not await _setup(hass, mock_config_entry)

    assert mock_config_entry.state is ConfigEntryState.SETUP_RETRY
    assert fake_network.processes[0].returncode is not None


async def test_include_filter(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """Only included IPs end up in the coordinator data."""
    entry = make_entry(**{CONF_INCLUDE: ["192.168.1.10"]})

    assert await _setup(hass, entry)

    assert set(entry.runtime_data.data) == {MAC_PHONE}


async def test_exclude_filter(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """Excluded IPs are dropped."""
    entry = make_entry(**{CONF_EXCLUDE: ["192.168.1.11"]})

    assert await _setup(hass, entry)

    assert set(entry.runtime_data.data) == {MAC_PHONE}


async def test_options_update_reloads(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """Changing the options reloads the entry with the new settings."""
    assert await _setup(hass, mock_config_entry)

    hass.config_entries.async_update_entry(
        mock_config_entry, options={**ENTRY_OPTIONS, CONF_INCLUDE: ["192.168.1.11"]}
    )
    await hass.async_block_till_done()

    assert mock_config_entry.state is ConfigEntryState.LOADED
    assert set(mock_config_entry.runtime_data.data) == {MAC_LAPTOP}


async def test_scan_error_makes_entities_unavailable(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """A failed scan marks the trackers unavailable instead of away."""
    assert await _setup(hass, mock_config_entry)
    coordinator = mock_config_entry.runtime_data

    mock_scan.side_effect = ScanError("interface down")
    await coordinator.async_refresh()
    await hass.async_block_till_done()

    assert not coordinator.last_update_success
    assert coordinator.last_exception.translation_key == "scan_failed"
    assert str(coordinator.last_exception) == "ARP scan failed: interface down"
    assert hass.states.get("device_tracker.phone").state == STATE_UNAVAILABLE

    mock_scan.side_effect = None
    await coordinator.async_refresh()
    await hass.async_block_till_done()

    assert hass.states.get("device_tracker.phone").state == STATE_HOME


async def test_migrate_drops_scan_interval_and_timeout(
    hass: HomeAssistant, mock_scan: AsyncMock
) -> None:
    """Version 1.1 entries lose the removed options; consider_home becomes seconds."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=dict(ENTRY_DATA),
        options={
            "scan_interval": 30,
            "timeout": 2.0,
            CONF_CONSIDER_HOME: "0:05:00",
            CONF_RESOLVE_HOSTNAMES: False,
        },
    )

    assert await _setup(hass, entry)

    assert entry.minor_version == 2
    assert entry.options == {CONF_CONSIDER_HOME: 300, CONF_RESOLVE_HOSTNAMES: False}
    assert entry.runtime_data.update_interval == SCAN_INTERVAL


async def test_migrate_invalid_consider_home(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """An unparsable consider_home falls back to the default."""
    entry = MockConfigEntry(
        domain=DOMAIN, data=dict(ENTRY_DATA), options={CONF_CONSIDER_HOME: "soon"}
    )

    assert await _setup(hass, entry)

    assert entry.options == {CONF_CONSIDER_HOME: 180}


async def test_migrate_from_future_version_fails(hass: HomeAssistant) -> None:
    """Entries from a newer version are not loaded."""
    entry = MockConfigEntry(domain=DOMAIN, data=dict(ENTRY_DATA), version=2)

    assert not await _setup(hass, entry)

    assert entry.state is ConfigEntryState.MIGRATION_ERROR


async def test_remove_device(
    hass: HomeAssistant,
    hass_ws_client: WebSocketGenerator,
    mock_config_entry: MockConfigEntry,
    mock_scan: AsyncMock,
) -> None:
    """Users can remove tracked devices they no longer want."""
    assert await async_setup_component(hass, "config", {})
    assert await _setup(hass, mock_config_entry)
    device = dr.async_get(hass).async_get_device_by_connection(
        (dr.CONNECTION_NETWORK_MAC, MAC_PHONE), mock_config_entry.entry_id
    )
    assert device is not None

    client = await hass_ws_client(hass)
    await client.send_json_auto_id(
        {
            "type": "config/device_registry/remove_config_entry",
            "config_entry_id": mock_config_entry.entry_id,
            "device_id": device.id,
        }
    )
    response = await client.receive_json()

    assert response["success"]
    assert dr.async_get(hass).async_get(device.id) is None
