"""Tests for the ARP-Scan diagnostics."""

from homeassistant.core import HomeAssistant
from pytest_homeassistant.common import MockConfigEntry
from pytest_homeassistant.components.diagnostics import get_diagnostics_for_config_entry
from pytest_homeassistant.typing import ClientSessionGenerator

from .conftest import ENTRY_DATA, MAC_LAPTOP, MAC_PHONE, FakeNetwork


async def test_diagnostics(
    hass: HomeAssistant,
    hass_client: ClientSessionGenerator,
    mock_config_entry: MockConfigEntry,
    fake_network: FakeNetwork,
) -> None:
    """Diagnostics show the scan result with hostnames redacted."""
    mock_config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    diagnostics = await get_diagnostics_for_config_entry(hass, hass_client, mock_config_entry)

    assert diagnostics["entry"]["data"] == ENTRY_DATA
    assert diagnostics["last_update_success"] is True
    assert diagnostics["last_exception"] is None
    phone = next(d for d in diagnostics["devices"] if d["mac"] == MAC_PHONE)
    assert phone["ip"] == "192.168.1.10"
    assert phone["hostname"] == "**REDACTED**"
    assert set(diagnostics["known_devices"]) == {MAC_PHONE, MAC_LAPTOP}

    await hass.config_entries.async_unload(mock_config_entry.entry_id)
