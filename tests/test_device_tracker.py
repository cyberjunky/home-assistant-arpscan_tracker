"""Tests for the ARP-Scan device tracker entities."""

from unittest.mock import AsyncMock

from homeassistant.const import STATE_HOME, STATE_NOT_HOME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant.common import MockConfigEntry

from custom_components.arpscan_tracker.const import (
    CONF_CONSIDER_HOME,
    CONF_DEVICES_ENABLED,
    CONF_TRACK_NEW_DEVICES,
    DATA_COORDINATOR,
    DOMAIN,
)

from .conftest import ENTRY_DATA, ENTRY_OPTIONS, MAC_LAPTOP, MAC_PHONE, scan_result

MAC_OLD = "aa:bb:cc:dd:ee:99"


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


def _entity_id(hass: HomeAssistant, mac: str) -> str | None:
    return er.async_get(hass).async_get_entity_id("device_tracker", DOMAIN, mac)


async def test_entities_created_from_scan(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """Each scanned device becomes a home tracker named after its hostname or MAC."""
    await _setup(hass, mock_config_entry)

    phone_id = _entity_id(hass, MAC_PHONE)
    laptop_id = _entity_id(hass, MAC_LAPTOP)
    assert phone_id == "device_tracker.phone"
    assert laptop_id is not None

    phone = hass.states.get(phone_id)
    assert phone.state == STATE_HOME
    assert phone.attributes["ip"] == "192.168.1.10"
    assert phone.attributes["mac"] == MAC_PHONE
    assert phone.attributes["vendor"] == "Acme"
    assert phone.attributes["host_name"] == "phone"
    assert phone.attributes["source_type"] == "router"
    assert "last_seen" in phone.attributes

    laptop = hass.states.get(laptop_id)
    assert laptop.state == STATE_HOME
    # No hostname: the entity name falls back to the MAC without colons
    assert laptop.name.endswith("aabbccddee02")


async def test_device_goes_away_and_new_device_added(
    hass: HomeAssistant, mock_scan: AsyncMock
) -> None:
    """A device missing past consider_home is not_home; new devices are added on refresh."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=dict(ENTRY_DATA),
        options={**ENTRY_OPTIONS, CONF_CONSIDER_HOME: 0},
    )
    await _setup(hass, entry)
    coordinator = hass.data[DOMAIN][entry.entry_id][DATA_COORDINATOR]

    mock_scan.return_value = [
        scan_result()[0],
        {"ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:03", "vendor": "X", "hostname": "tv"},
    ]
    await coordinator.async_refresh()
    await hass.async_block_till_done()

    assert hass.states.get("device_tracker.phone").state == STATE_HOME
    laptop = hass.states.get(_entity_id(hass, MAC_LAPTOP))
    assert laptop.state == STATE_NOT_HOME
    assert "ip" not in laptop.attributes
    assert hass.states.get("device_tracker.tv").state == STATE_HOME


async def test_track_new_devices_disabled(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """No entities are created for discovered devices when tracking new devices is off."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=dict(ENTRY_DATA),
        options={**ENTRY_OPTIONS, CONF_TRACK_NEW_DEVICES: False},
    )
    await _setup(hass, entry)

    assert _entity_id(hass, MAC_PHONE) is None
    assert hass.states.async_entity_ids("device_tracker") == []


async def test_restore_registry_entities(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """Offline devices from the registry are restored; IP-based names are re-derived."""
    entry = MockConfigEntry(domain=DOMAIN, data=dict(ENTRY_DATA), options=dict(ENTRY_OPTIONS))
    entry.add_to_hass(hass)
    ent_reg = er.async_get(hass)
    ent_reg.async_get_or_create(
        "device_tracker",
        DOMAIN,
        MAC_OLD,
        config_entry=entry,
        original_name="192_168_1_99",
        suggested_object_id="old_device",
    )
    ent_reg.async_get_or_create(
        "device_tracker", DOMAIN, "not-a-mac", config_entry=entry, suggested_object_id="junk"
    )

    await _setup(hass, entry)

    state = hass.states.get("device_tracker.old_device")
    assert state is not None
    assert state.state == STATE_NOT_HOME
    # The old IP-based name is dropped in favour of the MAC-based fallback
    assert state.name.endswith("aabbccddee99")
    assert "192_168_1_99" not in state.name
    assert hass.states.get("device_tracker.junk") is None


async def test_devices_disabled_option(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """devices_enabled=False disables registry entries and new entities by default."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        data=dict(ENTRY_DATA),
        options={**ENTRY_OPTIONS, CONF_DEVICES_ENABLED: False},
    )
    entry.add_to_hass(hass)
    ent_reg = er.async_get(hass)
    old = ent_reg.async_get_or_create("device_tracker", DOMAIN, MAC_OLD, config_entry=entry)

    await _setup(hass, entry)

    assert ent_reg.async_get(old.entity_id).disabled_by is er.RegistryEntryDisabler.INTEGRATION
    phone = ent_reg.async_get(_entity_id(hass, MAC_PHONE))
    assert phone.disabled_by is er.RegistryEntryDisabler.INTEGRATION
