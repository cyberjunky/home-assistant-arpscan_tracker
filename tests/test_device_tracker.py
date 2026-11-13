"""Tests for the ARP-Scan device tracker entities."""

from datetime import timedelta
from unittest.mock import AsyncMock

from freezegun.api import FrozenDateTimeFactory
from homeassistant.const import STATE_HOME, STATE_NOT_HOME
from homeassistant.core import HomeAssistant, State
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant.common import (
    MockConfigEntry,
    async_fire_time_changed,
    mock_restore_cache,
)

from custom_components.arpscan_tracker.const import (
    CONF_CONSIDER_HOME,
    CONF_DEVICES_ENABLED,
    CONF_TRACK_NEW_DEVICES,
    DOMAIN,
    SCAN_INTERVAL,
)

from .conftest import MAC_LAPTOP, MAC_PHONE, FakeNetwork, make_entry, scan_result

MAC_OLD = "aa:bb:cc:dd:ee:99"


async def _setup(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()


def _entity_id(hass: HomeAssistant, mac: str) -> str | None:
    return er.async_get(hass).async_get_entity_id("device_tracker", DOMAIN, mac)


def _device(hass: HomeAssistant, entry: MockConfigEntry, mac: str) -> dr.DeviceEntry | None:
    return dr.async_get(hass).async_get_device_by_connection(
        (dr.CONNECTION_NETWORK_MAC, mac), entry.entry_id
    )


async def test_entities_created_from_scan(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """Each scanned device becomes a home tracker on a device named after it."""
    await _setup(hass, mock_config_entry)

    phone_id = _entity_id(hass, MAC_PHONE)
    assert phone_id == "device_tracker.phone"
    phone = hass.states.get(phone_id)
    assert phone.state == STATE_HOME
    assert phone.name == "phone"
    assert phone.attributes["ip"] == "192.168.1.10"
    assert phone.attributes["mac"] == MAC_PHONE
    assert phone.attributes["vendor"] == "Acme"
    assert phone.attributes["host_name"] == "phone"
    assert phone.attributes["source_type"] == "router"
    assert "last_seen" in phone.attributes
    assert _device(hass, mock_config_entry, MAC_PHONE).name == "phone"

    # Without a hostname the device is named after the MAC
    laptop = hass.states.get(_entity_id(hass, MAC_LAPTOP))
    assert laptop.state == STATE_HOME
    assert laptop.name == "aabbccddee02"
    assert _device(hass, mock_config_entry, MAC_LAPTOP).name == "aabbccddee02"


async def test_device_goes_away_and_new_device_added(
    hass: HomeAssistant, mock_scan: AsyncMock
) -> None:
    """A device missing past consider_home is not_home; new devices are added on refresh."""
    entry = make_entry(**{CONF_CONSIDER_HOME: 0})
    await _setup(hass, entry)

    mock_scan.return_value = [
        scan_result()[0],
        {"ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:03", "vendor": "X", "hostname": "tv"},
    ]
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()

    assert hass.states.get("device_tracker.phone").state == STATE_HOME
    laptop = hass.states.get(_entity_id(hass, MAC_LAPTOP))
    assert laptop.state == STATE_NOT_HOME
    assert "ip" not in laptop.attributes
    assert hass.states.get("device_tracker.tv").state == STATE_HOME


async def test_sleeping_phone_stays_home_within_consider_home(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, fake_network: FakeNetwork
) -> None:
    """A phone missing from scans is home until consider_home passes.

    Its MAC and IP are handed to the following scans so the probe worker can
    wake it up.
    """
    entry = make_entry(**{CONF_CONSIDER_HOME: 30})
    await _setup(hass, entry)
    phone_id = _entity_id(hass, MAC_PHONE)
    assert fake_network.requests[0]["known_devices"] == {}

    fake_network.devices = [("192.168.1.11", MAC_LAPTOP)]
    freezer.tick(SCAN_INTERVAL)
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done(wait_background_tasks=True)

    assert fake_network.requests[-1]["known_devices"][MAC_PHONE] == "192.168.1.10"
    assert hass.states.get(phone_id).state == STATE_HOME

    freezer.tick(timedelta(seconds=30))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done(wait_background_tasks=True)

    assert hass.states.get(phone_id).state == STATE_NOT_HOME

    await hass.config_entries.async_unload(entry.entry_id)


async def test_track_new_devices_disabled(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """No entities are created for found devices when tracking new devices is off."""
    await _setup(hass, make_entry(**{CONF_TRACK_NEW_DEVICES: False}))

    assert _entity_id(hass, MAC_PHONE) is None
    assert hass.states.async_entity_ids("device_tracker") == []


async def test_restore_registry_entities(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """Offline devices from the registry are restored; old names name new devices."""
    entry = make_entry()
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
        "device_tracker",
        DOMAIN,
        "aa:bb:cc:dd:ee:98",
        config_entry=entry,
        original_name="Johns phone",
        suggested_object_id="johns_phone",
    )
    ent_reg.async_get_or_create(
        "device_tracker", DOMAIN, "not-a-mac", config_entry=entry, suggested_object_id="junk"
    )

    await _setup(hass, entry)

    state = hass.states.get("device_tracker.old_device")
    assert state.state == STATE_NOT_HOME
    # The old IP-based name is dropped in favour of the MAC
    assert state.name == "aabbccddee99"
    # A name from before devices were created names the new device
    assert hass.states.get("device_tracker.johns_phone").name == "Johns phone"
    assert hass.states.get("device_tracker.junk") is None


async def test_device_renamed_when_hostname_appears(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """A device named after its MAC is renamed once its hostname resolves."""
    await _setup(hass, mock_config_entry)
    laptop_id = _entity_id(hass, MAC_LAPTOP)
    assert hass.states.get(laptop_id).name == "aabbccddee02"

    mock_scan.return_value = [
        scan_result()[0],
        {**scan_result()[1], "hostname": "laptop"},
    ]
    await mock_config_entry.runtime_data.async_refresh()
    await hass.async_block_till_done()

    assert _device(hass, mock_config_entry, MAC_LAPTOP).name == "laptop"
    assert hass.states.get(laptop_id).name == "laptop"
    assert hass.states.get(laptop_id).attributes["host_name"] == "laptop"


async def test_device_rename_keeps_user_name(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """A new hostname doesn't override the name the user gave the device."""
    await _setup(hass, mock_config_entry)
    dev_reg = dr.async_get(hass)
    device = _device(hass, mock_config_entry, MAC_PHONE)
    dev_reg.async_update_device(device.id, name_by_user="Ron's phone")

    mock_scan.return_value = [{**scan_result()[0], "hostname": "galaxy"}, scan_result()[1]]
    await mock_config_entry.runtime_data.async_refresh()
    await hass.async_block_till_done()

    device = _device(hass, mock_config_entry, MAC_PHONE)
    assert device.name == "galaxy"
    assert device.name_by_user == "Ron's phone"
    assert hass.states.get("device_tracker.phone").name == "Ron's phone"


async def test_device_not_renamed_while_hostname_unchanged(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """Scans with the same hostname leave a device name set elsewhere alone."""
    await _setup(hass, mock_config_entry)
    dev_reg = dr.async_get(hass)
    device = _device(hass, mock_config_entry, MAC_PHONE)
    # E.g. named by another integration that knows the same MAC
    dev_reg.async_update_device(device.id, name="Living room phone")

    await mock_config_entry.runtime_data.async_refresh()
    await hass.async_block_till_done()

    assert _device(hass, mock_config_entry, MAC_PHONE).name == "Living room phone"


async def test_offline_device_keeps_its_name(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, mock_scan: AsyncMock
) -> None:
    """A device that is offline at startup keeps its name, also a user's name."""
    await _setup(hass, mock_config_entry)
    dev_reg = dr.async_get(hass)
    dev_reg.async_update_device(
        _device(hass, mock_config_entry, MAC_PHONE).id, name_by_user="Ron's phone"
    )
    await hass.config_entries.async_unload(mock_config_entry.entry_id)

    mock_scan.return_value = scan_result()[1:]
    assert await hass.config_entries.async_setup(mock_config_entry.entry_id)
    await hass.async_block_till_done()

    device = _device(hass, mock_config_entry, MAC_PHONE)
    assert device.name == "phone"
    assert device.name_by_user == "Ron's phone"
    assert hass.states.get("device_tracker.phone").name == "Ron's phone"


async def test_last_seen_restored(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """A device offline at startup that was seen recently is still home."""
    entry = make_entry()
    entry.add_to_hass(hass)
    er.async_get(hass).async_get_or_create(
        "device_tracker", DOMAIN, MAC_OLD, config_entry=entry, suggested_object_id="old_device"
    )
    last_seen = dt_util.utcnow() - timedelta(seconds=60)
    mock_restore_cache(
        hass,
        [
            State(
                "device_tracker.old_device",
                STATE_HOME,
                {"last_seen": last_seen.isoformat(), "host_name": "old", "vendor": "Acme"},
            )
        ],
    )

    await _setup(hass, entry)

    state = hass.states.get("device_tracker.old_device")
    assert state.state == STATE_HOME
    assert state.attributes["last_seen"] == last_seen.isoformat()
    assert state.attributes["host_name"] == "old"
    assert state.attributes["vendor"] == "Acme"


async def test_devices_disabled_option(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """devices_enabled=False disables registry entries and new entities by default."""
    entry = make_entry(**{CONF_DEVICES_ENABLED: False})
    entry.add_to_hass(hass)
    ent_reg = er.async_get(hass)
    old = ent_reg.async_get_or_create("device_tracker", DOMAIN, MAC_OLD, config_entry=entry)

    await _setup(hass, entry)

    assert ent_reg.async_get(old.entity_id).disabled_by is er.RegistryEntryDisabler.INTEGRATION
    phone = ent_reg.async_get(_entity_id(hass, MAC_PHONE))
    assert phone.disabled_by is er.RegistryEntryDisabler.INTEGRATION


async def test_devices_enabled_option_reenables(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """devices_enabled=True enables entries the integration disabled before."""
    entry = make_entry()
    entry.add_to_hass(hass)
    ent_reg = er.async_get(hass)
    old = ent_reg.async_get_or_create(
        "device_tracker",
        DOMAIN,
        MAC_OLD,
        config_entry=entry,
        disabled_by=er.RegistryEntryDisabler.INTEGRATION,
    )

    await _setup(hass, entry)

    assert ent_reg.async_get(old.entity_id).disabled_by is None


async def test_device_seen_by_two_entries(hass: HomeAssistant, mock_scan: AsyncMock) -> None:
    """A device on two scanned interfaces is tracked by one entry only."""
    first = make_entry()
    await _setup(hass, first)
    second = MockConfigEntry(
        domain=DOMAIN,
        data={"interface": "eth1", "network": "192.168.1.0/24"},
        options=dict(first.options),
        unique_id=f"{DOMAIN}_eth1",
        minor_version=2,
    )

    await _setup(hass, second)

    ent_reg = er.async_get(hass)
    assert ent_reg.async_get(_entity_id(hass, MAC_PHONE)).config_entry_id == first.entry_id
    assert er.async_entries_for_config_entry(ent_reg, second.entry_id) == []
