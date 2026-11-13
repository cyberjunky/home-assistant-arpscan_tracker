"""End-to-end tests for known devices being handed to later scans."""

import json
from collections.abc import Generator
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import STATE_HOME, STATE_NOT_HOME
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util
from pytest_homeassistant.common import (
    MockConfigEntry,
    async_fire_time_changed,
)

from custom_components.arpscan_tracker.const import (
    CONF_CONSIDER_HOME,
    CONF_INTERFACE,
    CONF_NETWORK,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)

PHONE = {
    "ip": "192.168.1.3",
    "mac": "bb:bb:bb:bb:bb:02",
    "vendor": "Samsung Electronics Co.,Ltd",
    "hostname": "galaxy-s24",
}


class FakeScanProcess:
    """Stand-in for the scan subprocess."""

    def __init__(self, scans: FakeScans) -> None:
        """Initialize."""
        self._scans = scans
        self.returncode = 0

    async def communicate(self, data: bytes) -> tuple[bytes, bytes]:
        """Record the scan parameters and emit the next result."""
        self._scans.params.append(json.loads(data))
        return json.dumps(self._scans.result).encode(), b""


class FakeScans:
    """Controls what the scan subprocess reports."""

    def __init__(self) -> None:
        """Initialize."""
        self.result: list[dict[str, Any]] = []
        self.params: list[dict[str, Any]] = []

    async def create_subprocess_exec(self, *_args: Any, **_kwargs: Any) -> FakeScanProcess:
        """Replace asyncio.create_subprocess_exec."""
        return FakeScanProcess(self)


@pytest.fixture
def scans() -> Generator[FakeScans]:
    """Patch the scan subprocess."""
    fake = FakeScans()
    with patch(
        "custom_components.arpscan_tracker.scanner.asyncio.create_subprocess_exec",
        side_effect=fake.create_subprocess_exec,
    ):
        yield fake


async def _setup(hass: HomeAssistant, consider_home: int = 60) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=f"{DOMAIN}_eth0",
        data={CONF_INTERFACE: "eth0", CONF_NETWORK: "192.168.1.0/24"},
        options={CONF_CONSIDER_HOME: consider_home},
    )
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def _next_scan(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, seconds: int = DEFAULT_SCAN_INTERVAL
) -> None:
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass, dt_util.utcnow())
    await hass.async_block_till_done()


def _phone_entity_id(hass: HomeAssistant) -> str:
    entity_id = er.async_get(hass).async_get_entity_id("device_tracker", DOMAIN, PHONE["mac"])
    assert entity_id
    return entity_id


async def test_device_found_and_known_to_next_scan(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, scans: FakeScans
) -> None:
    """A found phone is tracked and passed to later scans for probing."""
    scans.result = [PHONE]
    entry = await _setup(hass)

    assert entry.state is ConfigEntryState.LOADED
    state = hass.states.get(_phone_entity_id(hass))
    assert state is not None
    assert state.state == STATE_HOME
    assert state.attributes["ip"] == PHONE["ip"]
    assert scans.params[0]["known_devices"] == {}

    # The phone falls asleep and stops answering
    scans.result = []
    await _next_scan(hass, freezer)

    assert scans.params[-1]["known_devices"] == {PHONE["mac"]: PHONE["ip"]}
    # Still within consider_home
    assert hass.states.get(_phone_entity_id(hass)).state == STATE_HOME


async def test_device_away_after_consider_home(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, scans: FakeScans
) -> None:
    """A device missing from scans longer than consider_home is not_home."""
    scans.result = [PHONE]
    await _setup(hass, consider_home=30)

    scans.result = []
    await _next_scan(hass, freezer, 45)

    assert hass.states.get(_phone_entity_id(hass)).state == STATE_NOT_HOME


async def test_unload_entry(hass: HomeAssistant, scans: FakeScans) -> None:
    """The config entry unloads cleanly."""
    scans.result = [PHONE]
    entry = await _setup(hass)

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.NOT_LOADED
