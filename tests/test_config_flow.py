"""Tests for the ARP-Scan Device Tracker config, reconfigure and options flows."""

from collections.abc import Generator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.config_entries import SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
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
    CONF_TRACK_NEW_DEVICES,
    DOMAIN,
)

from .conftest import ENTRY_OPTIONS, INTERFACE, NETWORK, FakeNetwork, make_entry

pytestmark = pytest.mark.usefixtures("mock_interfaces", "fake_network")


@pytest.fixture(autouse=True)
def mock_setup_entry() -> Generator[AsyncMock]:
    """Prevent the created entry from actually being set up."""
    with patch(
        "custom_components.arpscan_tracker.async_setup_entry", return_value=True
    ) as mock_setup:
        yield mock_setup


async def _user_flow(hass: HomeAssistant, user_input: dict[str, Any]) -> Any:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    return await hass.config_entries.flow.async_configure(result["flow_id"], user_input)


async def test_user_flow_creates_entry(hass: HomeAssistant, mock_setup_entry: AsyncMock) -> None:
    """The user step creates an entry with default options and parsed hosts."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_INTERFACE: INTERFACE, CONF_NETWORK: "10.0.0.7/24", CONF_HOSTS: "10.0.0.5,10.0.0.6"},
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == f"ARP Scan ({INTERFACE})"
    # The network is normalized
    assert result["data"] == {CONF_INTERFACE: INTERFACE, CONF_NETWORK: "10.0.0.0/24"}
    assert result["options"] == {**ENTRY_OPTIONS, CONF_HOSTS: ["10.0.0.5", "10.0.0.6"]}
    assert result["result"].unique_id == f"{DOMAIN}_{INTERFACE}"
    assert result["result"].minor_version == 2
    assert len(mock_setup_entry.mock_calls) == 1


async def test_user_flow_autodetects_network(hass: HomeAssistant) -> None:
    """An empty network field is filled from the interface."""
    result = await _user_flow(hass, {CONF_INTERFACE: INTERFACE})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_NETWORK] == NETWORK


async def test_user_flow_cannot_detect_network(hass: HomeAssistant) -> None:
    """A network that cannot be detected shows an error and recovers afterwards."""
    with patch(
        "custom_components.arpscan_tracker.config_flow.get_interface_network",
        return_value=None,
    ):
        result = await _user_flow(hass, {CONF_INTERFACE: "wlan0"})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_detect_network"}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: "wlan0", CONF_NETWORK: "192.168.5.0/24"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY


@pytest.mark.parametrize(
    ("user_input", "errors"),
    [
        ({CONF_NETWORK: "192.168.1.300/24"}, {CONF_NETWORK: "invalid_network"}),
        ({CONF_NETWORK: "not a network"}, {CONF_NETWORK: "invalid_network"}),
        ({CONF_NETWORK: "10.0.0.0/16"}, {CONF_NETWORK: "network_too_large"}),
        ({CONF_HOSTS: "10.0.0.5, printer"}, {CONF_HOSTS: "invalid_ip"}),
    ],
)
async def test_user_flow_validation(
    hass: HomeAssistant, user_input: dict[str, str], errors: dict[str, str]
) -> None:
    """Invalid networks and host lists are rejected."""
    result = await _user_flow(hass, {CONF_INTERFACE: INTERFACE, **user_input})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == errors


async def test_user_flow_large_network_with_hosts(hass: HomeAssistant) -> None:
    """A large network is fine when only specific hosts are probed."""
    result = await _user_flow(
        hass, {CONF_INTERFACE: INTERFACE, CONF_NETWORK: "10.0.0.0/8", CONF_HOSTS: "10.1.2.3"}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_user_flow_detected_network_too_large(hass: HomeAssistant) -> None:
    """A too large detected network asks for a smaller range."""
    with patch(
        "custom_components.arpscan_tracker.config_flow.get_interface_network",
        return_value="172.16.0.0/12",
    ):
        result = await _user_flow(hass, {CONF_INTERFACE: INTERFACE})

    assert result["errors"] == {CONF_NETWORK: "network_too_large"}


async def test_user_flow_test_scan_fails(hass: HomeAssistant, fake_network: FakeNetwork) -> None:
    """A failing test scan is shown in the form, and setup works once it scans."""
    fake_network.error = "Permission denied, Home Assistant needs the CAP_NET_RAW capability"

    result = await _user_flow(hass, {CONF_INTERFACE: INTERFACE})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_scan"}
    assert "CAP_NET_RAW" in result["description_placeholders"]["error"]
    # The test scan's worker is stopped again
    assert all(proc.returncode is not None for proc in fake_network.processes)

    fake_network.error = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: INTERFACE}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert fake_network.requests[-1] == {
        "interface": INTERFACE,
        "network": NETWORK,
        "hosts": None,
        "known_devices": {},
    }


async def test_user_flow_already_configured(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """A second entry for the same interface is aborted."""
    mock_config_entry.add_to_hass(hass)

    result = await _user_flow(hass, {CONF_INTERFACE: INTERFACE})

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_reconfigure_flow(hass: HomeAssistant, mock_config_entry: MockConfigEntry) -> None:
    """The interface and network can be changed."""
    mock_config_entry.add_to_hass(hass)

    result = await mock_config_entry.start_reconfigure_flow(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reconfigure"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: "wlan0", CONF_NETWORK: "192.168.7.0/24"}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert mock_config_entry.data == {CONF_INTERFACE: "wlan0", CONF_NETWORK: "192.168.7.0/24"}
    assert mock_config_entry.unique_id == f"{DOMAIN}_wlan0"
    assert mock_config_entry.title == "ARP Scan (wlan0)"


async def test_reconfigure_flow_invalid_network(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """An invalid network is rejected when reconfiguring."""
    mock_config_entry.add_to_hass(hass)

    result = await mock_config_entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: INTERFACE, CONF_NETWORK: "nope"}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {CONF_NETWORK: "invalid_network"}


async def test_reconfigure_flow_test_scan_fails(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry, fake_network: FakeNetwork
) -> None:
    """A failing test scan keeps the old interface and network."""
    mock_config_entry.add_to_hass(hass)
    fake_network.error = "Sending ARP requests on wlan0 failed: No such device"

    result = await mock_config_entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: "wlan0", CONF_NETWORK: "192.168.7.0/24"}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_scan"}
    assert mock_config_entry.data[CONF_INTERFACE] == INTERFACE


async def test_reconfigure_flow_interface_in_use(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Reconfiguring to an interface of another entry is aborted."""
    mock_config_entry.add_to_hass(hass)
    other = MockConfigEntry(
        domain=DOMAIN,
        data={CONF_INTERFACE: "wlan0", CONF_NETWORK: NETWORK},
        unique_id=f"{DOMAIN}_wlan0",
        minor_version=2,
    )
    other.add_to_hass(hass)

    result = await mock_config_entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: "wlan0"}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


OPTIONS_INPUT = {
    CONF_CONSIDER_HOME: 60,
    CONF_RESOLVE_HOSTNAMES: False,
    CONF_DEVICES_ENABLED: False,
    CONF_TRACK_NEW_DEVICES: False,
}


async def test_options_flow(hass: HomeAssistant, mock_config_entry: MockConfigEntry) -> None:
    """The options flow stores the new options with parsed IP lists."""
    mock_config_entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {**OPTIONS_INPUT, CONF_EXCLUDE: "192.168.1.1 192.168.1.2"}
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.options == {
        **OPTIONS_INPUT,
        CONF_INCLUDE: [],
        CONF_EXCLUDE: ["192.168.1.1", "192.168.1.2"],
        CONF_HOSTS: [],
    }


@pytest.mark.parametrize(
    ("user_input", "errors"),
    [
        ({CONF_INCLUDE: "192.168.1.1, router"}, {CONF_INCLUDE: "invalid_ip"}),
        (
            {CONF_INCLUDE: "192.168.1.1", CONF_EXCLUDE: "192.168.1.2"},
            {"base": "include_and_exclude"},
        ),
    ],
)
async def test_options_flow_validation(
    hass: HomeAssistant,
    mock_config_entry: MockConfigEntry,
    user_input: dict[str, str],
    errors: dict[str, str],
) -> None:
    """Invalid IP lists and conflicting filters are rejected."""
    mock_config_entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {**OPTIONS_INPUT, **user_input}
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == errors


async def test_options_flow_clearing_hosts_of_large_network(hass: HomeAssistant) -> None:
    """Hosts can't be cleared when the network is too large to scan."""
    entry = make_entry(**{CONF_HOSTS: ["10.1.2.3"]})
    entry.add_to_hass(hass)
    hass.config_entries.async_update_entry(entry, data={**entry.data, CONF_NETWORK: "10.0.0.0/8"})

    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {**OPTIONS_INPUT, CONF_HOSTS: ""}
    )

    assert result["errors"] == {CONF_HOSTS: "network_too_large"}
