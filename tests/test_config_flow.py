"""Tests for the ARP-Scan Device Tracker config and options flows."""

from collections.abc import Generator
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.config_entries import SOURCE_IMPORT, SOURCE_USER
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
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
    CONF_TRACK_NEW_DEVICES,
    DEFAULT_TIMEOUT,
    DOMAIN,
)

from .conftest import INTERFACE, NETWORK

pytestmark = pytest.mark.usefixtures("mock_interfaces")


@pytest.fixture(autouse=True)
def mock_setup_entry() -> Generator[AsyncMock]:
    """Prevent the created entry from actually being set up."""
    with patch(
        "custom_components.arpscan_tracker.async_setup_entry", return_value=True
    ) as mock_setup:
        yield mock_setup


async def test_user_flow_creates_entry(hass: HomeAssistant, mock_setup_entry: AsyncMock) -> None:
    """The user step shows a form and creates an entry with parsed IP lists."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"] == {}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            CONF_INTERFACE: INTERFACE,
            CONF_NETWORK: "10.0.0.0/24",
            CONF_INCLUDE: "192.168.1.10, 192.168.1.11 192.168.1.12",
            CONF_EXCLUDE: "",
            CONF_HOSTS: "10.0.0.5,10.0.0.6",
        },
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == f"ARP Scan ({INTERFACE})"
    assert result["data"] == {CONF_INTERFACE: INTERFACE, CONF_NETWORK: "10.0.0.0/24"}
    options = result["options"]
    assert options[CONF_INCLUDE] == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    assert options[CONF_EXCLUDE] == []
    assert options[CONF_HOSTS] == ["10.0.0.5", "10.0.0.6"]
    assert options[CONF_SCAN_INTERVAL] == 15
    assert result["result"].unique_id == f"{DOMAIN}_{INTERFACE}"
    assert len(mock_setup_entry.mock_calls) == 1


async def test_user_flow_autodetects_network(hass: HomeAssistant) -> None:
    """An empty network field is filled from the interface."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: INTERFACE}
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_NETWORK] == NETWORK


async def test_user_flow_cannot_detect_network(hass: HomeAssistant) -> None:
    """A network that cannot be detected shows an error and recovers afterwards."""
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})

    with patch(
        "custom_components.arpscan_tracker.config_flow.get_interface_network",
        return_value=None,
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_INTERFACE: "wlan0"}
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_detect_network"}

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: "wlan0", CONF_NETWORK: "192.168.5.0/24"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_user_flow_already_configured(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """A second entry for the same interface is aborted."""
    mock_config_entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {CONF_INTERFACE: INTERFACE}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_import_flow(hass: HomeAssistant) -> None:
    """Legacy YAML is imported, parsing scan_options and normalising time values."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_IMPORT},
        data={
            "platform": DOMAIN,
            "interval_seconds": timedelta(seconds=30),
            "consider_home": timedelta(minutes=5),
            "include": ["192.168.2.10"],
            "scan_options": "--interface=eth1 192.168.2.0/24",
        },
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {CONF_INTERFACE: "eth1", CONF_NETWORK: "192.168.2.0/24"}
    assert result["options"][CONF_SCAN_INTERVAL] == 30
    assert result["options"][CONF_CONSIDER_HOME] == 300
    assert result["options"][CONF_TIMEOUT] == DEFAULT_TIMEOUT
    assert result["options"][CONF_INCLUDE] == ["192.168.2.10"]


async def test_import_flow_cannot_detect_network(hass: HomeAssistant) -> None:
    """Import aborts when no interface/network can be determined."""
    with patch(
        "custom_components.arpscan_tracker.config_flow.get_default_interface",
        return_value=None,
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_IMPORT}, data={}
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "cannot_detect_network"


async def test_import_flow_already_configured(
    hass: HomeAssistant, mock_config_entry: MockConfigEntry
) -> None:
    """Importing an already configured interface is aborted."""
    mock_config_entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_IMPORT}, data={}
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_options_flow(hass: HomeAssistant, mock_config_entry: MockConfigEntry) -> None:
    """The options flow stores the new options with parsed IP lists."""
    mock_config_entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(mock_config_entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "init"

    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            CONF_SCAN_INTERVAL: 30,
            CONF_CONSIDER_HOME: 60,
            CONF_TIMEOUT: 2.0,
            CONF_RESOLVE_HOSTNAMES: False,
            CONF_DEVICES_ENABLED: False,
            CONF_TRACK_NEW_DEVICES: False,
            CONF_EXCLUDE: "192.168.1.1 192.168.1.2",
        },
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert mock_config_entry.options == {
        CONF_SCAN_INTERVAL: 30,
        CONF_CONSIDER_HOME: 60,
        CONF_TIMEOUT: 2.0,
        CONF_RESOLVE_HOSTNAMES: False,
        CONF_DEVICES_ENABLED: False,
        CONF_TRACK_NEW_DEVICES: False,
        CONF_INCLUDE: [],
        CONF_EXCLUDE: ["192.168.1.1", "192.168.1.2"],
        CONF_HOSTS: [],
    }
