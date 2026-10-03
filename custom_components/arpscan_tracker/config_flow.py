"""Config flow for ARP-Scan Device Tracker integration."""

import logging
import re
from datetime import timedelta
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback

from .const import (
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
    DEFAULT_CONSIDER_HOME,
    DEFAULT_DEVICES_ENABLED,
    DEFAULT_RESOLVE_HOSTNAMES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TIMEOUT,
    DEFAULT_TRACK_NEW_DEVICES,
    DOMAIN,
)
from .scanner import get_available_interfaces, get_default_interface, get_interface_network

_LOGGER = logging.getLogger(__name__)


def _normalize_time_value(value: int | float | timedelta, default: int) -> int:
    """Convert timedelta or numeric value to integer seconds.

    Home Assistant's device_tracker schema applies cv.time_period to consider_home,
    which converts integers to timedelta objects before they reach our import handler.
    This function ensures we always store integer seconds in the config entry.
    """
    if value is None:
        return default
    if isinstance(value, timedelta):
        return int(value.total_seconds())
    return int(value)


def _get_interface_schema(interfaces: list[str], default: str | None) -> vol.Schema:
    """Build schema for interface selection."""
    if not interfaces:
        interfaces = ["eth0"]  # Fallback
    if default and default not in interfaces:
        interfaces.insert(0, default)

    return vol.Schema(
        {
            vol.Required(CONF_INTERFACE, default=default or interfaces[0]): vol.In(interfaces),
        }
    )


class ArpScanConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for ARP-Scan Device Tracker."""

    VERSION = 1
    MINOR_VERSION = 1

    def __init__(self) -> None:
        """Initialize config flow."""
        self._interfaces: list[str] = []
        self._selected_interface: str | None = None

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        # Get available interfaces
        self._interfaces = await self.hass.async_add_executor_job(get_available_interfaces)
        default_interface = await self.hass.async_add_executor_job(get_default_interface)

        if user_input is not None:
            interface = user_input[CONF_INTERFACE]
            network = user_input.get(CONF_NETWORK)

            # If network is empty, auto-detect
            if not network:
                network = await self.hass.async_add_executor_job(get_interface_network, interface)
                if not network:
                    errors["base"] = "cannot_detect_network"

            if not errors:
                # Parse include/exclude/hosts as comma-separated lists
                include_str = user_input.get(CONF_INCLUDE, "")
                exclude_str = user_input.get(CONF_EXCLUDE, "")
                hosts_str = user_input.get(CONF_HOSTS, "")

                # Parse IPs - accept both comma and space as separators
                include_list = (
                    [ip.strip() for ip in re.split(r"[,\s]+", include_str) if ip.strip()]
                    if include_str
                    else []
                )

                exclude_list = (
                    [ip.strip() for ip in re.split(r"[,\s]+", exclude_str) if ip.strip()]
                    if exclude_str
                    else []
                )

                hosts_list = (
                    [ip.strip() for ip in re.split(r"[,\s]+", hosts_str) if ip.strip()]
                    if hosts_str
                    else []
                )

                # Check if already configured with same interface
                await self.async_set_unique_id(f"{DOMAIN}_{interface}")
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=f"ARP Scan ({interface})",
                    data={
                        CONF_INTERFACE: interface,
                        CONF_NETWORK: network,
                    },
                    options={
                        CONF_SCAN_INTERVAL: user_input.get(
                            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                        ),
                        CONF_CONSIDER_HOME: user_input.get(
                            CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME
                        ),
                        CONF_TIMEOUT: user_input.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
                        CONF_RESOLVE_HOSTNAMES: user_input.get(
                            CONF_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES
                        ),
                        CONF_DEVICES_ENABLED: user_input.get(
                            CONF_DEVICES_ENABLED, DEFAULT_DEVICES_ENABLED
                        ),
                        CONF_TRACK_NEW_DEVICES: user_input.get(
                            CONF_TRACK_NEW_DEVICES, DEFAULT_TRACK_NEW_DEVICES
                        ),
                        CONF_INCLUDE: include_list,
                        CONF_EXCLUDE: exclude_list,
                        CONF_HOSTS: hosts_list,
                    },
                )

        # Auto-detect network for default interface
        default_network = None
        if default_interface:
            default_network = await self.hass.async_add_executor_job(
                get_interface_network, default_interface
            )

        interface_options = self._interfaces or [default_interface or "eth0"]
        if default_interface and default_interface not in interface_options:
            interface_options.insert(0, default_interface)

        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_INTERFACE,
                    default=default_interface
                    or (interface_options[0] if interface_options else "eth0"),
                ): vol.In(interface_options),
                vol.Optional(
                    CONF_NETWORK, description={"suggested_value": default_network or ""}
                ): str,
                vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
                    vol.Coerce(int), vol.Range(min=5, max=300)
                ),
                vol.Optional(CONF_CONSIDER_HOME, default=DEFAULT_CONSIDER_HOME): vol.All(
                    vol.Coerce(int), vol.Range(min=10, max=1800)
                ),
                vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): vol.All(
                    vol.Coerce(float), vol.Range(min=0.5, max=10.0)
                ),
                vol.Optional(CONF_RESOLVE_HOSTNAMES, default=DEFAULT_RESOLVE_HOSTNAMES): bool,
                vol.Optional(CONF_DEVICES_ENABLED, default=DEFAULT_DEVICES_ENABLED): bool,
                vol.Optional(CONF_TRACK_NEW_DEVICES, default=DEFAULT_TRACK_NEW_DEVICES): bool,
                vol.Optional(CONF_INCLUDE, default=""): str,
                vol.Optional(CONF_EXCLUDE, default=""): str,
                vol.Optional(CONF_HOSTS, default=""): str,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

    async def async_step_import(self, import_config: dict[str, Any]) -> ConfigFlowResult:
        """Handle import from YAML configuration."""
        _LOGGER.info("Importing ARP-Scan configuration from YAML")

        # Extract interface from scan_options if present
        interface = None
        network = None
        scan_options = import_config.get("scan_options", "")

        if "--interface=" in scan_options:
            # Parse --interface=eth0 from options
            for part in scan_options.split():
                if part.startswith("--interface="):
                    interface = part.split("=")[1]
                elif "/" in part and "." in part:
                    # Likely a network range like 192.168.1.0/24
                    network = part

        if not interface:
            interface = await self.hass.async_add_executor_job(get_default_interface)

        if not network and interface:
            network = await self.hass.async_add_executor_job(get_interface_network, interface)

        if not interface or not network:
            _LOGGER.error("Cannot import YAML config: unable to determine interface or network")
            return self.async_abort(reason="cannot_detect_network")

        # Check for duplicates
        await self.async_set_unique_id(f"{DOMAIN}_{interface}")
        self._abort_if_unique_id_configured()

        return self.async_create_entry(
            title=f"ARP Scan ({interface})",
            data={
                CONF_INTERFACE: interface,
                CONF_NETWORK: network,
            },
            options={
                CONF_SCAN_INTERVAL: _normalize_time_value(
                    import_config.get("interval_seconds", DEFAULT_SCAN_INTERVAL),
                    DEFAULT_SCAN_INTERVAL,
                ),
                CONF_CONSIDER_HOME: _normalize_time_value(
                    import_config.get("consider_home", DEFAULT_CONSIDER_HOME),
                    DEFAULT_CONSIDER_HOME,
                ),
                CONF_TIMEOUT: DEFAULT_TIMEOUT,
                CONF_INCLUDE: import_config.get(CONF_INCLUDE, []),
                CONF_EXCLUDE: import_config.get(CONF_EXCLUDE, []),
                CONF_HOSTS: import_config.get(CONF_HOSTS, []),
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return ArpScanOptionsFlow()


class ArpScanOptionsFlow(OptionsFlow):
    """Handle options flow for ARP-Scan Device Tracker."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            # Parse include/exclude as comma-separated lists
            include_str = user_input.get(CONF_INCLUDE, "")
            exclude_str = user_input.get(CONF_EXCLUDE, "")

            # Parse IPs - accept both comma and space as separators
            include_list = (
                [ip.strip() for ip in re.split(r"[,\s]+", include_str) if ip.strip()]
                if include_str
                else []
            )

            exclude_list = (
                [ip.strip() for ip in re.split(r"[,\s]+", exclude_str) if ip.strip()]
                if exclude_str
                else []
            )

            # Parse hosts list
            hosts_str = user_input.get(CONF_HOSTS, "")
            hosts_list = (
                [ip.strip() for ip in re.split(r"[,\s]+", hosts_str) if ip.strip()]
                if hosts_str
                else []
            )

            return self.async_create_entry(
                title="",
                data={
                    CONF_SCAN_INTERVAL: user_input[CONF_SCAN_INTERVAL],
                    CONF_CONSIDER_HOME: user_input[CONF_CONSIDER_HOME],
                    CONF_TIMEOUT: user_input[CONF_TIMEOUT],
                    CONF_RESOLVE_HOSTNAMES: user_input.get(
                        CONF_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES
                    ),
                    CONF_DEVICES_ENABLED: user_input.get(
                        CONF_DEVICES_ENABLED, DEFAULT_DEVICES_ENABLED
                    ),
                    CONF_TRACK_NEW_DEVICES: user_input.get(
                        CONF_TRACK_NEW_DEVICES, DEFAULT_TRACK_NEW_DEVICES
                    ),
                    CONF_INCLUDE: include_list,
                    CONF_EXCLUDE: exclude_list,
                    CONF_HOSTS: hosts_list,
                },
            )

        # Current values
        current_hosts = self.config_entry.options.get(CONF_HOSTS, [])
        current_include = self.config_entry.options.get(CONF_INCLUDE, [])
        current_exclude = self.config_entry.options.get(CONF_EXCLUDE, [])

        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=self.config_entry.options.get(
                        CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                    ),
                ): vol.All(vol.Coerce(int), vol.Range(min=5, max=300)),
                vol.Required(
                    CONF_CONSIDER_HOME,
                    default=self.config_entry.options.get(
                        CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME
                    ),
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=1800)),
                vol.Required(
                    CONF_TIMEOUT,
                    default=self.config_entry.options.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
                ): vol.All(vol.Coerce(float), vol.Range(min=0.5, max=10.0)),
                vol.Required(
                    CONF_RESOLVE_HOSTNAMES,
                    default=self.config_entry.options.get(
                        CONF_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES
                    ),
                ): bool,
                vol.Required(
                    CONF_DEVICES_ENABLED,
                    default=self.config_entry.options.get(
                        CONF_DEVICES_ENABLED, DEFAULT_DEVICES_ENABLED
                    ),
                ): bool,
                vol.Required(
                    CONF_TRACK_NEW_DEVICES,
                    default=self.config_entry.options.get(
                        CONF_TRACK_NEW_DEVICES, DEFAULT_TRACK_NEW_DEVICES
                    ),
                ): bool,
                # Use suggested_value rather than default: a default would be
                # re-applied when the user clears the field, making it
                # impossible to empty these lists again.
                vol.Optional(
                    CONF_INCLUDE,
                    description={"suggested_value": ", ".join(current_include)},
                ): str,
                vol.Optional(
                    CONF_EXCLUDE,
                    description={"suggested_value": ", ".join(current_exclude)},
                ): str,
                vol.Optional(
                    CONF_HOSTS,
                    description={"suggested_value": ", ".join(current_hosts)},
                ): str,
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=data_schema,
        )
