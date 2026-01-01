"""Config flow for ARP-Scan Device Tracker integration."""

from __future__ import annotations

import logging
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
    CONF_EXCLUDE,
    CONF_INCLUDE,
    CONF_INTERFACE,
    CONF_NETWORK,
    CONF_RESOLVE_HOSTNAMES,
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_RESOLVE_HOSTNAMES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_TIMEOUT,
    DOMAIN,
)
from .scanner import get_available_interfaces, get_default_interface, get_interface_network

_LOGGER = logging.getLogger(__name__)


def _get_interface_schema(interfaces: list[str], default: str | None) -> vol.Schema:
    """Build schema for interface selection."""
    if not interfaces:
        interfaces = ["eth0"]  # Fallback
    if default and default not in interfaces:
        interfaces.insert(0, default)

    return vol.Schema({
        vol.Required(CONF_INTERFACE, default=default or interfaces[0]): vol.In(interfaces),
    })


class ArpScanConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for ARP-Scan Device Tracker."""

    VERSION = 1
    MINOR_VERSION = 1

    def __init__(self) -> None:
        """Initialize config flow."""
        self._interfaces: list[str] = []
        self._selected_interface: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
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
                network = await self.hass.async_add_executor_job(
                    get_interface_network, interface
                )
                if not network:
                    errors["base"] = "cannot_detect_network"

            if not errors:
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
                        CONF_INCLUDE: user_input.get(CONF_INCLUDE, []),
                        CONF_EXCLUDE: user_input.get(CONF_EXCLUDE, []),
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

        data_schema = vol.Schema({
            vol.Required(
                CONF_INTERFACE,
                default=default_interface or (interface_options[0] if interface_options else "eth0")
            ): vol.In(interface_options),
            vol.Optional(
                CONF_NETWORK,
                description={"suggested_value": default_network or ""}
            ): str,
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=DEFAULT_SCAN_INTERVAL
            ): vol.All(vol.Coerce(int), vol.Range(min=5, max=300)),
            vol.Optional(
                CONF_CONSIDER_HOME,
                default=DEFAULT_CONSIDER_HOME
            ): vol.All(vol.Coerce(int), vol.Range(min=10, max=600)),
            vol.Optional(
                CONF_TIMEOUT,
                default=DEFAULT_TIMEOUT
            ): vol.All(vol.Coerce(float), vol.Range(min=0.5, max=10.0)),
            vol.Optional(
                CONF_RESOLVE_HOSTNAMES,
                default=DEFAULT_RESOLVE_HOSTNAMES
            ): bool,
        })

        return self.async_show_form(
            step_id="user",
            data_schema=data_schema,
            errors=errors,
        )

    async def async_step_import(
        self, import_config: dict[str, Any]
    ) -> ConfigFlowResult:
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
            network = await self.hass.async_add_executor_job(
                get_interface_network, interface
            )

        if not interface or not network:
            _LOGGER.error(
                "Cannot import YAML config: unable to determine interface or network"
            )
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
                CONF_SCAN_INTERVAL: import_config.get("interval_seconds", DEFAULT_SCAN_INTERVAL),
                CONF_CONSIDER_HOME: import_config.get("consider_home", DEFAULT_CONSIDER_HOME),
                CONF_TIMEOUT: DEFAULT_TIMEOUT,
                CONF_INCLUDE: import_config.get(CONF_INCLUDE, []),
                CONF_EXCLUDE: import_config.get(CONF_EXCLUDE, []),
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return ArpScanOptionsFlow()


class ArpScanOptionsFlow(OptionsFlow):
    """Handle options flow for ARP-Scan Device Tracker."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            # Parse include/exclude as comma-separated lists
            include_str = user_input.get(CONF_INCLUDE, "")
            exclude_str = user_input.get(CONF_EXCLUDE, "")

            include_list = [
                ip.strip()
                for ip in include_str.split(",")
                if ip.strip()
            ] if include_str else []

            exclude_list = [
                ip.strip()
                for ip in exclude_str.split(",")
                if ip.strip()
            ] if exclude_str else []

            return self.async_create_entry(
                title="",
                data={
                    CONF_SCAN_INTERVAL: user_input[CONF_SCAN_INTERVAL],
                    CONF_CONSIDER_HOME: user_input[CONF_CONSIDER_HOME],
                    CONF_TIMEOUT: user_input[CONF_TIMEOUT],
                    CONF_RESOLVE_HOSTNAMES: user_input.get(
                        CONF_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES
                    ),
                    CONF_INCLUDE: include_list,
                    CONF_EXCLUDE: exclude_list,
                },
            )

        # Current values
        current_include = self.config_entry.options.get(CONF_INCLUDE, [])
        current_exclude = self.config_entry.options.get(CONF_EXCLUDE, [])

        data_schema = vol.Schema({
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
            ): vol.All(vol.Coerce(int), vol.Range(min=10, max=600)),
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
            vol.Optional(
                CONF_INCLUDE,
                default=", ".join(current_include) if current_include else "",
            ): str,
            vol.Optional(
                CONF_EXCLUDE,
                default=", ".join(current_exclude) if current_exclude else "",
            ): str,
        })

        return self.async_show_form(
            step_id="init",
            data_schema=data_schema,
        )
