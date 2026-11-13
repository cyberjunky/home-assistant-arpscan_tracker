"""Config flow for ARP-Scan Device Tracker integration."""

import re
from ipaddress import IPv4Address, IPv4Network
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
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
    CONF_TRACK_NEW_DEVICES,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_DEVICES_ENABLED,
    DEFAULT_RESOLVE_HOSTNAMES,
    DEFAULT_TRACK_NEW_DEVICES,
    DOMAIN,
    MAX_NETWORK_ADDRESSES,
)
from .coordinator import ArpScanConfigEntry
from .probe import (
    ScanError,
    get_available_interfaces,
    get_default_interface,
    get_interface_network,
)
from .scanner import ArpScanner


def _parse_ip_list(value: str | None) -> list[str]:
    """Parse a comma or space separated list of IPv4 addresses.

    Raises:
        ValueError: An entry is not an IPv4 address.
    """
    return [str(IPv4Address(ip)) for ip in re.split(r"[,\s]+", value or "") if ip]


def _validate_network(network: str, hosts: list[str]) -> tuple[str | None, str | None]:
    """Validate a CIDR network.

    Returns:
        The normalized network, and an error key or None.
    """
    try:
        parsed = IPv4Network(network, strict=False)
    except ValueError:
        return None, "invalid_network"
    # The size only matters when the whole network is scanned
    if not hosts and parsed.num_addresses > MAX_NETWORK_ADDRESSES:
        return None, "network_too_large"
    return str(parsed), None


async def _async_test_scan(
    interface: str, network: str | None, hosts: list[str], placeholders: dict[str, str]
) -> str | None:
    """Run one scan to check that scanning works.

    Returns an error key, with the reason in placeholders, or None.
    """
    scanner = ArpScanner(
        interface=interface, network=network, hosts=hosts or None, resolve_hostnames=False
    )
    try:
        await scanner.async_scan()
    except ScanError as err:
        placeholders["error"] = str(err)
        return "cannot_scan"
    finally:
        await scanner.async_close()
    return None


def _interface_options(interfaces: list[str], default: str | None) -> list[str]:
    """Return the interfaces to choose from, with the default one first."""
    options = list(interfaces)
    if default and default not in options:
        options.insert(0, default)
    return options or ["eth0"]


class ArpScanConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for ARP-Scan Device Tracker."""

    VERSION = 1
    MINOR_VERSION = 2

    async def _async_validate_target(
        self, user_input: dict[str, Any], hosts: list[str], errors: dict[str, str]
    ) -> str | None:
        """Return the validated network to scan, detecting it if not given."""
        if network := user_input.get(CONF_NETWORK):
            network, error = _validate_network(network, hosts)
            if error:
                errors[CONF_NETWORK] = error
            return network

        network = await self.hass.async_add_executor_job(
            get_interface_network, user_input[CONF_INTERFACE]
        )
        if network is None:
            errors["base"] = "cannot_detect_network"
            return None
        network, error = _validate_network(network, hosts)
        if error:
            # Ask for a smaller range than the detected one
            errors[CONF_NETWORK] = error
        return network

    async def _async_interface_schema(
        self, interface: str | None = None, network: str | None = None
    ) -> vol.Schema:
        """Return the schema to pick an interface and network."""
        interfaces = await self.hass.async_add_executor_job(get_available_interfaces)
        default_interface = interface or await self.hass.async_add_executor_job(
            get_default_interface
        )
        if network is None and default_interface:
            network = await self.hass.async_add_executor_job(
                get_interface_network, default_interface
            )
        options = _interface_options(interfaces, default_interface)
        return vol.Schema(
            {
                vol.Required(CONF_INTERFACE, default=default_interface or options[0]): vol.In(
                    options
                ),
                vol.Optional(CONF_NETWORK, description={"suggested_value": network or ""}): str,
            }
        )

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Pick the interface and network to scan."""
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {"error": ""}

        if user_input is not None:
            interface = user_input[CONF_INTERFACE]
            await self.async_set_unique_id(f"{DOMAIN}_{interface}")
            self._abort_if_unique_id_configured()

            try:
                hosts = _parse_ip_list(user_input.get(CONF_HOSTS))
            except ValueError:
                errors[CONF_HOSTS] = "invalid_ip"
                hosts = []
            network = await self._async_validate_target(user_input, hosts, errors)
            if not errors and (
                error := await _async_test_scan(interface, network, hosts, placeholders)
            ):
                errors["base"] = error

            if not errors:
                return self.async_create_entry(
                    title=f"ARP Scan ({interface})",
                    data={CONF_INTERFACE: interface, CONF_NETWORK: network},
                    options={
                        CONF_CONSIDER_HOME: DEFAULT_CONSIDER_HOME,
                        CONF_RESOLVE_HOSTNAMES: DEFAULT_RESOLVE_HOSTNAMES,
                        CONF_DEVICES_ENABLED: DEFAULT_DEVICES_ENABLED,
                        CONF_TRACK_NEW_DEVICES: DEFAULT_TRACK_NEW_DEVICES,
                        CONF_INCLUDE: [],
                        CONF_EXCLUDE: [],
                        CONF_HOSTS: hosts,
                    },
                )

        schema = (await self._async_interface_schema()).extend(
            {vol.Optional(CONF_HOSTS, default=""): str}
        )
        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(schema, user_input),
            errors=errors,
            description_placeholders=placeholders,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change the interface or network of an entry."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {"error": ""}

        if user_input is not None:
            interface = user_input[CONF_INTERFACE]
            unique_id = f"{DOMAIN}_{interface}"
            if unique_id != entry.unique_id:
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()

            hosts = entry.options.get(CONF_HOSTS, [])
            network = await self._async_validate_target(user_input, hosts, errors)
            if not errors and (
                error := await _async_test_scan(interface, network, hosts, placeholders)
            ):
                errors["base"] = error
            if not errors:
                return self.async_update_reload_and_abort(
                    entry,
                    unique_id=unique_id,
                    title=f"ARP Scan ({interface})",
                    data_updates={CONF_INTERFACE: interface, CONF_NETWORK: network},
                )

        schema = await self._async_interface_schema(
            entry.data[CONF_INTERFACE], entry.data.get(CONF_NETWORK)
        )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self.add_suggested_values_to_schema(schema, user_input),
            errors=errors,
            description_placeholders=placeholders,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ArpScanConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return ArpScanOptionsFlow()


class ArpScanOptionsFlow(OptionsFlow):
    """Handle options flow for ARP-Scan Device Tracker."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Manage the options."""
        errors: dict[str, str] = {}

        if user_input is not None:
            lists: dict[str, list[str]] = {}
            for key in (CONF_INCLUDE, CONF_EXCLUDE, CONF_HOSTS):
                try:
                    lists[key] = _parse_ip_list(user_input.get(key))
                except ValueError:
                    errors[key] = "invalid_ip"
            if lists.get(CONF_INCLUDE) and lists.get(CONF_EXCLUDE):
                errors["base"] = "include_and_exclude"
            if not errors and not lists[CONF_HOSTS]:
                # Without hosts the whole network is scanned again
                _, error = _validate_network(self.config_entry.data[CONF_NETWORK], [])
                if error:
                    errors[CONF_HOSTS] = error

            if not errors:
                return self.async_create_entry(
                    data={
                        CONF_CONSIDER_HOME: user_input[CONF_CONSIDER_HOME],
                        CONF_RESOLVE_HOSTNAMES: user_input[CONF_RESOLVE_HOSTNAMES],
                        CONF_DEVICES_ENABLED: user_input[CONF_DEVICES_ENABLED],
                        CONF_TRACK_NEW_DEVICES: user_input[CONF_TRACK_NEW_DEVICES],
                        **lists,
                    }
                )

        options = self.config_entry.options
        schema = vol.Schema(
            {
                vol.Required(
                    CONF_CONSIDER_HOME,
                    default=options.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME),
                ): vol.All(vol.Coerce(int), vol.Range(min=10, max=1800)),
                vol.Required(
                    CONF_RESOLVE_HOSTNAMES,
                    default=options.get(CONF_RESOLVE_HOSTNAMES, DEFAULT_RESOLVE_HOSTNAMES),
                ): bool,
                vol.Required(
                    CONF_DEVICES_ENABLED,
                    default=options.get(CONF_DEVICES_ENABLED, DEFAULT_DEVICES_ENABLED),
                ): bool,
                vol.Required(
                    CONF_TRACK_NEW_DEVICES,
                    default=options.get(CONF_TRACK_NEW_DEVICES, DEFAULT_TRACK_NEW_DEVICES),
                ): bool,
                # Suggested values rather than defaults: a default would be
                # re-applied when the user clears the field, making it
                # impossible to empty these lists again.
                vol.Optional(CONF_INCLUDE): str,
                vol.Optional(CONF_EXCLUDE): str,
                vol.Optional(CONF_HOSTS): str,
            }
        )
        suggested = user_input or {
            key: ", ".join(options.get(key, [])) for key in (CONF_INCLUDE, CONF_EXCLUDE, CONF_HOSTS)
        }
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(schema, suggested),
            errors=errors,
        )
