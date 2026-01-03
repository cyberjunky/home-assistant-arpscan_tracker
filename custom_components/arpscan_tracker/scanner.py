"""Pure Python ARP scanner using scapy."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from ipaddress import IPv4Interface
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

_LOGGER = logging.getLogger(__name__)


def get_default_interface() -> str | None:
    """Get the default network interface name.

    Returns the interface used for the default route.
    """
    try:
        # Read the routing table
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) >= 2:
                    iface = parts[0]
                    dest = parts[1]
                    # Default route has destination 00000000
                    if dest == "00000000":
                        return iface
    except (OSError, IndexError) as err:
        _LOGGER.debug("Failed to read routing table: %s", err)

    # Fallback: try common interface names
    import os
    for iface in ["eth0", "ens18", "enp0s3", "wlan0"]:
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface

    return None


def get_interface_network(interface: str) -> str | None:
    """Get the network range for an interface in CIDR notation.

    Args:
        interface: Network interface name (e.g., eth0)

    Returns:
        Network in CIDR notation (e.g., 192.168.1.0/24) or None if not found
    """
    try:
        import fcntl

        # Get IP address
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip_bytes = fcntl.ioctl(
            sock.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack("256s", interface.encode()[:15])
        )[20:24]
        ip_addr = socket.inet_ntoa(ip_bytes)

        # Get netmask
        netmask_bytes = fcntl.ioctl(
            sock.fileno(),
            0x891B,  # SIOCGIFNETMASK
            struct.pack("256s", interface.encode()[:15])
        )[20:24]
        netmask = socket.inet_ntoa(netmask_bytes)

        sock.close()

        # Calculate network
        iface = IPv4Interface(f"{ip_addr}/{netmask}")
        return str(iface.network)

    except (OSError, struct.error) as err:
        _LOGGER.debug("Failed to get network for interface %s: %s", interface, err)
        return None


def get_available_interfaces() -> list[str]:
    """Get list of available network interfaces.

    Returns:
        List of interface names that are up and have IPv4 addresses.
    """
    interfaces = []
    try:
        import os
        net_dir = "/sys/class/net"
        if os.path.isdir(net_dir):
            for iface in os.listdir(net_dir):
                # Skip loopback
                if iface == "lo":
                    continue
                # Check if interface is up
                operstate_file = f"{net_dir}/{iface}/operstate"
                if os.path.exists(operstate_file):
                    with open(operstate_file) as f:
                        if f.read().strip() == "up":
                            # Check if it has an IPv4 address
                            if get_interface_network(iface):
                                interfaces.append(iface)
    except OSError as err:
        _LOGGER.debug("Failed to list interfaces: %s", err)

    return interfaces


class ArpScanner:
    """Pure Python ARP scanner using scapy."""

    def __init__(
        self,
        interface: str | None = None,
        network: str | None = None,
        timeout: float = 1.0,
        resolve_hostnames: bool = True,
    ) -> None:
        """Initialize the ARP scanner.

        Args:
            interface: Network interface to use (auto-detect if None)
            network: Network range in CIDR notation (auto-detect if None)
            timeout: Timeout for ARP requests in seconds
            resolve_hostnames: Whether to resolve hostnames via reverse DNS
        """
        self._interface = interface
        self._network = network
        self._timeout = timeout
        self._resolve_hostnames = resolve_hostnames
        self._oui_lookup: Callable[[str], str | None] | None = None

        # Initialize OUI lookup if available
        try:
            from ouilookup import OuiLookup
            self._oui_db = OuiLookup()
            self._oui_lookup = self._lookup_vendor
        except ImportError:
            _LOGGER.debug("OUI lookup not available")
            self._oui_db = None

    def _lookup_vendor(self, mac: str) -> str | None:
        """Look up vendor from MAC address."""
        if self._oui_db is None:
            return None
        try:
            result = self._oui_db.query(mac)
            if result and len(result) > 0:
                # Result is a list of dicts like [{'AA:BB:CC': 'Vendor Name'}]
                for item in result:
                    if isinstance(item, dict):
                        for _, vendor in item.items():
                            return str(vendor)
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.debug("OUI lookup failed for %s: %s", mac, err)
        return None

    def _lookup_hostname(self, ip: str) -> str | None:
        """Look up hostname via reverse DNS."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            # Return hostname without domain if it's a FQDN
            if hostname and "." in hostname:
                # Keep short hostname, but also keep if it looks like a real name
                short_name = hostname.split(".")[0]
                # If short name is just the IP with dashes, return full hostname
                if short_name.replace("-", ".") == ip:
                    return hostname
                return short_name
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            # No reverse DNS entry
            return None

    @property
    def interface(self) -> str | None:
        """Get the interface (resolved if auto-detect was used)."""
        if self._interface is None:
            return get_default_interface()
        return self._interface

    @property
    def network(self) -> str | None:
        """Get the network (resolved if auto-detect was used)."""
        if self._network is None:
            iface = self.interface
            if iface:
                return get_interface_network(iface)
            return None
        return self._network

    def _scan_sync(self) -> list[dict[str, str | None]]:
        """Perform synchronous ARP scan.

        This method must be run in an executor as it blocks.

        Returns:
            List of dicts with keys: ip, mac, vendor
        """
        from scapy.all import ARP, Ether, conf, srp

        interface = self.interface
        network = self.network

        if not interface:
            _LOGGER.error("No network interface available for ARP scan")
            return []

        if not network:
            _LOGGER.error("No network range available for ARP scan")
            return []

        _LOGGER.debug(
            "Starting ARP scan on interface %s, network %s",
            interface,
            network
        )

        # Suppress scapy warnings
        conf.verb = 0

        # Create ARP request packet
        # Ether(dst="ff:ff:ff:ff:ff:ff") = broadcast
        # ARP(pdst=network) = ARP request for all IPs in network
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        try:
            # Send packets and receive responses
            # srp returns (answered, unanswered)
            answered, _ = srp(
                packet,
                timeout=self._timeout,
                iface=interface,
                verbose=0,
                retry=0,
            )
        except PermissionError as err:
            _LOGGER.error(
                "Permission denied for ARP scan. "
                "Ensure Home Assistant has CAP_NET_RAW capability: %s",
                err
            )
            return []
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("ARP scan failed: %s", err)
            return []

        # Parse responses, ignoring duplicates (like arp-scan -g)
        seen_macs: set[str] = set()
        devices: list[dict[str, str | None]] = []

        for _sent, received in answered:
            mac = received.hwsrc.lower()
            ip = received.psrc

            # Skip duplicates
            if mac in seen_macs:
                continue
            seen_macs.add(mac)

            # Look up vendor
            vendor = None
            if self._oui_lookup:
                vendor = self._oui_lookup(mac)

            # Look up hostname via reverse DNS (if enabled)
            hostname = None
            if self._resolve_hostnames:
                hostname = self._lookup_hostname(ip)

            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor or "Unknown",
                "hostname": hostname,
            })

        _LOGGER.debug("ARP scan found %d devices", len(devices))
        return devices

    async def async_scan(self) -> list[dict[str, str | None]]:
        """Perform asynchronous ARP scan.

        Returns:
            List of dicts with keys: ip, mac, vendor
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._scan_sync)
