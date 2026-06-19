"""Pure Python ARP scanner using scapy."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import struct
import sys
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
            struct.pack("256s", interface.encode()[:15]),
        )[20:24]
        ip_addr = socket.inet_ntoa(ip_bytes)

        # Get netmask
        netmask_bytes = fcntl.ioctl(
            sock.fileno(),
            0x891B,  # SIOCGIFNETMASK
            struct.pack("256s", interface.encode()[:15]),
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
                        state = f.read().strip()
                        # Include "up" and "unknown" - virtual interfaces like
                        # ZeroTier and WireGuard report "unknown" but are operational
                        if state in ("up", "unknown"):
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
        hosts: list[str] | None = None,
    ) -> None:
        """Initialize the ARP scanner.

        Args:
            interface: Network interface to use (auto-detect if None)
            network: Network range in CIDR notation (auto-detect if None)
            timeout: Timeout for ARP requests in seconds
            resolve_hostnames: Whether to resolve hostnames via reverse DNS
            hosts: Specific IP addresses to probe (if provided, skips network scan)
        """
        self._interface = interface
        self._network = network
        self._timeout = timeout
        self._resolve_hostnames = resolve_hostnames
        self._hosts = hosts
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
        # Save and set explicit timeout to ensure we wait long enough
        # for local DNS servers (routers) to respond
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5.0)
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)

            # If hostname is the same as the IP, it's not a real hostname
            if hostname == ip:
                return None

            # Return hostname without domain if it's a FQDN
            if hostname and "." in hostname:
                # Keep short hostname, but also keep if it looks like a real name
                short_name = hostname.split(".")[0]

                # If short name is just the IP with dashes, return full hostname
                if short_name.replace("-", ".") == ip:
                    return hostname

                # If short name is just a number (first octet of IP), it's not useful
                if short_name.isdigit():
                    return None

                return short_name

            # Reject hostnames that are just numbers (partial IPs like "192")
            if hostname.isdigit():
                return None

            return hostname
        except (socket.herror, socket.gaierror, OSError):
            # No reverse DNS entry
            return None
        finally:
            socket.setdefaulttimeout(old_timeout)

    def _get_interface_info(self, interface: str) -> tuple[str | None, str | None]:
        """Get IP and MAC address for an interface.

        Args:
            interface: Network interface name

        Returns:
            Tuple of (ip_address, mac_address) or (None, None) if not available
        """
        try:
            from scapy.all import get_if_addr, get_if_hwaddr

            ip_addr = get_if_addr(interface)
            mac_addr = get_if_hwaddr(interface)

            # get_if_addr returns "0.0.0.0" if no IP is configured
            if ip_addr == "0.0.0.0":
                # Try to get from the interface network method
                network_str = get_interface_network(interface)
                if network_str:
                    # Extract first usable IP from network
                    from ipaddress import IPv4Network

                    network = IPv4Network(network_str)
                    # Use the interface's actual IP (first host in network)
                    first_host = next(iter(network.hosts()), None)
                    ip_addr = str(first_host) if first_host else "0.0.0.0"

            return (
                ip_addr if ip_addr and ip_addr != "0.0.0.0" else None,
                mac_addr,
            )
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.debug("Failed to get interface info for %s: %s", interface, err)
            return None, None


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
        # If specific hosts are configured, probe only those
        if self._hosts:
            return self._scan_hosts_sync()

        from scapy.all import ARP, Ether, conf, srp  # type: ignore[attr-defined]

        interface = self.interface
        network = self.network

        if not interface:
            _LOGGER.error("No network interface available for ARP scan")
            return []

        if not network:
            _LOGGER.error("No network range available for ARP scan")
            return []

        _LOGGER.debug("Starting ARP scan on interface %s, network %s", interface, network)

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
                retry=3,
            )
        except PermissionError as err:
            _LOGGER.error(
                "Permission denied for ARP scan. "
                "Ensure Home Assistant has CAP_NET_RAW capability: %s",
                err,
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

            devices.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor or "Unknown",
                    "hostname": hostname,
                }
            )

        _LOGGER.debug("ARP scan found %d devices", len(devices))
        return devices

    def _scan_hosts_sync(self) -> list[dict[str, str | None]]:
        """Probe specific hosts with ARP requests.

        This is more reliable for VPN/virtual interfaces like ZeroTier
        where broadcast ARP may not work correctly.

        Returns:
            List of dicts with keys: ip, mac, vendor, hostname
        """
        from scapy.all import ARP, Ether, conf, srp  # type: ignore[attr-defined]

        interface = self.interface

        if not interface:
            _LOGGER.error("No network interface available for ARP scan")
            return []

        if not self._hosts:
            return []

        # Get interface IP and MAC for proper ARP packet construction
        # This is critical for virtual interfaces like ZeroTier that use bridging
        iface_ip, iface_mac = self._get_interface_info(interface)

        if not iface_ip:
            _LOGGER.warning(
                "Could not determine IP address for interface %s, "
                "ARP requests may not work on virtual/bridged networks",
                interface,
            )

        _LOGGER.debug(
            "Probing %d specific hosts on interface %s (IP: %s, MAC: %s): %s",
            len(self._hosts),
            interface,
            iface_ip or "auto",
            iface_mac or "auto",
            self._hosts,
        )

        # Suppress scapy warnings
        conf.verb = 0

        devices: list[dict[str, str | None]] = []
        seen_macs: set[str] = set()

        # Send ARP requests to each specific host
        # We still use broadcast Ethernet, but target specific IPs
        for host_ip in self._hosts:
            try:
                # Explicitly set source IP and MAC in ARP layer for ZeroTier compatibility
                # ZeroTier's bridging needs these fields to properly route ARP requests
                # across virtual networks to remote physical networks
                arp_request = ARP(
                    pdst=host_ip,
                    psrc=iface_ip if iface_ip else None,  # Sender IP
                    hwsrc=iface_mac if iface_mac else None,  # Sender MAC
                )

                # Ethernet layer - also set source MAC if available
                if iface_mac:
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff", src=iface_mac)
                else:
                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

                packet = broadcast / arp_request

                # Use longer timeout and more retries for individual hosts
                answered, _ = srp(
                    packet,
                    timeout=self._timeout * 2,  # Double timeout for reliability
                    iface=interface,
                    verbose=0,
                    retry=5,  # More retries for VPN networks
                )

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

                    devices.append(
                        {
                            "ip": ip,
                            "mac": mac,
                            "vendor": vendor or "Unknown",
                            "hostname": hostname,
                        }
                    )
                    _LOGGER.debug("Found device at %s: %s", ip, mac)

            except PermissionError as err:
                _LOGGER.error(
                    "Permission denied for ARP scan. "
                    "Ensure Home Assistant has CAP_NET_RAW capability: %s",
                    err,
                )
                return []
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.debug("ARP probe to %s failed: %s", host_ip, err)
                continue

        _LOGGER.debug("Host probe found %d devices", len(devices))
        return devices

    async def async_scan(self) -> list[dict[str, str | None]]:
        """Perform asynchronous ARP scan.

        The scan runs in a short-lived **subprocess** rather than an executor
        thread. scapy's ``srp()`` uses ``select.select()`` internally, which
        raises ``filedescriptor out of range in select()`` once any file
        descriptor is >= ``FD_SETSIZE`` (1024). A long-running Home Assistant
        process accumulates enough open FDs that the raw socket scapy opens
        lands above that ceiling and every scan fails. A freshly-spawned child
        process starts with low FD numbers, so ``select()`` stays valid.

        Returns:
            List of dicts with keys: ip, mac, vendor, hostname
        """
        params = {
            "interface": self._interface,
            "network": self._network,
            "timeout": self._timeout,
            "resolve_hostnames": self._resolve_hostnames,
            "hosts": self._hosts,
        }
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                os.path.abspath(__file__),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as err:
            _LOGGER.error("Failed to start ARP scan subprocess: %s", err)
            return []

        stdout, stderr = await proc.communicate(json.dumps(params).encode())

        if proc.returncode != 0:
            _LOGGER.error(
                "ARP scan subprocess exited %s: %s",
                proc.returncode,
                stderr.decode(errors="ignore").strip(),
            )
            return []

        try:
            return json.loads(stdout.decode() or "[]")
        except json.JSONDecodeError as err:
            _LOGGER.error("ARP scan subprocess returned invalid output: %s", err)
            return []


def _subprocess_entrypoint() -> int:
    """Run a single scan and emit the result as JSON on stdout.

    Invoked as ``python scanner.py`` by :meth:`ArpScanner.async_scan` so the
    scapy ``srp()``/``select.select()`` call runs in a fresh low-FD process
    (see async_scan for the FD_SETSIZE rationale). Scan parameters are read as
    a JSON object on stdin; the result (``list[dict]``) is written to stdout.
    """
    try:
        params = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        params = {}

    scanner = ArpScanner(
        interface=params.get("interface"),
        network=params.get("network"),
        timeout=params.get("timeout", 1.0),
        resolve_hostnames=params.get("resolve_hostnames", True),
        hosts=params.get("hosts"),
    )
    json.dump(scanner._scan_sync(), sys.stdout)  # noqa: SLF001
    return 0


if __name__ == "__main__":
    raise SystemExit(_subprocess_entrypoint())
