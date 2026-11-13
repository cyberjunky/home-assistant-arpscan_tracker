"""Pure Python ARP scanner using scapy."""

import asyncio
import json
import logging
import os
import socket
import struct
import sys
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import TYPE_CHECKING, NamedTuple, cast

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

_LOGGER = logging.getLogger(__name__)

# Path of this module, executed as a script by ArpScanner.async_scan
_SCRIPT_PATH = os.path.abspath(__file__)

# UDP port used to wake sleeping devices before probing them (mDNS). Any
# unicast packet makes the access point flag the station in its beacon, so
# a power-saving phone wakes its radio; the same trick iPhoneDetect uses.
WAKE_PORT = 5353
WAKE_PAYLOAD = b"arpscan_tracker"

# Netlink constants for reading the kernel neighbor (ARP) table
_RTM_NEWNEIGH = 28
_RTM_GETNEIGH = 30
_NLMSG_ERROR = 2
_NLMSG_DONE = 3
_NLM_F_REQUEST = 0x01
_NLM_F_DUMP = 0x300
_NDA_DST = 1
_NDA_LLADDR = 2
_NLMSG_HDR = struct.Struct("=LHHLL")
_NDMSG = struct.Struct("=BBHiHBB")
_RTATTR = struct.Struct("=HH")

# Neighbor (NUD) states
NUD_REACHABLE = 0x02
NUD_STALE = 0x04
NUD_DELAY = 0x08
NUD_PROBE = 0x10
# Entries that carry a MAC learned from the network, worth probing again
_NUD_CANDIDATE = NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE


class Neighbor(NamedTuple):
    """An entry from the kernel neighbor table."""

    ifindex: int
    state: int
    ip: str
    mac: str


def _align4(length: int) -> int:
    """Round a netlink length up to the 4-byte boundary."""
    return (length + 3) & ~3


def parse_neighbor_messages(data: bytes) -> tuple[list[Neighbor], bool]:
    """Parse a netlink RTM_NEWNEIGH dump buffer.

    Returns the IPv4 neighbors that have a link-layer address, and whether
    the end of the dump (NLMSG_DONE or an error) was reached.
    """
    neighbors: list[Neighbor] = []
    offset = 0
    while offset + _NLMSG_HDR.size <= len(data):
        msg_len, msg_type, _flags, _seq, _pid = _NLMSG_HDR.unpack_from(data, offset)
        if msg_len < _NLMSG_HDR.size:
            return neighbors, True
        if msg_type in (_NLMSG_DONE, _NLMSG_ERROR):
            return neighbors, True

        payload = offset + _NLMSG_HDR.size
        end = offset + msg_len
        if msg_type == _RTM_NEWNEIGH and payload + _NDMSG.size <= end:
            family, _, _, ifindex, state, _, _ = _NDMSG.unpack_from(data, payload)
            ip = mac = None
            attr = payload + _NDMSG.size
            while attr + _RTATTR.size <= end:
                attr_len, attr_type = _RTATTR.unpack_from(data, attr)
                if attr_len < _RTATTR.size:
                    break
                value = data[attr + _RTATTR.size : attr + attr_len]
                if attr_type == _NDA_DST and len(value) == 4:
                    ip = socket.inet_ntoa(value)
                elif attr_type == _NDA_LLADDR and len(value) == 6:
                    mac = ":".join(f"{b:02x}" for b in value)
                attr += _align4(attr_len)
            if family == socket.AF_INET and ip and mac and mac != "00:00:00:00:00:00":
                neighbors.append(Neighbor(ifindex, state, ip, mac))

        offset += _align4(msg_len)
    return neighbors, False


def read_neighbor_table(interface: str | None = None) -> list[Neighbor]:
    """Read the IPv4 kernel neighbor table via netlink.

    Args:
        interface: Only return entries for this interface (all if None)

    Returns:
        Neighbor entries, or an empty list if the table can't be read.
    """
    if not hasattr(socket, "AF_NETLINK"):
        return []
    try:
        ifindex = socket.if_nametoindex(interface) if interface else 0
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
            sock.settimeout(2.0)
            request = _NDMSG.pack(socket.AF_INET, 0, 0, 0, 0, 0, 0)
            header = _NLMSG_HDR.pack(
                _NLMSG_HDR.size + len(request),
                _RTM_GETNEIGH,
                _NLM_F_REQUEST | _NLM_F_DUMP,
                1,
                0,
            )
            sock.send(header + request)

            neighbors: list[Neighbor] = []
            done = False
            while not done:
                batch, done = parse_neighbor_messages(sock.recv(65536))
                neighbors.extend(batch)
    except OSError as err:
        _LOGGER.debug("Failed to read neighbor table: %s", err)
        return []

    if ifindex:
        neighbors = [n for n in neighbors if n.ifindex == ifindex]
    return neighbors


def send_wake_packets(ips: Iterable[str], port: int = WAKE_PORT) -> None:
    """Send a small unicast UDP packet to each IP to wake sleeping devices.

    Sending also makes the kernel resolve (re-confirm) the neighbor entry
    with a unicast ARP probe, which sleeping phones answer far more reliably
    than broadcast ARP requests.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            for ip in ips:
                try:
                    sock.sendto(WAKE_PAYLOAD, (ip, port))
                except OSError as err:
                    _LOGGER.debug("Failed to send wake packet to %s: %s", ip, err)
    except OSError as err:
        _LOGGER.debug("Failed to open wake socket: %s", err)


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

        # The context manager closes the socket even when the ioctl fails
        # (e.g. interface without an IPv4 address)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # Get IP address
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
        known_devices: dict[str, str] | None = None,
    ) -> None:
        """Initialize the ARP scanner.

        Args:
            interface: Network interface to use (auto-detect if None)
            network: Network range in CIDR notation (auto-detect if None)
            timeout: Timeout for ARP requests in seconds
            resolve_hostnames: Whether to resolve hostnames via reverse DNS
            hosts: Specific IP addresses to probe (if provided, skips network scan)
            known_devices: MAC -> IP of devices seen before; any of these the
                broadcast scan misses are probed directly (sleeping phones)
        """
        self._interface = interface
        self._network = network
        self._timeout = timeout
        self._resolve_hostnames = resolve_hostnames
        self._hosts = hosts
        self._known_devices: dict[str, str] = dict(known_devices or {})
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
        except socket.herror, socket.gaierror, OSError:
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

    def _make_device(self, ip: str, mac: str) -> dict[str, str | None]:
        """Build a scan result entry, looking up vendor and hostname."""
        vendor = self._oui_lookup(mac) if self._oui_lookup else None
        hostname = self._lookup_hostname(ip) if self._resolve_hostnames else None
        return {
            "ip": ip,
            "mac": mac,
            "vendor": vendor or "Unknown",
            "hostname": hostname,
        }

    def _in_scope(self, ip: str) -> bool:
        """Return True if ip belongs to the configured hosts or network."""
        if self._hosts:
            return ip in self._hosts
        network = self.network
        if not network:
            return True
        try:
            return IPv4Address(ip) in IPv4Network(network, strict=False)
        except ValueError:
            return False

    def _scan_sync(self) -> list[dict[str, str | None]]:
        """Perform synchronous ARP scan.

        This method must be run in a subprocess or executor as it blocks.

        Returns:
            List of dicts with keys: ip, mac, vendor, hostname
        """
        # If specific hosts are configured, probe only those
        if self._hosts:
            devices = self._scan_hosts_sync()
        else:
            devices = self._scan_network_sync()

        interface = self.interface
        if interface:
            devices.extend(self._probe_sleeping_sync(interface, devices))
        return devices

    def _probe_sleeping_sync(
        self, interface: str, found: list[dict[str, str | None]]
    ) -> list[dict[str, str | None]]:
        """Find known devices the broadcast scan missed.

        Phones in Wi-Fi power save (notably Samsung/Android and iPhones)
        ignore broadcast ARP requests while asleep. For every device we know
        the MAC and IP of (earlier scans plus the kernel neighbor table) that
        did not answer, send a UDP wake packet followed by a unicast ARP
        request addressed to its MAC, which the access point buffers and
        delivers when the phone wakes. Finally, neighbors the kernel reports
        as REACHABLE (recently confirmed) are counted as present too.

        Returns:
            Additional devices not already in found.
        """
        found_macs = {str(d["mac"]) for d in found}
        neighbors = read_neighbor_table(interface)

        # MAC -> IP of devices worth probing, the latest kernel knowledge wins
        candidates = dict(self._known_devices)
        for neighbor in neighbors:
            if neighbor.state & _NUD_CANDIDATE:
                candidates[neighbor.mac] = neighbor.ip
        candidates = {
            mac: ip
            for mac, ip in candidates.items()
            if mac not in found_macs and self._in_scope(ip)
        }

        present: dict[str, str] = {}
        if candidates:
            _LOGGER.debug(
                "Probing %d known devices missing from broadcast scan: %s",
                len(candidates),
                candidates,
            )
            send_wake_packets(candidates.values())
            present.update(self._unicast_arp_sync(interface, candidates))
            # The wake packets make the kernel re-confirm these entries, so
            # read the table again to catch replies after our ARP timeout
            neighbors = read_neighbor_table(interface)

        for neighbor in neighbors:
            if (
                neighbor.state & NUD_REACHABLE
                and neighbor.mac not in found_macs
                and neighbor.mac not in present
                and self._in_scope(neighbor.ip)
            ):
                present[neighbor.mac] = neighbor.ip

        devices = [self._make_device(ip, mac) for mac, ip in present.items()]
        _LOGGER.debug("Sleeping device probe found %d extra devices", len(devices))
        return devices

    def _unicast_arp_sync(self, interface: str, targets: dict[str, str]) -> dict[str, str]:
        """Send unicast ARP requests to known MAC/IP pairs.

        Returns:
            MAC -> IP of the targets that answered.
        """
        from scapy.all import ARP, Ether, conf, srp  # type: ignore[attr-defined]

        conf.verb = 0
        packets = [Ether(dst=mac) / ARP(pdst=ip, hwdst=mac) for mac, ip in targets.items()]
        try:
            answered, _ = srp(
                packets,
                timeout=self._timeout,
                iface=interface,
                verbose=0,
                retry=2,
            )
        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.debug("Unicast ARP probe failed: %s", err)
            return {}

        return {received.hwsrc.lower(): received.psrc for _sent, received in answered}

    def _scan_network_sync(self) -> list[dict[str, str | None]]:
        """Broadcast ARP requests to the whole network."""
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

            devices.append(self._make_device(ip, mac))

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

                    devices.append(self._make_device(ip, mac))
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
            "known_devices": self._known_devices,
        }
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                _SCRIPT_PATH,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as err:
            _LOGGER.error("Failed to start ARP scan subprocess: %s", err)
            return []

        # Bound the wait: without a timeout, a wedged subprocess (e.g. an
        # interface that vanished mid-scan, or hostname lookups stacking up
        # across many hosts) would hang this coordinator refresh forever,
        # leaving every entity stuck at its last-known state permanently
        # rather than eventually reporting the scan as failed.
        scan_timeout = max(60.0, self._timeout * 10)
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(json.dumps(params).encode()), timeout=scan_timeout
            )
        except TimeoutError:
            _LOGGER.error("ARP scan subprocess timed out after %.1fs, killing it", scan_timeout)
            proc.kill()
            await proc.wait()
            return []

        if proc.returncode != 0:
            _LOGGER.error(
                "ARP scan subprocess exited %s: %s",
                proc.returncode,
                stderr.decode(errors="ignore").strip(),
            )
            return []

        try:
            devices = cast(list[dict[str, str | None]], json.loads(stdout.decode() or "[]"))
        except json.JSONDecodeError as err:
            _LOGGER.error("ARP scan subprocess returned invalid output: %s", err)
            return []

        self._remember_devices(devices)
        return devices

    def _remember_devices(self, devices: list[dict[str, str | None]]) -> None:
        """Remember MAC -> IP of found devices so later scans can probe them.

        A MAC whose IP now belongs to a different device is forgotten, so a
        reassigned DHCP lease doesn't keep probing the wrong device.
        """
        found = {str(d["mac"]): str(d["ip"]) for d in devices if d.get("mac") and d.get("ip")}
        taken_ips = set(found.values())
        self._known_devices = {
            mac: ip for mac, ip in self._known_devices.items() if ip not in taken_ips
        }
        self._known_devices.update(found)


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
        known_devices=params.get("known_devices"),
    )
    json.dump(scanner._scan_sync(), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(_subprocess_entrypoint())
