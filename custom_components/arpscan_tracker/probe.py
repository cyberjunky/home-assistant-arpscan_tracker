"""ARP probing with scapy, run in a worker process.

This module is executed as a script (``python probe.py``) by
:class:`~.scanner.ArpScanner` and must not import Home Assistant or other
modules of this package. scapy's ``srp()`` uses ``select.select()``, which
fails once a file descriptor is >= ``FD_SETSIZE`` (1024); a long-running Home
Assistant process easily has that many open, while this small worker keeps its
file descriptors low.

Protocol: one JSON request per line on stdin, answered by one JSON line on
stdout: ``{"devices": [[ip, mac], ...]}`` or ``{"error": "message"}``.
"""

import json
import logging
import os
import socket
import struct
import sys
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Iterable

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 1.5  # seconds per ARP round
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"

# UDP port used to wake sleeping devices before probing them (mDNS). Any
# unicast packet makes the access point flag the station in its beacon, so
# a power-saving phone wakes its radio; the same trick iPhoneDetect uses.
WAKE_PORT = 5353
WAKE_PAYLOAD = b"arpscan_tracker"

# ioctl requests for an interface's IPv4 address and netmask
_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B

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


class ScanError(Exception):
    """The ARP scan could not be performed."""


class Neighbor(NamedTuple):
    """An entry from the kernel neighbor table."""

    ifindex: int
    state: int
    ip: str
    mac: str


def get_default_interface() -> str | None:
    """Return the interface of the default route, or a common fallback."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:  # Skip header
                parts = line.split()
                # The default route has destination 00000000
                if len(parts) >= 2 and parts[1] == "00000000":
                    return parts[0]
    except OSError as err:
        _LOGGER.debug("Failed to read routing table: %s", err)

    for iface in ("eth0", "ens18", "enp0s3", "wlan0"):
        if os.path.exists(f"/sys/class/net/{iface}"):
            return iface
    return None


def get_interface_address(interface: str) -> IPv4Interface | None:
    """Return the IPv4 address and netmask of an interface."""
    try:
        import fcntl

        request = struct.pack("256s", interface.encode()[:15])
        # The context manager closes the socket even when the ioctl fails
        # (e.g. interface without an IPv4 address)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            address = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, request)[20:24]
            netmask = fcntl.ioctl(sock.fileno(), _SIOCGIFNETMASK, request)[20:24]
        return IPv4Interface(f"{socket.inet_ntoa(address)}/{socket.inet_ntoa(netmask)}")
    except (OSError, struct.error, ValueError) as err:
        _LOGGER.debug("Failed to get address of interface %s: %s", interface, err)
        return None


def get_interface_network(interface: str) -> str | None:
    """Return the network of an interface in CIDR notation, e.g. 192.168.1.0/24."""
    address = get_interface_address(interface)
    return str(address.network) if address else None


def get_available_interfaces() -> list[str]:
    """Return the interfaces that are up and have an IPv4 address."""
    net_dir = "/sys/class/net"
    interfaces = []
    try:
        names = sorted(os.listdir(net_dir))
    except OSError as err:
        _LOGGER.debug("Failed to list interfaces: %s", err)
        return []

    for iface in names:
        if iface == "lo":
            continue
        try:
            with open(f"{net_dir}/{iface}/operstate") as f:
                state = f.read().strip()
        except OSError:
            continue
        # Virtual interfaces like ZeroTier and WireGuard report "unknown"
        # but are operational
        if state in ("up", "unknown") and get_interface_address(iface):
            interfaces.append(iface)
    return interfaces


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
        if msg_len < _NLMSG_HDR.size or msg_type in (_NLMSG_DONE, _NLMSG_ERROR):
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


def _srp(packets: Any, interface: str, timeout: float, retry: int) -> list[tuple[str, str]]:
    """Send ARP requests and return the (ip, mac) of every reply.

    Raises:
        ScanError: Sending failed, e.g. without CAP_NET_RAW.
    """
    from scapy.all import conf, srp

    conf.verb = 0
    try:
        answered, _ = srp(packets, timeout=timeout, iface=interface, verbose=0, retry=retry)
    except PermissionError as err:
        raise ScanError(
            f"Permission denied, Home Assistant needs the CAP_NET_RAW capability: {err}"
        ) from err
    except Exception as err:  # pylint: disable=broad-except  # scapy raises many types
        raise ScanError(f"Sending ARP requests on {interface} failed: {err}") from err
    return [(received.psrc, received.hwsrc.lower()) for _sent, received in answered]


class ArpProber:
    """Finds devices on a network with ARP requests."""

    def __init__(
        self,
        interface: str | None = None,
        network: str | None = None,
        hosts: list[str] | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        known_devices: dict[str, str] | None = None,
    ) -> None:
        """Initialize the prober.

        Args:
            interface: Network interface to use (auto-detect if None)
            network: Network in CIDR notation (auto-detect if None)
            hosts: Probe only these IPs instead of the whole network
            timeout: Seconds to wait for replies per ARP round
            known_devices: MAC -> IP of devices seen before; any of these the
                scan misses are probed directly (sleeping phones)
        """
        self._interface = interface or get_default_interface()
        self._network = network
        if not self._network and self._interface:
            self._network = get_interface_network(self._interface)
        self._hosts = hosts or []
        self._timeout = timeout
        self._known_devices = known_devices or {}

    def probe(self) -> dict[str, str]:
        """Probe the network.

        Returns:
            MAC -> IP of every device found.

        Raises:
            ScanError: The scan could not be performed.
        """
        if not (interface := self._interface):
            raise ScanError("No network interface available")

        found = self._probe_hosts(interface) if self._hosts else self._probe_network(interface)
        found.update(self._probe_sleeping(interface, found))
        return found

    def _probe_network(self, interface: str) -> dict[str, str]:
        """Broadcast an ARP request to every address of the network."""
        from scapy.all import ARP, Ether  # type: ignore[attr-defined]

        if not self._network:
            raise ScanError(f"No IPv4 network found for interface {interface}")

        _LOGGER.debug("ARP scan of %s on %s", self._network, interface)
        packet = Ether(dst=BROADCAST_MAC) / ARP(pdst=self._network)
        replies = _srp(packet, interface, self._timeout, retry=3)
        # Keep the first reply per MAC (like arp-scan -g)
        found: dict[str, str] = {}
        for ip, mac in replies:
            found.setdefault(mac, ip)
        return found

    def _probe_hosts(self, interface: str) -> dict[str, str]:
        """ARP the configured hosts, for VPN interfaces like ZeroTier.

        Broadcast ARP to a whole subnet doesn't work reliably there, and the
        bridging needs the sender IP and MAC set explicitly in every request.
        """
        from scapy.all import ARP, Ether, get_if_hwaddr  # type: ignore[attr-defined]

        address = get_interface_address(interface)
        try:
            iface_mac = get_if_hwaddr(interface)
        except Exception as err:  # pylint: disable=broad-except  # scapy raises many types
            raise ScanError(f"Cannot read the MAC address of {interface}: {err}") from err
        # Never guess a sender IP: claiming another host's address would
        # poison the ARP caches of the devices we probe. Without an address
        # of our own, let scapy pick the source from the routing table.
        sender_ip = str(address.ip) if address else None

        _LOGGER.debug("ARP probe of %s on %s", self._hosts, interface)
        packets = [
            Ether(dst=BROADCAST_MAC, src=iface_mac) / ARP(pdst=ip, psrc=sender_ip, hwsrc=iface_mac)
            for ip in self._hosts
        ]
        # Longer timeout and more retries for VPN networks
        replies = _srp(packets, interface, self._timeout * 2, retry=5)
        return {mac: ip for ip, mac in replies}

    def _in_scope(self, ip: str) -> bool:
        """Return True if ip belongs to the configured hosts or network."""
        if self._hosts:
            return ip in self._hosts
        if not self._network:
            return False
        try:
            return IPv4Address(ip) in IPv4Network(self._network, strict=False)
        except ValueError:
            return False

    def _probe_sleeping(self, interface: str, found: dict[str, str]) -> dict[str, str]:
        """Find known devices the scan missed.

        Phones in Wi-Fi power save (notably Samsung/Android and iPhones)
        ignore broadcast ARP requests while asleep. Every device we know the
        MAC and IP of (earlier scans plus the kernel neighbor table) that did
        not answer gets a UDP wake packet followed by a unicast ARP request
        addressed to its MAC, which the access point buffers and delivers
        when the phone wakes. Neighbors the kernel reports as REACHABLE
        (recently confirmed) afterwards are counted as present too.

        Returns:
            MAC -> IP of additional devices not already in found.
        """
        neighbors = read_neighbor_table(interface)

        # MAC -> IP of devices worth probing, the latest kernel knowledge wins
        candidates = dict(self._known_devices)
        for neighbor in neighbors:
            if neighbor.state & _NUD_CANDIDATE:
                candidates[neighbor.mac] = neighbor.ip
        candidates = {
            mac: ip for mac, ip in candidates.items() if mac not in found and self._in_scope(ip)
        }

        present: dict[str, str] = {}
        if candidates:
            _LOGGER.debug("Probing %d known devices the scan missed", len(candidates))
            send_wake_packets(candidates.values())
            try:
                present.update(self._unicast_arp(interface, candidates))
            except ScanError as err:
                # The main scan worked, so keep its result
                _LOGGER.debug("Unicast ARP probe failed: %s", err)
            # The wake packets make the kernel re-confirm these entries, so
            # read the table again to catch replies after our ARP timeout
            neighbors = read_neighbor_table(interface)

        for neighbor in neighbors:
            if (
                neighbor.state & NUD_REACHABLE
                and neighbor.mac not in found
                and neighbor.mac not in present
                and self._in_scope(neighbor.ip)
            ):
                present[neighbor.mac] = neighbor.ip
        return present

    def _unicast_arp(self, interface: str, targets: dict[str, str]) -> dict[str, str]:
        """Send ARP requests addressed to known MAC/IP pairs.

        Returns:
            MAC -> IP of the targets that answered.
        """
        from scapy.all import ARP, Ether  # type: ignore[attr-defined]

        packets = [Ether(dst=mac) / ARP(pdst=ip, hwdst=mac) for mac, ip in targets.items()]
        return {mac: ip for ip, mac in _srp(packets, interface, self._timeout, retry=2)}


def handle_request(request: dict[str, Any]) -> dict[str, Any]:
    """Run one probe request and return the response message."""
    try:
        found = ArpProber(
            interface=request.get("interface"),
            network=request.get("network"),
            hosts=request.get("hosts"),
            known_devices=request.get("known_devices"),
        ).probe()
    except ScanError as err:
        return {"error": str(err)}
    except Exception as err:  # pylint: disable=broad-except  # report anything to HA
        return {"error": f"Unexpected error: {err!r}"}
    return {"devices": [[ip, mac] for mac, ip in found.items()]}


def main() -> int:
    """Serve probe requests from stdin until it is closed."""
    # Keep stray prints (e.g. from scapy) out of the protocol stream
    protocol = sys.stdout
    sys.stdout = sys.stderr
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError as err:
            response: dict[str, Any] = {"error": f"Invalid request: {err}"}
        else:
            response = handle_request(request)
        protocol.write(json.dumps(response) + "\n")
        protocol.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
