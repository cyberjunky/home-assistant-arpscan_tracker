"""Tests for the ARP scanner helper (no real subprocess, raw sockets or scapy I/O)."""

import json
import socket
import struct
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from scapy.all import ARP, Ether

from custom_components.arpscan_tracker import scanner as scanner_mod
from custom_components.arpscan_tracker.scanner import (
    NUD_REACHABLE,
    NUD_STALE,
    ArpScanner,
    Neighbor,
    parse_neighbor_messages,
    read_neighbor_table,
    send_wake_packets,
)

SUBPROCESS = "custom_components.arpscan_tracker.scanner.asyncio.create_subprocess_exec"


def _proc(stdout: bytes, returncode: int = 0, stderr: bytes = b"") -> MagicMock:
    proc = MagicMock()
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    proc.returncode = returncode
    proc.wait = AsyncMock()
    return proc


async def test_async_scan_parses_subprocess_output() -> None:
    """The JSON emitted by the scan subprocess is returned, with params passed on stdin."""
    devices = [{"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "vendor": "X", "hostname": None}]
    proc = _proc(json.dumps(devices).encode())
    scanner = ArpScanner(interface="eth0", network="192.168.1.0/24", hosts=["192.168.1.10"])

    with patch(SUBPROCESS, AsyncMock(return_value=proc)):
        assert await scanner.async_scan() == devices

    params = json.loads(proc.communicate.call_args.args[0])
    assert params["interface"] == "eth0"
    assert params["network"] == "192.168.1.0/24"
    assert params["hosts"] == ["192.168.1.10"]


@pytest.mark.parametrize(
    "proc",
    [
        _proc(b"", returncode=1, stderr=b"permission denied"),
        _proc(b"not json"),
    ],
)
async def test_async_scan_failures_return_empty(proc: MagicMock) -> None:
    """A failing subprocess or invalid output results in an empty scan."""
    with patch(SUBPROCESS, AsyncMock(return_value=proc)):
        assert await ArpScanner(interface="eth0", network="10.0.0.0/24").async_scan() == []


async def test_async_scan_cannot_start_subprocess() -> None:
    """An OSError starting the subprocess results in an empty scan."""
    with patch(SUBPROCESS, AsyncMock(side_effect=OSError("no exec"))):
        assert await ArpScanner(interface="eth0", network="10.0.0.0/24").async_scan() == []


@pytest.mark.parametrize(
    ("lookup", "expected"),
    [
        (("phone.lan", [], []), "phone"),
        (("printer", [], []), "printer"),
        (("192.168.1.10", [], []), None),
        (("192-168-1-10.isp.example", [], []), "192-168-1-10.isp.example"),
        (("192.in-addr.arpa", [], []), None),
        (socket.herror("not found"), None),
    ],
)
def test_lookup_hostname(lookup: tuple | Exception, expected: str | None) -> None:
    """Reverse DNS results are reduced to a useful short hostname."""
    scanner = ArpScanner(interface="eth0", network="192.168.1.0/24")
    kwargs = {"side_effect": lookup} if isinstance(lookup, Exception) else {"return_value": lookup}
    with patch("custom_components.arpscan_tracker.scanner.socket.gethostbyaddr", **kwargs):
        assert scanner._lookup_hostname("192.168.1.10") == expected


def test_resolved_interface_and_network() -> None:
    """Interface and network are auto-detected when not configured."""
    with (
        patch(
            "custom_components.arpscan_tracker.scanner.get_default_interface",
            return_value="eth9",
        ),
        patch(
            "custom_components.arpscan_tracker.scanner.get_interface_network",
            return_value="10.9.0.0/16",
        ),
    ):
        scanner = ArpScanner()
        assert scanner.interface == "eth9"
        assert scanner.network == "10.9.0.0/16"


# Sleeping device probe

PROBE_NETWORK = "192.168.1.0/29"
BROADCAST = "ff:ff:ff:ff:ff:ff"

ROUTER_IP, ROUTER_MAC = "192.168.1.1", "aa:aa:aa:aa:aa:01"
PHONE_IP, PHONE_MAC = "192.168.1.3", "bb:bb:bb:bb:bb:02"
OUTSIDE_IP, OUTSIDE_MAC = "10.0.0.5", "cc:cc:cc:cc:cc:03"


class FakeLan:
    """Answers scapy srp() calls like a LAN with sleeping phones.

    Devices in `sleepers` ignore broadcast ARP but answer ARP requests
    addressed to their own MAC, like a phone in Wi-Fi power save.
    """

    def __init__(self, devices: dict[str, str], sleepers: set[str] | None = None) -> None:
        """Initialize with IP -> MAC of devices that answer ARP."""
        self.devices = devices
        self.sleepers = sleepers or set()
        self.unicast_probes: list[tuple[str, str]] = []

    def srp(self, packets: Any, **kwargs: Any) -> tuple[list[Any], list[Any]]:
        """Return (answered, unanswered) like scapy's srp."""
        answered = []
        for packet in packets if isinstance(packets, list) else [packets]:
            # Read fields without building the packet, which would look up
            # the interface's MAC on the real host
            dst = packet[Ether].dst
            pdst = packet[ARP].pdst
            for ip in [pdst] if isinstance(pdst, str) else list(pdst):
                if dst != BROADCAST:
                    self.unicast_probes.append((dst, ip))
                mac = self.devices.get(ip)
                if mac is None:
                    continue
                if dst == BROADCAST and mac in self.sleepers:
                    continue
                if dst not in (BROADCAST, mac):
                    continue
                answered.append((packet, SimpleNamespace(hwsrc=mac.upper(), psrc=ip)))
        return answered, []


def _scan(
    lan: FakeLan,
    neighbors: list[list[Neighbor]] | None = None,
    **scanner_kwargs: Any,
) -> tuple[dict[str, str], list[str]]:
    """Run a synchronous scan against the fake LAN.

    Returns MAC -> IP of the found devices and the IPs that were woken.
    """
    woken: list[str] = []
    tables = iter(neighbors or [])
    scanner = ArpScanner(
        interface="eth0",
        network=PROBE_NETWORK,
        resolve_hostnames=False,
        **scanner_kwargs,
    )
    with (
        patch("scapy.all.srp", side_effect=lan.srp),
        patch.object(
            scanner_mod, "read_neighbor_table", side_effect=lambda _iface: next(tables, [])
        ),
        patch.object(scanner_mod, "send_wake_packets", side_effect=lambda ips: woken.extend(ips)),
        patch.object(
            ArpScanner, "_get_interface_info", return_value=("192.168.1.2", "aa:aa:aa:aa:aa:aa")
        ),
    ):
        devices = scanner._scan_sync()
    return {str(d["mac"]): str(d["ip"]) for d in devices}, woken


def test_awake_devices_found_by_broadcast() -> None:
    """Devices answering broadcast ARP are found without extra probing."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC})

    found, woken = _scan(lan)

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == []
    assert lan.unicast_probes == []


def test_sleeping_known_device_found_by_unicast_probe() -> None:
    """A known phone ignoring broadcast ARP is woken and probed directly."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC}, sleepers={PHONE_MAC})

    found, woken = _scan(lan, known_devices={PHONE_MAC: PHONE_IP})

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]
    assert lan.unicast_probes == [(PHONE_MAC, PHONE_IP)]


def test_sleeping_unknown_device_is_missed() -> None:
    """Without prior knowledge of a sleeping phone there is nothing to probe."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC}, sleepers={PHONE_MAC})

    found, woken = _scan(lan)

    assert found == {ROUTER_MAC: ROUTER_IP}
    assert woken == []


def test_neighbor_table_provides_probe_candidates() -> None:
    """A stale kernel ARP entry (e.g. after a restart) is probed too."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC}, sleepers={PHONE_MAC})
    stale = [Neighbor(2, NUD_STALE, PHONE_IP, PHONE_MAC)]

    found, woken = _scan(lan, neighbors=[stale, stale])

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]


def test_reachable_neighbor_after_wake_counts_as_present() -> None:
    """A phone confirmed by the kernel after the wake packet is present."""
    # The phone never answers our own ARP requests in time
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})
    before = [Neighbor(2, NUD_STALE, PHONE_IP, PHONE_MAC)]
    after = [Neighbor(2, NUD_REACHABLE, PHONE_IP, PHONE_MAC)]

    found, woken = _scan(lan, neighbors=[before, after])

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]


def test_stale_neighbor_that_does_not_answer_is_absent() -> None:
    """A stale ARP entry alone is no evidence the device is present."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})
    stale = [Neighbor(2, NUD_STALE, PHONE_IP, PHONE_MAC)]

    found, woken = _scan(lan, neighbors=[stale, stale], known_devices={PHONE_MAC: PHONE_IP})

    assert found == {ROUTER_MAC: ROUTER_IP}
    assert woken == [PHONE_IP]


def test_out_of_scope_devices_are_ignored() -> None:
    """Known or neighbor devices outside the scanned network are skipped."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})
    reachable = [Neighbor(2, NUD_REACHABLE, OUTSIDE_IP, OUTSIDE_MAC)]

    found, woken = _scan(
        lan, neighbors=[reachable, reachable], known_devices={OUTSIDE_MAC: OUTSIDE_IP}
    )

    assert found == {ROUTER_MAC: ROUTER_IP}
    assert woken == []


def test_hosts_mode_probes_sleeping_host() -> None:
    """Specific hosts mode also wakes and probes known sleeping hosts."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC}, sleepers={PHONE_MAC})

    found, woken = _scan(lan, hosts=[PHONE_IP], known_devices={PHONE_MAC: PHONE_IP})

    assert found == {PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]


def test_unicast_probe_failure_is_not_fatal() -> None:
    """An error during the unicast probe keeps the broadcast results."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})

    def srp(packets: Any, **kwargs: Any) -> tuple[list[Any], list[Any]]:
        if isinstance(packets, list):
            raise OSError("network down")
        return lan.srp(packets, **kwargs)

    scanner = ArpScanner(interface="eth0", network=PROBE_NETWORK, resolve_hostnames=False)
    scanner._known_devices = {PHONE_MAC: PHONE_IP}
    with (
        patch("scapy.all.srp", side_effect=srp),
        patch.object(scanner_mod, "read_neighbor_table", return_value=[]),
        patch.object(scanner_mod, "send_wake_packets"),
    ):
        devices = scanner._scan_sync()

    assert [d["mac"] for d in devices] == [ROUTER_MAC]


def _rtattr(attr_type: int, value: bytes) -> bytes:
    """Build a padded netlink route attribute."""
    attr = struct.pack("=HH", 4 + len(value), attr_type) + value
    return attr + b"\0" * (-len(attr) % 4)


def _neigh_msg(
    family: int, state: int, ip: bytes | None, mac: bytes | None, ifindex: int = 2
) -> bytes:
    """Build an RTM_NEWNEIGH netlink message."""
    body = struct.pack("=BBHiHBB", family, 0, 0, ifindex, state, 0, 1)
    if ip is not None:
        body += _rtattr(1, ip)
    if mac is not None:
        body += _rtattr(2, mac)
    return struct.pack("=LHHLL", 16 + len(body), 28, 2, 1, 0) + body


DONE_MSG = struct.pack("=LHHLL", 20, 3, 2, 1, 0) + b"\0\0\0\0"


def test_parse_neighbor_messages() -> None:
    """IPv4 entries with a MAC are parsed, others are skipped."""
    data = (
        _neigh_msg(
            socket.AF_INET, NUD_REACHABLE, socket.inet_aton(PHONE_IP), bytes.fromhex("bbbbbbbbbb02")
        )
        + _neigh_msg(
            socket.AF_INET, NUD_STALE, socket.inet_aton(ROUTER_IP), bytes.fromhex("aaaaaaaaaa01"), 3
        )
        # Incomplete entry without a link-layer address
        + _neigh_msg(socket.AF_INET, 0x01, socket.inet_aton("192.168.1.4"), None)
        # Failed entry with an all-zero MAC
        + _neigh_msg(socket.AF_INET, 0x20, socket.inet_aton("192.168.1.5"), bytes(6))
        # IPv6 neighbor
        + _neigh_msg(socket.AF_INET6, NUD_REACHABLE, bytes(16), bytes.fromhex("dddddddddd04"))
    )

    neighbors, done = parse_neighbor_messages(data)

    assert neighbors == [
        Neighbor(2, NUD_REACHABLE, PHONE_IP, PHONE_MAC),
        Neighbor(3, NUD_STALE, ROUTER_IP, ROUTER_MAC),
    ]
    assert done is False

    neighbors, done = parse_neighbor_messages(DONE_MSG)
    assert neighbors == []
    assert done is True


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="netlink is Linux only")
@pytest.mark.usefixtures("socket_enabled")
def test_read_neighbor_table_from_kernel() -> None:
    """Reading the real kernel neighbor table works and returns entries."""
    neighbors = read_neighbor_table()

    assert isinstance(neighbors, list)
    assert all(isinstance(n, Neighbor) for n in neighbors)


def test_read_neighbor_table_unknown_interface() -> None:
    """An unknown interface yields an empty table instead of raising."""
    assert read_neighbor_table("does-not-exist0") == []


@pytest.mark.usefixtures("socket_enabled")
def test_send_wake_packets() -> None:
    """A UDP wake packet is sent to every IP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(2.0)
        port = listener.getsockname()[1]

        send_wake_packets(["127.0.0.1", "not-an-ip"], port=port)

        data, _ = listener.recvfrom(1024)
    assert data == scanner_mod.WAKE_PAYLOAD


class FakeProcess:
    """Stand-in for the scan subprocess, recording the parameters it got."""

    def __init__(self, result: list[dict[str, Any]], calls: list[dict[str, Any]]) -> None:
        """Initialize with the scan result to emit."""
        self._result = result
        self._calls = calls
        self.returncode = 0

    async def communicate(self, data: bytes) -> tuple[bytes, bytes]:
        """Record the parameters and return the result as JSON."""
        self._calls.append(json.loads(data))
        return json.dumps(self._result).encode(), b""


def _device(ip: str, mac: str) -> dict[str, Any]:
    return {"ip": ip, "mac": mac, "vendor": "Unknown", "hostname": None}


async def test_async_scan_remembers_devices_for_next_scan() -> None:
    """Devices found earlier are handed to the next scan to probe."""
    calls: list[dict[str, Any]] = []
    results = iter(
        [
            [_device(ROUTER_IP, ROUTER_MAC), _device(PHONE_IP, PHONE_MAC)],
            # The phone is asleep and the router is still there
            [_device(ROUTER_IP, ROUTER_MAC)],
            # A new device took over the phone's DHCP lease
            [_device(PHONE_IP, OUTSIDE_MAC)],
            [],
        ]
    )

    async def fake_exec(*_args: Any, **_kwargs: Any) -> FakeProcess:
        return FakeProcess(next(results), calls)

    scanner = ArpScanner(interface="eth0", network=PROBE_NETWORK, resolve_hostnames=False)
    with patch.object(scanner_mod.asyncio, "create_subprocess_exec", side_effect=fake_exec):
        for _ in range(4):
            await scanner.async_scan()

    assert [call["known_devices"] for call in calls] == [
        {},
        {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP},
        # A sleeping phone stays known
        {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP},
        # The phone's old IP now belongs to another device
        {ROUTER_MAC: ROUTER_IP, OUTSIDE_MAC: PHONE_IP},
    ]
