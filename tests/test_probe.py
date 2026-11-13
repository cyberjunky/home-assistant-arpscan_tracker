"""Tests for the ARP probe worker (probe.py), without raw sockets."""

import socket
import struct
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from scapy.all import ARP, Ether

from custom_components.arpscan_tracker import probe as probe_mod
from custom_components.arpscan_tracker.probe import (
    NUD_REACHABLE,
    NUD_STALE,
    ArpProber,
    Neighbor,
    ScanError,
    handle_request,
    parse_neighbor_messages,
    read_neighbor_table,
    send_wake_packets,
)

NETWORK = "192.168.1.0/29"
BROADCAST = "ff:ff:ff:ff:ff:ff"
OWN_IP, OWN_MAC = "192.168.1.2", "aa:aa:aa:aa:aa:aa"

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
        self.sender_ips: list[str | None] = []
        self.broadcasts: list[str] = []
        self.calls: list[dict[str, Any]] = []

    def srp(self, packets: Any, **kwargs: Any) -> tuple[list[Any], list[Any]]:
        """Return (answered, unanswered) like scapy's srp."""
        answered = []
        self.calls.append(kwargs)
        for packet in packets if isinstance(packets, list) else [packets]:
            # Read fields without building the packet, which would look up
            # the interface's MAC on the real host
            dst = packet[Ether].dst
            pdst = packet[ARP].pdst
            self.sender_ips.append(packet[ARP].getfieldval("psrc"))
            for ip in [pdst] if isinstance(pdst, str) else list(pdst):
                if dst == BROADCAST:
                    self.broadcasts.append(ip)
                else:
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


def _probe(
    lan: FakeLan,
    neighbors: list[list[Neighbor]] | None = None,
    own_address: str | None = f"{OWN_IP}/29",
    **prober_kwargs: Any,
) -> tuple[dict[str, str], list[str]]:
    """Probe the fake LAN.

    Returns MAC -> IP of the found devices and the IPs that were woken.
    """
    woken: list[str] = []
    tables = iter(neighbors or [])
    prober_kwargs.setdefault("network", NETWORK)
    with (
        patch("scapy.all.srp", side_effect=lan.srp),
        patch("scapy.all.get_if_hwaddr", return_value=OWN_MAC),
        patch.object(
            probe_mod,
            "get_interface_address",
            return_value=probe_mod.IPv4Interface(own_address) if own_address else None,
        ),
        patch.object(probe_mod, "read_neighbor_table", side_effect=lambda _iface: next(tables, [])),
        patch.object(probe_mod, "send_wake_packets", side_effect=lambda ips: woken.extend(ips)),
    ):
        found = ArpProber(interface="eth0", **prober_kwargs).probe()
    return found, woken


def test_awake_devices_found_by_broadcast() -> None:
    """Devices answering broadcast ARP are found without extra probing."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC})

    found, woken = _probe(lan)

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == []
    assert lan.unicast_probes == []


def test_sleeping_known_device_found_by_unicast_probe() -> None:
    """A known phone ignoring broadcast ARP is woken and probed directly."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC}, sleepers={PHONE_MAC})

    found, woken = _probe(lan, known_devices={PHONE_MAC: PHONE_IP})

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]
    assert lan.unicast_probes == [(PHONE_MAC, PHONE_IP)]


def test_sleeping_unknown_device_is_missed() -> None:
    """Without prior knowledge of a sleeping phone there is nothing to probe."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC}, sleepers={PHONE_MAC})

    found, woken = _probe(lan)

    assert found == {ROUTER_MAC: ROUTER_IP}
    assert woken == []


def test_neighbor_table_provides_probe_candidates() -> None:
    """A stale kernel ARP entry (e.g. after a restart) is probed too."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC}, sleepers={PHONE_MAC})
    stale = [Neighbor(2, NUD_STALE, PHONE_IP, PHONE_MAC)]

    found, woken = _probe(lan, neighbors=[stale, stale])

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]


def test_reachable_neighbor_after_wake_counts_as_present() -> None:
    """A phone confirmed by the kernel after the wake packet is present."""
    # The phone never answers our own ARP requests in time
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})
    before = [Neighbor(2, NUD_STALE, PHONE_IP, PHONE_MAC)]
    after = [Neighbor(2, NUD_REACHABLE, PHONE_IP, PHONE_MAC)]

    found, woken = _probe(lan, neighbors=[before, after])

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]


def test_stale_neighbor_that_does_not_answer_is_absent() -> None:
    """A stale ARP entry alone is no evidence the device is present."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})
    stale = [Neighbor(2, NUD_STALE, PHONE_IP, PHONE_MAC)]

    found, woken = _probe(lan, neighbors=[stale, stale], known_devices={PHONE_MAC: PHONE_IP})

    assert found == {ROUTER_MAC: ROUTER_IP}
    assert woken == [PHONE_IP]


def test_out_of_scope_devices_are_ignored() -> None:
    """Known or neighbor devices outside the scanned network are skipped."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})
    reachable = [Neighbor(2, NUD_REACHABLE, OUTSIDE_IP, OUTSIDE_MAC)]

    found, woken = _probe(
        lan, neighbors=[reachable, reachable], known_devices={OUTSIDE_MAC: OUTSIDE_IP}
    )

    assert found == {ROUTER_MAC: ROUTER_IP}
    assert woken == []


def test_hosts_mode_probes_sleeping_host() -> None:
    """Specific hosts mode also wakes and probes known sleeping hosts."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC}, sleepers={PHONE_MAC})

    found, woken = _probe(lan, hosts=[PHONE_IP], known_devices={PHONE_MAC: PHONE_IP})

    assert found == {PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]


def test_hosts_mode_uses_own_ip_as_sender() -> None:
    """Hosts mode ARP requests carry the interface's own IP as sender."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})

    _probe(lan, hosts=[ROUTER_IP])

    assert lan.sender_ips[0] == OWN_IP


def test_hosts_mode_never_guesses_a_sender_ip() -> None:
    """Without an own IP, the sender is left to scapy, never another host's IP."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})

    found, _ = _probe(lan, own_address=None, hosts=[ROUTER_IP])

    assert found == {ROUTER_MAC: ROUTER_IP}
    assert lan.sender_ips[0] is None


def test_permission_denied_raises() -> None:
    """Missing CAP_NET_RAW is reported as a scan error."""
    with (
        patch("scapy.all.srp", side_effect=PermissionError("Operation not permitted")),
        pytest.raises(ScanError, match="CAP_NET_RAW"),
    ):
        ArpProber(interface="eth0", network=NETWORK).probe()


def test_scapy_failure_raises() -> None:
    """Any scapy failure in the main scan is reported as a scan error."""
    with (
        patch("scapy.all.srp", side_effect=OSError("No such device")),
        pytest.raises(ScanError, match="No such device"),
    ):
        ArpProber(interface="eth0", network=NETWORK).probe()


def test_no_interface_or_network_raises() -> None:
    """A scan without interface or network is an error, not an empty result."""
    with (
        patch.object(probe_mod, "get_default_interface", return_value=None),
        pytest.raises(ScanError, match="No network interface"),
    ):
        ArpProber().probe()

    with (
        patch.object(probe_mod, "get_interface_network", return_value=None),
        pytest.raises(ScanError, match="No IPv4 network"),
    ):
        ArpProber(interface="eth0").probe()


def test_unicast_probe_failure_keeps_scan_result() -> None:
    """An error during the unicast probe keeps the broadcast results."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})

    def srp(packets: Any, **kwargs: Any) -> tuple[list[Any], list[Any]]:
        if isinstance(packets, list):
            raise OSError("network down")
        return lan.srp(packets, **kwargs)

    with (
        patch("scapy.all.srp", side_effect=srp),
        patch.object(probe_mod, "read_neighbor_table", return_value=[]),
        patch.object(probe_mod, "send_wake_packets"),
    ):
        found = ArpProber(
            interface="eth0", network=NETWORK, known_devices={PHONE_MAC: PHONE_IP}
        ).probe()

    assert found == {ROUTER_MAC: ROUTER_IP}


def test_sweep_spreads_out_broadcasts() -> None:
    """A sweep retries once and spaces its broadcast requests."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})

    _probe(lan)

    assert lan.calls == [
        {"timeout": 1.5, "iface": "eth0", "verbose": 0, "retry": 1, "inter": probe_mod.SWEEP_INTER}
    ]


def test_known_devices_probed_without_broadcast() -> None:
    """Between sweeps the known devices are ARPed directly, nothing else."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC, PHONE_IP: PHONE_MAC, "192.168.1.4": OUTSIDE_MAC})

    found, woken = _probe(
        lan, sweep=False, known_devices={ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    )

    # The unknown device at .4 is left for the next sweep
    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert lan.broadcasts == []
    assert sorted(lan.unicast_probes) == [(ROUTER_MAC, ROUTER_IP), (PHONE_MAC, PHONE_IP)]
    # Devices that answered right away are not woken
    assert woken == []


def test_known_device_missing_between_sweeps_is_woken() -> None:
    """A known device that misses the direct probe gets the sleeping-phone treatment."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})
    phone_back = [Neighbor(2, NUD_REACHABLE, PHONE_IP, PHONE_MAC)]

    found, woken = _probe(
        lan,
        neighbors=[[], [], phone_back],
        sweep=False,
        known_devices={ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP},
    )

    assert found == {ROUTER_MAC: ROUTER_IP, PHONE_MAC: PHONE_IP}
    assert woken == [PHONE_IP]
    assert lan.broadcasts == []


def test_neighbors_probed_between_sweeps() -> None:
    """Devices from the kernel neighbor table are probed between sweeps too."""
    lan = FakeLan({PHONE_IP: PHONE_MAC})

    found, _woken = _probe(
        lan, neighbors=[[Neighbor(2, NUD_STALE, PHONE_IP, PHONE_MAC)]], sweep=False
    )

    assert found == {PHONE_MAC: PHONE_IP}
    assert lan.broadcasts == []


def test_nothing_known_between_sweeps() -> None:
    """Without known devices there is nothing to probe until the next sweep."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})

    found, woken = _probe(lan, sweep=False)

    assert found == {}
    assert woken == []
    assert lan.calls == []


def test_hosts_mode_ignores_sweep_flag() -> None:
    """Configured hosts are always probed."""
    lan = FakeLan({ROUTER_IP: ROUTER_MAC})

    found, _woken = _probe(lan, network=None, hosts=[ROUTER_IP], sweep=False)

    assert found == {ROUTER_MAC: ROUTER_IP}


def test_handle_request() -> None:
    """Requests are answered with [ip, mac] pairs or an error message."""
    with patch.object(ArpProber, "probe", return_value={ROUTER_MAC: ROUTER_IP}):
        assert handle_request({"interface": "eth0", "network": NETWORK}) == {
            "devices": [[ROUTER_IP, ROUTER_MAC]]
        }
    with patch.object(ArpProber, "__init__", return_value=None) as init, patch.object(
        ArpProber, "probe", return_value={}
    ):
        handle_request({"interface": "eth0", "network": NETWORK})
        assert init.call_args.kwargs["sweep"] is True
        handle_request({"interface": "eth0", "network": NETWORK, "sweep": False})
        assert init.call_args.kwargs["sweep"] is False
    with patch.object(ArpProber, "probe", side_effect=ScanError("no permission")):
        assert handle_request({"interface": "eth0", "network": NETWORK}) == {
            "error": "no permission"
        }
    with patch.object(ArpProber, "probe", side_effect=KeyError("bug")):
        assert handle_request({"interface": "eth0", "network": NETWORK})["error"].startswith(
            "Unexpected error"
        )


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
    assert data == probe_mod.WAKE_PAYLOAD


@pytest.mark.usefixtures("socket_enabled")
def test_interface_helpers_on_loopback() -> None:
    """The ioctl based interface helpers read a real interface."""
    assert str(probe_mod.get_interface_address("lo")) == "127.0.0.1/8"
    assert probe_mod.get_interface_network("lo") == "127.0.0.0/8"
    assert probe_mod.get_interface_address("does-not-exist0") is None
    assert "lo" not in probe_mod.get_available_interfaces()
