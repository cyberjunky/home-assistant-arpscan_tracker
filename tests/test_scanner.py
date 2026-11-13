"""Tests for the ARP scanner: probe worker handling and result enrichment."""

import socket
from typing import Any
from unittest.mock import patch

import pytest

from custom_components.arpscan_tracker import scanner as scanner_mod
from custom_components.arpscan_tracker.probe import ScanError
from custom_components.arpscan_tracker.scanner import ArpScanner, lookup_hostname

from .conftest import MAC_LAPTOP, MAC_PHONE, FakeNetwork

PHONE_IP = "192.168.1.10"
LAPTOP_IP = "192.168.1.11"
NEW_MAC = "aa:bb:cc:dd:ee:03"


@pytest.fixture
def scanner() -> ArpScanner:
    """Return a scanner for eth0."""
    return ArpScanner(interface="eth0", network="192.168.1.0/24")


async def test_scan_returns_enriched_devices(
    scanner: ArpScanner, fake_network: FakeNetwork
) -> None:
    """Probe results get a hostname and vendor; the request carries the settings."""
    devices = await scanner.async_scan()
    await scanner.async_close()

    assert [(d["ip"], d["mac"], d["hostname"]) for d in devices] == [
        (PHONE_IP, MAC_PHONE, "phone"),
        (LAPTOP_IP, MAC_LAPTOP, None),
    ]
    assert all(d["vendor"] for d in devices)
    request = fake_network.requests[0]
    assert request["interface"] == "eth0"
    assert request["network"] == "192.168.1.0/24"
    assert request["hosts"] is None


async def test_worker_is_reused(scanner: ArpScanner, fake_network: FakeNetwork) -> None:
    """One worker process serves all scans until the scanner is closed."""
    for _ in range(3):
        await scanner.async_scan()
    assert len(fake_network.processes) == 1

    await scanner.async_close()
    assert fake_network.processes[0].returncode == 0
    assert fake_network.killed == 0


async def test_probe_error_raises(scanner: ArpScanner, fake_network: FakeNetwork) -> None:
    """An error reported by the probe is raised, not turned into an empty scan."""
    fake_network.error = "Permission denied, Home Assistant needs the CAP_NET_RAW capability"

    with pytest.raises(ScanError, match="CAP_NET_RAW"):
        await scanner.async_scan()
    await scanner.async_close()


async def test_worker_crash_raises_and_restarts(
    scanner: ArpScanner, fake_network: FakeNetwork
) -> None:
    """A crashed worker is reported with its last output and replaced next scan."""
    fake_network.respond = lambda request: "crash"

    with pytest.raises(ScanError, match="exited with code 1: Traceback: boom"):
        await scanner.async_scan()

    fake_network.respond = fake_network._default_respond
    assert len(await scanner.async_scan()) == 2
    assert len(fake_network.processes) == 2
    await scanner.async_close()


async def test_worker_timeout_kills_worker(scanner: ArpScanner, fake_network: FakeNetwork) -> None:
    """A wedged worker is killed and the scan fails."""
    fake_network.respond = lambda request: None

    with (
        patch.object(scanner_mod, "PROBE_TIMEOUT", 0.01),
        pytest.raises(ScanError, match="timed out"),
    ):
        await scanner.async_scan()

    assert fake_network.killed == 1
    await scanner.async_close()


async def test_worker_cannot_start() -> None:
    """Failing to start the worker is a scan error."""
    with (
        patch.object(scanner_mod.asyncio, "create_subprocess_exec", side_effect=OSError("no exec")),
        pytest.raises(ScanError, match="Cannot start"),
    ):
        await ArpScanner(interface="eth0").async_scan()


async def test_known_devices_handed_to_next_scan(
    scanner: ArpScanner, fake_network: FakeNetwork
) -> None:
    """Devices found earlier are handed to the next scan to probe."""
    results = iter(
        [
            [[PHONE_IP, MAC_PHONE], [LAPTOP_IP, MAC_LAPTOP]],
            # The phone is asleep, the laptop still there
            [[LAPTOP_IP, MAC_LAPTOP]],
            # A new device took over the phone's DHCP lease
            [[PHONE_IP, NEW_MAC]],
            [],
        ]
    )
    fake_network.respond = lambda request: {"devices": next(results)}

    for _ in range(4):
        await scanner.async_scan()
    await scanner.async_close()

    assert [request["known_devices"] for request in fake_network.requests] == [
        {},
        {MAC_PHONE: PHONE_IP, MAC_LAPTOP: LAPTOP_IP},
        # A sleeping phone stays known
        {MAC_PHONE: PHONE_IP, MAC_LAPTOP: LAPTOP_IP},
        # The phone's old IP now belongs to another device
        {MAC_LAPTOP: LAPTOP_IP, NEW_MAC: PHONE_IP},
    ]
    assert scanner.known_devices == {MAC_LAPTOP: LAPTOP_IP, NEW_MAC: PHONE_IP}


async def test_hostnames_are_cached(scanner: ArpScanner, fake_network: FakeNetwork) -> None:
    """Reverse DNS runs once per device, not on every scan."""
    for _ in range(3):
        await scanner.async_scan()
    await scanner.async_close()

    assert sorted(fake_network.dns_lookups) == [PHONE_IP, LAPTOP_IP]


async def test_known_hostname_survives_dns_failure(
    scanner: ArpScanner, fake_network: FakeNetwork
) -> None:
    """A hostname stays known when a later lookup fails."""
    await scanner.async_scan()
    fake_network.hostnames.clear()
    # Expire the cache so the next scan looks the names up again
    scanner._hostnames = {key: (name, 0.0) for key, (name, _) in scanner._hostnames.items()}

    devices = await scanner.async_scan()
    await scanner.async_close()

    assert len(fake_network.dns_lookups) == 4
    assert devices[0]["hostname"] == "phone"


async def test_resolve_hostnames_disabled(fake_network: FakeNetwork) -> None:
    """No reverse DNS lookups are done when disabled."""
    scanner = ArpScanner(interface="eth0", resolve_hostnames=False)

    devices = await scanner.async_scan()
    await scanner.async_close()

    assert [device["hostname"] for device in devices] == [None, None]
    assert fake_network.dns_lookups == []


async def test_vendor_lookup_cached_per_mac(scanner: ArpScanner, fake_network: FakeNetwork) -> None:
    """The OUI database is queried once for every new MAC."""
    queries: list[list[str]] = []

    class FakeOui:
        def query(self, macs: list[str]) -> list[dict[str, Any]]:
            queries.append(macs)
            return [{mac.replace(":", "").upper(): "Acme"} for mac in macs]

    with patch("ouilookup.OuiLookup", FakeOui):
        await scanner.async_scan()
        fake_network.devices.append(("192.168.1.12", NEW_MAC))
        devices = await scanner.async_scan()
    await scanner.async_close()

    assert queries == [[MAC_PHONE, MAC_LAPTOP], [NEW_MAC]]
    assert {device["vendor"] for device in devices} == {"Acme"}


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
    kwargs = {"side_effect": lookup} if isinstance(lookup, Exception) else {"return_value": lookup}
    with patch.object(scanner_mod.socket, "gethostbyaddr", **kwargs):
        assert lookup_hostname("192.168.1.10") == expected


def test_resolved_interface_and_network() -> None:
    """Interface and network are auto-detected when not configured."""
    with (
        patch.object(scanner_mod, "get_default_interface", return_value="eth9"),
        patch.object(scanner_mod, "get_interface_network", return_value="10.9.0.0/16"),
    ):
        scanner = ArpScanner()
        assert scanner.interface == "eth9"
        assert scanner.network == "10.9.0.0/16"


async def test_real_worker_reports_errors() -> None:
    """The real probe.py worker starts, answers over its protocol and exits.

    Probing an interface that doesn't exist fails in any environment, with
    or without CAP_NET_RAW, so the error must come back as a ScanError.
    """
    scanner = ArpScanner(interface="does-not-exist0", network="192.0.2.0/30")

    with pytest.raises(ScanError):
        await scanner.async_scan()
    # The worker survives a failed probe and serves the next request
    with pytest.raises(ScanError):
        await scanner.async_scan()
    await scanner.async_close()


async def _scan_at(scanner: ArpScanner, now: float) -> None:
    """Run a scan at the given monotonic time."""
    with patch.object(scanner_mod.time, "monotonic", return_value=now):
        await scanner.async_scan()


async def test_full_sweep_only_every_sweep_interval(
    scanner: ArpScanner, fake_network: FakeNetwork
) -> None:
    """The network is swept on the first scan and then every SWEEP_INTERVAL."""
    for now in (1000.0, 1015.0, 1030.0, 1000.0 + scanner_mod.SWEEP_INTERVAL, 1315.0):
        await _scan_at(scanner, now)
    await scanner.async_close()

    assert [request["sweep"] for request in fake_network.requests] == [
        True,
        False,
        False,
        True,
        False,
    ]


async def test_missing_device_triggers_early_sweep(
    scanner: ArpScanner, fake_network: FakeNetwork
) -> None:
    """A device that disappears causes a sweep, at most once per MIN_SWEEP_GAP."""
    gap = scanner_mod.MIN_SWEEP_GAP
    await _scan_at(scanner, 1000.0)
    # The phone is gone (or moved to a new IP)
    fake_network.devices = [(LAPTOP_IP, MAC_LAPTOP)]
    await _scan_at(scanner, 1015.0)
    # Too soon after the first sweep
    await _scan_at(scanner, 1000.0 + gap - 1)
    await _scan_at(scanner, 1000.0 + gap)
    # Swept; the phone staying away doesn't trigger more sweeps
    await _scan_at(scanner, 1000.0 + 2 * gap + 1)
    await scanner.async_close()

    assert [request["sweep"] for request in fake_network.requests] == [
        True,
        False,
        False,
        True,
        False,
    ]


async def test_failed_sweep_is_retried(scanner: ArpScanner, fake_network: FakeNetwork) -> None:
    """A sweep that failed is attempted again on the next scan."""
    fake_network.error = "interface down"
    with pytest.raises(ScanError):
        await _scan_at(scanner, 1000.0)
    fake_network.error = None
    await _scan_at(scanner, 1015.0)
    await _scan_at(scanner, 1030.0)
    await scanner.async_close()

    assert [request["sweep"] for request in fake_network.requests] == [True, True, False]
