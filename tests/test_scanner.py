"""Tests for the ARP scanner helper (no real subprocess, sockets or scapy)."""

import json
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.arpscan_tracker.scanner import ArpScanner

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
