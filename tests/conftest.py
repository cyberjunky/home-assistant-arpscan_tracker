"""Fixtures for ARP-Scan Device Tracker tests."""

import asyncio
import json
import socket
from collections.abc import Callable, Generator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant.common import MockConfigEntry

from custom_components.arpscan_tracker.const import (
    CONF_CONSIDER_HOME,
    CONF_DEVICES_ENABLED,
    CONF_EXCLUDE,
    CONF_HOSTS,
    CONF_INCLUDE,
    CONF_INTERFACE,
    CONF_NETWORK,
    CONF_RESOLVE_HOSTNAMES,
    CONF_TRACK_NEW_DEVICES,
    DOMAIN,
)

INTERFACE = "eth0"
NETWORK = "192.168.1.0/24"

MAC_PHONE = "aa:bb:cc:dd:ee:01"
MAC_LAPTOP = "aa:bb:cc:dd:ee:02"

ENTRY_DATA = {CONF_INTERFACE: INTERFACE, CONF_NETWORK: NETWORK}

ENTRY_OPTIONS = {
    CONF_CONSIDER_HOME: 180,
    CONF_RESOLVE_HOSTNAMES: True,
    CONF_DEVICES_ENABLED: True,
    CONF_TRACK_NEW_DEVICES: True,
    CONF_INCLUDE: [],
    CONF_EXCLUDE: [],
    CONF_HOSTS: [],
}


def scan_result() -> list[dict[str, str | None]]:
    """Return a typical ArpScanner.async_scan result."""
    return [
        {"ip": "192.168.1.10", "mac": MAC_PHONE, "vendor": "Acme", "hostname": "phone"},
        {"ip": "192.168.1.11", "mac": MAC_LAPTOP, "vendor": "Unknown", "hostname": None},
    ]


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Enable loading of the custom integration in all tests."""
    return enable_custom_integrations


def make_entry(**options: Any) -> MockConfigEntry:
    """Return a config entry for INTERFACE with the given option overrides."""
    return MockConfigEntry(
        domain=DOMAIN,
        title=f"ARP Scan ({INTERFACE})",
        data=dict(ENTRY_DATA),
        options={**ENTRY_OPTIONS, **options},
        unique_id=f"{DOMAIN}_{INTERFACE}",
        minor_version=2,
    )


@pytest.fixture
def mock_config_entry() -> MockConfigEntry:
    """Return a mocked config entry."""
    return make_entry()


@pytest.fixture
def mock_scan() -> Generator[AsyncMock]:
    """Patch the ARP scan so no worker process or raw socket is used."""
    with patch(
        "custom_components.arpscan_tracker.scanner.ArpScanner.async_scan",
        new_callable=AsyncMock,
        return_value=scan_result(),
    ) as mock:
        yield mock


@pytest.fixture
def mock_interfaces() -> Generator[None]:
    """Patch interface/network detection used by the config flow."""
    with (
        patch(
            "custom_components.arpscan_tracker.config_flow.get_available_interfaces",
            return_value=[INTERFACE, "wlan0"],
        ),
        patch(
            "custom_components.arpscan_tracker.config_flow.get_default_interface",
            return_value=INTERFACE,
        ),
        patch(
            "custom_components.arpscan_tracker.config_flow.get_interface_network",
            return_value=NETWORK,
        ),
    ):
        yield


class _FakeStdin:
    """The worker's stdin, handing each request line to the worker."""

    def __init__(self, worker: FakeWorkerProcess) -> None:
        self._worker = worker

    def write(self, data: bytes) -> None:
        self._worker.handle(json.loads(data))

    async def drain(self) -> None:
        return

    def close(self) -> None:
        self._worker.exit(0)


class _FakeStream:
    """A stdout/stderr pipe of the fake worker."""

    def __init__(self) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()

    async def readline(self) -> bytes:
        return await self.queue.get()

    def __aiter__(self) -> _FakeStream:
        return self

    async def __anext__(self) -> bytes:
        if line := await self.queue.get():
            return line
        raise StopAsyncIteration


class FakeWorkerProcess:
    """Stand-in for the probe.py worker process."""

    def __init__(self, network: FakeNetwork) -> None:
        self._network = network
        self._exited = asyncio.Event()
        self.returncode: int | None = None
        self.stdin = _FakeStdin(self)
        self.stdout = _FakeStream()
        self.stderr = _FakeStream()

    def handle(self, request: dict[str, Any]) -> None:
        self._network.requests.append(request)
        response = self._network.respond(request)
        if response is None:
            return  # Hang, like a wedged worker
        if response == "crash":
            self.stderr.queue.put_nowait(b"Traceback: boom\n")
            self.exit(1)
            return
        self.stdout.queue.put_nowait(json.dumps(response).encode() + b"\n")

    def exit(self, code: int) -> None:
        if self.returncode is None:
            self.returncode = code
            self.stdout.queue.put_nowait(b"")
            self.stderr.queue.put_nowait(b"")
            self._exited.set()

    def kill(self) -> None:
        self._network.killed += 1
        self.exit(-9)

    async def wait(self) -> int:
        await self._exited.wait()
        assert self.returncode is not None
        return self.returncode


class FakeNetwork:
    """Controls what the fake probe worker finds.

    Set `devices` to the (ip, mac) pairs on the network, `error` to make the
    probe fail, or `respond` for full control. Hostnames come from
    `hostnames` (ip -> FQDN) via a patched reverse DNS.
    """

    def __init__(self) -> None:
        self.devices: list[tuple[str, str]] = [
            ("192.168.1.10", MAC_PHONE),
            ("192.168.1.11", MAC_LAPTOP),
        ]
        self.error: str | None = None
        self.hostnames: dict[str, str] = {"192.168.1.10": "phone.lan"}
        self.requests: list[dict[str, Any]] = []
        self.dns_lookups: list[str] = []
        self.processes: list[FakeWorkerProcess] = []
        self.killed = 0
        self.respond: Callable[[dict[str, Any]], Any] = self._default_respond

    def _default_respond(self, request: dict[str, Any]) -> dict[str, Any]:
        if self.error:
            return {"error": self.error}
        return {"devices": [[ip, mac] for ip, mac in self.devices]}

    async def create_subprocess_exec(self, *_args: Any, **_kwargs: Any) -> FakeWorkerProcess:
        proc = FakeWorkerProcess(self)
        self.processes.append(proc)
        return proc

    def gethostbyaddr(self, ip: str) -> tuple[str, list[str], list[str]]:
        self.dns_lookups.append(ip)
        if ip not in self.hostnames:
            raise socket.herror(1, "Unknown host")
        return self.hostnames[ip], [], [ip]


@pytest.fixture
def fake_network() -> Generator[FakeNetwork]:
    """Run scans against a fake probe worker and reverse DNS."""
    network = FakeNetwork()
    with (
        patch(
            "custom_components.arpscan_tracker.scanner.asyncio.create_subprocess_exec",
            side_effect=network.create_subprocess_exec,
        ),
        patch(
            "custom_components.arpscan_tracker.scanner.socket.gethostbyaddr",
            side_effect=network.gethostbyaddr,
        ),
    ):
        yield network
