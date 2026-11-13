"""ARP scanner: runs the probe worker and enriches its results."""

import asyncio
import json
import logging
import socket
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

from .probe import ScanError, get_default_interface, get_interface_network

_LOGGER = logging.getLogger(__name__)

# probe.py runs as a script in the worker process
_PROBE_SCRIPT = str(Path(__file__).with_name("probe.py"))

# Seconds to wait for one probe request; a wedged worker (e.g. an interface
# that vanished mid-scan) is killed and restarted on the next scan
PROBE_TIMEOUT = 60.0
# Seconds to wait for the worker to exit when closing
CLOSE_TIMEOUT = 5.0
# Max size of one protocol line from the worker
_LINE_LIMIT = 4 * 1024 * 1024

# Reverse DNS results are cached; lookups that failed are retried sooner
HOSTNAME_TTL = 3600.0
HOSTNAME_RETRY = 300.0
HOSTNAME_LOOKUP_TIMEOUT = 10.0
HOSTNAME_LOOKUP_CONCURRENCY = 8

type Device = dict[str, str | None]


def lookup_hostname(ip: str) -> str | None:
    """Return a useful short hostname for ip via reverse DNS, or None."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except OSError:
        return None

    # A hostname that is just the IP or a number (partial IP like "192")
    # is not useful
    if hostname == ip or hostname.isdigit():
        return None

    if "." in hostname:
        short_name = hostname.split(".")[0]
        # An ISP style name like 192-168-1-10.isp.example: keep it whole
        if short_name.replace("-", ".") == ip:
            return hostname
        if short_name.isdigit():
            return None
        return short_name

    return hostname


class _ProbeWorker:
    """A long-lived ``probe.py`` worker process.

    Keeping the worker alive avoids importing scapy for every scan.
    """

    def __init__(self) -> None:
        self._proc: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task[None] | None = None
        self._stderr_tail: deque[str] = deque(maxlen=10)
        self._lock = asyncio.Lock()

    async def async_request(self, request: dict[str, Any]) -> list[list[str]]:
        """Send a probe request and return the [ip, mac] pairs found.

        Raises:
            ScanError: The worker failed or the probe reported an error.
        """
        async with self._lock:
            proc = await self._async_ensure_started()
            assert proc.stdin is not None
            assert proc.stdout is not None
            try:
                proc.stdin.write(json.dumps(request).encode() + b"\n")
                await proc.stdin.drain()
                line = await asyncio.wait_for(proc.stdout.readline(), PROBE_TIMEOUT)
            except TimeoutError:
                await self._async_stop(kill=True)
                raise ScanError(f"ARP scan timed out after {PROBE_TIMEOUT:.0f}s") from None
            except (OSError, ValueError) as err:
                # BrokenPipe/ConnectionReset, or a line over the size limit
                await self._async_stop(kill=True)
                raise ScanError(f"ARP scan worker failed: {err}") from err

            if not line:
                returncode = await proc.wait()
                await self._async_stop()
                details = "; ".join(self._stderr_tail) or "no output"
                raise ScanError(f"ARP scan worker exited with code {returncode}: {details}")

        try:
            response = json.loads(line)
        except json.JSONDecodeError as err:
            raise ScanError(f"ARP scan worker returned invalid output: {err}") from err
        if "error" in response:
            raise ScanError(response["error"])
        devices: list[list[str]] = response["devices"]
        return devices

    async def _async_ensure_started(self) -> asyncio.subprocess.Process:
        """Start the worker if it isn't running."""
        if self._proc is not None and self._proc.returncode is None:
            return self._proc
        await self._async_stop()
        self._stderr_tail.clear()
        try:
            self._proc = await asyncio.create_subprocess_exec(
                sys.executable,
                _PROBE_SCRIPT,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=_LINE_LIMIT,
            )
        except OSError as err:
            raise ScanError(f"Cannot start the ARP scan worker: {err}") from err
        self._stderr_task = asyncio.create_task(self._async_read_stderr(self._proc))
        return self._proc

    async def _async_read_stderr(self, proc: asyncio.subprocess.Process) -> None:
        """Log worker stderr and keep its tail for error messages."""
        assert proc.stderr is not None
        async for raw in proc.stderr:
            if line := raw.decode(errors="replace").rstrip():
                self._stderr_tail.append(line)
                _LOGGER.debug("ARP scan worker: %s", line)

    async def _async_stop(self, kill: bool = False) -> None:
        """Stop the worker, gracefully unless kill is set."""
        proc, self._proc = self._proc, None
        if proc is not None and proc.returncode is None:
            if kill:
                proc.kill()
            elif proc.stdin is not None:
                # Closing stdin ends the worker's request loop
                proc.stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), CLOSE_TIMEOUT)
            except TimeoutError:
                proc.kill()
                await proc.wait()
        if self._stderr_task is not None:
            # Read what's left so the tail holds the worker's last words
            try:
                await asyncio.wait_for(self._stderr_task, CLOSE_TIMEOUT)
            except TimeoutError:
                self._stderr_task.cancel()
            self._stderr_task = None

    async def async_close(self) -> None:
        """Stop the worker."""
        async with self._lock:
            await self._async_stop()


class ArpScanner:
    """Scans a network for devices.

    The ARP probing runs in a worker process (see probe.py). Vendor and
    hostname lookups run here, cached, so a slow DNS server cannot stall the
    scan itself.
    """

    def __init__(
        self,
        interface: str | None = None,
        network: str | None = None,
        resolve_hostnames: bool = True,
        hosts: list[str] | None = None,
    ) -> None:
        """Initialize the scanner.

        Args:
            interface: Network interface to use (auto-detect if None)
            network: Network range in CIDR notation (auto-detect if None)
            resolve_hostnames: Whether to resolve hostnames via reverse DNS
            hosts: Specific IP addresses to probe (if provided, skips network scan)
        """
        self._interface = interface
        self._network = network
        self._resolve_hostnames = resolve_hostnames
        self._hosts = hosts
        self._worker = _ProbeWorker()
        # MAC -> IP of devices seen before, probed directly when they go quiet
        self._known_devices: dict[str, str] = {}
        # (mac, ip) -> (hostname, expiry as monotonic time)
        self._hostnames: dict[tuple[str, str], tuple[str | None, float]] = {}
        self._hostname_semaphore = asyncio.Semaphore(HOSTNAME_LOOKUP_CONCURRENCY)
        self._vendors: dict[str, str | None] = {}
        self._oui_db: Any = None

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
            return get_interface_network(iface) if iface else None
        return self._network

    @property
    def known_devices(self) -> dict[str, str]:
        """Return MAC -> IP of the devices probed directly when they go quiet."""
        return dict(self._known_devices)

    async def async_scan(self) -> list[Device]:
        """Scan the network.

        Returns:
            List of dicts with keys: ip, mac, vendor, hostname

        Raises:
            ScanError: The scan could not be performed.
        """
        pairs = await self._worker.async_request(
            {
                "interface": self._interface,
                "network": self._network,
                "hosts": self._hosts,
                "known_devices": self._known_devices,
            }
        )
        self._remember_devices(pairs)
        return await self._async_enrich(pairs)

    async def async_close(self) -> None:
        """Stop the probe worker."""
        await self._worker.async_close()

    def _remember_devices(self, pairs: list[list[str]]) -> None:
        """Remember MAC -> IP of found devices so later scans can probe them.

        A MAC whose IP now belongs to a different device is forgotten, so a
        reassigned DHCP lease doesn't keep probing the wrong device.
        """
        found = {mac: ip for ip, mac in pairs}
        taken_ips = set(found.values())
        self._known_devices = {
            mac: ip for mac, ip in self._known_devices.items() if ip not in taken_ips
        }
        self._known_devices.update(found)

    async def _async_enrich(self, pairs: list[list[str]]) -> list[Device]:
        """Add vendor and hostname to the scan results."""
        loop = asyncio.get_running_loop()
        new_macs = [mac for _ip, mac in pairs if mac not in self._vendors]
        if new_macs:
            self._vendors.update(await loop.run_in_executor(None, self._lookup_vendors, new_macs))

        hostnames: list[str | None] = [None] * len(pairs)
        if self._resolve_hostnames:
            hostnames = await asyncio.gather(*(self._async_hostname(mac, ip) for ip, mac in pairs))

        return [
            {
                "ip": ip,
                "mac": mac,
                "vendor": self._vendors.get(mac) or "Unknown",
                "hostname": hostname,
            }
            for (ip, mac), hostname in zip(pairs, hostnames, strict=True)
        ]

    def _lookup_vendors(self, macs: list[str]) -> dict[str, str | None]:
        """Look up the vendors of MAC addresses in the OUI database."""
        if self._oui_db is None:
            try:
                from ouilookup import OuiLookup

                self._oui_db = OuiLookup()
            except Exception as err:  # pylint: disable=broad-except  # optional enrichment
                _LOGGER.debug("OUI lookup not available: %s", err)
                return dict.fromkeys(macs)

        vendors: dict[str, str | None] = {}
        try:
            # One query for all MACs: ouilookup reads its database per query.
            # The result is a list like [{"AABBCC...": "Vendor"}] in order.
            result = self._oui_db.query(macs)
            for mac, item in zip(macs, result, strict=True):
                vendor = next(iter(item.values()), None)
                vendors[mac] = str(vendor) if vendor else None
        except Exception as err:  # pylint: disable=broad-except  # optional enrichment
            _LOGGER.debug("OUI lookup failed: %s", err)
            return dict.fromkeys(macs)
        return vendors

    async def _async_hostname(self, mac: str, ip: str) -> str | None:
        """Return the cached hostname of a device, looking it up when stale."""
        key = (mac, ip)
        now = time.monotonic()
        if (cached := self._hostnames.get(key)) is not None and cached[1] > now:
            return cached[0]

        async with self._hostname_semaphore:
            loop = asyncio.get_running_loop()
            try:
                hostname = await asyncio.wait_for(
                    loop.run_in_executor(None, lookup_hostname, ip), HOSTNAME_LOOKUP_TIMEOUT
                )
            except TimeoutError:
                _LOGGER.debug("Reverse DNS lookup of %s timed out", ip)
                hostname = None

        if hostname is None and cached is not None:
            # Keep a previously known name through a DNS hiccup
            hostname = cached[0]
        ttl = HOSTNAME_TTL if hostname else HOSTNAME_RETRY
        self._hostnames[key] = (hostname, time.monotonic() + ttl)
        return hostname
