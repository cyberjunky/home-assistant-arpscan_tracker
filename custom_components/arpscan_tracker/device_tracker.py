"""
Support for scanning a network with arp-scan.

For more details about this platform, please refer to the documentation at
https://github.com/cyberjunky/hass-arpscan_tracker/
"""
import logging
import re
import subprocess
from collections import namedtuple
from datetime import timedelta

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.util import Throttle

_LOGGER = logging.getLogger(__name__)

CONF_EXCLUDE = 'exclude'
CONF_INCLUDE = 'include'
CONF_OPTIONS = 'scan_options'
DEFAULT_OPTIONS = '-l -g -t1 -q'

MIN_TIME_BETWEEN_SCANS = timedelta(seconds=5)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_INCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_EXCLUDE, default=[]):
        vol.All(cv.ensure_list, [cv.string]),
    vol.Optional(CONF_OPTIONS, default=DEFAULT_OPTIONS):
        cv.string
})


def get_scanner(hass, config):
    """Validate the configuration and return a ArpScan scanner."""
    return ArpScanDeviceScanner(config[DOMAIN])

Device = namedtuple('Device', ['mac', 'name', 'ip', 'last_update'])


class ArpScanDeviceScanner(DeviceScanner):
    """This class scans for devices using arp-scan."""

    exclude = []
    include = []

    def __init__(self, config):
        """Initialize the scanner."""
        self.last_results = []

        self.exclude = config[CONF_EXCLUDE]
        self.include = config[CONF_INCLUDE]
        self._options = config[CONF_OPTIONS]

        self.success_init = self._update_info()
        _LOGGER.debug("Scanner initialized")


    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()

        _LOGGER.debug("arpscan last results %s", self.last_results)

        return [device.mac for device in self.last_results]


    def get_device_name(self, mac):
        """Return the name of the given device."""

        return mac.replace(':', '')


    def get_extra_attributes(self, device):
        """Return the IP of the given device."""
        filter_ip = next(
            (result.ip for result in self.last_results if result.mac == device), None
        )
        return {"ip": filter_ip}


    @Throttle(MIN_TIME_BETWEEN_SCANS)
    def _update_info(self):
        """
        Scan the network for devices.
        Returns boolean if scanning successful.
        """
        _LOGGER.debug("Scanning...")

        options = self._options

        last_results = []
        exclude_hosts = self.exclude
        include_hosts = self.include

        """ignore exclude if include present"""
        if include_hosts:
            exclude_hosts = []

        scandata = subprocess.getoutput("arp-scan "+options)
        _LOGGER.debug("Scandata %s", scandata)

        now = dt_util.now()
        for line in scandata.splitlines():
            ipv4 = re.findall(r'[0-9]+(?:\.[0-9]+){3}', line)
            if not ipv4:
                continue

            parts = line.split()
            ipv4 = parts[0]

            if include_hosts:
                if not ipv4 in include_hosts:
                    _LOGGER.debug("Excluded %s", ipv4)
                    continue

            if ipv4 in exclude_hosts:
                _LOGGER.debug("Excluded %s", ipv4)
                continue

            mac = parts[1]
            last_results.append(Device(mac, mac.replace(':', ''), ipv4, now))

        self.last_results = last_results

        _LOGGER.debug("Arpscan successful")
        return True
