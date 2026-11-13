## Changelog

### 2.2.1

- Much less broadcast traffic: the network is swept with broadcast ARP every 5 minutes instead of every 15 seconds, with one retry instead of three and the requests spread out. Known devices are still checked every 15 seconds with ARP requests addressed to them directly, so home/away detection is as fast as before; new devices can take up to 5 minutes to show up. A full broadcast sweep every 15 seconds could disturb Wi-Fi clients, notably ESP32-based devices

### 2.2.0

- **Breaking**: YAML configuration (`device_tracker` with `platform: arpscan_tracker`) is removed; add the integration via the UI instead
- **Breaking**: The scan interval and ARP timeout are no longer configurable; the network is scanned every 15 seconds. Existing settings are removed automatically
- **Breaking**: Every tracker now has a device, named after the hostname or MAC address; the trackers take their name from the device. Rename the device to rename the tracker
- A failed scan (missing permission, interface down, scan worker crash) now makes the trackers `unavailable` instead of quietly reporting every device as away, and is logged once instead of on every scan
- Hostnames are resolved in parallel and cached for an hour, so a slow DNS server can no longer time out the scan; vendor lookups are cached too
- The ARP scan runs in a long-lived worker process instead of starting a new process (and importing scapy) every 15 seconds
- The network range and host lists are validated; networks larger than 1024 addresses (/22) can only be used with specific hosts
- Added a reconfigure flow to change the interface or network without removing the integration
- Setup and reconfigure run a test scan, so a missing permission or broken interface is shown in the form
- Scan errors are translatable
- The setup form only asks for the interface, network and hosts; all other settings are under **Configure**
- Include and exclude lists can no longer be used together
- Specific hosts mode no longer uses another host's IP as sender address when the interface's own IP can't be read
- A device seen on two configured interfaces is tracked by the first entry only, instead of failing with a duplicate unique ID
- Devices can be removed from the device page
- Added diagnostics
- A device is renamed when its hostname shows up or changes while Home Assistant runs (#138)
- Uses the config entry runtime data and passes the config entry to the coordinator

### 2.1.9

- Better detection of sleeping phones (Samsung/Android, iPhone) that ignore broadcast ARP in Wi-Fi power save (#83): known devices missing from the scan are now woken with a UDP packet and probed with a unicast ARP request, and devices the kernel recently confirmed as reachable count as present. This reduces home/not_home flapping, but phones that ignore all traffic in deep sleep can still drop out
- Code formatted with `ruff format`

### 2.1.8

- **Breaking**: Requires Home Assistant 2026.3.0 or newer (Python 3.14)
- Added local brand images (`brand/` folder), so the integration icon shows up without the Home Assistant brands repository
- Fixed newly discovered devices being created disabled until the next reload, even with **Enable Found Devices** on
- Fixed Include/Exclude/Hosts options that could not be cleared again once set
- Fixed socket leak when probing interfaces without an IPv4 address

### 2.1.7

- Devices without a resolvable hostname are now named after their MAC address instead of their IP (#82); existing IP-based names are migrated automatically, entity IDs are unaffected
- Run the ARP scan in a subprocess to avoid the `select()` file descriptor limit (#74)
- Added a timeout to the ARP scan subprocess, so a wedged scan fails and retries instead of leaving every device stuck "away" (#75)
- Added Simplified Chinese translation (`zh_Hans`), thanks to @acooler15
- Bumped `scapy` to `>=2.7.0` and `ouilookup` to `>=0.3.1`

### 2.1.6

- Fixed new devices being created in a disabled state

### 2.1.5

- Better DNS resolving of device names

### 2.1.4

- Fixed wrong device entity names when no DNS name was returned

### 2.1.3

- Added **Enable Found Devices** option to enable/disable all device tracker entities
- Added **Track New Devices** option to control auto-creation of entities for newly discovered devices
- Fixed mypy type errors in scanner.py

### 2.0.8

- Added ZeroTier/VPN Hosts option to probe specific IPs instead of network scanning
- Fixed entity unavailable state on restart when device is offline
- Updated README with ZeroTier/VPN troubleshooting documentation

### 2.0.7

- Introduced a retry of 3 for ARP requests (was 0)
- Set last_seen back in time for known devices that were offline after restart

### 2.0.6

- Fixed issue with ZeroTier interfaces not being detected
- Removed custom config field
- Better IP include/exclude config parsing
- More debug logging for IP include/exclude

### 2.0.5

- Disable unavailable state

### 2.0.4

- Use RestoreEntity to survive reboots/restarts
- Bump ruff from 0.14.10 to 0.14.11 by @dependabot[bot] in #25
- Fix timedelta serialization bug in YAML import by @jleinenbach in #24

### 2.0.3

- Added extra safeguard against possible corrupted config data

### 2.0.2

- You can now set consider_home up to 30 minutes (1800 seconds)

### 2.0.1

- Extended linting, fixed linting bugs, fixed manifext

### 2.0.0

- **Breaking**: Replaced external `arp-scan` command with pure Python (scapy)
- Added GUI configuration flow
- Added YAML migration support
- Added options flow for runtime configuration
- Added vendor lookup via OUI database
- Updated to modern Home Assistant patterns (ScannerEntity, DataUpdateCoordinator)

### 1.x

- Legacy version using external `arp-scan` command
- YAML-only configuration
