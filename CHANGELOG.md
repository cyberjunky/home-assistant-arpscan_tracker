## Changelog

### 2.1.8

- **Breaking**: Requires Home Assistant 2026.3.0 or newer (Python 3.14)
- Added local brand images (`brand/` folder), so the integration icon shows up without the Home Assistant brands repository
- Fixed newly discovered devices being created disabled until the next reload, even with **Enable Found Devices** on
- Fixed Include/Exclude/Hosts options that could not be cleared again once set
- Fixed socket leak when probing interfaces without an IPv4 address

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
