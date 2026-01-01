## Changelog

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
