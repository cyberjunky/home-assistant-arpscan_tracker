[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg)](https://github.com/custom-components/hacs) [![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/) [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/cyberjunkynl/)

# Arpscan Device Tracker Component
This is a Custom Component for Home-Assistant (https://home-assistant.io) that tracks devices using the arp-scan linux command, it's very fast, and reasonably accurate.

{% if not installed %}

## Installation

- Install this integration using HACS.
- Configure using configuration instructions below.
- Restart Home-Assistant.

{% endif %}

## Usage
To use this component in your installation, add the following to your `configuration.yaml` file:

```yaml
# Example configuration.yaml entry

device_tracker:
  - platform: arpscan_tracker
    interval_seconds: 15
    consider_home: 60
    track_new_devices: true
    exclude:
      - 192.168.178.1
      - 192.168.178.3
```

Configuration variables:

- **interval_seconds** (*Optional*) Seconds between each scan for new devices. (default = 12)
- **consider_home** (*Optional*): Seconds to marking device as 'not home' after not being seen (default = 180)
- **track_new_device** (*Optional*): If new discovered devices are tracked by default. (default = True)
- **exclude** (*Optional*): List of IP addresses to skip tracking for.
- **scan_options** (*Optional*): Configurable scan options for arp-scan. (default is `-l -g -t1 -q`)

## Network adapter
Sometimes your host has more than one network adapter (on Hass.io for example),
and you need to figure out which one to use for the scans, you can specify the correct one using scan_options.

Examples:
```yaml
scan_options: " --interface=enp2s0 192.168.178.0/24 -g"
```
LAN interface:
```yaml
scan_options: " --interface=eth0 192.168.1.0/24 -g"
```

## Donation
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/cyberjunkynl/)
