# Suricata IDS Setup

## Installation
- OS: Ubuntu Server 22.04
- Suricata version: 6.0.4
- Installed via: apt install suricata

## Configuration
- Config file: /etc/suricata/suricata.yaml
- Interface: ens33
- HOME_NET: 192.168.0.0/16
- Mode: af-packet (promiscuous)

## Rules
- Source: ET Open (suricata-update)
- Location: /var/lib/suricata/rules/suricata.rules
- Total rules: 49,361
- Custom rules: /var/lib/suricata/rules/custom.rules

## Custom Rules
| SID | Description | Trigger |
|-----|-------------|---------|
| 9000001 | SSH Brute Force Attempt | 5+ SSH attempts in 60s from same IP |

## Alert Output
- File: /var/log/suricata/eve.json
- Format: JSON (one event per line)
- Filter alerts only: event_type = "alert"

## Verified Attacks Detected
| Attack | Tool | Result |
|--------|------|--------|
| Kali hostname detection | DHCP | ✅ Detected |
| SSH Brute Force | Hydra | ✅ Detected |

## Key Commands
```bash
# Start/stop/restart
sudo systemctl restart suricata

# Watch alerts live
sudo tail -f /var/log/suricata/eve.json | grep '"event_type":"alert"'

# Check rules loaded
sudo tail -20 /var/log/suricata/suricata.log | grep "rules"

# Update rules
sudo suricata-update
```