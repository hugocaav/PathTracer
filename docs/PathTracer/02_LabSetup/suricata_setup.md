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
| SID     | Description             | Trigger                             |
| ------- | ----------------------- | ----------------------------------- |
| 9000001 | SSH Brute Force Attempt | 5+ SSH attempts in 60s from same IP |
## Custom Rules (v2)
| SID     | Description             | Classtype              | Priority |
| ------- | ----------------------- | ---------------------- | -------- |
| 9000001 | SSH Brute Force Attempt | attempted-admin        | 1        |
| 9000002 | Nmap SYN Scan           | attempted-recon        | 2        |
| 9000003 | Nmap NULL Scan          | attempted-recon        | 2        |
| 9000004 | Nmap FIN Scan           | attempted-recon        | 2        |
| 9000005 | Nmap XMAS Scan          | attempted-recon        | 2        |
| 9000006 | ICMP Ping Sweep         | attempted-recon        | 2        |
| 9000007 | FTP Brute Force         | attempted-admin        | 1        |
| 9000008 | Telnet Brute Force      | attempted-admin        | 1        |
| 9000009 | HTTP Directory Scan     | web-application-attack | 2        |
| 9000010 | Port Scan Generic       | attempted-recon        | 2        |
| 9000011 | SMB Scan                | attempted-recon        | 2        |
| 9000012 | RDP Scan                | attempted-recon        | 2        |
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