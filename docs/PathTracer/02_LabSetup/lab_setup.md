# Lab Environment Setup

## Network Architecture
- Type: VMware Host-Only Network
- Subnet: 192.168.100.0/24 (assigned by VMware)
- Purpose: Fully isolated attack simulation network

## Virtual Machines

### Attacker — Kali Linux
| Property | Value |
|----------|-------|
| OS | Kali Linux 2025 x64 |
| RAM | 4 GB |
| Disk | 80 GB (dynamic) |
| Network | Host-Only |
| Tools | Nmap, Hydra |
| Role | Simulates threat actor |

### Victim — Ubuntu Server 22.04
| Property | Value |
|----------|-------|
| OS | Ubuntu Server 22.04 LTS |
| RAM | 4 GB |
| Disk | 40 GB |
| Network | Host-Only |
| Services | OpenSSH, Suricata IDS |
| Role | Target + detection layer |

## Key Concept — Why Ubuntu Server?
No GUI needed. Ubuntu Server is lightweight and mirrors
real-world server environments that attackers target.
We only need CLI access via SSH.

## Key Concept — Why Host-Only?
Attack traffic must never reach the real internet.
Host-Only creates a virtual LAN visible only inside VMware.
Both VMs can see each other but nothing outside VMware can
see them, and they cannot reach external networks.

## IPs (to fill after setup)
| Machine         | IP Address      |
| --------------- | --------------- |
| Kali (attacker) | 192.168.12.129  |
| Ubuntu (victim) | 192.168.12.128  |
| Network:        | 192.168.12.0/24 |

## Status
- [x] Kali VM configured (Host-Only, tools verified)
- [x] Ubuntu ISO downloaded
- [x] Ubuntu VM installed
- [x] Network connectivity verified (ping test)
- [x] Suricata installed on Ubuntu
- [x] First alert generated