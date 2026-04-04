# PathTracer — Project Overview

## Purpose
A defensive security dashboard that ingests IDS alerts from a controlled
lab environment, correlates them into incidents, visualizes attack paths
on a network map, scores risk using CVSS data, and generates AI-powered
incident summaries with recommended mitigations.

## Problem Statement
Traditional IDS tools generate raw alerts that are difficult to interpret
in context. Analysts must manually correlate alerts across hosts, look up
severity scores, and determine next steps. PathTracer automates this
pipeline and makes internal attack detection clearer and faster.

## Scope
- Controlled lab environment only (no production networks)
- Simulated attacks: port scans (Nmap) and brute-force (Hydra)
- Single attacker VM → Single victim VM
- Local network, no real internet-facing targets

## Core Features
1. Alert ingestion from Suricata IDS (eve.json)
2. Incident correlation by source IP and time window
3. Visual attack map (network graph)
4. Risk scoring via NIST NVD API (CVSS v3)
5. MITRE ATT&CK technique labeling
6. AI-generated incident summary and mitigations

## Tech Stack

### Lab / Attack Simulation
| Tool | Role |
|------|------|
| Kali Linux (VM) | Attacker machine |
| Ubuntu 22.04 (VM) | Victim machine |
| Nmap | Port scan simulation |
| Hydra | Brute-force simulation |
| Suricata IDS | Alert generation on victim |

### Backend
| Tool | Role |
|------|------|
| Django | Web framework + API endpoints |
| SQLite | Local database |
| SQLAlchemy | ORM (optional, Django ORM default) |
| Python scripts | Log ingestion pipeline |

### Data Sources
| Source | Role |
|--------|------|
| Suricata eve.json | Raw IDS alerts |
| NIST NVD API v2.0 | CVSS severity scores |
| MITRE ATT&CK | Technique labeling |

### Frontend
| Tool | Role |
|------|------|
| Django Templates + HTMX | Dynamic dashboard |
| Tailwind CSS | Styling |
| D3.js or Vis.js | Network attack map (graph) |

### AI
| Tool | Role |
|------|------|
| Claude API (or GPT-4o) | Incident summary + mitigations |

## Architecture Summary
Kali VM → [attack traffic] → Ubuntu VM → Suricata → eve.json
→ Ingestion Script → Django + SQLite → Dashboard + AI Summary

## Project Status
- [x] Lab environment setup
- [x] Network connectivity verified
- [x] Suricata installed and configured (49,361 rules)
- [x] First alert generated (Kali hostname detected)
- [x] SSH Brute Force alerts confirmed
- [ ] Backend scaffolding
- [ ] Alert ingestion pipeline
- [ ] Data enrichment (CVSS + ATT&CK)
- [ ] Frontend dashboard
- [ ] AI integration
- [ ] Demo script

## Author
Hugo — UTEP CS / Ethical Hacking
Spring 2026