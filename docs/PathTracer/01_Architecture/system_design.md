# System Design

## Overview
PathTracer follows a pipeline architecture with 4 distinct layers:
Lab → Ingestion → Backend → Presentation

Each layer has a single responsibility and communicates with the next
through a defined interface.

---

## Layer 1 — Lab Environment

### Purpose
Generate realistic attack traffic in a controlled, isolated network.
No real systems are targeted. Everything stays inside VMware.

### Components
| Component | Role | Specs |
|-----------|------|-------|
| Kali Linux VM | Attacker | 4GB RAM, 40GB disk |
| Ubuntu 22.04 VM | Victim + IDS | 4GB RAM, 40GB disk |
| VMware Host-Only Network | Isolated network | 192.168.100.0/24 |

### Key Concept — Host-Only Network
A virtual network that exists only inside VMware.
VMs can talk to each other but cannot reach the real internet.
This is critical for safety — attack traffic never leaves your laptop.

### Attack Simulations
| Tool | Attack Type | MITRE Technique |
|------|-------------|-----------------|
| Nmap | Port scan | T1046 - Network Service Discovery |
| Hydra | Brute-force SSH | T1110 - Brute Force |

---

## Layer 2 — Ingestion Pipeline

### Purpose
Read Suricata's output file and transform raw alerts into structured
data that the backend can store and query.

### Key Concept — eve.json
Suricata writes every alert to a file called eve.json.
Each line is a JSON object representing one event.
Example:
```json
{
  "timestamp": "2026-04-04T10:23:11",
  "event_type": "alert",
  "src_ip": "192.168.100.10",
  "dest_ip": "192.168.100.20",
  "alert": {
    "signature": "ET SCAN Nmap",
    "severity": 2
  }
}
```

### Ingestion Script responsibilities
1. Watch eve.json for new lines (tail -f equivalent in Python)
2. Parse each JSON object
3. Filter only event_type = "alert"
4. Insert into Django database via Django ORM

---

## Layer 3 — Backend

### Purpose
Store alerts, correlate them into incidents, enrich with external
data, and expose everything via API endpoints.

### Key Concept — Correlation
Multiple alerts from the same source IP within a time window
(e.g. 5 minutes) are grouped into a single Incident.
This is how we go from 500 raw alerts → 1 meaningful incident.

### Key Concept — Enrichment
Once we know what type of attack occurred, we query:
- NIST NVD API → get CVSS score (numeric risk: 0.0 - 10.0)
- MITRE ATT&CK → get technique ID and description

### Django Models (planned)
| Model | Fields |
|-------|--------|
| Alert | timestamp, src_ip, dest_ip, signature, severity, raw_json |
| Incident | src_ip, start_time, end_time, alert_count, cvss_score, technique_id |
| Host | ip_address, hostname, role, first_seen, last_seen |

---

## Layer 4 — Presentation

### Purpose
Make the data human-readable and actionable.

### Dashboard components
| Component | Technology | Purpose |
|-----------|------------|---------|
| Alert table | HTMX | Live-updating list of alerts |
| Attack map | D3.js or Vis.js | Visual graph of attacker → victim |
| Risk panel | Tailwind | CVSS score + ATT&CK technique |
| AI summary | Claude API | Plain English incident explanation |

### Key Concept — HTMX
Allows the page to update specific sections without a full reload.
When a new alert comes in, only the table refreshes, not the whole page.

### Key Concept — Attack Map
A network graph where:
- Nodes = IP addresses (hosts)
- Edges = alert connections between them
- Color = severity (green → yellow → red)

---

## Data Flow Summary
Kali runs Nmap/Hydra 
↓ 
Ubuntu Suricata detects → writes to eve.json 
↓ 
Python ingestion script reads eve.json 
↓ 
Alert saved to SQLite via Django ORM 
↓ 
Correlation engine groups alerts → Incident created 
↓ 
Enrichment: NIST NVD API + MITRE ATT&CK 
↓ 
Dashboard displays: table + map + risk score 
↓ 
AI generates: incident summary + mitigations

---

## Design Decisions

| Decision | Chosen | Reason |
|----------|--------|--------|
| Database | SQLite | Simple, no server needed, sufficient for lab scale |
| Web framework | Django | Batteries included, ORM, admin panel for free |
| Frontend reactivity | HTMX | Avoids full JS framework complexity |
| Attack map | D3.js/Vis.js | Purpose-built for network graphs |
| AI provider | Claude API | Best instruction-following for structured summaries |
