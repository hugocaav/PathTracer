# Backend Structure

## Framework
Django 6.0.3 — monolithic web framework with built-in ORM,
admin panel, and routing.

## Apps
| App | Purpose |
|-----|---------|
| core | Main app — alerts, incidents, hosts |

## Key Concept — Django Apps
Django projects are divided into "apps" — self-contained modules.
Our `core` app handles everything: models, views, and URLs.
If the project grows, we can split into multiple apps.

## Models (planned)
| Model | Purpose |
|-------|---------|
| Alert | Single IDS alert from Suricata eve.json |
| Incident | Grouped alerts from same source IP |
| Host | Known IP addresses in the network |

## API Endpoints (planned)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| /api/alerts/ | GET | List all alerts |
| /api/incidents/ | GET | List all incidents |
| /api/hosts/ | GET | List all hosts |
| /api/incidents/<id>/summary/ | GET | AI summary for incident |

## Status
- [x] Django project created
- [x] Core app created
- [x] Models defined (Alerts, Incident, Host)
- [x] Database migrated
- [x] Admin panel configured
- [ ] Ingestion script connected
- [ ] API endpoints working