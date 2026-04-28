# PathTracer

AI-powered Intrusion Detection Dashboard for network attack
visualization and incident response.

## Team
- Hugo Cabrera
- Nacim Elias
- Saul Gonzalez
- Gael Rodriguez

## Stack
- **Lab:** Kali Linux, Ubuntu Server, Suricata IDS
- **Backend:** Django, SQLite, SQLAlchemy
- **Frontend:** HTMX, Tailwind CSS, D3.js
- **AI:** Claude/GPT API
- **Data:** NIST NVD API, MITRE ATT&CK

## Setup
Documentation in `/docs`

Run 
python manage.py runserver 0.0.0.0:8000 
to listen on the network.

Add alowed devices via
ALLOWED_HOSTS in settings.py

## Project Structure
```
PathTracer/
├── docs/        # Project documentation (Obsidian vault)
├── backend/     # Django application
├── frontend/    # Templates and static files
└── ingestion/   # Suricata log ingestion scripts
```
