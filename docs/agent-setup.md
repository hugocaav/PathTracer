# Agent Host Setup

Steps required before an external host can POST to `/api/ingest/alerts/`.
See [`api-ingest-endpoint.md`](./api-ingest-endpoint.md) for the API contract itself.

## 1. PathTracer server: bind to a non-loopback interface

Default `runserver 127.0.0.1:8000` won't accept connections from other hosts. Choose one:

```bash
# Quick lab option — bind to all interfaces
INGEST_ALLOWED_IPS="192.168.12.128" python manage.py runserver 0.0.0.0:8000

# Production-ish option — gunicorn behind a proper bind
gunicorn pathtracer.wsgi --bind 0.0.0.0:8000
```

## 2. PathTracer server: fix `ALLOWED_HOSTS`

Currently `backend/pathtracer/settings.py:29` is `ALLOWED_HOSTS = []`. With `DEBUG=True` this works because Django auto-allows local addresses, but the agent will be POSTing using the server's LAN IP/hostname in the `Host:` header, so you must add it:

```python
ALLOWED_HOSTS = ["192.168.12.10", "pathtracer.lab", "localhost", "127.0.0.1"]
```

Or read from env:

```python
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "localhost").split(",") if h.strip()]
```

## 3. PathTracer server: configure the IP allowlist

```bash
export INGEST_ALLOWED_IPS="192.168.12.128,192.168.12.129"   # one entry per agent host
# or for early testing only:
export INGEST_ALLOWED_IPS="*"
```

Empty/unset = 403 for everything. The view reads `request.META["REMOTE_ADDR"]` directly — it does **not** trust `X-Forwarded-For`. If you put a reverse proxy in front later, this needs to change.

## 4. PathTracer server: open the firewall

```bash
# macOS — System Settings → Privacy & Security → Firewall, allow Python/gunicorn
# Linux example:
sudo ufw allow from 192.168.12.0/24 to any port 8000 proto tcp
```

## 5. Verify reachability from the agent host

Before installing anything, just confirm the path works end-to-end:

```bash
# from the agent host
curl -v http://192.168.12.10:8000/api/ingest/alerts/   # expect 405 (GET not allowed)
curl -X POST http://192.168.12.10:8000/api/ingest/alerts/ \
  -H "Content-Type: application/json" \
  -d '{"events":[]}'                                    # expect 200 with all-zero counts
```

If you get a connection timeout → firewall. `Connection refused` → wrong bind address. `400 Bad Request: ALLOWED_HOSTS` → step 2. `403 ip not allowed` → step 3.

## 6. Agent host: prerequisites

```bash
# Python 3.9+ and requests
python3 -m pip install requests

# Suricata is producing eve.json
sudo systemctl status suricata
ls -la /var/log/suricata/eve.json

# The user that will run the agent needs read access on eve.json
# Default Suricata perms are 0640 root:suricata — add the agent user to suricata group:
sudo usermod -aG suricata <agent-user>
# Verify:
sudo -u <agent-user> head -1 /var/log/suricata/eve.json

# Writable state directory for offset tracking
sudo mkdir -p /var/lib/suricata-agent
sudo chown <agent-user>: /var/lib/suricata-agent
```

## 7. Agent host: deploy and run the agent script

Drop the script (the one in [`api-ingest-endpoint.md`](./api-ingest-endpoint.md)) somewhere like `/opt/suricata-agent/agent.py`, set `INGEST_URL` to the server, then run it. Once it works in the foreground, install as a systemd unit so it survives reboots:

```ini
# /etc/systemd/system/suricata-agent.service
[Unit]
Description=PathTracer Suricata reporter agent
After=network.target suricata.service

[Service]
Type=simple
User=<agent-user>
ExecStart=/usr/bin/python3 /opt/suricata-agent/agent.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now suricata-agent
sudo journalctl -u suricata-agent -f
```

## 8. Watch the trace on the server side (while the temp `[INGEST]` logging is in)

In the same terminal where `runserver` is running, you'll see lines like:

```
[INGEST] hit  remote=192.168.12.128 body_bytes=2310
[INGEST.svc] validate  valid=14 invalid=0 src_ips=[...]
[INGEST.svc] bulk_create  alerts=14 skipped_dup=0
[INGEST.svc]   correlate NEW  incident_id=11 src_ip=... family=brute_force ...
[INGEST.svc]   enrich  incident_id=11  ('', 'brute_force', None) -> ('T1110.001', ..., 7.5)
[INGEST] done  {'received': 14, 'stored': 14, ...}
```

That's how you confirm the first real agent batch arrived end-to-end. Once you trust it, strip the `[INGEST]` and `[INGEST.svc]` prints from `views.py` and `services/ingestion.py`.

## Order to actually do it in

1. Set `ALLOWED_HOSTS` (one-line settings change) and start the server bound to `0.0.0.0` with `INGEST_ALLOWED_IPS` set.
2. From the agent host: `curl -X POST .../api/ingest/alerts/ -d '{"events":[]}'` and confirm `200`. **Stop and fix here if it doesn't work** — nothing past this point will succeed otherwise.
3. Manually POST one real alert dict you grep out of `eve.json` and confirm it shows up in the dashboard.
4. Only then deploy the long-running agent script + systemd unit.

The first three steps are the ones that catch 95% of the integration problems.
