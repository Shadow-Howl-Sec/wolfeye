# WolfEye

**AI-powered Threat Intelligence & Incident Response Platform**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What Is WolfEye?

WolfEye automates the work a security analyst does manually: collecting threat indicators, checking reputations, detecting anomalies, raising alerts, and taking basic response actions — all on a live public dashboard.

**End-to-end pipeline:**

```
Threat Feeds (URLhaus, ThreatFox)
        ↓
  Ingestion & Dedup
        ↓
  Enrichment (VirusTotal, Shodan, AbuseIPDB)
        ↓
  Anomaly Scoring (Isolation Forest — Member B)
        ↓
  Alerting & Playbooks (Member A)
        ↓
  Dashboard & Reports (Bootstrap, Chart.js, Leaflet — Member C)
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3 + Flask |
| Database | SQLAlchemy + SQLite (dev) / PostgreSQL/Supabase (prod) |
| ML | scikit-learn Isolation Forest |
| Threat Feeds | URLhaus, ThreatFox |
| Enrichment APIs | VirusTotal, Shodan, AbuseIPDB |
| Scheduling | APScheduler |
| Hosting | Render (free tier) |
| Keep-alive | UptimeRobot |

---

## Quick Start (Local Development)

### 1. Clone & enter repo

```bash
git clone https://github.com/Shadow-Howl-Sec/wolfeye.git
cd wolfeye
```

### 2. Create virtual environment

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set up environment variables

```bash
cp .env.example .env
# Edit .env and add your API keys
```

### 5. Seed the database

```bash
python data/seed.py
```

### 6. Run the development server

```bash
flask run
```

Open [http://localhost:5000](http://localhost:5000)

**Demo login:** `demo` / `wolfeye-demo` (read-only)
**Admin login:** `admin` / *(set in .env)*

---

## Project Structure

```
WolfEye/
├── app/
│   ├── __init__.py         # Flask app factory
│   ├── config.py           # Dev / Prod / Test configs
│   ├── models/             # SQLAlchemy models (IOC, Enrichment, Alert, AuditLog, User)
│   ├── routes/             # API blueprints (iocs, alerts, stats, auth, system)
│   ├── services/           # Business logic (ingestion, enrichment, alerting, playbooks, scheduler)
│   ├── ml/                 # Anomaly scoring interface (Member B fills model.joblib)
│   ├── templates/          # Jinja2 templates (Member C)
│   └── static/             # CSS, JS, assets (Member C)
├── data/
│   └── seed.py             # Demo data seed script
├── tests/
│   ├── test_ingestion.py   # Ingestion unit tests
│   └── test_api.py         # API endpoint smoke tests
├── docs/
│   └── architecture.md     # System architecture diagram
├── .env.example            # Environment variable template
├── .gitignore
├── requirements.txt
├── Procfile                # Render deployment
└── README.md
```

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/login` | Login, returns session cookie |
| POST | `/api/auth/logout` | Clear session |
| GET | `/api/auth/me` | Current user info |

### IOCs

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/iocs` | Public | List with pagination + filters |
| GET | `/api/iocs/<id>` | Public | Single IOC + enrichment + score |
| GET | `/api/iocs/export` | Public | CSV or JSON export |
| GET | `/api/iocs/<id>/audit` | Public | Audit trail |
| POST | `/api/iocs/<id>/investigate` | Admin | Mark investigated |
| POST | `/api/iocs/<id>/watchlist` | Admin | Add to watchlist |
| DELETE | `/api/iocs/<id>/watchlist` | Admin | Remove from watchlist |

### Alerts

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/alerts` | Public | List with filters |
| GET | `/api/alerts/<id>` | Public | Single alert |
| POST | `/api/alerts/<id>/resolve` | Admin | Resolve alert |

### Stats (for charts)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/stats/summary` | Dashboard numbers |
| GET | `/api/stats/trends` | Daily IOC count trend |
| GET | `/api/stats/top-countries` | Top countries by IOC count |
| GET | `/api/stats/severity-mix` | Alerts by severity |
| GET | `/api/stats/ioc-type-mix` | IOCs by type |
| GET | `/api/stats/top-sources` | IOCs by source feed |

### System

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/system/ping` | Liveness probe (UptimeRobot) |
| GET | `/api/system/health` | DB + scheduler status |

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Deployment (Render)

1. Push to GitHub — Render auto-deploys on push to `main`.
2. Set environment variables in the Render dashboard (copy from `.env.example`).
3. Set `DATABASE_URL` to your Supabase PostgreSQL connection string.
4. After first deploy, run seed: SSH into the service or add a one-off job.
5. Set up UptimeRobot to ping `https://your-app.onrender.com/api/system/ping` every 5 minutes.

---

## Member Responsibilities

| Member | Scope |
|---|---|
| **A (this repo)** | Backend, ingestion, enrichment, alerting, playbooks, API, deployment |
| **B** | Isolation Forest model — trains, saves to `app/ml/model.joblib` |
| **C** | Frontend — Bootstrap dashboard, Chart.js, Leaflet map, WeasyPrint PDF |

---

## DB Schema

```
IOC(id, value, type, source, first_seen, created_at, status, watchlisted, anomaly_score)
Enrichment(id, ioc_id→IOC, vt_reputation, vt_detections, abuseipdb_score,
           shodan_ports[JSON], country, raw_*_json, last_updated)
Alert(id, ioc_id→IOC, anomaly_score, severity, status, created_at, notes)
AuditLog(id, ioc_id→IOC, action, performed_by, detail, timestamp)
User(id, username, password_hash, role, created_at, last_login)
```

---

## License

MIT
