<div align="center">

# 🐺 WolfEye

### AI-Powered Threat Intelligence & Incident Response Platform

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-D71F00?style=for-the-badge&logo=sqlalchemy&logoColor=white)](https://www.sqlalchemy.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)](LICENSE)
[![Render](https://img.shields.io/badge/Deployed%20on-Render-46E3B7?style=for-the-badge&logo=render&logoColor=white)](https://render.com)

_Automate threat detection. Accelerate response. Stay ahead of adversaries._

</div>

---

## Overview

**WolfEye** is an end-to-end, open-source threat intelligence and incident response platform built for security teams that need real-time visibility into malicious infrastructure. It ingests live threat feeds, enriches indicators with leading threat intelligence APIs, applies machine-learning anomaly scoring, and surfaces everything through a live analyst dashboard — all without manual toil.

```
┌─────────────────────────────────────────────────────────────────┐
│                       WolfEye Pipeline                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Threat Feeds          Enrichment           ML Scoring          │
│  ┌──────────┐    ┌───────────────────┐  ┌──────────────────┐   │
│  │ URLhaus  │    │  VirusTotal       │  │ Isolation Forest │   │
│  │ ThreatFox│───▶│  Shodan           │─▶│ Anomaly Scoring  │   │
│  └──────────┘    │  AbuseIPDB        │  └────────┬─────────┘   │
│  Ingest & Dedup  └───────────────────┘           │             │
│                                                  ▼             │
│                         Alerting & Playbooks ◀───┘             │
│                                  │                             │
│                                  ▼                             │
│                    Live Dashboard & PDF Reports                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

| Feature                        | Description                                                           |
| ------------------------------ | --------------------------------------------------------------------- |
| 🔄 **Live Feed Ingestion**     | Automated collection from URLhaus and ThreatFox with deduplication    |
| 🔍 **Multi-Source Enrichment** | VirusTotal, Shodan, and AbuseIPDB reputation lookups per IOC          |
| 🤖 **ML Anomaly Detection**    | Isolation Forest model scores each indicator for novelty and risk     |
| 🚨 **Automated Alerting**      | Severity-based alert generation with optional email notifications     |
| 📖 **Response Playbooks**      | Predefined automated response actions triggered by alert rules        |
| 🗺️ **Geolocation Map**         | Leaflet-powered world map visualizing IOC origins                     |
| 📊 **Analytics Dashboard**     | Real-time charts (Chart.js) for trends, severity mix, and top sources |
| 📄 **PDF Reporting**           | Exportable incident reports via WeasyPrint                            |
| 🔐 **Role-Based Access**       | Admin and read-only demo roles with session-based authentication      |
| 📦 **Audit Trail**             | Full audit log of analyst actions per IOC                             |

---

## 🛠️ Tech Stack

| Layer                | Technology                                               |
| -------------------- | -------------------------------------------------------- |
| **Backend**          | Python 3.11+ · Flask 3.0                                 |
| **ORM / Database**   | SQLAlchemy · SQLite (dev) · PostgreSQL / Supabase (prod) |
| **Machine Learning** | scikit-learn · Isolation Forest                          |
| **Threat Feeds**     | URLhaus · ThreatFox                                      |
| **Enrichment APIs**  | VirusTotal · Shodan · AbuseIPDB                          |
| **Task Scheduling**  | APScheduler                                              |
| **Frontend**         | Bootstrap · Chart.js · Leaflet · Jinja2                  |
| **PDF Export**       | WeasyPrint                                               |
| **Hosting**          | Render (free tier)                                       |
| **Keep-alive**       | UptimeRobot                                              |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11 or higher
- `pip` package manager
- API keys for VirusTotal, Shodan, and AbuseIPDB _(free tiers available)_

### 1 — Clone the repository

```bash
git clone https://github.com/Shadow-Howl-Sec/wolfeye.git
cd wolfeye
```

### 2 — Create and activate a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### 4 — Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and populate your API keys and credentials:

```ini
# Core
FLASK_ENV=development
SECRET_KEY=your-long-random-secret

# Enrichment API Keys
VIRUSTOTAL_API_KEY=your_vt_key
SHODAN_API_KEY=your_shodan_key
ABUSEIPDB_API_KEY=your_abuseipdb_key

# Database (leave blank for SQLite in dev)
DATABASE_URL=
```

### 5 — Seed the database

```bash
python data/seed.py
```

### 6 — Start the development server

```bash
flask run
```

Navigate to **[http://localhost:5000](http://localhost:5000)**

| Account        | Username | Password          |
| -------------- | -------- | ----------------- |
| Read-only demo | `demo`   | `wolfeye-demo`    |
| Admin          | `admin`  | _(set in `.env`)_ |

---

## 📁 Project Structure

```
wolfeye/
├── app/
│   ├── __init__.py         # Flask application factory
│   ├── config.py           # Dev / Prod / Test configuration classes
│   ├── models/             # SQLAlchemy models — IOC, Enrichment, Alert, AuditLog, User
│   ├── routes/             # API blueprints — iocs, alerts, stats, auth, system
│   ├── services/           # Business logic — ingestion, enrichment, alerting, playbooks, scheduler
│   ├── ml/                 # Anomaly scoring interface (model.joblib)
│   ├── templates/          # Jinja2 HTML templates
│   └── static/             # CSS, JavaScript, and static assets
├── data/
│   └── seed.py             # Demo data seed script
├── tests/
│   ├── test_ingestion.py   # Unit tests for ingestion service
│   └── test_api.py         # Smoke tests for API endpoints
├── docs/
│   └── architecture.md     # System architecture reference
├── .env.example            # Environment variable template
├── .gitignore
├── requirements.txt
├── Procfile                # Render deployment entry point
└── README.md
```

---

## 📡 API Reference

### Authentication

| Method | Endpoint           | Description                               |
| ------ | ------------------ | ----------------------------------------- |
| `POST` | `/api/auth/login`  | Authenticate user, returns session cookie |
| `POST` | `/api/auth/logout` | Invalidate session                        |
| `GET`  | `/api/auth/me`     | Retrieve current authenticated user       |

### Indicators of Compromise (IOCs)

| Method   | Endpoint                     | Auth   | Description                                  |
| -------- | ---------------------------- | ------ | -------------------------------------------- |
| `GET`    | `/api/iocs`                  | Public | Paginated list with filters                  |
| `GET`    | `/api/iocs/<id>`             | Public | Single IOC with enrichment and anomaly score |
| `GET`    | `/api/iocs/export`           | Public | Bulk export (CSV or JSON)                    |
| `GET`    | `/api/iocs/<id>/audit`       | Public | Audit trail for an IOC                       |
| `POST`   | `/api/iocs/<id>/investigate` | Admin  | Mark IOC as investigated                     |
| `POST`   | `/api/iocs/<id>/watchlist`   | Admin  | Add IOC to watchlist                         |
| `DELETE` | `/api/iocs/<id>/watchlist`   | Admin  | Remove IOC from watchlist                    |

### Alerts

| Method | Endpoint                   | Auth   | Description                       |
| ------ | -------------------------- | ------ | --------------------------------- |
| `GET`  | `/api/alerts`              | Public | Paginated alert list with filters |
| `GET`  | `/api/alerts/<id>`         | Public | Single alert detail               |
| `POST` | `/api/alerts/<id>/resolve` | Admin  | Mark alert as resolved            |

### Statistics & Analytics

| Method | Endpoint                   | Description                      |
| ------ | -------------------------- | -------------------------------- |
| `GET`  | `/api/stats/summary`       | Aggregate dashboard counters     |
| `GET`  | `/api/stats/trends`        | Daily IOC count trend            |
| `GET`  | `/api/stats/top-countries` | Top countries by IOC volume      |
| `GET`  | `/api/stats/severity-mix`  | Alert distribution by severity   |
| `GET`  | `/api/stats/ioc-type-mix`  | IOC breakdown by type            |
| `GET`  | `/api/stats/top-sources`   | IOC volume by threat feed source |

### System

| Method | Endpoint             | Description                            |
| ------ | -------------------- | -------------------------------------- |
| `GET`  | `/api/system/ping`   | Liveness probe (UptimeRobot heartbeat) |
| `GET`  | `/api/system/health` | Database and scheduler status          |

---

## 🗄️ Database Schema

```
IOC
  id, value, type, source, first_seen, created_at, status, watchlisted, anomaly_score

Enrichment
  id, ioc_id → IOC
  vt_reputation, vt_detections, abuseipdb_score
  shodan_ports [JSON], country
  raw_vt_json, raw_abuseipdb_json, raw_shodan_json
  last_updated

Alert
  id, ioc_id → IOC, anomaly_score, severity, status, created_at, notes

AuditLog
  id, ioc_id → IOC, action, performed_by, detail, timestamp

User
  id, username, password_hash, role, created_at, last_login
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

All tests run against an in-memory SQLite database — no external API calls are made during the test suite.

---

## ☁️ Deployment (Render)

1. **Push to GitHub** — Render auto-deploys on every push to `main`.
2. **Set environment variables** in the Render dashboard (mirror your `.env.example`).
3. **Set `DATABASE_URL`** to your Supabase PostgreSQL connection string.
4. **Seed the database** — SSH into the service or add a one-off job to run `python data/seed.py`.
5. **Configure UptimeRobot** to ping `https://your-app.onrender.com/api/system/ping` every 5 minutes to prevent the free-tier dyno from sleeping.

---

## 🤝 Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or pull request on [GitHub](https://github.com/Shadow-Howl-Sec/wolfeye).

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push and open a Pull Request

---

## 📄 License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for full terms.

> You are free to use, modify, and distribute this software. Modified versions must carry prominent notices of changes. The Apache 2.0 license also provides an express grant of patent rights from contributors.

---

<div align="center">
  <sub>Built with 🧠 by the TECHWOLF</sub>
</div>
