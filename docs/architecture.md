# WolfEye — System Architecture

## Pipeline Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      Threat Feeds (Public)                   │
│                                                             │
│   URLhaus / ThreatFox / MalwareBazaar / Feodo Tracker      │
│   ─ URLs, IPs, domains, hashes                              │
│   ─ Free public feeds; API keys optional                    │
└──────────────────────────┬───────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│       Local Security Agent (opt-in, metadata only)           │
│   email / download / file / network / application events     │
│   POST /api/observations → extract indicators, no raw content│
└──────────────────────────┬───────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│             Ingestion Service (app/services/ingestion.py)    │
│                                                             │
│   1. Fetch public threat feeds                              │
│   2. Normalize → {value, type, source, first_seen}          │
│   3. Deduplicate via UNIQUE(value, type) constraint         │
│   4. Persist to IOC table + write AuditLog                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│            Enrichment Service (app/services/enrichment.py)   │
│                                                             │
│   Queries (per IOC, 24h cache):                             │
│   ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐   │
│   │  VirusTotal  │ │  AbuseIPDB   │ │      Shodan      │   │
│   │  v3 API      │ │  v2 API      │ │   Host Info API  │   │
│   │  detections, │ │  abuse score,│ │  open ports, org │   │
│   │  reputation  │ │  country,ISP │ │  country         │   │
│   └──────────────┘ └──────────────┘ └──────────────────┘   │
│                                                             │
│   Stores parsed fields + raw JSON in Enrichment table       │
│   Graceful fallback if API is down or rate-limited          │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│          Anomaly Scoring (app/ml/predict.py) ← Member B     │
│                                                             │
│   Feature vector: [vt_detections, vt_reputation,           │
│                    abuseipdb_score, num_shodan_ports]       │
│                                                             │
│   Model: Isolation Forest (sklearn, saved as model.joblib)  │
│   Fallback: heuristic scorer when model not present         │
│                                                             │
│   Output: anomaly_score ∈ [0, 1] stored on IOC row         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│           Alerting Service (app/services/alerting.py)        │
│                                                             │
│   score ≥ threshold → create Alert record                   │
│   Severity banding:                                         │
│     [0.60–0.69] Low   [0.70–0.79] Medium                   │
│     [0.80–0.89] High  [0.90+]     Critical                  │
│                                                             │
│   High/Critical → optional email (smtplib)                  │
│   All actions → AuditLog entry                              │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│          REST API Layer (app/routes/)                        │
│                                                             │
│   GET  /api/iocs               paginate, filter, search     │
│   GET  /api/iocs/<id>          detail + enrichment + score  │
│   GET  /api/iocs/export        CSV / JSON export            │
│   POST /api/iocs/<id>/investigate  playbook action (admin)  │
│   POST /api/iocs/<id>/watchlist    playbook action (admin)  │
│   GET  /api/alerts             list with severity filter     │
│   POST /api/alerts/<id>/resolve    resolve alert (admin)     │
│   GET  /api/stats/*            chart data for Member C      │
│   GET  /api/system/health      scheduler + DB status        │
│   GET  /api/system/ping        UptimeRobot liveness probe   │
│                                                             │
│   Auth: session-based                                       │
│     readonly (demo) → all GET endpoints                     │
│     admin           → all endpoints incl. playbooks         │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│        Frontend Dashboard (Member C)                         │
│                                                             │
│   Bootstrap 5 — responsive UI                               │
│   Chart.js — trend / severity / source graphs               │
│   Leaflet.js — geographic threat map                        │
│   WeasyPrint — PDF report generation                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Database Schema

```
┌──────────────────────────────────────────────────────────────┐
│  IOC                                                         │
│  ─────────────────────────────────────────────────────────── │
│  id (PK)  value  type  source  first_seen  created_at        │
│  status   watchlisted  anomaly_score                         │
└──────────────────┬───────────────────────────────────────────┘
                   │ 1:1
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  Enrichment                                                  │
│  ─────────────────────────────────────────────────────────── │
│  id (PK)  ioc_id (FK)  vt_reputation  vt_detections          │
│  abuseipdb_score  abuseipdb_country  abuseipdb_isp           │
│  shodan_ports (JSON)  shodan_org  country                    │
│  raw_vt_json  raw_abuseipdb_json  raw_shodan_json            │
│  last_updated                                                │
└──────────────────────────────────────────────────────────────┘
                   │ 1:N
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  Alert                                                       │
│  ─────────────────────────────────────────────────────────── │
│  id (PK)  ioc_id (FK)  anomaly_score  severity  status       │
│  created_at  updated_at  notes                               │
└──────────────────────────────────────────────────────────────┘
                   │ 1:N
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  AuditLog (append-only)                                      │
│  ─────────────────────────────────────────────────────────── │
│  id (PK)  ioc_id (FK)  action  performed_by  detail          │
│  timestamp                                                   │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  User                                                        │
│  ─────────────────────────────────────────────────────────── │
│  id (PK)  username (UNIQUE)  password_hash  role             │
│  created_at  last_login                                      │
└──────────────────────────────────────────────────────────────┘
```

---

## Infrastructure

```
┌─────────────┐       ┌──────────────────┐      ┌─────────────┐
│   GitHub    │──────▶│  Render (Free)   │◀─────│ UptimeRobot │
│  (main br.) │  CD   │  Web Service     │ ping │ (5 min)     │
└─────────────┘       │  gunicorn        │      └─────────────┘
                      └────────┬─────────┘
                               │
                               ▼
                      ┌──────────────────┐
                      │  Supabase        │
                      │  PostgreSQL      │
                      │  (free 500 MB)   │
                      └──────────────────┘
```

---

## Security Design Decisions

| Concern | Approach |
|---|---|
| Secrets | `.env` in `.gitignore`; `.env.example` with placeholders only |
| Auth | Session-based; demo read-only; admin write; `admin_required` decorator |
| Rate limiting | `flask-limiter` on all write endpoints |
| Input validation | `get_json(silent=True)` + explicit field checks on all POST routes |
| CORS | `flask-cors` with `supports_credentials=True`; restrict origins in prod |
| API keys | Never hardcoded; loaded from `os.getenv()` via `app.config` |
| Local telemetry | Agent token required; only extracted indicators are stored; raw content is not retained |
