# WolfEye

> **Inline threat intelligence and response for applications, hosts, and network flows.**

WolfEye is a cross-platform security platform that combines threat-feed ingestion,
indicator enrichment, flow analysis, expert review, and deterministic enforcement.
It can operate as an application middleware layer, a reverse-proxy data-plane
component, or a local host protection service.

The design principle is simple:

- **Threat intelligence and machine learning provide evidence.**
- **Human experts decide what to do with suspicious activity.**
- **Only explicit blocklists and rate-based abuse rules block automatically.**

This separation prevents an uncertain model prediction from becoming an
unreviewed production outage.

---

## Contents

- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Decision model](#decision-model)
- [Deployment modes](#deployment-modes)
- [Web console](#web-console)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [API overview](#api-overview)
- [Packet capture and flow ML](#packet-capture-and-flow-ml)
- [Security and privacy boundaries](#security-and-privacy-boundaries)
- [Development](#development)
- [Project layout](#project-layout)
- [Production guidance](#production-guidance)
- [License](#license)

---

## Capabilities

### Inline request enforcement

WolfEye evaluates request metadata before it reaches the protected application.
It can inspect source IPs, destination information, hosts, URLs, ports, protocol
metadata, request paths, and flow statistics when those values are visible to the
selected deployment mode.

### Threat intelligence

The platform supports:

- Local IOC storage and deduplication.
- URLhaus, ThreatFox, MalwareBazaar, and Feodo Tracker ingestion.
- Optional VirusTotal, AbuseIPDB, and Shodan enrichment.
- Optional MISP and OpenCTI synchronization.
- Risk scoring, anomaly scoring, alerts, and audit records.

### Expert review

Suspicious but non-DoS activity is allowed through immediately and can be placed
in the review queue. An analyst or administrator can then:

- Block an IP, CIDR range, domain, or URL prefix.
- Clear the item and optionally create an allowlist entry.
- Apply an optional expiry time.
- Record a reason and retain an auditable decision trail.

### Automated abuse protection

The local sliding-window rate engine detects repeated requests and connection
abuse from a source. Rate violations can be blocked automatically, with
escalating block durations.

### Live flow analysis

The packet-capture module accumulates the complete 52-feature CICIDS2017 flow
vector expected by the existing CNN-LSTM model. Payloads are not stored or
submitted to the model.

---

## Architecture

```text
                         ┌─────────────────────────┐
                         │      WolfEye Console    │
                         │ alerts · review · lists │
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │       Control plane     │
                         │ Flask API · SQLite/SQL  │
                         │ feeds · enrichment · ML │
                         └────────────┬────────────┘
                                      │ list snapshots
                                      │ alerts / telemetry
┌───────────────┐       ┌────────────▼────────────┐       ┌───────────────┐
│ Client / host │──────▶│      Inline data plane  │──────▶│ Protected app │
└───────────────┘       │ gateway · middleware    │       └───────────────┘
                        │ host capture · rate     │
                        └─────────────────────────┘
```

The control plane manages intelligence, persistence, review, and reporting. The
data plane performs the low-latency decision that is safe to make synchronously.
This separation allows the data plane to continue using its last known
enforcement snapshot when control-plane synchronization is delayed.

---

## Decision model

WolfEye uses the following precedence:

| Signal | Immediate result | Requires expert review |
|---|---|---|
| Active IP, CIDR, domain, or URL-prefix blocklist match | Block | No |
| Repeated-request or connection rate violation | Block automatically | No |
| Threat-intelligence match | Allow and alert | Yes |
| Advisory ML result | Allow and alert | Yes |
| Shadow ML result | Allow and log | No |
| No signal | Allow | No |

`DRY_RUN=true` changes an automatic rate/blocklist rejection into a recorded
would-block decision. It does not change expert review behavior.

The CNN-LSTM is trained on CICIDS2017 lab traffic. Live traffic is therefore
treated as a domain-shifted input and starts in `shadow` mode. Evaluate locally
captured benign traffic before enabling `advisory` mode. Even in advisory mode,
the model cannot block traffic by itself.

---

## Deployment modes

### 1. Reverse-proxy gateway

Place the gateway in front of an application. The gateway owns the request
boundary and can inspect URLs and request metadata when it terminates TLS.
Configure:

```ini
NODE_MODE=gateway
UPSTREAM_URLS=http://127.0.0.1:5000
LISTEN_HOST=0.0.0.0
LISTEN_PORT=8080
INLINE_ENABLED=true
```

### 2. Flask middleware

Wrap a Flask WSGI application with `FlaskInlineMiddleware`:

```python
from app.services.inline import FlaskInlineMiddleware, build_policy

application.wsgi_app = FlaskInlineMiddleware(
    application.wsgi_app,
    build_policy(application.config),
    mode="middleware",
    node_id="app-node-01",
)
```

This is the first supported in-application integration target. TLS must terminate
at the application or middleware layer for full URL visibility.

### 3. Local host mode

Use host mode for personal protection or a single-machine deployment. It combines
the local inline adapter with optional packet capture:

```ini
NODE_MODE=host
INLINE_ENABLED=true
CAPTURE_ENABLED=true
CAPTURE_INTERFACE=
CAPTURE_FILTER=
```

Capture is disabled by default. Enable it only after reviewing operating-system
permissions and the privacy requirements of the environment.

---

## Web console

Start the backend and open:

```text
http://127.0.0.1:5000/login
```

The console includes:

- **Dashboard** — operational posture and node telemetry.
- **IOCs** — searchable indicator inventory and exports.
- **Alerts** — prioritized threat alerts with review handoff.
- **Packet detections** — metadata-only flow detections and analyst blocking.
- **Operations** — health, deployment status, review decisions, enforcement-list
  management, and interactive flow analysis.
- **Threat map** — geographic threat context where available.
- **Reports** — CSV, JSON, and incident-report exports.

Write actions require an analyst or administrator session. Read-only users can
inspect data without modifying enforcement state.

---

## Quick start

### Requirements

- Python 3.11–3.14.
- `pip`.
- Elevated packet-capture privileges only if capture is enabled.

### Install

```bash
git clone https://github.com/Shadow-Howl-Sec/wolfeye.git
cd wolfeye
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Linux/macOS:

```bash
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env
```

Set a strong production `SECRET_KEY` and replace the default administrator
password before exposing the service.

### Run

Run both the Flask API and Streamlit dashboard:

```bash
python scripts/run.py all
```

Run one service:

```bash
python scripts/run.py backend
python scripts/run.py dashboard
```

The launcher uses the active Python interpreter and works on Windows, Linux,
and macOS.

### Health checks

```bash
curl http://127.0.0.1:5000/api/system/ping
curl http://127.0.0.1:5000/api/system/health
```

---

## Configuration

Copy [.env.example](.env.example) to `.env`. The most important settings are:

| Variable | Purpose | Default |
|---|---|---|
| `NODE_MODE` | `gateway`, `middleware`, or `host` | `gateway` |
| `INLINE_ENABLED` | Enable inline WSGI enforcement | `false` |
| `BLOCKING_ENABLED` | Permit automatic enforcement responses | `true` |
| `DRY_RUN` | Record would-block decisions without rejecting | `false` |
| `RATE_LIMIT_REQUESTS` | Requests allowed per source in the window | `100` |
| `RATE_LIMIT_CONNECTIONS` | New connections allowed per source | `50` |
| `RATE_WINDOW_SECONDS` | Sliding-window size | `10` |
| `FLOW_MODEL_MODE` | `shadow` or `advisory` | `shadow` |
| `CAPTURE_ENABLED` | Enable optional packet capture | `false` |
| `CAPTURE_INTERFACE` | Capture interface name | empty |
| `CAPTURE_FILTER` | Optional BPF capture filter | empty |
| `OWN_NETWORKS` | Networks excluded from rate enforcement | RFC1918/loopback defaults |
| `CONTROL_PLANE_URL` | Remote control-plane endpoint for nodes | empty |
| `NODE_TOKEN` | Node authentication token | empty |

Threat-intelligence integrations are optional. Configure only the providers
required by the deployment:

```ini
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
MISP_URL=
MISP_KEY=
OPENCTI_URL=
OPENCTI_TOKEN=
```

Do not commit `.env` or any credential-bearing configuration.

---

## API overview

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/auth/login` | Start a session |
| `POST` | `/api/auth/logout` | End a session |
| `GET` | `/api/auth/me` | Inspect the current user |
| `GET` | `/api/system/health` | Database, scheduler, and data-plane status |
| `GET` | `/api/iocs` | Search and list indicators |
| `GET` | `/api/alerts` | List alerts with filters and pagination |
| `POST` | `/api/review/alerts/<id>` | Add an alert to expert review |
| `GET` | `/api/review` | List review items |
| `POST` | `/api/review/<id>/block` | Apply an expert block decision |
| `POST` | `/api/review/<id>/clear` | Clear an item and optionally allow it |
| `GET` | `/api/enforcement/lists` | Fetch blocklist and allowlist snapshots |
| `POST` | `/api/enforcement/blocks` | Create a block entry |
| `POST` | `/api/enforcement/allows` | Create an allow entry |
| `POST` | `/api/detections/analyze` | Analyze one flow or a batch of flows |
| `GET` | `/api/detections` | List recent packet detections |
| `POST` | `/api/observations` | Ingest metadata-only host observations |

Packet analysis accepts metadata such as source/destination IP, protocol, ports,
packet count, byte count, duration, and TCP flags. Request bodies and packet
payloads are intentionally outside the API contract.

---

## Packet capture and flow ML

The live flow accumulator emits the 52 model features defined by the
CICIDS2017 preprocessing artifact, including:

- Packet and byte counts.
- Forward and backward packet-length statistics.
- Flow and direction-specific rates.
- Inter-arrival-time statistics.
- TCP flags and header lengths.
- Window sizes and active/idle timing metrics.

The model artifacts are loaded lazily. A missing or invalid model artifact is an
operational error and should be fixed before enabling advisory mode; it is not
converted into an automatic block decision.

### Required permissions

Packet capture requires elevated access:

- **Linux:** root or `CAP_NET_RAW`.
- **Windows:** Administrator privileges and Npcap.
- **macOS:** appropriate BPF access.

### Visibility with encryption

For encrypted pass-through traffic, WolfEye can generally observe only IP
addresses, ports, SNI, and flow statistics. URLs and payloads are available only
when the gateway or middleware terminates TLS itself.

### DDoS boundary

A volumetric attack that saturates the network link cannot be stopped by software
running behind that same saturated link. WolfEye addresses application-level
floods, repeated-request abuse, and inline request decisions. Upstream network
or provider-level DDoS protection is required for link saturation.

---

## Security and privacy boundaries

- Request and packet bodies are not persisted by the metadata-only paths.
- Sensitive query parameters and headers are redacted by the event model.
- ML output never creates an automatic block.
- Allowlist and blocklist changes are authenticated and auditable.
- The default model mode is `shadow`.
- Local capture is opt-in and requires explicit OS privileges.
- Production deployments should use HTTPS, a strong secret key, non-default
  credentials, restricted database access, and a persistent rate-limit store.

Review and validate `TRUSTED_PROXIES` before relying on forwarded client IP
headers. An incorrect proxy trust configuration can cause rate limits and
enforcement decisions to be applied to the wrong source address.

---

## Development

Run the focused test suite:

```bash
python -m unittest tests.test_core tests.test_packet_analysis tests.test_inline -v
```

Run the full test suite when `pytest` is installed:

```bash
python -m pytest tests/ -v
```

Before opening a pull request:

1. Run the tests.
2. Compile the Python packages:

   ```bash
   python -m compileall -q core app tests
   ```

3. Verify the configured deployment mode and model mode.
4. Confirm no secrets or local databases are included in the change.
5. Test both analyst decisions and automatic rate-limit behavior.

---

## Project layout

```text
app/
  models/                 SQLAlchemy persistence models
  routes/                 Flask API and browser routes
  services/               ingestion, enrichment, alerting, capture, and inline services
  templates/              dashboard and operations UI
  static/                 JavaScript and CSS assets
core/
  events.py               validated, redacted telemetry events
  inline.py               shared inline decision policy
  lists.py                atomic enforcement-list matcher
  rate.py                 sliding-window rate engine
ml/cnn_lstm/
  saved_model/            CNN-LSTM artifact
  predict.py              production inference adapter
  preprocess.py           CICIDS2017 feature preprocessing
tests/                    unit and behavior tests
scripts/run.py            cross-platform local launcher
```

---

## Production guidance

For a company deployment:

1. Place the control plane behind HTTPS and an authenticated network boundary.
2. Run the data plane close to the protected application.
3. Keep `FLOW_MODEL_MODE=shadow` until locally captured benign traffic has been
   evaluated.
4. Configure a persistent database and rate-limit storage.
5. Define safe networks, health sources, and control-plane addresses carefully.
6. Establish an analyst on-call process for the review queue.
7. Use upstream DDoS protection for volumetric network attacks.
8. Monitor `/api/system/health`, scheduler errors, list version drift, and
   model evaluation results.

For personal use, begin with host mode, keep capture disabled until permissions
are understood, and use `DRY_RUN=true` to validate enforcement behavior before
rejecting traffic.

---

## License

WolfEye is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
