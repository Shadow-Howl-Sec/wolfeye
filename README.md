# WolfEye

WolfEye is a cross-platform threat-intelligence and incident-response
platform. It provides a Flask API, a SQLite/PostgreSQL data layer, scheduled
threat-feed ingestion, optional MISP/OpenCTI integrations, and a Streamlit
CNN-LSTM dashboard.

## Requirements

- Python 3.11–3.14
- `pip`
- API keys are optional for local testing. Public threat feeds work without
  VirusTotal, Shodan, or AbuseIPDB keys.

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/Shadow-Howl-Sec/wolfeye.git
cd wolfeye
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# Linux/macOS
source .venv/bin/activate
```

If PowerShell blocks activation, run the Windows command directly through the
environment instead of activating it:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Create the environment file:

```powershell
# Windows PowerShell
Copy-Item .env.example .env
```

```bash
# Linux/macOS
cp .env.example .env
```

At minimum, set a production `SECRET_KEY`. For local development, the
application uses SQLite automatically when `DATABASE_URL` is empty.

## Run locally

The cross-platform launcher starts the Flask API and Streamlit dashboard:

```bash
python scripts/run.py all
```

Open:

- API: http://127.0.0.1:5000
- Dashboard: http://127.0.0.1:8501

Stop both services with `Ctrl+C`.

Run one service only:

```bash
python scripts/run.py backend
python scripts/run.py dashboard
```

Use different ports when required:

```bash
python scripts/run.py all --backend-port 5510 --dashboard-port 8510
```

The launcher works on Windows, Linux, and macOS and uses the active Python
interpreter instead of OS-specific `flask.exe` or `streamlit.exe` launchers.

### Manual commands

Backend:

```bash
python -m flask --app "app:create_app('development')" run
```

Dashboard:

```bash
python -m streamlit run app.py
```

The dashboard loads the included model and preprocessing artifacts. Put
`cicids2017_cleaned.csv` in the repository root to enable real-data sample
presets.

## Default accounts

| Account | Username | Password |
| --- | --- | --- |
| Read-only demo | `demo` | `wolfeye-demo` |
| Administrator | `admin` | Set `ADMIN_PASSWORD` in `.env` |

Change these credentials before deploying.

## Configuration

Configuration is read from `.env` or the process environment. Common settings:

```ini
FLASK_ENV=development
SECRET_KEY=change-me
DATABASE_URL=
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
ABUSEIPDB_API_KEY=
LOCAL_INGEST_TOKEN=
MISP_URL=
MISP_KEY=
OPENCTI_URL=
OPENCTI_TOKEN=
```

MISP and OpenCTI are optional. OpenCTI requires its own external services.

## API health checks

```bash
curl http://127.0.0.1:5000/api/system/ping
curl http://127.0.0.1:5000/api/system/health
```

The backend also provides authentication, IOC, alert, statistics, observation,
integration, and report endpoints under `/api`.

Important endpoints:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/login` | Create a session |
| `GET` | `/api/auth/me` | Get the current user |
| `GET` | `/api/iocs` | List indicators |
| `GET` | `/api/alerts` | List alerts |
| `GET` | `/api/stats/summary` | Dashboard summary |
| `POST` | `/api/observations` | Receive metadata-only observations |
| `GET` | `/api/system/ping` | Liveness check |
| `GET` | `/api/system/health` | Database and scheduler status |

## Seed data and tests

Seed local demo data:

```bash
python data/seed.py
```

Run tests:

```bash
python -m pytest tests/ -v
```

## Project structure

```text
app/                  Flask factory, routes, models, services, templates
data/seed.py          Demo data seeder
ml/cnn_lstm/          CNN-LSTM training and inference code
ml/outputs/           Preprocessing artifacts
scripts/run.py        Cross-platform local launcher
.streamlit/           Streamlit configuration
requirements.txt      Application dependencies
.env.example          Environment variable template
```

## Deployment

The included `Procfile` provides a Gunicorn entrypoint for Render or another
WSGI host. Set the production environment variables, including `SECRET_KEY`
and `DATABASE_URL`, in the hosting provider's configuration.

## License

Apache License 2.0. See [LICENSE](LICENSE).
