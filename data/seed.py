"""
data/seed.py
-------------
Populate the database with realistic demo IOCs so the WolfEye dashboard
is never empty when opened by an external visitor (panel, recruiter).

Usage:
    python data/seed.py

The script is idempotent — running it multiple times will not create
duplicate records (unique constraint on value+type).
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import choice, randint, uniform

# Ensure the project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models.ioc import IOC, IOCType, IOCStatus
from app.models.enrichment import Enrichment
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.audit_log import AuditLog, AuditAction


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAMPLE_IPS = [
    "185.220.101.45", "62.233.50.246", "91.92.136.80", "194.165.16.29",
    "45.33.32.156",   "192.241.220.70", "104.21.37.252", "198.199.119.17",
    "178.128.34.89",  "159.89.214.31",  "206.81.4.25",  "143.110.250.183",
]

SAMPLE_DOMAINS = [
    "update-flash-player.xyz", "login-secure-bank.ru", "paypal-verify.cc",
    "download-malware.top",    "phishing-site.net",    "ransomware-c2.pw",
    "trojan-drop.ru",          "botnet-ctrl.xyz",
]

SAMPLE_URLS = [
    "http://malicious-cdn.ru/payload.exe",
    "http://phishing.xyz/fake-login.html",
    "http://evil-drop.pw/stage2.ps1",
    "http://c2-server.ru/beacon",
    "http://ransomware.top/decrypt-key.php",
]

SAMPLE_HASHES = [
    "5d41402abc4b2a76b9719d911017c592",  # md5
    "aaf4c61ddcc5e8a2dabede0f3b482cd9",
    "9f86d081884c7d659a2feaa0c55ad015",
    "098f6bcd4621d373cade4e832627b4f6",
]

COUNTRIES = ["US", "CN", "RU", "NL", "DE", "BR", "KR", "IN", "FR", "UA"]
SOURCES = ["urlhaus", "threatfox", "manual"]
ISPS = ["AS-CHOOPA", "Digital Ocean", "Hetzner", "OVH", "Linode", "Vultr", "Amazon AWS"]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

def _random_dt(days_back: int = 30) -> datetime:
    offset = timedelta(seconds=randint(0, days_back * 86400))
    return datetime.now(timezone.utc) - offset


def generate_seed_iocs() -> list[dict]:
    iocs = []

    for ip in SAMPLE_IPS:
        iocs.append({
            "value": ip, "type": IOCType.IP, "source": choice(SOURCES),
            "first_seen": _random_dt(30), "status": choice([IOCStatus.NEW, IOCStatus.INVESTIGATED]),
            "anomaly_score": round(uniform(0.3, 0.99), 4),
            "enrichment": {
                "vt_reputation": -randint(0, 80),
                "vt_detections": randint(0, 60),
                "vt_total_engines": 90,
                "abuseipdb_score": randint(0, 100),
                "abuseipdb_country": choice(COUNTRIES),
                "abuseipdb_isp": choice(ISPS),
                "shodan_ports": json.dumps([22, 80, 443, randint(1024, 9999)]),
                "shodan_org": choice(ISPS),
                "shodan_country": choice(COUNTRIES),
                "country": choice(COUNTRIES),
            },
        })

    for domain in SAMPLE_DOMAINS:
        iocs.append({
            "value": domain, "type": IOCType.DOMAIN, "source": choice(SOURCES),
            "first_seen": _random_dt(20), "status": IOCStatus.NEW,
            "anomaly_score": round(uniform(0.4, 0.95), 4),
            "enrichment": {
                "vt_reputation": -randint(5, 90),
                "vt_detections": randint(1, 70),
                "vt_total_engines": 90,
                "country": choice(COUNTRIES),
            },
        })

    for url in SAMPLE_URLS:
        iocs.append({
            "value": url, "type": IOCType.URL, "source": "urlhaus",
            "first_seen": _random_dt(10), "status": IOCStatus.NEW,
            "anomaly_score": round(uniform(0.55, 0.99), 4),
            "enrichment": {
                "vt_reputation": -randint(10, 100),
                "vt_detections": randint(5, 80),
                "vt_total_engines": 90,
                "country": choice(COUNTRIES),
            },
        })

    for h in SAMPLE_HASHES:
        iocs.append({
            "value": h, "type": IOCType.HASH, "source": "threatfox",
            "first_seen": _random_dt(7), "status": IOCStatus.NEW,
            "anomaly_score": round(uniform(0.6, 0.99), 4),
            "enrichment": {
                "vt_reputation": -randint(20, 100),
                "vt_detections": randint(10, 90),
                "vt_total_engines": 90,
            },
        })

    return iocs


# ---------------------------------------------------------------------------
# Seed runner
# ---------------------------------------------------------------------------

def seed() -> None:
    from sqlalchemy.exc import IntegrityError

    data = generate_seed_iocs()
    inserted = 0
    skipped = 0

    for entry in data:
        enr_data = entry.pop("enrichment", {})
        try:
            ioc = IOC(
                value=entry["value"],
                type=entry["type"],
                source=entry["source"],
                first_seen=entry["first_seen"],
                status=entry.get("status", IOCStatus.NEW),
                anomaly_score=entry.get("anomaly_score"),
            )
            db.session.add(ioc)
            db.session.flush()

            if enr_data:
                enr = Enrichment(ioc_id=ioc.id, **{k: v for k, v in enr_data.items() if hasattr(Enrichment, k)})
                db.session.add(enr)

            # Create alert for high-scoring IOCs
            score = entry.get("anomaly_score") or 0
            if score >= 0.60:
                severity = AlertSeverity.from_score(score)
                alert = Alert(
                    ioc_id=ioc.id,
                    anomaly_score=score,
                    severity=severity,
                    status=choice([AlertStatus.OPEN, AlertStatus.OPEN, AlertStatus.RESOLVED]),
                    created_at=entry["first_seen"],
                )
                db.session.add(alert)

            log = AuditLog(ioc_id=ioc.id, action=AuditAction.INGESTED, performed_by="seed_script")
            db.session.add(log)
            inserted += 1
        except IntegrityError:
            db.session.rollback()
            skipped += 1

    db.session.commit()
    print(f"Seed complete — inserted={inserted} skipped={skipped}")


if __name__ == "__main__":
    app = create_app("development")
    with app.app_context():
        seed()
