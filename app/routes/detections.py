"""Packet-analysis and threat-response API."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request, session

from app import db
from app.models.block_entry import BlockEntry
from app.models.config_setting import ConfigSetting
from app.models.event_log import EventLog
from app.models.flow_record import FlowRecord
from app.models.ioc import IOC, IOCType
from app.models.threat_detection import ThreatDetection
from app.routes.auth import analyst_required
from app.services.alerting import create_alert_if_needed
from app.services.packet_analysis import PacketValidationError, analyze_packet

detections_bp = Blueprint("detections", __name__, url_prefix="/api/detections")


def _list_version() -> None:
    setting = ConfigSetting.query.filter_by(key="enforcement_list_version").first()
    if setting is None:
        setting = ConfigSetting(key="enforcement_list_version", value="2")
        db.session.add(setting)
    else:
        setting.value = str(int(setting.value or 1) + 1)


@detections_bp.route("/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(silent=True)
    if isinstance(payload, dict) and isinstance(payload.get("packets"), list):
        packets = payload["packets"]
    else:
        packets = [payload]
    if not isinstance(packets, list) or not packets or len(packets) > 100:
        return jsonify({"error": "provide one packet or 1-100 packets"}), 400

    results = []
    for packet in packets:
        try:
            result = analyze_packet(packet)
        except (PacketValidationError, TypeError, ValueError) as exc:
            return jsonify({"error": str(exc)}), 400

        flow = FlowRecord(
            flow_id=str(packet.get("flow_id") or f"packet-{datetime.now(timezone.utc).timestamp()}"),
            src_ip=result.source_ip,
            dst_ip=result.destination_ip,
            ports=f"{result.source_port or ''}->{result.destination_port or ''}",
            protocol=result.protocol,
            features=json.dumps(result.features),
        )
        db.session.add(flow)
        db.session.flush()

        ioc = IOC.query.filter_by(value=result.destination_ip, type=IOCType.IP).first() if result.destination_ip else None
        if ioc is None and result.score >= 0.6 and result.destination_ip:
            ioc = IOC(value=result.destination_ip, type=IOCType.IP, source="packet_analysis",
                      risk_score=result.score, anomaly_score=result.score, score_method="heuristic")
            db.session.add(ioc)
            db.session.flush()
        alert = create_alert_if_needed(ioc, result.score) if ioc and result.score >= 0.6 else None

        detection = ThreatDetection(
            flow_record_id=flow.id,
            alert_id=alert.id if alert else None,
            source_ip=result.source_ip,
            destination_ip=result.destination_ip,
            protocol=result.protocol,
            threat_type=result.threat_type,
            severity=result.severity,
            score=result.score,
            indicators=json.dumps(result.indicators),
            decision="alerted" if alert else "allowed",
        )
        db.session.add(detection)
        db.session.add(EventLog(
            event_type="packet_analysis",
            source_ip=result.source_ip,
            destination=result.destination_ip,
            payload=json.dumps(result.to_dict()),
        ))
        db.session.commit()
        results.append({**result.to_dict(), "detection_id": detection.id, "alert_id": alert.id if alert else None})
    return jsonify({"accepted": len(results), "results": results}), 202


@detections_bp.route("", methods=["GET"])
def list_detections():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 100)
    rows = ThreatDetection.query.order_by(ThreatDetection.created_at.desc()).limit(limit).all()
    return jsonify({"data": [row.to_dict() for row in rows]}), 200


@detections_bp.route("/<int:detection_id>/block", methods=["POST"])
@analyst_required
def block_detection(detection_id: int):
    detection = ThreatDetection.query.get_or_404(detection_id)
    if not detection.destination_ip:
        return jsonify({"error": "detection has no destination IP to block"}), 400
    if detection.blocked:
        return jsonify({"message": "detection is already blocked", "detection": detection.to_dict()}), 200

    data = request.get_json(silent=True) or {}
    ttl = data.get("ttl")
    try:
        ttl_seconds = int(ttl) if ttl is not None else None
    except (TypeError, ValueError):
        return jsonify({"error": "ttl must be an integer number of seconds"}), 400
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds) if ttl_seconds and ttl_seconds > 0 else None
    entry = BlockEntry(
        kind="ip",
        value=detection.destination_ip,
        reason=str(data.get("reason") or f"blocked detection {detection.id}")[:255],
        source="detection",
        created_by=session.get("username", "analyst"),
        expires_at=expires_at,
        related_alert_id=detection.alert_id,
    )
    db.session.add(entry)
    detection.blocked = True
    detection.decision = "blocked"
    _list_version()
    db.session.commit()
    return jsonify({"message": "Threat blocked", "entry": entry.to_dict(), "detection": detection.to_dict()}), 201
