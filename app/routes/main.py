"""Browser-facing pages for the WolfEye dashboard."""

from __future__ import annotations

from flask import Blueprint, render_template

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def dashboard():
    return render_template("dashboard.html")


@main_bp.get("/iocs")
def iocs():
    return render_template("iocs.html")


@main_bp.get("/alerts")
def alerts():
    return render_template("alerts.html")


@main_bp.get("/detections")
def detections():
    return render_template("detections.html")


@main_bp.get("/map")
def map_view():
    return render_template("map.html")


@main_bp.get("/reports")
def reports():
    return render_template("reports.html")


@main_bp.get("/operations")
def operations():
    return render_template("operations.html")


@main_bp.get("/login")
def login():
    return render_template("login.html")
