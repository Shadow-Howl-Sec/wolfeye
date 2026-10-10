"""
app/routes/auth.py
-------------------
Session-based authentication endpoints.

POST /api/auth/login   — accepts username + password, creates session
POST /api/auth/logout  — clears session
GET  /api/auth/me      — returns current session user info

Roles:
    readonly  → demo account; all GET endpoints
    admin     → write endpoints (playbooks, etc.)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import wraps
from typing import Callable

from flask import Blueprint, jsonify, request, session

from app import db
from app.models.user import User

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


# ---------------------------------------------------------------------------
# Decorators (reused by other blueprints)
# ---------------------------------------------------------------------------

def login_required(f: Callable) -> Callable:
    """Require any authenticated session (readonly or admin)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def analyst_required(f: Callable) -> Callable:
    """Require an analyst or admin-role session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        role = session.get("user_role")
        if role not in {"analyst", "admin"}:
            return jsonify({"error": "Analyst or admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


def admin_required(f: Callable) -> Callable:
    """Require an admin-role session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        if session.get("user_role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate a user and create a session.

    Request body (JSON):
        {"username": "...", "password": "..."}

    Returns 200 with user info on success, 401 on bad credentials.
    """
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if user is None or not user.check_password(password):
        logger.warning("Failed login attempt for username=%r", username)
        return jsonify({"error": "Invalid credentials"}), 401

    # Record last login
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()

    session.permanent = True
    session["user_id"] = user.id
    session["username"] = user.username
    session["user_role"] = user.role

    logger.info("User %r logged in (role=%s)", username, user.role)
    return jsonify({"message": "Login successful", "user": user.to_dict()}), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Clear the current session."""
    username = session.pop("username", "unknown")
    session.clear()
    logger.info("User %r logged out", username)
    return jsonify({"message": "Logged out successfully"}), 200


@auth_bp.route("/me", methods=["GET"])
@login_required
def me():
    """Return the currently authenticated user's info."""
    user = User.query.get(session["user_id"])
    if user is None:
        session.clear()
        return jsonify({"error": "User not found"}), 404
    return jsonify({"user": user.to_dict()}), 200
