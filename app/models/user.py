"""
app/models/user.py
-------------------
User — authentication and role-based access control.

Roles:
    readonly  — demo account; can call all GET endpoints
    admin     — full access; can call POST/DELETE playbook endpoints

Schema:
    User(id, username, password_hash, role, created_at, last_login)
"""

from __future__ import annotations

from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from app import db


class UserRole:
    READONLY = "readonly"
    ANALYST = "analyst"
    ADMIN = "admin"


class User(db.Model):
    """Platform user with hashed password and role."""

    __tablename__ = "user"
    __allow_unmapped__ = True

    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(128), unique=True, nullable=False, index=True)
    password_hash: str = db.Column(db.String(256), nullable=False, default="")
    role: str = db.Column(db.String(32), nullable=False, default=UserRole.READONLY)

    created_at: datetime = db.Column(
        db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    last_login: datetime | None = db.Column(db.DateTime(timezone=True), nullable=True)

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------

    def set_password(self, plaintext: str) -> None:
        """Hash and store the password."""
        self.password_hash = generate_password_hash(plaintext)

    def check_password(self, plaintext: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        return check_password_hash(self.password_hash, plaintext)

    # ------------------------------------------------------------------
    # Role helpers
    # ------------------------------------------------------------------

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN

    @property
    def is_analyst(self) -> bool:
        return self.role == UserRole.ANALYST

    @property
    def is_readonly(self) -> bool:
        return self.role == UserRole.READONLY

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role!r}>"
