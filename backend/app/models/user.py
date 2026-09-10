"""User entity - user accounts, authentication details and role assignments."""
from datetime import datetime

from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db

ROLE_ADMINISTRATOR = "Administrator"
ROLE_DEVELOPER = "Developer"
VALID_ROLES = (ROLE_ADMINISTRATOR, ROLE_DEVELOPER)


class User(db.Model):
    __tablename__ = "User"

    UserID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Username = db.Column(db.String(50), unique=True, nullable=False)
    Email = db.Column(db.String(100), unique=True, nullable=False, index=True)
    PasswordHash = db.Column(db.String(255), nullable=False)
    Role = db.Column(db.String(20), nullable=False, default=ROLE_DEVELOPER)
    IsActive = db.Column(db.Boolean, nullable=False, default=True)
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    LastLogin = db.Column(db.DateTime, nullable=True)

    scans = db.relationship(
        "Scan", backref="user", lazy="dynamic", cascade="all, delete-orphan"
    )
    audit_logs = db.relationship(
        "SecurityAuditLog", backref="user", lazy="dynamic"
    )

    # ------------------------------------------------------------- helpers
    def set_password(self, password):
        self.PasswordHash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.PasswordHash, password)

    @property
    def is_administrator(self):
        return self.Role == ROLE_ADMINISTRATOR

    @property
    def is_developer(self):
        return self.Role == ROLE_DEVELOPER

    def to_dict(self, include_private=False):
        data = {
            "UserID": self.UserID,
            "Username": self.Username,
            "Email": self.Email,
            "Role": self.Role,
            "IsActive": self.IsActive,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
            "LastLogin": self.LastLogin.isoformat() if self.LastLogin else None,
        }
        if include_private:
            data["PasswordHash"] = self.PasswordHash
        return data

    def __repr__(self):
        return f"<User {self.Username!r} ({self.Role})>"
