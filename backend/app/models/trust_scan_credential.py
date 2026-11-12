"""Temporary, organisation-approved credentials for authenticated scans.

Only the encrypted secret is stored.  API serialisation never includes it, and
the plaintext is decrypted in the scan worker for the duration of one login
handshake only.
"""
from datetime import datetime

from app.extensions import db
from app.trust.constants import (
    AUTH_TYPE_FORM,
    CREDENTIAL_APPROVED,
    CREDENTIAL_PENDING,
    CREDENTIAL_USED,
)


class TrustScanCredential(db.Model):
    __tablename__ = "TrustScanCredential"
    __table_args__ = (
        db.ForeignKeyConstraint(
            ["OrganisationID", "ProjectID"],
            ["TrustProject.OrganisationID", "TrustProject.ProjectID"],
            name="fk_trust_credential_project",
            ondelete="NO ACTION",
        ),
        db.ForeignKeyConstraint(
            ["ProjectID", "AssetID"],
            ["TrustAsset.ProjectID", "TrustAsset.AssetID"],
            name="fk_trust_credential_asset",
            ondelete="NO ACTION",
        ),
        db.CheckConstraint(
            "Status IN "
            "('PendingApproval','Approved','Rejected','Revoked','Expired','Used')",
            name="ck_trust_credential_status",
        ),
        db.CheckConstraint(
            "AuthType IN ('FORM')",
            name="ck_trust_credential_auth_type",
        ),
    )

    CredentialID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    OrganisationID = db.Column(db.Integer, nullable=False, index=True)
    ProjectID = db.Column(db.Integer, nullable=False, index=True)
    AssetID = db.Column(db.Integer, nullable=False, index=True)
    Name = db.Column(db.String(100), nullable=False)
    AuthType = db.Column(db.String(10), nullable=False, default=AUTH_TYPE_FORM)

    LoginURL = db.Column(db.String(500), nullable=False)
    UsernameField = db.Column(db.String(64), nullable=True)
    PasswordField = db.Column(db.String(64), nullable=True)
    ExtraFieldsJson = db.Column(db.String(1000), nullable=True)
    SuccessURLContains = db.Column(db.String(255), nullable=True)
    SuccessText = db.Column(db.String(255), nullable=True)

    Username = db.Column(db.String(255), nullable=False)
    SecretEncrypted = db.Column(db.Text, nullable=True)

    Status = db.Column(db.String(20), nullable=False, default=CREDENTIAL_PENDING)
    ExpiresAt = db.Column(db.DateTime, nullable=False)
    CreatedByUserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )
    ApprovedByUserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=True,
    )
    ApprovedAt = db.Column(db.DateTime, nullable=True)
    ApprovalStatementHash = db.Column(db.String(64), nullable=True)
    RejectedAt = db.Column(db.DateTime, nullable=True)
    RevokedAt = db.Column(db.DateTime, nullable=True)
    RevokedByUserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=True,
    )
    StatusReason = db.Column(db.String(500), nullable=True)
    UsedAt = db.Column(db.DateTime, nullable=True)
    LastUsedAt = db.Column(db.DateTime, nullable=True)
    LastTestedAt = db.Column(db.DateTime, nullable=True)
    FailureReason = db.Column(db.String(500), nullable=True)
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    UpdatedAt = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    Version = db.Column(db.Integer, nullable=False, default=1)

    binding = db.relationship(
        "TrustScanCredentialBinding",
        back_populates="credential",
        uselist=False,
        lazy="select",
    )

    @property
    def has_secret(self):
        return bool(self.SecretEncrypted)

    def is_expired(self, now=None):
        now = now or datetime.utcnow()
        return self.ExpiresAt is None or self.ExpiresAt <= now

    def is_available_for_scan(self, now=None):
        return (
            self.Status == CREDENTIAL_APPROVED
            and not self.is_expired(now)
            and self.has_secret
            and self.binding is None
        )

    def is_available_for_retest(self, now=None):
        return (
            self.Status == CREDENTIAL_USED
            and not self.is_expired(now)
            and self.has_secret
            and self.binding is not None
        )

    def to_dict(self):
        return {
            "CredentialID": self.CredentialID,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "AssetID": self.AssetID,
            "Name": self.Name,
            "AuthType": self.AuthType,
            "LoginURL": self.LoginURL,
            "Username": self.Username,
            "Status": self.Status,
            "ExpiresAt": self.ExpiresAt.isoformat() if self.ExpiresAt else None,
            "CreatedByUserID": self.CreatedByUserID,
            "ApprovedByUserID": self.ApprovedByUserID,
            "ApprovedAt": self.ApprovedAt.isoformat() if self.ApprovedAt else None,
            "RejectedAt": self.RejectedAt.isoformat() if self.RejectedAt else None,
            "RevokedAt": self.RevokedAt.isoformat() if self.RevokedAt else None,
            "StatusReason": self.StatusReason,
            "UsedAt": self.UsedAt.isoformat() if self.UsedAt else None,
            "LastTestedAt": (
                self.LastTestedAt.isoformat() if self.LastTestedAt else None
            ),
            "FailureReason": self.FailureReason,
            "BoundScanID": (
                self.binding.ScanID if self.binding is not None else None
            ),
            "HasSecret": self.has_secret,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
        }

    def __repr__(self):
        return f"<TrustScanCredential {self.CredentialID} [{self.Status}]>"


class TrustScanCredentialBinding(db.Model):
    """One credential may be bound to at most one scan (single-use)."""

    __tablename__ = "TrustScanCredentialBinding"

    ScanID = db.Column(
        db.Integer,
        db.ForeignKey("Scan.ScanID", ondelete="CASCADE"),
        primary_key=True,
    )
    CredentialID = db.Column(
        db.Integer,
        db.ForeignKey("TrustScanCredential.CredentialID", ondelete="NO ACTION"),
        nullable=False,
        unique=True,
        index=True,
    )
    BoundAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    credential = db.relationship(
        "TrustScanCredential",
        back_populates="binding",
        lazy="select",
    )

    def to_dict(self):
        return {
            "ScanID": self.ScanID,
            "CredentialID": self.CredentialID,
            "BoundAt": self.BoundAt.isoformat() if self.BoundAt else None,
        }
