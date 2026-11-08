"""TrustAsset - registered hostname and its verification state."""
from datetime import datetime

from app.extensions import db
from app.trust.constants import ASSET_UNVERIFIED


class TrustAsset(db.Model):
    __tablename__ = "TrustAsset"
    __table_args__ = (
        db.UniqueConstraint(
            "ProjectID", "Hostname", name="uq_trust_asset_project_hostname"
        ),
        db.UniqueConstraint(
            "ProjectID", "AssetID", name="uq_trust_asset_project_asset"
        ),
        db.ForeignKeyConstraint(
            ["OrganisationID", "ProjectID"],
            ["TrustProject.OrganisationID", "TrustProject.ProjectID"],
            name="fk_trust_asset_project",
            ondelete="NO ACTION",
        ),
        db.CheckConstraint(
            "VerificationStatus IN "
            "('Unverified','PendingVerification','Verified','Expired','Revoked')",
            name="ck_trust_asset_verification_status",
        ),
        db.CheckConstraint(
            "VerificationMethod IS NULL OR VerificationMethod IN ('DNS_TXT','WEB_FILE')",
            name="ck_trust_asset_verification_method",
        ),
    )

    AssetID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    OrganisationID = db.Column(db.Integer, nullable=False, index=True)
    ProjectID = db.Column(db.Integer, nullable=False, index=True)
    Hostname = db.Column(db.String(253), nullable=False)
    Scheme = db.Column(db.String(10), nullable=False, default="https")
    VerificationStatus = db.Column(
        db.String(24), nullable=False, default=ASSET_UNVERIFIED
    )
    VerificationMethod = db.Column(db.String(10), nullable=True)
    VerificationTokenHash = db.Column(db.String(64), nullable=True)
    VerificationTokenExpiresAt = db.Column(db.DateTime, nullable=True)
    VerifiedAt = db.Column(db.DateTime, nullable=True)
    VerificationExpiresAt = db.Column(db.DateTime, nullable=True)
    VerificationEvidence = db.Column(db.String(1000), nullable=True)
    LastVerificationIP = db.Column(db.String(45), nullable=True)
    VerifiedByUserID = db.Column(
        db.Integer, db.ForeignKey("User.UserID", ondelete="NO ACTION"), nullable=True
    )
    RevokedAt = db.Column(db.DateTime, nullable=True)
    RevokedByUserID = db.Column(
        db.Integer, db.ForeignKey("User.UserID", ondelete="NO ACTION"), nullable=True
    )
    CreatedByUserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    UpdatedAt = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    Version = db.Column(db.Integer, nullable=False, default=1)

    def is_currently_verified(self, now=None):
        now = now or datetime.utcnow()
        return (
            self.VerificationStatus == "Verified"
            and self.VerificationExpiresAt is not None
            and self.VerificationExpiresAt > now
        )

    def to_dict(self):
        return {
            "AssetID": self.AssetID,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "Hostname": self.Hostname,
            "Scheme": self.Scheme,
            "VerificationStatus": self.VerificationStatus,
            "VerificationMethod": self.VerificationMethod,
            "VerifiedAt": self.VerifiedAt.isoformat() if self.VerifiedAt else None,
            "VerificationExpiresAt": (
                self.VerificationExpiresAt.isoformat()
                if self.VerificationExpiresAt else None
            ),
            "VerificationEvidence": self.VerificationEvidence,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
        }

    def __repr__(self):
        return f"<TrustAsset {self.Hostname!r} [{self.VerificationStatus}]>"
