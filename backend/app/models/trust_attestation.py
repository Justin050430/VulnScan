"""TrustAuthorizationAttestation - explicit authorisation to test an asset."""
from datetime import datetime

from app.extensions import db
from app.trust.constants import ATTESTATION_ACTIVE, ATTESTATION_STATEMENT_VERSION


class TrustAuthorizationAttestation(db.Model):
    __tablename__ = "TrustAuthorizationAttestation"
    __table_args__ = (
        db.ForeignKeyConstraint(
            ["OrganisationID", "ProjectID"],
            ["TrustProject.OrganisationID", "TrustProject.ProjectID"],
            name="fk_trust_attestation_project",
            ondelete="NO ACTION",
        ),
        db.ForeignKeyConstraint(
            ["ProjectID", "AssetID"],
            ["TrustAsset.ProjectID", "TrustAsset.AssetID"],
            name="fk_trust_attestation_asset",
            ondelete="NO ACTION",
        ),
        db.CheckConstraint(
            "Status IN ('Active','Expired','Revoked')",
            name="ck_trust_attestation_status",
        ),
        db.Index(
            "ux_trust_attestation_active_asset",
            "AssetID",
            unique=True,
            mssql_where=db.text("Status = 'Active'"),
            sqlite_where=db.text("Status = 'Active'"),
        ),
    )

    AttestationID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    OrganisationID = db.Column(db.Integer, nullable=False, index=True)
    ProjectID = db.Column(db.Integer, nullable=False, index=True)
    AssetID = db.Column(db.Integer, nullable=False, index=True)
    AttestedByUserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=False,
    )
    StatementVersion = db.Column(
        db.String(20), nullable=False, default=ATTESTATION_STATEMENT_VERSION
    )
    StatementText = db.Column(db.String(2000), nullable=False)
    StatementHash = db.Column(db.String(64), nullable=False)
    ScopeJson = db.Column(db.String(1000), nullable=True)
    Status = db.Column(db.String(20), nullable=False, default=ATTESTATION_ACTIVE)
    AttestedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ExpiresAt = db.Column(db.DateTime, nullable=False)
    IPAddress = db.Column(db.String(45), nullable=True)
    UserAgentHash = db.Column(db.String(64), nullable=True)
    Reference = db.Column(db.String(255), nullable=True)
    RevokedAt = db.Column(db.DateTime, nullable=True)
    RevokedByUserID = db.Column(
        db.Integer, db.ForeignKey("User.UserID", ondelete="NO ACTION"), nullable=True
    )
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    UpdatedAt = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    Version = db.Column(db.Integer, nullable=False, default=1)

    def is_valid(self, now=None):
        now = now or datetime.utcnow()
        return self.Status == ATTESTATION_ACTIVE and self.ExpiresAt > now

    def to_dict(self):
        return {
            "AttestationID": self.AttestationID,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "AssetID": self.AssetID,
            "AttestedByUserID": self.AttestedByUserID,
            "StatementVersion": self.StatementVersion,
            "StatementHash": self.StatementHash,
            "Status": self.Status,
            "AttestedAt": self.AttestedAt.isoformat() if self.AttestedAt else None,
            "ExpiresAt": self.ExpiresAt.isoformat() if self.ExpiresAt else None,
            "Reference": self.Reference,
            "RevokedAt": self.RevokedAt.isoformat() if self.RevokedAt else None,
        }

    def __repr__(self):
        return f"<TrustAuthorizationAttestation {self.AttestationID} [{self.Status}]>"
