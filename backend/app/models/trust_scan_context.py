"""TrustScanContext - binds an existing core Scan to the Trust Boundary."""
from datetime import datetime

from app.extensions import db


class TrustScanContext(db.Model):
    __tablename__ = "TrustScanContext"
    __table_args__ = (
        db.ForeignKeyConstraint(
            ["OrganisationID", "ProjectID"],
            ["TrustProject.OrganisationID", "TrustProject.ProjectID"],
            name="fk_trust_scan_context_project",
            ondelete="NO ACTION",
        ),
        db.ForeignKeyConstraint(
            ["ProjectID", "AssetID"],
            ["TrustAsset.ProjectID", "TrustAsset.AssetID"],
            name="fk_trust_scan_context_asset",
            ondelete="NO ACTION",
        ),
    )

    ScanID = db.Column(
        db.Integer,
        db.ForeignKey("Scan.ScanID", ondelete="CASCADE"),
        primary_key=True,
    )
    OrganisationID = db.Column(db.Integer, nullable=False, index=True)
    ProjectID = db.Column(db.Integer, nullable=False, index=True)
    AssetID = db.Column(db.Integer, nullable=False, index=True)
    AttestationID = db.Column(
        db.Integer,
        db.ForeignKey(
            "TrustAuthorizationAttestation.AttestationID", ondelete="NO ACTION"
        ),
        nullable=False,
        index=True,
    )
    CreditID = db.Column(
        db.Integer,
        db.ForeignKey("TrustScanCredit.CreditID", ondelete="NO ACTION"),
        nullable=False,
        unique=True,
    )
    StartedByUserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=False,
    )
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            "ScanID": self.ScanID,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "AssetID": self.AssetID,
            "AttestationID": self.AttestationID,
            "CreditID": self.CreditID,
            "StartedByUserID": self.StartedByUserID,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
        }

    def __repr__(self):
        return f"<TrustScanContext scan={self.ScanID} project={self.ProjectID}>"
