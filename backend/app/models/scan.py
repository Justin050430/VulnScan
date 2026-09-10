"""Scan entity - records each vulnerability scanning session."""
from datetime import datetime

from app.extensions import db
from app.utils.constants import SCAN_STATUS_PENDING


class Scan(db.Model):
    __tablename__ = "Scan"

    ScanID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ScanName = db.Column(db.String(100), nullable=False)
    TargetURL = db.Column(db.String(255), nullable=False)
    Status = db.Column(db.String(20), nullable=False, default=SCAN_STATUS_PENDING)
    StartedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    FinishedAt = db.Column(db.DateTime, nullable=True)

    UserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ScanProfileID = db.Column(
        db.Integer,
        db.ForeignKey("ScanProfile.ScanProfileID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    pages = db.relationship(
        "DiscoveredPage",
        backref="scan",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="DiscoveredPage.DiscoveryOrder",
    )

    @property
    def findings(self):
        """All findings for this scan, reached through discovered pages."""
        results = []
        for page in self.pages:
            results.extend(page.findings)
        return results

    @property
    def finding_count(self):
        return len(self.findings)

    def to_dict(self, include_relations=False):
        data = {
            "ScanID": self.ScanID,
            "ScanName": self.ScanName,
            "TargetURL": self.TargetURL,
            "Status": self.Status,
            "StartedAt": self.StartedAt.isoformat() if self.StartedAt else None,
            "FinishedAt": self.FinishedAt.isoformat() if self.FinishedAt else None,
            "UserID": self.UserID,
            "ScanProfileID": self.ScanProfileID,
            "ScanProfileName": (
                self.scan_profile.Name if self.scan_profile else None
            ),
            "Username": self.user.Username if self.user else None,
        }
        if include_relations:
            data["Pages"] = [p.to_dict() for p in self.pages]
            data["Findings"] = [f.to_dict() for f in self.findings]
        return data

    def __repr__(self):
        return f"<Scan {self.ScanName!r} [{self.Status}]>"
