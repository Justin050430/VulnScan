"""Finding entity - vulnerabilities detected during a scan with severity/evidence."""
from datetime import datetime
from decimal import Decimal

from app.extensions import db
from app.utils.constants import FINDING_STATUS_OPEN, SEVERITY_ORDER


class Finding(db.Model):
    __tablename__ = "Finding"

    FindingID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Severity = db.Column(db.String(20), nullable=False, default="Medium")
    RiskScore = db.Column(db.Numeric(3, 1), nullable=True)
    Confidence = db.Column(db.Numeric(5, 2), nullable=True)
    RequestMethod = db.Column(db.String(10), nullable=True)
    Parameter = db.Column(db.String(100), nullable=True)
    Payload = db.Column(db.UnicodeText, nullable=True)
    Evidence = db.Column(db.UnicodeText, nullable=True)
    Status = db.Column(db.String(20), nullable=False, default=FINDING_STATUS_OPEN)
    DetectedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    PageID = db.Column(
        db.Integer,
        db.ForeignKey("DiscoveredPage.PageID", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    VulnerabilityID = db.Column(
        db.Integer,
        db.ForeignKey("Vulnerability.VulnerabilityID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )

    #: Confidence at/above this value is treated as confirmed evidence.
    CONFIRMED_CONFIDENCE = 0.8

    @property
    def classification(self):
        """
        Evidence class derived from the detection confidence:
          * 'Confirmed'  - deterministic proof (DB error signature, byte-exact
                           unencoded reflection, header deterministically absent)
          * 'Suspected'  - differential/heuristic evidence requiring manual review
        """
        if self.Confidence is None:
            return "Unclassified"
        return (
            "Confirmed"
            if float(self.Confidence) >= self.CONFIRMED_CONFIDENCE
            else "Suspected"
        )

    def to_dict(self, include_vuln=True):
        data = {
            "FindingID": self.FindingID,
            "Severity": self.Severity,
            "RiskScore": float(self.RiskScore) if self.RiskScore is not None else None,
            "Confidence": (
                float(self.Confidence) if self.Confidence is not None else None
            ),
            "Classification": self.classification,
            "RequestMethod": self.RequestMethod,
            "Parameter": self.Parameter,
            "Payload": self.Payload,
            "Evidence": self.Evidence,
            "Status": self.Status,
            "DetectedAt": self.DetectedAt.isoformat() if self.DetectedAt else None,
            "PageID": self.PageID,
            "URL": self.page.URL if self.page else None,
            "VulnerabilityID": self.VulnerabilityID,
        }
        if include_vuln and self.vulnerability:
            data["VulnerabilityName"] = self.vulnerability.Name
            data["OWASPCategory"] = self.vulnerability.OWASPCategory
            data["Recommendation"] = self.vulnerability.Recommendation
            data["Description"] = self.vulnerability.Description
            data["Impact"] = self.vulnerability.Impact
        return data

    @property
    def severity_rank(self):
        return SEVERITY_ORDER.get(self.Severity, 0)

    def __repr__(self):
        return f"<Finding {self.FindingID} {self.Severity}>"
