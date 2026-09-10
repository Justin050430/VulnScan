"""ScanProfile entity - reusable scanning configurations."""
from app.extensions import db


class ScanProfile(db.Model):
    __tablename__ = "ScanProfile"

    ScanProfileID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Name = db.Column(db.String(30), unique=True, nullable=False)
    MaxDepth = db.Column(db.Integer, nullable=False, default=2)
    FollowExternalLinks = db.Column(db.Boolean, nullable=False, default=False)
    RequestDelayMs = db.Column(db.Integer, nullable=False, default=200)
    MaxPages = db.Column(db.Integer, nullable=False, default=30)

    modules = db.relationship(
        "ProfileModule",
        backref="scan_profile",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    scans = db.relationship("Scan", backref="scan_profile", lazy="dynamic")

    def to_dict(self, include_modules=True):
        data = {
            "ScanProfileID": self.ScanProfileID,
            "Name": self.Name,
            "MaxDepth": self.MaxDepth,
            "FollowExternalLinks": self.FollowExternalLinks,
            "RequestDelayMs": self.RequestDelayMs,
            "MaxPages": self.MaxPages,
        }
        if include_modules:
            data["Modules"] = [
                {
                    "ProfileModuleID": m.ProfileModuleID,
                    "VulnerabilityID": m.VulnerabilityID,
                    "Name": m.vulnerability.Name if m.vulnerability else None,
                    "ModuleKey": m.vulnerability.module_key if m.vulnerability else None,
                }
                for m in self.modules
            ]
        return data

    def __repr__(self):
        return f"<ScanProfile {self.Name!r}>"
