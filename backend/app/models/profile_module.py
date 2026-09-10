"""ProfileModule entity - associates a detection module (Vulnerability) with a scan profile."""
from app.extensions import db


class ProfileModule(db.Model):
    __tablename__ = "ProfileModule"
    __table_args__ = (
        db.UniqueConstraint(
            "ScanProfileID", "VulnerabilityID", name="uq_profile_module_profile_vuln"
        ),
    )

    ProfileModuleID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ScanProfileID = db.Column(
        db.Integer,
        db.ForeignKey("ScanProfile.ScanProfileID", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    VulnerabilityID = db.Column(
        db.Integer,
        db.ForeignKey("Vulnerability.VulnerabilityID", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    def __repr__(self):
        return (
            f"<ProfileModule profile={self.ScanProfileID} "
            f"vuln={self.VulnerabilityID}>"
        )
