"""TrustProject - project inside an organisation (Trust Boundary Extension)."""
from datetime import datetime

from app.extensions import db
from app.trust.constants import PROJECT_STATUS_ACTIVE


class TrustProject(db.Model):
    __tablename__ = "TrustProject"
    __table_args__ = (
        db.UniqueConstraint(
            "OrganisationID", "ProjectID", name="uq_trust_project_org_project"
        ),
        db.UniqueConstraint(
            "OrganisationID", "Slug", name="uq_trust_project_org_slug"
        ),
    )

    ProjectID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    OrganisationID = db.Column(
        db.Integer,
        db.ForeignKey("TrustOrganisation.OrganisationID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )
    Name = db.Column(db.String(120), nullable=False)
    Slug = db.Column(db.String(60), nullable=False)
    Status = db.Column(db.String(20), nullable=False, default=PROJECT_STATUS_ACTIVE)
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

    def to_dict(self):
        return {
            "ProjectID": self.ProjectID,
            "OrganisationID": self.OrganisationID,
            "Name": self.Name,
            "Slug": self.Slug,
            "Status": self.Status,
            "CreatedByUserID": self.CreatedByUserID,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
        }

    def __repr__(self):
        return f"<TrustProject {self.Slug!r}>"
