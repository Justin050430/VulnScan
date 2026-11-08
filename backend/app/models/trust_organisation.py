"""TrustOrganisation - tenant boundary (Trust Boundary Extension)."""
from datetime import datetime

from app.extensions import db
from app.trust.constants import ORG_STATUS_ACTIVE


class TrustOrganisation(db.Model):
    __tablename__ = "TrustOrganisation"

    OrganisationID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    Name = db.Column(db.String(120), nullable=False)
    Slug = db.Column(db.String(60), nullable=False, unique=True)
    Status = db.Column(db.String(20), nullable=False, default=ORG_STATUS_ACTIVE)
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
            "OrganisationID": self.OrganisationID,
            "Name": self.Name,
            "Slug": self.Slug,
            "Status": self.Status,
            "CreatedByUserID": self.CreatedByUserID,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
        }

    def __repr__(self):
        return f"<TrustOrganisation {self.Slug!r}>"
