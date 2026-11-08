"""TrustOrganisationMembership - user role inside an organisation."""
from datetime import datetime

from app.extensions import db
from app.trust.constants import MEMBERSHIP_INVITED, ORG_ROLE_OWNER


class TrustOrganisationMembership(db.Model):
    __tablename__ = "TrustOrganisationMembership"
    __table_args__ = (
        db.UniqueConstraint(
            "OrganisationID", "UserID", name="uq_trust_org_membership_org_user"
        ),
        db.CheckConstraint(
            "Status IN ('Invited','Active','Revoked')",
            name="ck_trust_org_membership_status",
        ),
        db.CheckConstraint(
            "Role IN ('ORG_OWNER')", name="ck_trust_org_membership_role"
        ),
    )

    OrganisationMembershipID = db.Column(
        db.Integer, primary_key=True, autoincrement=True
    )
    OrganisationID = db.Column(
        db.Integer,
        db.ForeignKey("TrustOrganisation.OrganisationID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )
    UserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )
    Role = db.Column(db.String(20), nullable=False, default=ORG_ROLE_OWNER)
    Status = db.Column(db.String(20), nullable=False, default=MEMBERSHIP_INVITED)
    InviteTokenHash = db.Column(db.String(64), nullable=True)
    InviteExpiresAt = db.Column(db.DateTime, nullable=True)
    InvitedByUserID = db.Column(
        db.Integer, db.ForeignKey("User.UserID", ondelete="NO ACTION"), nullable=True
    )
    AcceptedAt = db.Column(db.DateTime, nullable=True)
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    UpdatedAt = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    Version = db.Column(db.Integer, nullable=False, default=1)

    def to_dict(self):
        return {
            "OrganisationMembershipID": self.OrganisationMembershipID,
            "OrganisationID": self.OrganisationID,
            "UserID": self.UserID,
            "Role": self.Role,
            "Status": self.Status,
            "InvitedByUserID": self.InvitedByUserID,
            "AcceptedAt": self.AcceptedAt.isoformat() if self.AcceptedAt else None,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
        }

    def __repr__(self):
        return (
            f"<TrustOrganisationMembership org={self.OrganisationID} "
            f"user={self.UserID}>"
        )
