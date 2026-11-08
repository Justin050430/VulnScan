"""TrustProjectMembership - user role inside a project."""
from datetime import datetime

from app.extensions import db
from app.trust.constants import MEMBERSHIP_INVITED, PROJECT_ROLE_VIEWER


class TrustProjectMembership(db.Model):
    __tablename__ = "TrustProjectMembership"
    __table_args__ = (
        db.UniqueConstraint(
            "ProjectID", "UserID", name="uq_trust_project_membership_project_user"
        ),
        db.ForeignKeyConstraint(
            ["OrganisationID", "ProjectID"],
            ["TrustProject.OrganisationID", "TrustProject.ProjectID"],
            name="fk_trust_project_membership_project",
            ondelete="NO ACTION",
        ),
        db.CheckConstraint(
            "Status IN ('Invited','Active','Revoked')",
            name="ck_trust_project_membership_status",
        ),
        db.CheckConstraint(
            "Role IN ('PROJECT_OWNER','SCAN_OPERATOR','ANALYST','VIEWER')",
            name="ck_trust_project_membership_role",
        ),
    )

    ProjectMembershipID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    OrganisationID = db.Column(db.Integer, nullable=False, index=True)
    ProjectID = db.Column(db.Integer, nullable=False, index=True)
    UserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )
    Role = db.Column(db.String(30), nullable=False, default=PROJECT_ROLE_VIEWER)
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
            "ProjectMembershipID": self.ProjectMembershipID,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "UserID": self.UserID,
            "Role": self.Role,
            "Status": self.Status,
            "InvitedByUserID": self.InvitedByUserID,
            "AcceptedAt": self.AcceptedAt.isoformat() if self.AcceptedAt else None,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
        }

    def __repr__(self):
        return (
            f"<TrustProjectMembership project={self.ProjectID} "
            f"user={self.UserID}>"
        )
