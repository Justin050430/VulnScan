"""SecurityAuditLog entity - records significant user/system activities."""
from datetime import datetime

from app.extensions import db
from app.utils.constants import AUDIT_STATUS_SUCCESS


class SecurityAuditLog(db.Model):
    __tablename__ = "SecurityAuditLog"

    AuditID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EventTime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    Category = db.Column(db.String(30), nullable=False)
    Action = db.Column(db.String(100), nullable=False)
    EntityType = db.Column(db.String(30), nullable=True)
    EntityID = db.Column(db.Integer, nullable=True)
    Description = db.Column(db.UnicodeText, nullable=True)
    IPAddress = db.Column(db.String(45), nullable=True)
    Status = db.Column(db.String(20), nullable=False, default=AUDIT_STATUS_SUCCESS)

    UserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    def to_dict(self):
        return {
            "AuditID": self.AuditID,
            "EventTime": self.EventTime.isoformat() if self.EventTime else None,
            "Category": self.Category,
            "Action": self.Action,
            "EntityType": self.EntityType,
            "EntityID": self.EntityID,
            "Description": self.Description,
            "IPAddress": self.IPAddress,
            "Status": self.Status,
            "UserID": self.UserID,
            "Username": self.user.Username if self.user else None,
        }

    def __repr__(self):
        return f"<SecurityAuditLog {self.AuditID} {self.Action}>"
