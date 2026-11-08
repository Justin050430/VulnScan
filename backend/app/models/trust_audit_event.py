"""TrustAuditEvent - append-only audit ledger for the Trust Boundary.

There is intentionally no foreign key to User/Project so that history survives
entity changes, and there is no update/delete API: records are insert-only.
"""
from datetime import datetime

from app.extensions import db
from app.trust.constants import OUTCOME_SUCCESS


class TrustAuditEvent(db.Model):
    __tablename__ = "TrustAuditEvent"

    EventID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EventUUID = db.Column(db.String(36), nullable=False, unique=True)
    EventTime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    OrganisationID = db.Column(db.Integer, nullable=True, index=True)
    ProjectID = db.Column(db.Integer, nullable=True, index=True)
    ActorUserID = db.Column(db.Integer, nullable=True, index=True)
    EventType = db.Column(db.String(60), nullable=False, index=True)
    Outcome = db.Column(db.String(10), nullable=False, default=OUTCOME_SUCCESS)
    ReasonCode = db.Column(db.String(60), nullable=True)
    EntityType = db.Column(db.String(30), nullable=True)
    EntityID = db.Column(db.Integer, nullable=True)
    IPAddress = db.Column(db.String(45), nullable=True)
    UserAgentHash = db.Column(db.String(64), nullable=True)
    CorrelationID = db.Column(db.String(64), nullable=True, index=True)
    MetadataJson = db.Column(db.String(2000), nullable=True)
    PrevEventHash = db.Column(db.String(64), nullable=True)
    EventHash = db.Column(db.String(64), nullable=True)

    def to_dict(self):
        return {
            "EventID": self.EventID,
            "EventUUID": self.EventUUID,
            "EventTime": self.EventTime.isoformat() if self.EventTime else None,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "ActorUserID": self.ActorUserID,
            "EventType": self.EventType,
            "Outcome": self.Outcome,
            "ReasonCode": self.ReasonCode,
            "EntityType": self.EntityType,
            "EntityID": self.EntityID,
            "IPAddress": self.IPAddress,
            "CorrelationID": self.CorrelationID,
            "Metadata": self.MetadataJson,
        }

    def __repr__(self):
        return f"<TrustAuditEvent {self.EventType} [{self.Outcome}]>"
