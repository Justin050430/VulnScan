"""TrustScanCredit and TrustCreditRedemption - single-use scan entitlements."""
from datetime import datetime

from app.extensions import db
from app.trust.constants import (
    CREDIT_AVAILABLE,
    PAYMENT_PENDING,
    REDEMPTION_RESERVED,
)


class TrustScanCredit(db.Model):
    __tablename__ = "TrustScanCredit"
    __table_args__ = (
        db.UniqueConstraint(
            "PaymentTransactionID",
            "CreditSequence",
            name="uq_trust_credit_payment_sequence",
        ),
        db.ForeignKeyConstraint(
            ["OrganisationID", "ProjectID"],
            ["TrustProject.OrganisationID", "TrustProject.ProjectID"],
            name="fk_trust_credit_project",
            ondelete="NO ACTION",
        ),
        db.CheckConstraint(
            "Status IN ('Available','Reserved','Consumed','Expired','Refunded',"
            "'Failed','Disputed')",
            name="ck_trust_credit_status",
        ),
        db.CheckConstraint(
            "PurchasePriceMinor >= 0", name="ck_trust_credit_price"
        ),
    )

    CreditID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CreditUUID = db.Column(db.String(36), nullable=False, unique=True)
    OrganisationID = db.Column(db.Integer, nullable=False, index=True)
    ProjectID = db.Column(db.Integer, nullable=False, index=True)
    PaymentTransactionID = db.Column(
        db.Integer,
        db.ForeignKey(
            "TrustPaymentTransaction.PaymentTransactionID", ondelete="NO ACTION"
        ),
        nullable=False,
        index=True,
    )
    CreditSequence = db.Column(db.Integer, nullable=False)
    ProductCode = db.Column(db.String(40), nullable=False)
    Status = db.Column(db.String(20), nullable=False, default=CREDIT_AVAILABLE)
    IssuedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ExpiresAt = db.Column(db.DateTime, nullable=False)
    ReservedAt = db.Column(db.DateTime, nullable=True)
    ReservedUntil = db.Column(db.DateTime, nullable=True)
    ConsumedAt = db.Column(db.DateTime, nullable=True)
    ReservedByUserID = db.Column(
        db.Integer, db.ForeignKey("User.UserID", ondelete="NO ACTION"), nullable=True
    )
    PurchasePriceMinor = db.Column(db.Integer, nullable=False, default=0)
    Currency = db.Column(db.String(3), nullable=False, default="MYR")
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    UpdatedAt = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    Version = db.Column(db.Integer, nullable=False, default=1)

    def is_available(self, now=None):
        now = now or datetime.utcnow()
        return self.Status == CREDIT_AVAILABLE and self.ExpiresAt > now

    def to_dict(self):
        return {
            "CreditID": self.CreditID,
            "CreditUUID": self.CreditUUID,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "PaymentTransactionID": self.PaymentTransactionID,
            "ProductCode": self.ProductCode,
            "Status": self.Status,
            "IssuedAt": self.IssuedAt.isoformat() if self.IssuedAt else None,
            "ExpiresAt": self.ExpiresAt.isoformat() if self.ExpiresAt else None,
            "ReservedAt": self.ReservedAt.isoformat() if self.ReservedAt else None,
            "ReservedUntil": (
                self.ReservedUntil.isoformat() if self.ReservedUntil else None
            ),
            "ConsumedAt": self.ConsumedAt.isoformat() if self.ConsumedAt else None,
            "PurchasePriceMinor": self.PurchasePriceMinor,
            "Currency": self.Currency,
        }

    def __repr__(self):
        return f"<TrustScanCredit {self.CreditUUID} [{self.Status}]>"


class TrustCreditRedemption(db.Model):
    __tablename__ = "TrustCreditRedemption"
    __table_args__ = (
        db.ForeignKeyConstraint(
            ["OrganisationID", "ProjectID"],
            ["TrustProject.OrganisationID", "TrustProject.ProjectID"],
            name="fk_trust_redemption_project",
            ondelete="NO ACTION",
        ),
        db.CheckConstraint(
            "Status IN ('Reserved','Consumed','Released','Failed')",
            name="ck_trust_redemption_status",
        ),
        db.Index(
            "ux_trust_redemption_active_credit",
            "CreditID",
            unique=True,
            mssql_where=db.text("Status IN ('Reserved','Consumed')"),
            sqlite_where=db.text("Status IN ('Reserved','Consumed')"),
        ),
    )

    RedemptionID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CreditID = db.Column(
        db.Integer,
        db.ForeignKey("TrustScanCredit.CreditID", ondelete="NO ACTION"),
        nullable=False,
        index=True,
    )
    ScanID = db.Column(
        db.Integer,
        db.ForeignKey("Scan.ScanID", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    OrganisationID = db.Column(db.Integer, nullable=False, index=True)
    ProjectID = db.Column(db.Integer, nullable=False, index=True)
    UserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=False,
    )
    Status = db.Column(db.String(20), nullable=False, default=REDEMPTION_RESERVED)
    IdempotencyKey = db.Column(db.String(64), nullable=False, unique=True)
    ReservedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ConsumedAt = db.Column(db.DateTime, nullable=True)
    ReleasedAt = db.Column(db.DateTime, nullable=True)
    FailureReason = db.Column(db.String(255), nullable=True)
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    UpdatedAt = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    Version = db.Column(db.Integer, nullable=False, default=1)

    def to_dict(self):
        return {
            "RedemptionID": self.RedemptionID,
            "CreditID": self.CreditID,
            "ScanID": self.ScanID,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "UserID": self.UserID,
            "Status": self.Status,
            "ReservedAt": self.ReservedAt.isoformat() if self.ReservedAt else None,
            "ConsumedAt": self.ConsumedAt.isoformat() if self.ConsumedAt else None,
            "ReleasedAt": self.ReleasedAt.isoformat() if self.ReleasedAt else None,
            "FailureReason": self.FailureReason,
        }

    def __repr__(self):
        return f"<TrustCreditRedemption {self.RedemptionID} [{self.Status}]>"
