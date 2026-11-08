"""TrustPaymentTransaction - mock/sandbox payment record."""
from datetime import datetime

from app.extensions import db
from app.trust.constants import PAYMENT_PENDING, PROVIDER_MOCK


class TrustPaymentTransaction(db.Model):
    __tablename__ = "TrustPaymentTransaction"
    __table_args__ = (
        db.ForeignKeyConstraint(
            ["OrganisationID", "ProjectID"],
            ["TrustProject.OrganisationID", "TrustProject.ProjectID"],
            name="fk_trust_payment_project",
            ondelete="NO ACTION",
        ),
        db.CheckConstraint(
            "Status IN ('PendingPayment','PaymentVerified','Failed','Expired',"
            "'Refunded','Disputed')",
            name="ck_trust_payment_status",
        ),
        db.CheckConstraint(
            "Provider IN ('MOCK','BILLPLZ','TOYYIBPAY','SENANGPAY')",
            name="ck_trust_payment_provider",
        ),
        db.CheckConstraint("Quantity >= 1 AND Quantity <= 100",
                           name="ck_trust_payment_quantity"),
        db.CheckConstraint("AmountMinor > 0", name="ck_trust_payment_amount"),
    )

    PaymentTransactionID = db.Column(
        db.Integer, primary_key=True, autoincrement=True
    )
    PaymentUUID = db.Column(db.String(36), nullable=False, unique=True)
    OrganisationID = db.Column(db.Integer, nullable=False, index=True)
    ProjectID = db.Column(db.Integer, nullable=False, index=True)
    PurchasedByUserID = db.Column(
        db.Integer,
        db.ForeignKey("User.UserID", ondelete="NO ACTION"),
        nullable=False,
    )
    Provider = db.Column(db.String(20), nullable=False, default=PROVIDER_MOCK)
    ProviderTransactionID = db.Column(db.String(100), nullable=True)
    ProviderCheckoutID = db.Column(db.String(100), nullable=True)
    IdempotencyKey = db.Column(db.String(64), nullable=False, unique=True)
    ProductCode = db.Column(db.String(40), nullable=False)
    Quantity = db.Column(db.Integer, nullable=False, default=1)
    AmountMinor = db.Column(db.Integer, nullable=False)
    Currency = db.Column(db.String(3), nullable=False, default="MYR")
    Status = db.Column(db.String(24), nullable=False, default=PAYMENT_PENDING)
    FailureReason = db.Column(db.String(255), nullable=True)
    CallbackHash = db.Column(db.String(64), nullable=True)
    VerifiedAt = db.Column(db.DateTime, nullable=True)
    RefundedAt = db.Column(db.DateTime, nullable=True)
    CreatedAt = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    UpdatedAt = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    Version = db.Column(db.Integer, nullable=False, default=1)

    def to_dict(self):
        return {
            "PaymentTransactionID": self.PaymentTransactionID,
            "PaymentUUID": self.PaymentUUID,
            "OrganisationID": self.OrganisationID,
            "ProjectID": self.ProjectID,
            "Provider": self.Provider,
            "ProviderTransactionID": self.ProviderTransactionID,
            "ProductCode": self.ProductCode,
            "Quantity": self.Quantity,
            "AmountMinor": self.AmountMinor,
            "Currency": self.Currency,
            "Status": self.Status,
            "CreatedAt": self.CreatedAt.isoformat() if self.CreatedAt else None,
            "VerifiedAt": self.VerifiedAt.isoformat() if self.VerifiedAt else None,
        }

    def __repr__(self):
        return f"<TrustPaymentTransaction {self.PaymentUUID} [{self.Status}]>"
