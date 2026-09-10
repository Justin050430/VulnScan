"""DiscoveredPage entity - web pages identified during crawling."""
from app.extensions import db


class DiscoveredPage(db.Model):
    __tablename__ = "DiscoveredPage"

    PageID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    URL = db.Column(db.String(500), nullable=False)
    PageTitle = db.Column(db.String(255), nullable=True)
    HTTPStatus = db.Column(db.Integer, nullable=True)
    CrawlDepth = db.Column(db.Integer, nullable=False, default=0)
    DiscoveryOrder = db.Column(db.Integer, nullable=False, default=0)

    ScanID = db.Column(
        db.Integer,
        db.ForeignKey("Scan.ScanID", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    findings = db.relationship(
        "Finding",
        backref="page",
        lazy="selectin",
        cascade="all, delete-orphan",
        order_by="Finding.FindingID",
    )

    def to_dict(self):
        return {
            "PageID": self.PageID,
            "URL": self.URL,
            "PageTitle": self.PageTitle,
            "HTTPStatus": self.HTTPStatus,
            "CrawlDepth": self.CrawlDepth,
            "DiscoveryOrder": self.DiscoveryOrder,
            "ScanID": self.ScanID,
        }

    def __repr__(self):
        return f"<DiscoveredPage {self.URL!r}>"
