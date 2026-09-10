"""Detection module framework."""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PageInfo:
    """A page that the scanner is analysing."""

    url: str
    page_id: Optional[int] = None
    depth: int = 0
    order: int = 0
    http_status: Optional[int] = None
    title: Optional[str] = None
    error: Optional[str] = None

    @property
    def parameters(self):
        """Query-string parameters present on this page URL."""
        from urllib.parse import parse_qsl, urlparse

        return dict(parse_qsl(urlparse(self.url).query, keep_blank_values=True))


@dataclass
class DetectionResult:
    """A single confirmed vulnerability signal produced by a module."""

    module_key: str
    vulnerability_name: str
    severity: str
    risk_score: float
    confidence: float
    method: str = "GET"
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: str = ""
    detail: str = ""


class DetectionModule:
    """Base class for all vulnerability detection modules."""

    #: module key (registry) and canonical vulnerability KB name
    key = "base"
    vulnerability_name = ""

    #: default severity/risk when no CVSS vector is supplied
    severity = "Medium"
    risk_score = 5.0
    confidence = 0.7

    def __init__(self, http, page: PageInfo):
        self.http = http
        self.page = page

    def detect(self) -> List[DetectionResult]:
        raise NotImplementedError

    # ------------------------------------------------------------- helpers
    def _result(self, **overrides) -> DetectionResult:
        values = dict(
            module_key=self.key,
            vulnerability_name=self.vulnerability_name,
            severity=self.severity,
            risk_score=self.risk_score,
            confidence=self.confidence,
            method="GET",
        )
        values.update(overrides)
        return DetectionResult(**values)

    def _scored_result(self, cvss_vector, confidence, **overrides):
        """
        Build a result whose RiskScore/Severity are derived from a CVSS v3.1
        base vector (technically defensible, reproducible risk value).
        """
        from app.scanner.cvss import score_and_severity

        score, severity = score_and_severity(cvss_vector)
        overrides.update(
            severity=severity,
            risk_score=score,
            confidence=confidence,
        )
        return self._result(**overrides)
