"""Detection module framework."""
from dataclasses import dataclass, field
from typing import List, Optional

#: Upper bound on the number of injection points tested on a single page, so a
#: form-heavy page cannot multiply the scan's request count without limit.
MAX_INJECTION_POINTS_PER_PAGE = 10


@dataclass(frozen=True)
class InjectionPoint:
    """
    One place where attacker-controlled input can be delivered:

      * a query-string parameter (`form` is None), or
      * a field of an HTML form (`form` set, `method` is GET or POST).
    """

    name: str
    value: str
    method: str = "GET"
    target: str = ""
    form: object = None

    @property
    def is_form_field(self):
        return self.form is not None

    def describe(self):
        """Human-readable request description used in finding evidence."""
        if self.form is None:
            return f"query parameter '{self.name}' of GET {self.target}"
        return (
            f"form field '{self.name}' of {self.method} {self.target}"
        )


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
    #: HTML forms found on the page (app.scanner.forms.Form instances).
    forms: tuple = ()

    @property
    def parameters(self):
        """Query-string parameters present on this page URL."""
        from urllib.parse import parse_qsl, urlparse

        return dict(parse_qsl(urlparse(self.url).query, keep_blank_values=True))

    def injection_points(self, limit=MAX_INJECTION_POINTS_PER_PAGE):
        """Query-string parameters followed by the discovered form fields."""
        points = [
            InjectionPoint(name=name, value=value, method="GET", target=self.url)
            for name, value in self.parameters.items()
        ]
        query_names = set(self.parameters)
        for form in self.forms or ():
            for control in form.injectable_controls:
                if (
                    form.method == "GET"
                    and form.action == self.url
                    and control.name in query_names
                ):
                    # The same field is already tested through the query string.
                    continue
                points.append(
                    InjectionPoint(
                        name=control.name,
                        value=control.value,
                        method=form.method,
                        target=form.action,
                        form=form,
                    )
                )
        return points[:limit]


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
    #: detection technique label and CVSS v3.1 vector (stored with the evidence)
    technique: Optional[str] = None
    cvss_vector: Optional[str] = None


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
    def send(self, point, value):
        """
        Issue the injected request for an injection point.

        Query parameters and GET forms are sent in the query string; POST
        forms are submitted as an application/x-www-form-urlencoded body with
        every other control keeping the value the page served.
        """
        from app.utils.urls import merge_query_parameters, set_query_parameter

        if point.form is None:
            return self.http.get(set_query_parameter(self.page.url, point.name, value))
        data = point.form.data_with(point.name, value)
        if point.method == "POST":
            return self.http.post(point.target, data=data)
        return self.http.get(merge_query_parameters(point.target, data))

    def baseline(self, point):
        """Fetch the un-injected baseline for an injection point."""
        from app.utils.urls import merge_query_parameters

        if point.form is None:
            return self.http.get(self.page.url)
        data = point.form.data()
        if point.method == "POST":
            return self.http.post(point.target, data=data)
        return self.http.get(merge_query_parameters(point.target, data))

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
            cvss_vector=cvss_vector,
        )
        return self._result(**overrides)
