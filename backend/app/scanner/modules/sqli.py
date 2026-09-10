"""
SQL Injection detection module.

Two complementary techniques are used, matching the documented SQLi
flowchart (select parameter -> baseline request -> inject payload -> capture
response -> classify):

1. **Error-based (confirmed, high confidence).**
   A payload is injected and the response is checked for a database error
   signature.  A finding is only confirmed when the signature appears in the
   injected response *and was absent from the baseline response*, which
   prevents false positives on pages that legitimately display SQL-like text.

2. **Boolean-based differential (suspected, lower confidence).**
   A logically-true payload and a logically-false payload are each sent
   twice.  The responses (with injected-payload reflections masked out) are
   compared using token-set similarity.  A finding is reported only when all
   of the following hold:
     * the true/false responses are individually stable across repeats,
     * the true response still resembles the baseline,
     * the false response clearly differs from the baseline and the true
       response.
   This is a content-based comparison, not a response-length heuristic, so
   pages that merely echo the payload are not reported.  Findings from this
   technique are explicitly labelled SUSPECTED and carry low confidence.

Only safe, read-only payloads are used (no stacked queries, no writes).
"""
import logging
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.scanner.base import DetectionModule
from app.scanner.similarity import mask_reflection, token_similarity
from app.utils.constants import NAME_SQL_INJECTION

logger = logging.getLogger("vulnscan.sqli")

# CVSS v3.1 base vectors for the two evidence classes.
CVSS_ERROR_BASED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8 Critical
CVSS_BOOLEAN_SUSPECTED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 5.9 Medium

# Payloads chosen to trigger identifiable DBMS errors when echoed unsafely.
ERROR_PAYLOADS = [
    "'",
    '"',
    "1'",
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "1);--",
    "1' ORDER BY 1--",
]

# Payload pairs used for the boolean differential technique.
TRUE_SUFFIX = " AND '1'='1"
FALSE_SUFFIX = " AND '1'='2"

# Signatures commonly present when a DB engine reports an error.
SQL_ERROR_SIGNATURES = (
    "sql syntax",
    "syntax error",
    "unclosed quotation mark",
    "incorrect syntax near",
    "you have an error in your sql",
    "mysql_fetch",
    "mysqli",
    "ora-",
    "sqlstate",
    "postgresql",
    "pg_query",
    "microsoft ole db",
    "odbc sql server driver",
    "sqlserver jdbc",
    "sqlite3",
    'near "',
    "quoted string not properly terminated",
    "unknown column",
    "at line 1",
)

# Differential thresholds (documented, conservative).
MIN_STABILITY = 0.98        # repeated identical-payload responses must match
MAX_TRUE_FALSE_SIM = 0.90   # true vs false must differ meaningfully
MIN_BASE_MARGIN = 0.05      # true must resemble the baseline more than false


class SQLInjectionModule(DetectionModule):
    key = "sqli"
    vulnerability_name = NAME_SQL_INJECTION

    def detect(self):
        results = []
        parameters = self.page.parameters
        if not parameters:
            return results

        baseline = self.http.get(self.page.url)
        if not baseline.ok:
            return results
        baseline_masked = baseline.text or ""

        for name, value in parameters.items():
            confirmed = self._error_based(name, baseline_masked)
            if confirmed is not None:
                results.append(confirmed)
                continue
            suspected = self._boolean_differential(name, value)
            if suspected is not None:
                results.append(suspected)
        return results

    # ---------------------------------------------------------------- error
    def _error_based(self, param_name, baseline_body):
        baseline_lower = (baseline_body or "").lower()
        for payload in ERROR_PAYLOADS:
            response = self.http.get(self._build_url(param_name, payload))
            if not response.ok:
                continue
            body = response.text or ""
            signature = self._matched_signature(body.lower())
            if signature and signature not in baseline_lower:
                return self._scored_result(
                    CVSS_ERROR_BASED,
                    0.92,
                    parameter=param_name,
                    payload=payload,
                    evidence=(
                        f"CONFIRMED: database error signature '{signature}' appeared "
                        f"after injecting the payload {payload!r} into parameter "
                        f"'{param_name}'; the signature was absent from the baseline "
                        f"response."
                    ),
                    detail=(
                        "Error-based SQL injection. The application returned a database "
                        "error caused by the injected SQL metacharacter, indicating that "
                        "user input reaches a SQL query without parameterisation."
                    ),
                )
        return None

    # ------------------------------------------------------------ boolean
    def _boolean_differential(self, param_name, original_value):
        true_payload = f"{original_value}{TRUE_SUFFIX}"
        false_payload = f"{original_value}{FALSE_SUFFIX}"

        t1 = self.http.get(self._build_url(param_name, true_payload))
        t2 = self.http.get(self._build_url(param_name, true_payload))
        f1 = self.http.get(self._build_url(param_name, false_payload))
        f2 = self.http.get(self._build_url(param_name, false_payload))
        if not all(r.ok for r in (t1, t2, f1, f2)):
            return None

        baseline = self.http.get(self.page.url)
        if not baseline.ok:
            return None

        # Mask the injected payload from the injected responses; the baseline is
        # compared relative to these (a fixed absolute threshold would be
        # broken by harmless reflection of the original value).
        base = baseline.text or ""
        bt1 = mask_reflection(t1.text, true_payload)
        bt2 = mask_reflection(t2.text, true_payload)
        bf1 = mask_reflection(f1.text, false_payload)
        bf2 = mask_reflection(f2.text, false_payload)

        stability_true = token_similarity(bt1, bt2)
        stability_false = token_similarity(bf1, bf2)
        true_vs_false = token_similarity(bt1, bf1)
        base_vs_true = token_similarity(base, bt1)
        base_vs_false = token_similarity(base, bf1)

        if (
            stability_true >= MIN_STABILITY
            and stability_false >= MIN_STABILITY
            and true_vs_false <= MAX_TRUE_FALSE_SIM
            and base_vs_true >= base_vs_false + MIN_BASE_MARGIN
        ):
            return self._scored_result(
                CVSS_BOOLEAN_SUSPECTED,
                0.60,
                parameter=param_name,
                payload=true_payload,
                evidence=(
                    "SUSPECTED (blind/boolean): a logically-true SQL condition "
                    f"resembled the baseline response (similarity "
                    f"{base_vs_true:.2f}) more closely than the logically-false "
                    f"condition did ({base_vs_false:.2f}); the two responses also "
                    f"differed from each other (similarity {true_vs_false:.2f}) "
                    f"and were stable across repeats. Reflected payload text was "
                    f"masked before comparison. Manual verification is recommended."
                ),
                detail=(
                    "Boolean-based (blind) SQL injection is suspected. No database error "
                    "was observed, so this finding is reported with lower confidence; "
                    "confirmation requires manual testing."
                ),
            )
        return None

    # ---------------------------------------------------------------- utils
    def _build_url(self, param_name, new_value):
        parsed = urlparse(self.page.url)
        query = urlencode(
            [(k, v) if k != param_name else (k, new_value)
             for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        )
        return urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, "")
        )

    @staticmethod
    def _matched_signature(body_lower):
        for signature in SQL_ERROR_SIGNATURES:
            if signature in body_lower:
                return signature
        return None
