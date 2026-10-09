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
   The identical request is then repeated: the CONFIRMED class requires the
   signature to reproduce, otherwise the observation is reported as SUSPECTED
   (possible transient error page).

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
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.scanner.base import DetectionModule
from app.scanner.similarity import mask_reflection, token_similarity
from app.utils.constants import NAME_SQL_INJECTION

logger = logging.getLogger("vulnscan.sqli")

# CVSS v3.1 base vectors for the two evidence classes.
CVSS_ERROR_BASED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8 Critical
CVSS_BOOLEAN_SUSPECTED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 5.9 Medium

# Detection technique labels (stored with every finding's evidence).
TECHNIQUE_ERROR_BASED = "error-based (SQL metacharacter triggers a database error)"
TECHNIQUE_BOOLEAN_DIFFERENTIAL = "boolean differential (true/false responses compared)"

REFERENCES = (
    "OWASP Top 10 A03:2021 Injection (https://owasp.org/Top10/A03_2021-Injection/); "
    "OWASP WSTG - Testing for SQL Injection "
    "(https://owasp.org/www-project-web-security-testing-guide/)"
)

# Payloads chosen to trigger identifiable DBMS errors when echoed unsafely.
# All payloads are read-only: they provoke error messages, never extract data.
ERROR_PAYLOADS = [
    "'",
    '"',
    "1'",
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "1);--",
    "1' ORDER BY 1--",
    # DB-specific read-only error triggers (SQL Server / MySQL / PostgreSQL).
    "1' AND 1=CONVERT(int, @@version)--",
    "1' AND extractvalue(1,concat(0x7e,0x7e))--",
    "1' AND 1=CAST('a' AS int)--",
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

        for name, value in parameters.items():
            confirmed = self._error_based(name, baseline, value)
            if confirmed is not None:
                results.append(confirmed)
                continue
            suspected = self._boolean_differential(name, value)
            if suspected is not None:
                results.append(suspected)
        return results

    # ---------------------------------------------------------------- error
    def _error_based(self, param_name, baseline, original_value):
        baseline_text = baseline.text or ""
        baseline_lower = baseline_text.lower()
        inconclusive = None
        for payload in self._ordered_payloads(original_value):
            response = self.http.get(self._build_url(param_name, payload))
            if not response.ok:
                continue
            body = response.text or ""
            signature = self._matched_signature(body.lower())
            if not signature or signature in baseline_lower:
                continue

            # Reproduce the observation: a transient error page must not be
            # reported with confirmed evidence.
            repeat = self.http.get(self._build_url(param_name, payload))
            reproduced = bool(
                repeat.ok
                and self._matched_signature((repeat.text or "").lower()) == signature
            )
            if reproduced:
                return self._scored_result(
                    CVSS_ERROR_BASED,
                    0.92,
                    parameter=param_name,
                    payload=payload,
                    technique=TECHNIQUE_ERROR_BASED,
                    evidence=self._error_evidence(
                        param_name, payload, signature, baseline, response,
                        repeated=True,
                    ),
                    detail=(
                        "Error-based SQL injection. The application returned a database "
                        "error caused by the injected SQL metacharacter, indicating that "
                        "user input reaches a SQL query without parameterisation."
                    ),
                )
            if inconclusive is None:
                inconclusive = self._scored_result(
                    CVSS_ERROR_BASED,
                    0.65,
                    parameter=param_name,
                    payload=payload,
                    technique=TECHNIQUE_ERROR_BASED,
                    evidence=self._error_evidence(
                        param_name, payload, signature, baseline, response,
                        repeated=False,
                    ),
                    detail=(
                        "A database error appeared once after injecting the payload "
                        "but did not reproduce on the identical repeated request. "
                        "This is reported as SUSPECTED evidence; manual verification "
                        "is recommended before treating it as an SQL injection."
                    ),
                )
        return inconclusive

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
                technique=TECHNIQUE_BOOLEAN_DIFFERENTIAL,
                evidence=self._boolean_evidence(
                    param_name, true_payload, false_payload,
                    baseline=baseline, t1=t1, f1=f1,
                    base_vs_true=base_vs_true, base_vs_false=base_vs_false,
                    true_vs_false=true_vs_false,
                    stability_true=stability_true,
                    stability_false=stability_false,
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

    # ------------------------------------------------------------ evidence
    @staticmethod
    def _ordered_payloads(original_value):
        """Try payloads that match the parameter's input type first."""
        value = (original_value or "").strip()
        numeric = bool(re.fullmatch(r"-?\d+", value)) if value else False
        if not numeric:
            return ERROR_PAYLOADS
        numeric_first = [p for p in ERROR_PAYLOADS if p.startswith("1")]
        others = [p for p in ERROR_PAYLOADS if not p.startswith("1")]
        return numeric_first + others

    def _error_evidence(self, param_name, payload, signature, baseline, response,
                        repeated):
        baseline_status = (
            baseline.status_code if baseline.status_code is not None else "no response"
        )
        test_status = (
            response.status_code if response.status_code is not None else "no response"
        )
        if repeated:
            verdict = (
                f"CONFIRMED: database error signature '{signature}' appeared after "
                f"injecting the payload {payload!r} into parameter '{param_name}'; "
                f"the signature was absent from the baseline response and reproduced "
                f"on the identical repeated request."
            )
            reproducibility = "signature reproduced on 2/2 identical requests"
        else:
            verdict = (
                f"SUSPECTED (unreproduced error): database error signature "
                f"'{signature}' appeared once after injecting the payload {payload!r} "
                f"into parameter '{param_name}' but did NOT reproduce on the "
                f"identical repeated request."
            )
            reproducibility = (
                "signature NOT reproduced (possible transient server error page); "
                "reported as suspected evidence requiring manual verification"
            )
        return "\n".join([
            verdict,
            "",
            f"BASELINE REQUEST: GET {self.page.url} -> HTTP {baseline_status}; "
            f"database-error signature absent",
            f"TEST REQUEST: GET {self._build_url(param_name, payload)} -> "
            f"HTTP {test_status}; matched signature '{signature}'",
            f"REPRODUCIBILITY: {reproducibility}",
            "WHY THIS INDICATES SQL INJECTION: the response changed from a normal "
            "page to a database-engine error only when a SQL metacharacter was "
            "injected, and the error text identifies the database engine.",
            "ALTERNATIVE EXPLANATIONS / LIMITATIONS: only read-only payloads are "
            "used and no data was extracted; a custom error page could imitate a "
            "database error, so manual verification is recommended; the technique "
            "only applies where user input reaches a SQL query without "
            "parameterisation.",
            "REMEDIATION: use parameterised queries / prepared statements; "
            "validate and type-check input server-side; apply least-privilege "
            "database accounts; do not expose database error messages.",
            f"REFERENCES: {REFERENCES}",
            "VERIFICATION: Not retested yet.",
        ])

    def _boolean_evidence(self, param_name, true_payload, false_payload, *,
                          baseline, t1, f1, base_vs_true, base_vs_false,
                          true_vs_false, stability_true, stability_false):
        return "\n".join([
            "SUSPECTED (blind/boolean differential): a logically-true SQL "
            f"condition response resembled the baseline (similarity "
            f"{base_vs_true:.2f}) more closely than the logically-false condition "
            f"did ({base_vs_false:.2f}); the two responses differed from each "
            f"other (similarity {true_vs_false:.2f}) and each was stable across "
            "repeated identical requests.",
            "",
            f"BASELINE REQUEST: GET {self.page.url} -> HTTP {baseline.status_code}",
            f"TRUE CONDITION: GET {self._build_url(param_name, true_payload)} -> "
            f"HTTP {t1.status_code}",
            f"FALSE CONDITION: GET {self._build_url(param_name, false_payload)} -> "
            f"HTTP {f1.status_code}",
            f"DIFFERENTIAL METRICS: repeat stability {stability_true:.2f} / "
            f"{stability_false:.2f} (required >= {MIN_STABILITY}); true-vs-false "
            f"similarity {true_vs_false:.2f} (required <= {MAX_TRUE_FALSE_SIM}); "
            f"baseline margin {base_vs_true - base_vs_false:.2f} "
            f"(required >= {MIN_BASE_MARGIN}); reflected payload text masked "
            "before comparison",
            "WHY THIS INDICATES SQL INJECTION: the response changed systematically "
            "with the truth value of an injected SQL condition while remaining "
            "stable across repeats - behaviour that content-based comparison of a "
            "non-injectable parameter does not produce.",
            "ALTERNATIVE EXPLANATIONS / LIMITATIONS: a server-side reason that "
            "depends on the literal input text (not SQL truth) could mimic this; "
            "no database error was observed, so confirmation requires manual "
            "testing; only read-only conditions are used and no data was extracted.",
            "REMEDIATION: use parameterised queries / prepared statements; "
            "validate and type-check input server-side; apply least-privilege "
            "database accounts.",
            f"REFERENCES: {REFERENCES}",
            "VERIFICATION: Not retested yet.",
        ])
