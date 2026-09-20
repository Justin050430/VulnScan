"""Second pass: the two remaining module descriptions share one paragraph with
their heading label (separated by a <w:br/>), and the NIST citation needs an
in-text author fix."""
from docx import Document

SRC = r"c:\FYP\VulnScan\Assignment\OoiJianXin_RIS_Form2.docx"
doc = Document(SRC)
t1 = doc.tables[1]
paras = [p for row in t1.rows for c in row.cells for p in c.paragraphs]

STATS = []

RISK_NEW = (
    "Assigns a severity level and a risk score to each detected vulnerability "
    "using the Common Vulnerability Scoring System (CVSS) v3.1 base metrics "
    "(FIRST, 2019), which take into account the exploitability of the weakness "
    "and its potential impact on confidentiality, integrity and availability. "
    "This enables prioritization of critical vulnerabilities and supports more "
    "effective decision-making during remediation."
)

KB_NEW = (
    "Provides actionable mitigation suggestions for each detected "
    "vulnerability. For example, in the case of SQL Injection, the system "
    "recommends the use of parameterized queries and input validation "
    "techniques. Each knowledge base entry documents the vulnerability "
    "description, security impact, remediation recommendation, secure coding "
    "practice and OWASP reference, and administrators can maintain these "
    "entries through the system. This enhances the usability of the system by "
    "guiding developers on how to fix identified issues."
)


def replace_body(anchor, new_body):
    for p in paras:
        if not p.text.strip().startswith(anchor):
            continue
        for run in p.runs:
            if "\n" in run.text:
                run.text = "\n" + new_body
                STATS.append(f"rewrote body of '{anchor}'")
                return True
    STATS.append(f"!! body not found: {anchor}")
    return False


replace_body("Risk Assessment Module", RISK_NEW)
replace_body("Remediation Knowledge Base", KB_NEW)

# in-text citation: reference entry is 'Tracy, M., ...' so APA in-text is
# (Tracy et al., 2007), not (NIST, 2007)
fixed = False
for p in paras:
    for run in p.runs:
        if "(NIST, 2007)" in run.text:
            run.text = run.text.replace("(NIST, 2007)", "(Tracy et al., 2007)")
            fixed = True
STATS.append("in-text citation (NIST, 2007) -> (Tracy et al., 2007)"
             if fixed else "!! (NIST, 2007) not found")

# The header label sits in its own paragraph for other modules - confirm the
# label paragraphs are untouched and no duplicate labels were introduced.
labels = [p.text.strip() for p in paras
          if p.text.strip() in ("Risk Assessment Module",
                                "Remediation Knowledge Base")]
STATS.append(f"label paragraphs still intact: {labels}")

doc.save(SRC)
print("\n".join(" - " + s for s in STATS))
