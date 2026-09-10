# -*- coding: utf-8 -*-
"""
VulnScan FYP.docx — Chapters 1-4 consistency polish (text-level edits).
Run from the repo venv. Operates on Assignment/FYP.docx (backup exists).
"""
import docx, sys
from copy import deepcopy
from docx.text.paragraph import Paragraph

PATH = r"c:\FYP\VulnScan\Assignment\FYP.docx"
doc = docx.Document(PATH)
paras = doc.paragraphs

report = []
def log(msg):
    report.append(msg)

# ---------------------------------------------------------------- helpers
def set_para_text(p, text):
    """Replace paragraph text, preserving the first run's formatting + style."""
    runs = p.runs
    if runs:
        runs[0].text = text
        for r in runs[1:]:
            r._element.getparent().remove(r._element)
    else:
        p.add_run(text)

def find_paras(sub, start=0):
    out = []
    for i in range(start, len(paras)):
        if sub in paras[i].text:
            out.append(paras[i])
    return out

def replace_para(sub, new_text, expect=1):
    ms = find_paras(sub)
    if len(ms) != expect:
        log(f"!! replace '{sub[:50]}...' matched {len(ms)} (expected {expect}) -> SKIPPED")
        return False
    old = ms[0].text
    set_para_text(ms[0], new_text)
    log(f"OK  [{sub[:45]}...] len {len(old)} -> {len(new_text)}")
    return True

def clone_after(ref_p, anchor_p, text):
    """Insert a paragraph after anchor_p cloned from ref_p (keeps numPr/format)."""
    new_el = deepcopy(ref_p._p)
    anchor_p._p.addnext(new_el)
    np = Paragraph(new_el, ref_p._parent)
    set_para_text(np, text)
    return np

# ================================================================ Chapter 1
# 1.4.1 sub-items under "User Authentication and Role-Based Access Control"
replace_para(
    "The system supports secure user authentication using username and password.",
    "The system supports secure user authentication using a registered email address and password. "
    "Registered users may also sign in using their Google account through single sign-on (SSO).")

replace_para(
    "Administrators manage users, vulnerabilities, scan profiles, and system configurations, while Developers "
    "perform vulnerability assessments and view scan results.",
    "Administrators create and manage user accounts, vulnerabilities, scan profiles, and system configurations, "
    "while Developers perform vulnerability assessments and view scan results.")

# Insert new functional-scope item 7 (clone Security Audit Logging item pair) before 1.4.2
h_audit = find_paras("Security Audit Logging")
d_audit = find_paras("The system records significant security-related activities")
h_l42 = find_paras("1.4.2 Project Limitations")
if len(h_audit) == 1 and len(d_audit) == 1 and len(h_l42) == 1:
    new_d = deepcopy(d_audit[0]._p)
    new_h = deepcopy(h_audit[0]._p)
    # order: h then d, both before 1.4.2
    h_l42[0]._p.addprevious(new_d)
    h_l42[0]._p.addprevious(new_h)
    nh = Paragraph(new_h, h_audit[0]._parent)
    nd = Paragraph(new_d, d_audit[0]._parent)
    set_para_text(nh, "Report Generation and Data Export")
    set_para_text(nd, "The system generates structured scan reports that summarise detected vulnerabilities, "
                      "their severity and risk levels, and recommended remediation actions. Authorised users can "
                      "export scan results in portable formats for documentation and reporting purposes.")
    log("OK  inserted functional-scope item 7 (Report Generation and Data Export)")
else:
    log(f"!! functional-scope insert skipped (h_audit={len(h_audit)} d_audit={len(d_audit)} h_142={len(h_l42)})")

# 1.6 Organisation of Report -> seven chapters
replace_para("This report is organised into six chapters, each focusing on a specific aspect of the proposed project.",
    "This report is organised into seven chapters, each focusing on a specific aspect of the proposed project.")

replace_para(
    "Chapter 3 describes the research methodology adopted throughout the project. It explains the project "
    "development methodology, system development process, software and hardware requirements, overall system "
    "architecture, database design, and implementation approach used to develop VulnScan.",
    "Chapter 3 presents the methodology and requirements analysis conducted for the proposed system. It explains "
    "the Agile software development methodology adopted, the techniques used to gather requirements, and the "
    "functional and non-functional requirements identified for VulnScan.")

replace_para(
    "Chapter 4 presents the implementation and development of the proposed system. It discusses the implementation "
    "of major system modules, including user authentication, vulnerability scanning, risk assessment, scan profile "
    "management, vulnerability management, audit logging, and the integrated knowledge base. Database implementation "
    "and user interface design are also presented in this chapter.",
    "Chapter 4 presents the system design of VulnScan, including the overall software architecture, database design, "
    "user interface design, and detailed design of the major system modules such as user authentication, "
    "vulnerability scanning, and security audit logging.")

replace_para(
    "Chapter 5 evaluates the developed system through system testing and validation. The chapter presents the testing "
    "methodology, test cases, testing results, discussion of system performance, and an evaluation of whether the "
    "project objectives have been successfully achieved.",
    "Chapter 5 describes the implementation and testing of the developed system. It presents the implementation of "
    "the major system modules, the testing methodology and test cases carried out, and a discussion of the testing "
    "results against the system requirements and project objectives.")

replace_para(
    "Chapter 6 concludes the report by summarising the overall project, highlighting the project's contributions "
    "and achievements, discussing its limitations, and proposing recommendations and future enhancements for further "
    "system improvement.",
    "Chapter 6 discusses system deployment. Because VulnScan is developed as an academic project rather than a "
    "real-life industrial deployment, this chapter addresses deployment-related considerations where applicable.")

# Add Chapter 7 bullet (clone the last 1.6 bullet)
ch6 = find_paras("Chapter 6 discusses system deployment.")
if len(ch6) == 1:
    clone_after(ch6[0], ch6[0],
        "Chapter 7 concludes the report by summarising the overall project, evaluating its achievements against the "
        "project objectives, discussing the contributions of VulnScan, and proposing recommendations and future "
        "enhancements for further improvement.")
    log("OK  inserted 1.6 Chapter 7 bullet")
else:
    log("!! Chapter 7 bullet insert skipped")

# Fix duplicate period in 1.1.3 (Scambray) + keep period tidy
for p in find_paras("Scambray"):
    if "2021). . These" in p.text:
        set_para_text(p, p.text.replace("2021). . These", "2021). These"))
        log("OK  fixed duplicate period (Scambray, 2021)")

# ================================================================ Chapter 2
# 2.4 design implications forward reference
for p in find_paras("form the foundation of the system architecture presented in Chapter 3."):
    set_para_text(p, p.text.replace("presented in Chapter 3.", "presented in Chapter 4."))
    log("OK  2.4 forward reference -> Chapter 4")

# 2.5 summary forward reference
for p in find_paras("The following chapter discusses the research methodology, system architecture, database "
                    "design, and implementation approach adopted in developing the proposed system."):
    set_para_text(p, p.text.replace(
        "The following chapter discusses the research methodology, system architecture, database design, and "
        "implementation approach adopted in developing the proposed system.",
        "The following chapter presents the methodology and requirements analysis conducted for VulnScan, including "
        "the Agile software development methodology and the functional and non-functional requirements that guide "
        "the proposed system design."))
    log("OK  2.5 summary forward reference fixed")

# ================================================================ Chapter 3
# Agile definition citation (Beck et al., 2001)
for p in find_paras("regular delivery of functional software. Unlike traditional linear methodologies"):
    set_para_text(p, p.text.replace(
        "regular delivery of functional software.",
        "regular delivery of functional software (Beck et al., 2001).", 1))
    log("OK  3.1 added Beck et al. (2001) citation")

# ---------------------------------------------------------------- FR table
FR_TABLE_IDX = 3  # Table 3 = Functional Requirements
tbl = doc.tables[FR_TABLE_IDX]
FR_UPDATE = {
    "FR-01": "The system shall allow registered users to log in securely using their email address and password and "
             "to log out of the application.",
}
NEW_FRS = [
    ("FR-11", "User Management",
     "The system shall allow administrators to create, update, disable, and assign roles to user accounts."),
    ("FR-12", "Single Sign-On (Google)",
     "The system shall allow registered users to sign in using their Google account through OAuth 2.0 single sign-on "
     "when the verified email address matches a provisioned user account."),
    ("FR-13", "Scan Report Generation and Export",
     "The system shall generate structured scan reports summarising detected vulnerabilities, risk levels, and "
     "remediation guidance, and shall allow authorised users to export scan results in portable formats (e.g., "
     "PDF and CSV)."),
]

def set_cell(cell, text):
    for extra in cell.paragraphs[1:]:
        extra._element.getparent().remove(extra._element)
    set_para_text(cell.paragraphs[0], text)

rows = tbl.rows
# update FR-01 description
for r in rows:
    if r.cells[0].text.strip() == "FR-01":
        set_cell(r.cells[2], FR_UPDATE["FR-01"])
        log("OK  FR-01 description updated")
# append new FR rows (clone last data row to preserve formatting)
last_row_el = rows[-1]._tr
for fid, name, desc in NEW_FRS:
    new_tr = deepcopy(last_row_el)
    last_row_el.addnext(new_tr)
    last_row_el = new_tr
    # wrap to row object
    from docx.table import Table
    # cells accessible via the new tr through docx table model:
    new_tbl_row = None
    for r2 in tbl.rows:
        if r2._tr is new_tr:
            new_tbl_row = r2
            break
    set_cell(new_tbl_row.cells[0], fid)
    set_cell(new_tbl_row.cells[1], name)
    set_cell(new_tbl_row.cells[2], desc)
    log(f"OK  appended {fid} {name}")

# ================================================================ Chapter 4
# 4.1 Presentation Layer paragraph (developer -> view/select scan profiles)
replace_para(
    "The Presentation Layer provides separate interfaces for Developers and Administrators through a web "
    "application. Developers are able to initiate vulnerability scans, review scan results, and manage scan "
    "profiles, whereas Administrators perform system management tasks such as user administration, vulnerability "
    "management, and monitoring system activities.",
    "The Presentation Layer provides separate interfaces for Developers and Administrators through a web "
    "application. Developers are able to initiate vulnerability scans, view and select predefined scan profiles, "
    "and review scan results, whereas Administrators perform system management tasks such as user and scan profile "
    "management, vulnerability management, and monitoring of system activities.")

# 4.3 Developer dashboard description
replace_para(
    "The system provides separate interfaces based on user roles. After successful authentication, Developers are "
    "redirected to the Developer Dashboard, where they can manage scan profiles, initiate vulnerability scans, "
    "monitor scan progress, and review previous scan results.",
    "The system provides separate interfaces based on user roles. After successful authentication, Developers are "
    "redirected to the Developer Dashboard, where they can initiate vulnerability scans, select an appropriate scan "
    "profile, monitor scan progress, and review previous scan results.")

# 4.3 Login page paragraph (email/password + Google SSO + admin-provisioned)
replace_para(
    "The Login Page serves as the entry point to the system by allowing registered users to authenticate using "
    "their credentials. Upon successful login, users are redirected to the appropriate dashboard according to their "
    "assigned role.",
    "The Login Page serves as the entry point to the system, allowing registered users to authenticate using their "
    "email address and password or through Google single sign-on. Because user accounts are provisioned by "
    "Administrators, the system does not provide public registration. Upon successful login, users are redirected "
    "to the appropriate dashboard according to their assigned role.")

# 4.3 Figure 4.3 purpose (Google)
replace_para(
    "This interface serves as the entry point to the VulnScan platform, allowing registered users to authenticate "
    "securely using their email address and password.",
    "This interface serves as the entry point to the VulnScan platform, allowing registered users to authenticate "
    "securely using their email address and password or through Google single sign-on.")

# 4.3 Figure 4.4 purpose (scan history wording)
replace_para(
    "It demonstrates how users create new scans by selecting a target URL and scan profile while providing quick "
    "access to previous scan results and scan management features.",
    "It demonstrates how users create new scans by selecting a target URL and scan profile while providing quick "
    "access to previous scan results, scan history, and the scan profiles available to them.")

# 4.4.1 authentication paragraph wording
replace_para(
    "The user authentication process ensures that only authorised users can access the VulnScan platform. When a "
    "user submits their login credentials, the request is forwarded to the Flask REST API, where the credentials "
    "are validated against the information stored in the User entity. Passwords are verified using secure hashing "
    "techniques to protect user credentials during authentication.",
    "The user authentication process ensures that only authorised users can access the VulnScan platform. When a "
    "user signs in using their registered email address and password, the request is forwarded to the Flask REST "
    "API, where the credentials are validated against the information stored in the User entity. Passwords are "
    "stored and verified using secure hashing techniques to protect user credentials during authentication.")

# Insert Google SSO paragraph after the JWT paragraph (4.4.1)
jwt_paras = find_paras("Upon successful authentication, the system generates a JSON Web Token (JWT) that is returned "
                       "to the client.")
if len(jwt_paras) == 1:
    clone_after(jwt_paras[0], jwt_paras[0],
        "In addition to local authentication, VulnScan supports single sign-on through Google using the OAuth 2.0 "
        "authorisation code flow. When a user chooses to sign in with Google, the system redirects the user to "
        "Google's authorisation server, where the user consents to share their verified email address. The backend "
        "then exchanges the returned authorisation code for an access token and retrieves the user's profile "
        "information. The verified email address is matched against the User entity; if a matching active account "
        "exists, authentication succeeds and a JWT is issued. User accounts are provisioned by Administrators, so "
        "accounts are not created automatically during Google authentication. Successful and failed sign-in attempts, "
        "including Google authentication, are recorded in the SecurityAuditLog.")
    log("OK  inserted Google SSO paragraph in 4.4.1")
else:
    log(f"!! Google SSO insert skipped (matched {len(jwt_paras)})")

# ---------------------------------------------------------------- save
doc.save(PATH)
print("\n".join(report))
print("\nSaved:", PATH)
