"""
Reference/seed data for VulnScan.

Populates:
  * the Vulnerability knowledge base (the three implemented detection modules
    plus additional reference entries),
  * the default scan profiles,
  * the default Administrator and Developer accounts.

The seed is idempotent - existing records are never duplicated.
Default account credentials are supplied through environment variables and are
only used when no matching account exists yet.
"""
import logging
import os

from app.extensions import db
from app.models import ProfileModule, ScanProfile, User, Vulnerability
from app.utils.constants import (
    ROLE_ADMINISTRATOR,
    ROLE_DEVELOPER,
)

logger = logging.getLogger("vulnscan.seeds")

# ---------------------------------------------------------------------------
# Vulnerability knowledge base
# ---------------------------------------------------------------------------
VULNERABILITIES = [
    {
        "Name": "SQL Injection",
        "OWASPCategory": "Injection",
        "Description": (
            "SQL Injection (SQLi) occurs when untrusted user input is embedded "
            "directly into SQL queries without parameterisation. An attacker can "
            "manipulate queries to read, modify or delete database records, bypass "
            "authentication or execute administrative functions."
        ),
        "Impact": (
            "Unauthorised access to sensitive data, data loss or corruption, "
            "authentication bypass, and in severe cases full compromise of the "
            "database server."
        ),
        "Recommendation": (
            "Use parameterised queries / prepared statements and stored procedures "
            "exclusively. Apply strict input validation and least-privilege database "
            "accounts. Never concatenate user input into SQL."
        ),
        "SecurityCodingPractice": (
            "Use an ORM or parameterised statements; escape dynamic identifiers; "
            "validate and whitelist input; do not expose database errors to users."
        ),
        "OWASPReference": "A03:2021 - Injection",
        "ReferenceURL": "https://owasp.org/Top10/A03_2021-Injection/",
        "IsEnabled": True,
    },
    {
        "Name": "Cross-Site Scripting (XSS)",
        "OWASPCategory": "Injection",
        "Description": (
            "Cross-Site Scripting (XSS) allows an attacker to inject client-side "
            "scripts into web pages viewed by other users. Reflected XSS occurs when "
            "input is echoed back without output encoding."
        ),
        "Impact": (
            "Session hijacking, account takeover, credential theft, defacement and "
            "the execution of arbitrary actions in the context of the victim."
        ),
        "Recommendation": (
            "Apply context-aware output encoding, use a Content Security Policy "
            "(CSP), set the HttpOnly and Secure flags on cookies, and sanitise "
            "untrusted HTML input."
        ),
        "SecurityCodingPractice": (
            "Encode output based on context (HTML, attribute, URL, JavaScript); "
            "use frameworks that auto-escape; never use innerHTML with untrusted data."
        ),
        "OWASPReference": "A03:2021 - Injection",
        "ReferenceURL": "https://owasp.org/www-community/attacks/xss/",
        "IsEnabled": True,
    },
    {
        "Name": "Missing HTTP Security Headers",
        "OWASPCategory": "Security Misconfiguration",
        "Description": (
            "Security misconfiguration occurs when a web server or application is "
            "deployed without recommended HTTP security headers such as "
            "Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, "
            "Strict-Transport-Security, Referrer-Policy and Permissions-Policy."
        ),
        "Impact": (
            "Increased exposure to clickjacking, MIME sniffing, referrer leakage and "
            "weakened defence-in-depth against XSS and other client-side attacks."
        ),
        "Recommendation": (
            "Set the missing security headers with secure values; enforce HSTS on "
            "HTTPS pages; verify configuration after every deployment."
        ),
        "SecurityCodingPractice": (
            "Configure security headers centrally (web server / framework middleware) "
            "and include header checks in automated security tests."
        ),
        "OWASPReference": "A05:2021 - Security Misconfiguration",
        "ReferenceURL": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "IsEnabled": True,
    },
    {
        "Name": "Broken Access Control (IDOR)",
        "OWASPCategory": "Access Control",
        "Description": (
            "Broken access control allows users to act outside their intended "
            "permissions, e.g. accessing another user's records by changing an object "
            "identifier (Insecure Direct Object Reference)."
        ),
        "Impact": "Unauthorised viewing or modification of data and privilege escalation.",
        "Recommendation": (
            "Enforce server-side authorisation for every request, use indirect object "
            "references and deny by default."
        ),
        "SecurityCodingPractice": (
            "Never rely on client-side controls; validate object ownership on the "
            "server; apply the principle of least privilege."
        ),
        "OWASPReference": "A01:2021 - Broken Access Control",
        "ReferenceURL": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "IsEnabled": True,
    },
    {
        "Name": "Sensitive Data Exposure",
        "OWASPCategory": "Cryptographic Failures",
        "Description": (
            "Sensitive data (passwords, tokens, personal data) is exposed when it is "
            "transmitted or stored without adequate protection."
        ),
        "Impact": "Data breaches, identity theft and regulatory non-compliance.",
        "Recommendation": (
            "Encrypt data in transit (TLS) and at rest; hash passwords; avoid "
            "storing secrets in code or logs."
        ),
        "SecurityCodingPractice": (
            "Use modern authenticated encryption, key management and strong password "
            "hashing (e.g. PBKDF2, bcrypt, argon2)."
        ),
        "OWASPReference": "A02:2021 - Cryptographic Failures",
        "ReferenceURL": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        "IsEnabled": True,
    },
    {
        "Name": "Security Misconfiguration",
        "OWASPCategory": "Security Misconfiguration",
        "Description": (
            "Insecure default configurations, verbose error messages, directory "
            "listings or unnecessary features left enabled expose the application."
        ),
        "Impact": "Information disclosure and additional attack surface.",
        "Recommendation": (
            "Harden configurations, disable verbose errors, remove unused features "
            "and apply patches promptly."
        ),
        "SecurityCodingPractice": (
            "Adopt repeatable, reviewable configuration and infrastructure-as-code "
            "practices."
        ),
        "OWASPReference": "A05:2021 - Security Misconfiguration",
        "ReferenceURL": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        "IsEnabled": True,
    },
    {
        "Name": "Cross-Site Request Forgery (CSRF)",
        "OWASPCategory": "Broken Access Control",
        "Description": (
            "CSRF tricks an authenticated user's browser into submitting an unwanted "
            "request to an application in which they are trusted."
        ),
        "Impact": "State-changing actions performed without the user's consent.",
        "Recommendation": (
            "Use synchroniser tokens or SameSite cookies, and verify the origin of "
            "state-changing requests."
        ),
        "SecurityCodingPractice": (
            "Include a per-session CSRF token in forms; set SameSite=Lax/Strict on "
            "cookies."
        ),
        "OWASPReference": "A01:2021 - Broken Access Control",
        "ReferenceURL": "https://owasp.org/www-community/attacks/csrf",
        "IsEnabled": True,
    },
    {
        "Name": "Server-Side Request Forgery (SSRF)",
        "OWASPCategory": "Server-Side Request Forgery",
        "Description": (
            "SSRF allows an attacker to make the server issue requests to internal "
            "resources, potentially reading internal services or metadata endpoints."
        ),
        "Impact": "Access to internal networks/services and sensitive cloud metadata.",
        "Recommendation": (
            "Validate and allow-list destinations, block private/loopback addresses "
            "and avoid passing raw URLs to server-side fetch functions."
        ),
        "SecurityCodingPractice": (
            "Enforce an egress allow-list and reject requests to private networks."
        ),
        "OWASPReference": "A10:2021 - Server-Side Request Forgery",
        "ReferenceURL": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/",
        "IsEnabled": True,
    },
]

DEFAULT_PROFILES = [
    {
        "Name": "Quick Scan",
        "MaxDepth": 1,
        "FollowExternalLinks": False,
        "RequestDelayMs": 150,
        "MaxPages": 10,
        "Modules": ["Cross-Site Scripting (XSS)", "Missing HTTP Security Headers"],
    },
    {
        "Name": "OWASP Top 10 Full Scan",
        "MaxDepth": 2,
        "FollowExternalLinks": False,
        "RequestDelayMs": 200,
        "MaxPages": 30,
        "Modules": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Missing HTTP Security Headers",
        ],
    },
    {
        "Name": "Basic Security Headers",
        "MaxDepth": 1,
        "FollowExternalLinks": False,
        "RequestDelayMs": 100,
        "MaxPages": 20,
        "Modules": ["Missing HTTP Security Headers"],
    },
]


def _seed_vulnerabilities():
    created = []
    for item in VULNERABILITIES:
        existing = Vulnerability.query.filter_by(Name=item["Name"]).first()
        if existing:
            continue
        vuln = Vulnerability(**item)
        db.session.add(vuln)
        created.append(item["Name"])
    if created:
        db.session.flush()
    return created


def _seed_profiles():
    created = []
    for item in DEFAULT_PROFILES:
        profile = ScanProfile.query.filter_by(Name=item["Name"]).first()
        if profile:
            continue
        profile = ScanProfile(
            Name=item["Name"],
            MaxDepth=item["MaxDepth"],
            FollowExternalLinks=item["FollowExternalLinks"],
            RequestDelayMs=item["RequestDelayMs"],
            MaxPages=item["MaxPages"],
        )
        db.session.add(profile)
        db.session.flush()
        for vuln_name in item["Modules"]:
            vuln = Vulnerability.query.filter_by(Name=vuln_name).first()
            if vuln:
                db.session.add(
                    ProfileModule(
                        ScanProfileID=profile.ScanProfileID,
                        VulnerabilityID=vuln.VulnerabilityID,
                    )
                )
        created.append(item["Name"])
    return created


def _seed_users():
    """Create the default Administrator and Developer accounts if absent."""
    created = []

    admin_email = os.getenv("SEED_ADMIN_EMAIL", "admin@vulnscan.local")
    admin_password = os.getenv("SEED_ADMIN_PASSWORD", "Admin@VulnScan2025")
    admin_username = os.getenv("SEED_ADMIN_USERNAME", "admin")

    if User.query.filter_by(Email=admin_email).first() is None \
            and User.query.filter_by(Username=admin_username).first() is None:
        admin = User(
            Username=admin_username,
            Email=admin_email,
            Role=ROLE_ADMINISTRATOR,
            IsActive=True,
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        created.append(f"Administrator {admin_email}")

    dev_email = os.getenv("SEED_DEVELOPER_EMAIL", "developer@vulnscan.local")
    dev_password = os.getenv("SEED_DEVELOPER_PASSWORD", "Developer@VulnScan2025")
    dev_username = os.getenv("SEED_DEVELOPER_USERNAME", "developer")

    if User.query.filter_by(Email=dev_email).first() is None \
            and User.query.filter_by(Username=dev_username).first() is None:
        dev = User(
            Username=dev_username,
            Email=dev_email,
            Role=ROLE_DEVELOPER,
            IsActive=True,
        )
        dev.set_password(dev_password)
        db.session.add(dev)
        created.append(f"Developer {dev_email}")

    return created


def run_seed():
    vulns = _seed_vulnerabilities()
    profiles = _seed_profiles()
    users = _seed_users()
    db.session.commit()

    lines = []
    if vulns:
        lines.append(f"  vulnerabilities: {', '.join(vulns)}")
    if profiles:
        lines.append(f"  scan profiles: {', '.join(profiles)}")
    if users:
        lines.append(f"  users: {', '.join(users)}")
    if not lines:
        lines.append("  nothing to do (already seeded)")
    print("Seed complete:")
    print("\n".join(lines))
