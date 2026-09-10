"""Shared string constants used across VulnScan (avoid typos/magic strings)."""

# ------------------------------------------------------------- user roles
ROLE_ADMINISTRATOR = "Administrator"
ROLE_DEVELOPER = "Developer"

# ------------------------------------------------------------- scan status
SCAN_STATUS_PENDING = "Pending"
SCAN_STATUS_RUNNING = "Running"
SCAN_STATUS_COMPLETED = "Completed"
SCAN_STATUS_FAILED = "Failed"
SCAN_STATUS_CANCELLED = "Cancelled"
SCAN_STATUSES = (
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
    SCAN_STATUS_CANCELLED,
)

# ------------------------------------------------------------- finding status
FINDING_STATUS_OPEN = "Open"
FINDING_STATUS_RESOLVED = "Resolved"
FINDING_STATUS_FALSE_POSITIVE = "False Positive"
FINDING_STATUSES = (
    FINDING_STATUS_OPEN,
    FINDING_STATUS_RESOLVED,
    FINDING_STATUS_FALSE_POSITIVE,
)

# ------------------------------------------------------------- severity (CVSS)
SEVERITY_NONE = "None"
SEVERITY_LOW = "Low"
SEVERITY_MEDIUM = "Medium"
SEVERITY_HIGH = "High"
SEVERITY_CRITICAL = "Critical"
SEVERITIES = (
    SEVERITY_NONE,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    SEVERITY_HIGH,
    SEVERITY_CRITICAL,
)
SEVERITY_ORDER = {level: i for i, level in enumerate(SEVERITIES)}

# ------------------------------------------------------------- audit log
AUDIT_CATEGORY_AUTHENTICATION = "Authentication"
AUDIT_CATEGORY_USER_MANAGEMENT = "User Management"
AUDIT_CATEGORY_VULNERABILITY_MANAGEMENT = "Vulnerability Management"
AUDIT_CATEGORY_PROFILE_MANAGEMENT = "Scan Profile Management"
AUDIT_CATEGORY_SCAN = "Scan"
AUDIT_CATEGORY_FINDING = "Finding"
AUDIT_CATEGORY_REPORT = "Report"
AUDIT_CATEGORY_SYSTEM = "System"
AUDIT_CATEGORY_ACCESS = "Access Control"

AUDIT_STATUS_SUCCESS = "Success"
AUDIT_STATUS_FAILURE = "Failure"

# ------------------------------------------------------------- canonical vulnerability names used by modules
NAME_SQL_INJECTION = "SQL Injection"
NAME_CROSS_SITE_SCRIPTING = "Cross-Site Scripting (XSS)"
NAME_MISSING_SECURITY_HEADERS = "Missing HTTP Security Headers"
