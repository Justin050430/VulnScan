"""
VulnScan database models (8 entities per the final ERD).

    User, Scan, ScanProfile, ProfileModule, Vulnerability,
    DiscoveredPage, Finding, SecurityAuditLog
"""
from .discovered_page import DiscoveredPage
from .finding import Finding
from .profile_module import ProfileModule
from .scan import Scan
from .scan_profile import ScanProfile
from .security_audit_log import SecurityAuditLog
from .user import User
from .vulnerability import Vulnerability

__all__ = [
    "User",
    "Scan",
    "ScanProfile",
    "ProfileModule",
    "Vulnerability",
    "DiscoveredPage",
    "Finding",
    "SecurityAuditLog",
]
