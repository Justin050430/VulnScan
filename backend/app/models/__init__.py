"""
VulnScan database models.

Frozen core ERD (8 entities - do not modify):

    User, Scan, ScanProfile, ProfileModule, Vulnerability,
    DiscoveredPage, Finding, SecurityAuditLog

Trust Boundary Extension (additive - see docs/TRUST_BOUNDARY.md):

    TrustOrganisation, TrustProject, TrustOrganisationMembership,
    TrustProjectMembership, TrustAsset, TrustAuthorizationAttestation,
    TrustPaymentTransaction, TrustScanCredit, TrustCreditRedemption,
    TrustScanContext, TrustAuditEvent, TrustScanCredential,
    TrustScanCredentialBinding
"""
from .discovered_page import DiscoveredPage
from .finding import Finding
from .profile_module import ProfileModule
from .scan import Scan
from .scan_profile import ScanProfile
from .security_audit_log import SecurityAuditLog
from .trust_asset import TrustAsset
from .trust_attestation import TrustAuthorizationAttestation
from .trust_audit_event import TrustAuditEvent
from .trust_credit import TrustCreditRedemption, TrustScanCredit
from .trust_organisation import TrustOrganisation
from .trust_organisation_membership import TrustOrganisationMembership
from .trust_payment import TrustPaymentTransaction
from .trust_project import TrustProject
from .trust_project_membership import TrustProjectMembership
from .trust_scan_context import TrustScanContext
from .trust_scan_credential import (
    TrustScanCredential,
    TrustScanCredentialBinding,
)
from .user import User
from .vulnerability import Vulnerability

#: The frozen eight core entities.
CORE_ENTITIES = [
    "User",
    "Scan",
    "ScanProfile",
    "ProfileModule",
    "Vulnerability",
    "DiscoveredPage",
    "Finding",
    "SecurityAuditLog",
]

#: Additive Trust Boundary Extension entities.
TRUST_ENTITIES = [
    "TrustOrganisation",
    "TrustProject",
    "TrustOrganisationMembership",
    "TrustProjectMembership",
    "TrustAsset",
    "TrustAuthorizationAttestation",
    "TrustPaymentTransaction",
    "TrustScanCredit",
    "TrustCreditRedemption",
    "TrustScanContext",
    "TrustAuditEvent",
    "TrustScanCredential",
    "TrustScanCredentialBinding",
]

__all__ = CORE_ENTITIES + TRUST_ENTITIES
