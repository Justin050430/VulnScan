"""
Authentication service - credential validation, JWT issuance and logout.

JWT handling uses Flask-JWT-Extended.  Logout is enforced through a jti
(claim-id) revocation list stored in memory with the token expiry so revoked
tokens are rejected until they naturally expire.
"""
import logging
import threading
import time
from datetime import datetime, timezone

from flask_jwt_extended import create_access_token

from app.extensions import db
from app.models import User
from app.utils.constants import (
    AUDIT_CATEGORY_AUTHENTICATION,
    AUDIT_STATUS_FAILURE,
    AUDIT_STATUS_SUCCESS,
)

logger = logging.getLogger("vulnscan.auth")

# ---------------------------------------------------------------------------
# In-memory revocation store: {jti: exp_timestamp}
# ---------------------------------------------------------------------------
_revoked_lock = threading.Lock()
_revoked_jtis = {}


def _now():
    return int(time.time())


def revoke_jti(jti, exp):
    with _revoked_lock:
        _revoked_jtis[jti] = exp
        # opportunistic cleanup of expired entries
        cutoff = _now()
        expired = [k for k, v in _revoked_jtis.items() if v < cutoff]
        for k in expired:
            _revoked_jtis.pop(k, None)


def is_token_revoked(jwt_payload):
    jti = jwt_payload.get("jti")
    if jti is None:
        return False
    exp = jwt_payload.get("exp")
    with _revoked_lock:
        return jti in _revoked_jtis and (exp is None or exp > _now())


def authenticate_user(email, password):
    """Return the User on success, otherwise None."""
    if not email or not password:
        return None
    user = User.query.filter_by(Email=email.strip().lower()).first()
    if user is None or not user.IsActive:
        return None
    if not user.check_password(password):
        return None
    return user


def issue_token_for_user(user):
    """Create an access token carrying the user's identity and role."""
    additional_claims = {
        "role": user.Role,
        "email": user.Email,
        "name": user.Username,
    }
    return create_access_token(
        identity=str(user.UserID), additional_claims=additional_claims
    )


def record_login_success(user, ip_address=None):
    user.LastLogin = datetime.now(timezone.utc).replace(tzinfo=None)
    db.session.commit()
    from app.services.audit_service import write_audit

    write_audit(
        category=AUDIT_CATEGORY_AUTHENTICATION,
        action="LOGIN_SUCCESS",
        description=f"User {user.Email} signed in successfully.",
        user=user,
        entity_type="User",
        entity_id=user.UserID,
        status=AUDIT_STATUS_SUCCESS,
        ip_address=ip_address,
    )


def record_login_failure(email, ip_address=None, reason="invalid credentials"):
    from app.services.audit_service import write_audit

    write_audit(
        category=AUDIT_CATEGORY_AUTHENTICATION,
        action="LOGIN_FAILED",
        description=f"Failed sign-in attempt for {email}: {reason}.",
        user_id=None,
        entity_type="User",
        status=AUDIT_STATUS_FAILURE,
        ip_address=ip_address,
    )


def record_logout(user, ip_address=None):
    from app.services.audit_service import write_audit

    write_audit(
        category=AUDIT_CATEGORY_AUTHENTICATION,
        action="LOGOUT",
        description=f"User {user.Email} signed out.",
        user=user,
        entity_type="User",
        entity_id=user.UserID,
        status=AUDIT_STATUS_SUCCESS,
        ip_address=ip_address,
    )
