"""Scan profile management service."""
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import ProfileModule, Scan, ScanProfile, Vulnerability
from app.utils.validators import ValidationError, validate_int_field


class ScanProfileServiceError(Exception):
    pass


def list_profiles():
    return ScanProfile.query.order_by(ScanProfile.Name.asc()).all()


def get_profile(profile_id):
    return db.session.get(ScanProfile, int(profile_id))


def _normalise_profile_args(name, max_depth, follow_external, request_delay_ms, max_pages):
    if not name or not str(name).strip():
        raise ScanProfileServiceError("Profile name is required.")
    name = str(name).strip()
    if len(name) > 30:
        raise ScanProfileServiceError("Profile name must be 30 characters or fewer.")
    if ScanProfile.query.filter_by(Name=name).first() is not None:
        raise ScanProfileServiceError("A scan profile with this name already exists.")
    try:
        max_depth = validate_int_field(max_depth, "Max depth", 0, 5)
        request_delay_ms = validate_int_field(request_delay_ms, "Request delay", 0, 10000)
        max_pages = validate_int_field(max_pages, "Max pages", 1, 500)
    except ValidationError as exc:
        raise ScanProfileServiceError(str(exc)) from exc
    return name, max_depth, bool(follow_external), request_delay_ms, max_pages


def _resolve_module_ids(module_vuln_ids):
    """Return a validated, de-duplicated list of Vulnerability IDs."""
    ids = []
    for raw in module_vuln_ids or []:
        try:
            vid = int(raw)
        except (TypeError, ValueError):
            raise ScanProfileServiceError("Module list contains an invalid id.") from None
        vuln = db.session.get(Vulnerability, vid)
        if vuln is None:
            raise ScanProfileServiceError(
                f"Vulnerability module id {vid} does not exist."
            )
        if not vuln.IsEnabled:
            raise ScanProfileServiceError(
                f"Vulnerability '{vuln.Name}' is disabled."
            )
        if vid not in ids:
            ids.append(vid)
    return ids


def create_profile(name, max_depth=2, follow_external=False,
                   request_delay_ms=200, max_pages=30, module_vuln_ids=None):
    name, max_depth, follow_external, request_delay_ms, max_pages = _normalise_profile_args(
        name, max_depth, follow_external, request_delay_ms, max_pages
    )
    profile = ScanProfile(
        Name=name,
        MaxDepth=max_depth,
        FollowExternalLinks=follow_external,
        RequestDelayMs=request_delay_ms,
        MaxPages=max_pages,
    )
    db.session.add(profile)
    db.session.flush()
    for vid in _resolve_module_ids(module_vuln_ids):
        db.session.add(ProfileModule(ScanProfileID=profile.ScanProfileID, VulnerabilityID=vid))
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise ScanProfileServiceError("A scan profile with this name already exists.")
    return profile


def update_profile(profile_id, *, name=None, max_depth=None, follow_external=None,
                   request_delay_ms=None, max_pages=None, module_vuln_ids=None):
    profile = get_profile(profile_id)
    if profile is None:
        raise ScanProfileServiceError("Scan profile not found.")

    if name is not None:
        name = str(name).strip()
        if not name:
            raise ScanProfileServiceError("Profile name is required.")
        if len(name) > 30:
            raise ScanProfileServiceError("Profile name must be 30 characters or fewer.")
        existing = ScanProfile.query.filter(
            ScanProfile.Name == name,
            ScanProfile.ScanProfileID != profile.ScanProfileID,
        ).first()
        if existing:
            raise ScanProfileServiceError("A scan profile with this name already exists.")
        profile.Name = name

    try:
        if max_depth is not None:
            profile.MaxDepth = validate_int_field(max_depth, "Max depth", 0, 5)
        if follow_external is not None:
            profile.FollowExternalLinks = bool(follow_external)
        if request_delay_ms is not None:
            profile.RequestDelayMs = validate_int_field(request_delay_ms, "Request delay", 0, 10000)
        if max_pages is not None:
            profile.MaxPages = validate_int_field(max_pages, "Max pages", 1, 500)
    except ValidationError as exc:
        raise ScanProfileServiceError(str(exc)) from exc

    if module_vuln_ids is not None:
        new_ids = _resolve_module_ids(module_vuln_ids)
        existing = {pm.VulnerabilityID for pm in profile.modules}
        desired = set(new_ids)
        for pm in list(profile.modules):
            if pm.VulnerabilityID not in desired:
                db.session.delete(pm)
        for vid in new_ids:
            if vid not in existing:
                db.session.add(
                    ProfileModule(ScanProfileID=profile.ScanProfileID, VulnerabilityID=vid)
                )

    db.session.commit()
    return profile


def delete_profile(profile_id):
    profile = get_profile(profile_id)
    if profile is None:
        raise ScanProfileServiceError("Scan profile not found.")
    if profile.scans.count() > 0:
        raise ScanProfileServiceError(
            "This scan profile is referenced by existing scans and cannot be deleted."
        )
    db.session.delete(profile)
    db.session.commit()
    return True
