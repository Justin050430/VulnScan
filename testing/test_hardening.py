"""
Hardening tests (F1 orphan-scan recovery, F2 active-scan concurrency caps).

F1: a scan left Pending/Running by a previous process must be failed at
startup so users are never stuck with a permanently running scan - while a
scan that is alive in this process must never be touched.

F2: new scans are rejected once the per-user / global active-scan caps are
reached (counted from the database, so caps hold across workers).
"""
from datetime import datetime

from conftest import auth


def _target_ids(app):
    """(developer UserID, first ScanProfileID) for fabricating scan rows."""
    with app.app_context():
        from app.models import ScanProfile, User

        user = User.query.filter_by(Username="developer").first()
        profile = ScanProfile.query.first()
        return user.UserID, profile.ScanProfileID


def _fabricate_scan(app, *, name, status, scan_id=None):
    with app.app_context():
        from app.extensions import db
        from app.models import Scan

        user_id, profile_id = _target_ids(app)
        scan = Scan(
            ScanName=name,
            TargetURL="http://127.0.0.1:5199/",
            Status=status,
            StartedAt=datetime.utcnow(),
            UserID=user_id,
            ScanProfileID=profile_id,
        )
        if scan_id is not None:
            scan.ScanID = scan_id
        db.session.add(scan)
        db.session.commit()
        return scan.ScanID


def _basic_profile_id(client, token):
    profiles = client.get("/api/scan-profiles",
                          headers=auth(token)).get_json()["ScanProfiles"]
    return next(p for p in profiles
                if p["Name"] == "Basic Security Headers")["ScanProfileID"]


# -------------------------------------------------------------------------- F1
def test_orphan_scans_are_failed_on_recovery(app, client, dev_token):
    running_id = _fabricate_scan(app, name="Orphan running", status="Running")
    pending_id = _fabricate_scan(app, name="Orphan pending", status="Pending")

    with app.app_context():
        from app.extensions import db
        from app.models import Scan, SecurityAuditLog
        from app.services.scan_service import recover_orphan_scans

        recovered = recover_orphan_scans()
        assert set(recovered) == {running_id, pending_id}
        for sid in recovered:
            scan = db.session.get(Scan, sid)
            assert scan.Status == "Failed"
            assert scan.FinishedAt is not None
        # recovery is audited as a failure event
        entry = (SecurityAuditLog.query
                 .filter_by(Action="ORPHAN_SCANS_RECOVERED").first())
        assert entry is not None
        assert entry.Category == "System"
        assert "orphaned scan" in entry.Description

        # idempotent: nothing left to recover
        assert recover_orphan_scans() == []

    # the user now sees an honest Failed status (not a stuck Running scan)
    for sid in (running_id, pending_id):
        detail = client.get(f"/api/scans/{sid}",
                            headers=auth(dev_token)).get_json()["Scan"]
        assert detail["Status"] == "Failed"


def test_live_scan_is_not_treated_as_orphan(app):
    """A scan with an unfinished in-process progress entry is left alone."""
    live_id = _fabricate_scan(app, name="Live scan", status="Running",
                              scan_id=4242)
    with app.app_context():
        from app.extensions import db
        from app.models import Scan
        from app.scanner import progress
        from app.services.scan_service import recover_orphan_scans

        progress.start(live_id)
        try:
            recovered = recover_orphan_scans()
            assert live_id not in recovered
            assert db.session.get(Scan, live_id).Status == "Running"
        finally:
            progress.finish(live_id, "failed", error="test cleanup")


# -------------------------------------------------------------------------- F2
def test_per_user_active_scan_cap(monkeypatch, app, client, dev_token, target):
    monkeypatch.setitem(app.config, "SCAN_MAX_ACTIVE_PER_USER", 1)
    monkeypatch.setitem(app.config, "SCAN_MAX_ACTIVE_GLOBAL", 0)
    _fabricate_scan(app, name="Occupying scan", status="Running")

    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target,
        "scan_profile_id": _basic_profile_id(client, dev_token),
        "scan_name": "Should be capped",
    })
    assert resp.status_code == 400
    assert "active scan" in resp.get_json()["message"]


def test_global_active_scan_cap(monkeypatch, app, client, dev_token, target):
    monkeypatch.setitem(app.config, "SCAN_MAX_ACTIVE_PER_USER", 0)
    monkeypatch.setitem(app.config, "SCAN_MAX_ACTIVE_GLOBAL", 1)
    _fabricate_scan(app, name="Occupying scan", status="Running")

    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target,
        "scan_profile_id": _basic_profile_id(client, dev_token),
        "scan_name": "Should be capped globally",
    })
    assert resp.status_code == 400
    assert "busy" in resp.get_json()["message"]


def test_caps_ignore_finished_scans(monkeypatch, app, client, dev_token, target):
    """Completed/Failed scans never count towards the active-scan caps."""
    monkeypatch.setitem(app.config, "SCAN_MAX_ACTIVE_PER_USER", 1)
    monkeypatch.setitem(app.config, "SCAN_MAX_ACTIVE_GLOBAL", 1)
    _fabricate_scan(app, name="Old completed", status="Completed")
    _fabricate_scan(app, name="Old failed", status="Failed")

    resp = client.post("/api/scans", headers=auth(dev_token), json={
        "target_url": target,
        "scan_profile_id": _basic_profile_id(client, dev_token),
        "scan_name": "Allowed scan",
    })
    assert resp.status_code == 202
    scan_id = resp.get_json()["Scan"]["ScanID"]
    detail = client.get(f"/api/scans/{scan_id}",
                        headers=auth(dev_token)).get_json()["Scan"]
    assert detail["Status"] == "Completed"
