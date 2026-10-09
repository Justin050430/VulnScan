"""
In-memory, per-process scan progress registry (observability, B1).

The scan engine runs inside the web process (see scan_service); this registry
exposes live progress to `GET /api/scans/<id>/progress` without any schema
change.

Delivery contract - honest by design:
  * entries exist only in the process that executed the scan; a restarted
    process (or a different worker) reports `LiveAvailable: false`, and the
    API falls back to database-derived information;
  * `RequestsIssued` comes from the scanner's real request counter and is
    null when unknown - values are never fabricated.
"""
import threading
import time
from typing import Optional

_lock = threading.Lock()
_entries = {}


def start(scan_id, http=None):
    """Register a new scan run (replaces any previous entry for the id)."""
    with _lock:
        _entries[int(scan_id)] = {
            "stage": "queued",
            "started": time.monotonic(),
            "pages_found": 0,
            "pages_done": 0,
            "findings": 0,
            "errors": [],
            "error": None,
            "http": http,
            "finished": False,
        }


def update(scan_id, **fields):
    """Update counters/stage for a running scan (no-op when unknown)."""
    with _lock:
        entry = _entries.get(int(scan_id))
        if entry is None:
            return
        entry.update(fields)


def add_error(scan_id, message):
    """Record a per-module/step error (deduplicated)."""
    with _lock:
        entry = _entries.get(int(scan_id))
        if entry is not None and message not in entry["errors"]:
            entry["errors"].append(message)


def finish(scan_id, stage, error=None):
    """Mark the scan run as finished (stage: completed / failed)."""
    with _lock:
        entry = _entries.get(int(scan_id))
        if entry is None:
            return
        entry["stage"] = stage
        entry["error"] = error
        entry["finished"] = True


def snapshot(scan_id) -> Optional[dict]:
    """Return the live snapshot for a scan, or None when not tracked here."""
    with _lock:
        entry = _entries.get(int(scan_id))
        if entry is None:
            return None
        http = entry["http"]
        return {
            "stage": entry["stage"],
            "pages_found": entry["pages_found"],
            "pages_done": entry["pages_done"],
            "findings": entry["findings"],
            "requests": http.request_count if http is not None else None,
            "errors": list(entry["errors"]),
            "error": entry["error"],
            "finished": entry["finished"],
        }
