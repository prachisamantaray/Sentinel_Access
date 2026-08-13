"""Firestore access for the 'login_attempts' collection.

Queries deliberately filter on a single equality field (user_id) and do any
ordering/windowing in Python. This keeps every query covered by Firestore's
automatic single-field indexes, so no manual composite index setup is needed.
"""

from datetime import datetime, timedelta, timezone

from firebase_admin import firestore

from firebase_init import get_db

COLLECTION = "login_attempts"

FAILED_RESULTS = ("invalid_credentials",)


def log_attempt(user_id, ip, device, device_fingerprint, location, risk_score, result, signals):
    """Create a login_attempts document and return its DocumentReference."""
    db = get_db()
    doc = {
        "user_id": user_id,
        "ip": ip,
        "device": device,
        "device_fingerprint": device_fingerprint,
        "location": location,
        "risk_score": risk_score,
        "result": result,
        "risk_signals_triggered": signals,
        "timestamp": firestore.SERVER_TIMESTAMP,
    }
    _, ref = db.collection(COLLECTION).add(doc)
    return ref


def update_attempt_result(doc_id, result, extra_signals=None):
    db = get_db()
    update = {"result": result}
    if extra_signals:
        update["risk_signals_triggered"] = firestore.ArrayUnion(extra_signals)
    db.collection(COLLECTION).document(doc_id).update(update)


def _to_dict_with_id(snap):
    d = snap.to_dict() or {}
    d["id"] = snap.id
    return d


def get_recent_attempts_for_user(user_id, limit=200):
    """All recent attempts for a user, newest first (sorted in Python)."""
    db = get_db()
    query = db.collection(COLLECTION).where("user_id", "==", user_id).limit(limit)
    docs = [_to_dict_with_id(s) for s in query.stream()]
    docs.sort(key=lambda d: d.get("timestamp") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return docs


def count_recent_failed_logins(user_id, minutes=5, threshold_results=FAILED_RESULTS):
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    attempts = get_recent_attempts_for_user(user_id, limit=200)
    count = 0
    for a in attempts:
        ts = a.get("timestamp")
        if ts is None or a.get("result") not in threshold_results:
            continue
        if ts >= cutoff:
            count += 1
    return count


def device_seen_before(user_id, device_fingerprint):
    attempts = get_recent_attempts_for_user(user_id, limit=200)
    for a in attempts:
        if a.get("result") in FAILED_RESULTS:
            continue  # only count devices used on attempts where the password was correct
        if a.get("device_fingerprint") == device_fingerprint:
            return True
    return False


def get_last_known_location(user_id):
    """Most recent attempt (password was correct) that has location data, or None."""
    attempts = get_recent_attempts_for_user(user_id, limit=200)
    for a in attempts:
        if a.get("result") in FAILED_RESULTS:
            continue
        loc = a.get("location")
        ts = a.get("timestamp")
        if loc and ts:
            return {"location": loc, "timestamp": ts}
    return None


def get_all_attempts(limit=200):
    db = get_db()
    query = db.collection(COLLECTION).order_by("timestamp", direction=firestore.Query.DESCENDING).limit(limit)
    return [_to_dict_with_id(s) for s in query.stream()]
