"""Firestore access for the 'users' collection + password hashing.

Each user document is keyed by username for simple, direct lookups.
"""

from werkzeug.security import check_password_hash, generate_password_hash

from firebase_init import get_db

COLLECTION = "users"


def get_user(username):
    if not username:
        return None
    db = get_db()
    snap = db.collection(COLLECTION).document(username).get()
    if not snap.exists:
        return None
    data = snap.to_dict()
    data["username"] = snap.id
    return data


def create_user(username, password, role, typical_ip, typical_location, typical_login_hours, is_blocked=False):
    """Used by the seed script to provision demo/initial accounts."""
    db = get_db()
    db.collection(COLLECTION).document(username).set({
        # Explicit pbkdf2:sha256 - Werkzeug's newer scrypt default hits a Windows/OpenSSL
        # "malloc failure" intermittently on some setups; pbkdf2 is pure-hashlib and reliable.
        "password_hash": generate_password_hash(password, method="pbkdf2:sha256"),
        "role": role,
        "typical_ip": typical_ip,
        "typical_location": typical_location,
        "typical_login_hours": typical_login_hours,
        "is_blocked": is_blocked,
        "totp_secret": None,
        "mfa_enrolled": False,
    })


def verify_password(user, password):
    if not user or not user.get("password_hash"):
        return False
    return check_password_hash(user["password_hash"], password)


def set_blocked(username, blocked: bool):
    db = get_db()
    db.collection(COLLECTION).document(username).update({"is_blocked": blocked})


def set_totp_secret(username, secret):
    db = get_db()
    db.collection(COLLECTION).document(username).update({"totp_secret": secret})


def set_mfa_enrolled(username, enrolled: bool = True):
    db = get_db()
    db.collection(COLLECTION).document(username).update({"mfa_enrolled": enrolled})


def get_all_users():
    db = get_db()
    users = []
    for snap in db.collection(COLLECTION).stream():
        d = snap.to_dict()
        d["username"] = snap.id
        users.append(d)
    return users


def get_users_by_role(role):
    db = get_db()
    users = []
    for snap in db.collection(COLLECTION).where("role", "==", role).stream():
        d = snap.to_dict()
        d["username"] = snap.id
        users.append(d)
    return users
