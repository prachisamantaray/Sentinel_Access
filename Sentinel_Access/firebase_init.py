"""Firebase Admin SDK bootstrap.

Initializes a single Firebase Admin app from the service account key JSON
file and exposes a shared Firestore client via get_db().
"""

import os
import firebase_admin
from firebase_admin import credentials, firestore

_db = None


def init_firebase(cred_path=None):
    """Initialize the Firebase Admin app (once) and return the Firestore client."""
    global _db
    if _db is not None:
        return _db

    cred_path = cred_path or os.environ.get("FIREBASE_CRED_PATH", "serviceAccountKey.json")

    if not os.path.exists(cred_path):
        raise FileNotFoundError(
            f"Firebase service account key not found at '{cred_path}'.\n"
            "Download it from Firebase Console -> Project Settings -> Service Accounts "
            "-> Generate new private key, save it as 'serviceAccountKey.json' in the "
            "project root (or point FIREBASE_CRED_PATH at it), then try again."
        )

    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)

    _db = firestore.client()
    return _db


def get_db():
    """Return the shared Firestore client, initializing it on first use."""
    global _db
    if _db is None:
        return init_firebase()
    return _db
