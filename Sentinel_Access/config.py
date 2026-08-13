import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Central configuration for SentinelAccess, including the exact risk-engine
    weights and decision thresholds specified for the project."""

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    FIREBASE_CRED_PATH = os.environ.get("FIREBASE_CRED_PATH", "serviceAccountKey.json")

    IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "").strip()

    APP_ISSUER = "SentinelAccess"

    # --- Risk engine rule weights (exact scope) ---
    RISK_FAILED_LOGINS = 40       # 3+ failed logins in 5 min
    RISK_NEW_DEVICE = 20          # device fingerprint not seen before
    RISK_UNUSUAL_LOCATION = 25    # IP differs from typical location
    RISK_ODD_HOUR = 15            # login outside normal hours
    RISK_IMPOSSIBLE_TRAVEL = 50   # 2 far locations within short time

    # --- Decision thresholds ---
    RISK_ALLOW_MAX = 20        # 0-20   -> allow, no MFA
    RISK_MFA_MAX = 50          # 21-50  -> MFA required
    # 51+ -> block

    # --- Rule parameters ---
    FAILED_LOGIN_WINDOW_MINUTES = 5
    FAILED_LOGIN_THRESHOLD = 3
    IMPOSSIBLE_TRAVEL_KM = 500
    IMPOSSIBLE_TRAVEL_MINUTES = 60
    MAX_MFA_ATTEMPTS = 5

    LOGIN_ATTEMPTS_HISTORY_LIMIT = 200  # how many past attempts to pull per risk check
