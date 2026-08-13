"""Rule-based risk engine.

Scores a login attempt using the exact weighted rules specified:

  - 3+ failed logins in 5 min                         -> +40
  - Device fingerprint not seen before                 -> +20
  - IP differs from user's typical location             -> +25
  - Login outside user's normal hours                   -> +15
  - Login from 2 far locations within short time         -> +50 (impossible travel)

Decision thresholds (applied by the caller in routes/auth_routes.py):
  0-20   -> Allow
  21-50  -> Require MFA
  51+    -> Block
"""

from config import Config
from services import geo_service, log_service


def _hour_is_normal(hour, typical_login_hours):
    if not typical_login_hours or len(typical_login_hours) != 2:
        return True  # no baseline configured -> don't penalize
    start, end = typical_login_hours
    if start <= end:
        return start <= hour < end
    return hour >= start or hour < end  # overnight range, e.g. [22, 6]


def compute_risk(user, ip, device_fingerprint, login_time, location):
    """Return (risk_score, [signal_strings])."""
    username = user["username"]
    score = 0
    signals = []

    # Rule 1: 3+ failed logins in the last 5 minutes
    failed_count = log_service.count_recent_failed_logins(
        username,
        minutes=Config.FAILED_LOGIN_WINDOW_MINUTES,
    )
    if failed_count >= Config.FAILED_LOGIN_THRESHOLD:
        score += Config.RISK_FAILED_LOGINS
        signals.append(f"{failed_count} failed logins in the last {Config.FAILED_LOGIN_WINDOW_MINUTES} minutes")

    # Rule 2: device fingerprint not seen before
    if not log_service.device_seen_before(username, device_fingerprint):
        score += Config.RISK_NEW_DEVICE
        signals.append("New/unrecognized device")

    # Rule 3: IP/location differs from the user's typical location
    typical_ip = user.get("typical_ip")
    typical_location = user.get("typical_location")
    current_label = location.get("label") if location else None
    if ip != typical_ip and current_label != typical_location:
        score += Config.RISK_UNUSUAL_LOCATION
        signals.append(f"Unusual IP/location ({current_label or ip}, expected {typical_location or typical_ip})")

    # Rule 4: login outside the user's normal hours
    if not _hour_is_normal(login_time.hour, user.get("typical_login_hours")):
        score += Config.RISK_ODD_HOUR
        signals.append(f"Login at unusual hour ({login_time.strftime('%H:%M')})")

    # Rule 5: impossible travel - far apart locations in a short time window
    last = log_service.get_last_known_location(username)
    if last and location and last["location"].get("lat") is not None and location.get("lat") is not None:
        distance_km = geo_service.haversine_km(
            last["location"]["lat"], last["location"]["lon"],
            location["lat"], location["lon"],
        )
        minutes_elapsed = (login_time - last["timestamp"]).total_seconds() / 60.0
        if distance_km >= Config.IMPOSSIBLE_TRAVEL_KM and 0 <= minutes_elapsed <= Config.IMPOSSIBLE_TRAVEL_MINUTES:
            score += Config.RISK_IMPOSSIBLE_TRAVEL
            signals.append(
                f"Impossible travel: {int(distance_km)} km from last login in {int(minutes_elapsed)} min"
            )

    return score, signals


def decide(score):
    """Map a risk score to a decision: 'allow' | 'mfa_required' | 'block'."""
    if score <= Config.RISK_ALLOW_MAX:
        return "allow"
    if score <= Config.RISK_MFA_MAX:
        return "mfa_required"
    return "block"
