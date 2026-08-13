"""TOTP-based MFA service (pyotp + qrcode), compatible with Google Authenticator."""

import base64
from io import BytesIO

import pyotp
import qrcode


def generate_secret():
    return pyotp.random_base32()


def get_totp_uri(secret, username, issuer="SentinelAccess"):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_otp(secret, code):
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)
    except Exception:
        return False


def generate_qr_data_uri(uri):
    """Build a QR code PNG for the provisioning URI and return it as a base64 data URI."""
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
