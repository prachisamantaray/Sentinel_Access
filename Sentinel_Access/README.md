# SentinelAccess

Adaptive MFA & Role-Based Threat Detection System.

Flask + Firebase Firestore (firebase-admin) + pyotp/qrcode TOTP MFA + Bootstrap/vanilla JS frontend.

## System flow

```
[Login Page] -> [Auth Service] -> [Risk Engine] -> [MFA Challenge if needed] -> [Session + RBAC] -> [Dashboard]
```

1. **Auth Service** (`services/auth_service.py`) checks the Firestore `users` collection: role, blocked status, hashed password.
2. **Risk Engine** (`services/risk_engine.py`) scores the login attempt (see rules below) using recent history from `login_attempts`.
3. Depending on the score, the user is let straight in, sent to an **MFA challenge** (`services/mfa_service.py`, TOTP/QR via pyotp + qrcode), or **blocked**.
4. Every attempt is logged to Firestore `login_attempts` with IP, device, timestamp, risk score, result, and the signals that fired.
5. On success, a Flask session is created and **RBAC** (`decorators.py`) gates every route/API by role (`admin` / `manager` / `employee`), returning `403` on any cross-role access.
6. Admins get a live **Security Dashboard** of all login attempts plus one-click unblock.

## Project layout

```
app.py                  Flask app factory, blueprint registration, /dashboard router
config.py                Risk weights, thresholds, and settings
firebase_init.py         Firebase Admin SDK bootstrap -> Firestore client
decorators.py             login_required / roles_required (RBAC)
utils.py                  IP/device-fingerprint helpers
services/
  auth_service.py         users collection: lookup, password hashing, block/unblock
  log_service.py           login_attempts collection: writes + risk-relevant queries
  risk_engine.py            the 5 weighted rules + decision thresholds
  mfa_service.py             TOTP secret/URI/QR generation and OTP verification
  geo_service.py             ipinfo.io lookup with deterministic mock fallback
routes/
  auth_routes.py            /login, /mfa, /logout
  admin_routes.py            /admin/* (dashboard, users, security, APIs) - admin only
  manager_routes.py           /manager/* - manager only
  employee_routes.py           /employee/* - employee only
templates/, static/          Bootstrap 5 + vanilla JS frontend
scripts/seed_data.py          creates 3 demo accounts (admin/manager/employee)
```

## Firestore data model

**`users`** (document ID = username):
`password_hash, role (admin|manager|employee), typical_ip, typical_location, typical_login_hours ([start_hour, end_hour]), is_blocked, totp_secret, mfa_enrolled`

**`login_attempts`** (auto-ID):
`user_id, ip, device, device_fingerprint, location, timestamp, risk_score, result, risk_signals_triggered`

`result` is one of: `allowed`, `mfa_required`, `blocked` (the three risk-engine outcomes), plus `invalid_credentials` and `account_blocked` for wrong-password/already-blocked attempts - these extra values are necessary bookkeeping so the "3+ failed logins in 5 min" rule has something to count; they aren't a new feature.

## Risk engine (exact scope)

| Rule | Weight |
|---|---|
| 3+ failed logins in 5 min | +40 |
| Device fingerprint not seen before | +20 |
| IP differs from typical location | +25 |
| Login outside normal hours | +15 |
| Impossible travel (far location, short time) | +50 |

Decision: **0-20 allow** &nbsp;·&nbsp; **21-50 require MFA** &nbsp;·&nbsp; **51+ block** (and the account is flagged `is_blocked = true` until an admin unblocks it).

## Setup

### 1. Firebase

1. In [Firebase Console](https://console.firebase.google.com/), create a project and enable **Firestore Database**.
2. Project Settings -> Service Accounts -> **Generate new private key**.
3. Save the downloaded file as `serviceAccountKey.json` in the project root (same folder as `app.py`). It's git-ignored already.

### 2. Python environment

```bash
cd SentinelAccess
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 3. Configure

```bash
copy .env.example .env
```

Edit `.env` if you want: set `SECRET_KEY` to something random, and optionally `IPINFO_TOKEN` (leave blank to use built-in mock geolocation).

### 4. Seed demo users

```bash
python scripts/seed_data.py
```

Creates:

| Username | Password | Role |
|---|---|---|
| `admin1` | `Admin@123` | admin |
| `manager1` | `Manager@123` | manager |
| `employee1` | `Employee@123` | employee |

All seeded with `typical_ip = 127.0.0.1` and `typical_login_hours = [8, 20]`, so a normal local test login during 08:00-20:00 stays low-risk.

> **Windows note:** passwords are hashed with `pbkdf2:sha256` (set explicitly in `services/auth_service.py`). Werkzeug's newer default (`scrypt`) can intermittently throw `ValueError: [digital envelope routines] malloc failure` on some Windows/OpenSSL setups - if you ever see that, it's this same issue; re-running `python scripts/seed_data.py --reset` regenerates hashes with the safe method.

### 5. Run

```bash
python app.py
```

Visit http://127.0.0.1:5000 and log in.

## Trying out the risk engine

- **Low risk (allow):** log in normally during 08:00-20:00 from your usual browser -> straight to dashboard, no MFA.
- **New device (+20):** log in from a different browser (or clear cookies) -> pushes score into MFA range on a fresh account.
- **Odd hour (+15):** log in outside 08:00-20:00 server time.
- **3+ failed logins (+40):** enter the wrong password 3 times within 5 minutes, then log in correctly.
- **Unusual location (+25) / impossible travel (+50):** log in via a tool that sends a different `X-Forwarded-For` IP header, or edit the user's `typical_ip`/`typical_location` in Firestore.
- **MFA enrollment:** the first time a login lands in the 21-50 range, you'll see a QR code - scan it with Google Authenticator (or enter the shown secret manually), then enter the 6-digit code.
- **Block + unblock:** push the score to 51+ (e.g. combine several signals) - the account is auto-blocked; log in as `admin1` -> Security Dashboard or Manage Users -> Unblock.

## Attack simulation (demo)

```bash
python scripts/simulate_attack.py [username]
```

Simulates a brute-force login against the given account (default `employee1`) using the real `/login` view function (via Flask's test client - no separate server required, though one can be running alongside it). It sends 4 wrong-password attempts, then 1 attempt with the correct password - the risk engine evaluates the failed-login history plus a "new device" signal on that final attempt (`+40` + `+20` = `60`, past the `51+` block threshold) and auto-blocks the account, exactly mirroring how a real brute-force guess would be caught. Prints every attempt's HTTP status, risk score, result, and triggered signals. Automatically resets the account to unblocked at the start of each run, so it's repeatable.

## RBAC enforcement

- `admin1` can reach `/admin/*` (Security Dashboard, user management, unblock).
- `manager1` can reach `/manager/*` (team roster + limited stats) but gets **403** on any `/admin/*` route.
- `employee1` can reach `/employee/*` (own profile + own login history) but gets **403** on `/admin/*` and `/manager/*`.
- All `/admin/api/*`, `/manager/api/*`, `/employee/api/*` endpoints return **JSON 403** (not a redirect) when hit by an unauthorized role - test with curl/Postman using a logged-in session cookie from the "wrong" role.
