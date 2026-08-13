"""Attack simulation script (demo purposes only).

Simulates a brute-force login attack against SentinelAccess: several
wrong-password attempts in quick succession, followed by one attempt with
the CORRECT password, all against the real /login view function.

Why the last attempt uses the correct password
------------------------------------------------
The risk engine (services/risk_engine.py) only runs once a password has
been verified as correct - that's by design: a wrong password is already
rejected on its own, so there's nothing for the risk engine to score yet.
The "3+ failed logins in 5 min" signal (+40) is evaluated by looking back
at recent history, and it fires on the attempt where the failed-login
count crosses the threshold. So this script does exactly what a real
brute-force attacker's final, successful guess would trigger: 4 wrong
passwords, then a correct one - and *that* attempt is where the system
looks back, sees the failed-login pattern, adds the "new device" signal
(this script's own distinct User-Agent looks unrecognized), and blocks
the account in real time.

    +40 (3+ failed logins in 5 min) + 20 (new/unrecognized device) = 60
    60 >= 51  ->  BLOCK

This uses Flask's own test client, so it calls the exact same /login view
function as the live app, against the exact same Firestore project - no
separate server needs to be running. If you *do* have `python app.py`
running in another terminal with the Security Dashboard open, you'll see
these attempts land there live (it polls every 5 seconds).

Usage:
    python scripts/simulate_attack.py [username] [--password CORRECT_PASSWORD]

    python scripts/simulate_attack.py                 # attacks employee1 (default demo account)
    python scripts/simulate_attack.py manager1         # attacks manager1 (known demo password)
    python scripts/simulate_attack.py alice --password Secret123   # any other seeded user
"""

import argparse
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app  # noqa: E402
from services import auth_service, log_service  # noqa: E402

WRONG_PASSWORD = "WrongPassword!123"
NUM_FAILED_ATTEMPTS = 4  # + 1 final attempt with the correct password = 5 total, per spec

# Known demo passwords from scripts/seed_data.py, so `python scripts/simulate_attack.py`
# with no arguments just works out of the box.
KNOWN_DEMO_PASSWORDS = {
    "admin1": "Admin@123",
    "manager1": "Manager@123",
    "employee1": "Employee@123",
}


def print_attempt(label, resp, row):
    print(f"  HTTP {resp.status_code}  |  risk_score={row.get('risk_score', 0):<3}  |  "
          f"result={row.get('result', '?'):<18}  |  {label}")
    signals = row.get("risk_signals_triggered") or []
    if signals:
        print(f"    signals: {', '.join(signals)}")


def main():
    parser = argparse.ArgumentParser(description="Simulate a brute-force attack for the SentinelAccess demo.")
    parser.add_argument("username", nargs="?", default="employee1", help="Target username (default: employee1)")
    parser.add_argument("--password", default=None,
                         help="The account's real password (defaults are known for admin1/manager1/employee1)")
    args = parser.parse_args()

    username = args.username
    correct_password = args.password or KNOWN_DEMO_PASSWORDS.get(username)

    user = auth_service.get_user(username)
    if not user:
        print(f"No such user '{username}' in Firestore. Run `python scripts/seed_data.py` first, "
              f"or pass an existing username.")
        return

    if not correct_password:
        print(f"Don't know the real password for '{username}'. Pass it with --password, e.g.\n"
              f"    python scripts/simulate_attack.py {username} --password <their-password>")
        return

    # Reset to a clean, unblocked state so this demo is repeatable run after run.
    if user.get("is_blocked"):
        auth_service.set_blocked(username, False)
        print(f"(Reset: '{username}' was already blocked from a previous run - unblocked to start clean.)\n")

    # A fresh, unique "device" every run, so the new-device signal fires reliably every time
    # this script is demoed - just like a real attacker's unfamiliar machine would.
    device_tag = uuid.uuid4().hex[:8]
    headers = {"User-Agent": f"AttackSimulator/1.0 (demo-run-{device_tag})"}

    print(f"=== Simulating brute-force attack against '{username}' ===")
    print(f"({NUM_FAILED_ATTEMPTS} wrong-password attempts, then 1 correct-password attempt, all within a minute)\n")

    client = app.test_client()
    responses = []  # (label, http_response) in request order

    for i in range(1, NUM_FAILED_ATTEMPTS + 1):
        resp = client.post("/login", data={"username": username, "password": WRONG_PASSWORD},
                            headers=headers, follow_redirects=False)
        responses.append((f"attempt {i}/{NUM_FAILED_ATTEMPTS + 1} - wrong password (rejected)", resp))
        time.sleep(0.5)  # quick succession, well inside the 5-minute lookback window

    print(f"  Now trying the CORRECT password - this is where the risk engine looks back at "
          f"the last {NUM_FAILED_ATTEMPTS} failed attempts...\n")
    resp = client.post("/login", data={"username": username, "password": correct_password},
                        headers=headers, follow_redirects=False)
    responses.append((f"attempt {NUM_FAILED_ATTEMPTS + 1}/{NUM_FAILED_ATTEMPTS + 1} - correct password", resp))

    # Pull recent history in one shot and line the newest N up with the requests we just made,
    # in order. Note: get_recent_attempts_for_user() applies its `limit` before sorting (it
    # sorts client-side to avoid needing a Firestore composite index), so we ask for a
    # generously large limit here rather than exactly len(responses) - otherwise, once a demo
    # account has more historical rows than that, an exact-sized limit could come back as an
    # arbitrary subset instead of the true most recent ones.
    history = log_service.get_recent_attempts_for_user(username, limit=100)  # newest-first
    rows = list(reversed(history[:len(responses)]))  # the newest N, oldest-first
    for (label, resp), row in zip(responses, rows):
        print_attempt(label, resp, row)

    print()
    final_row = rows[-1] if rows else {}
    user_after = auth_service.get_user(username)
    if user_after and user_after.get("is_blocked"):
        print(f"RESULT: '{username}' is now BLOCKED (is_blocked=True). Auto-block triggered by the risk engine.")
        print("Unblock it from the Admin Security Dashboard (or Manage Users) to reset for the next demo run.")
    else:
        print(f"RESULT: '{username}' was NOT blocked (risk_score={final_row.get('risk_score')}, "
              f"result={final_row.get('result')}). Check the signals above against config.py's thresholds.")


if __name__ == "__main__":
    main()
