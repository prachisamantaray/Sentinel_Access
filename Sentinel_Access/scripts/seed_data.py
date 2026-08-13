"""Seed Firestore with three demo accounts - one per role - for local testing.

Run this once after placing serviceAccountKey.json in the project root:

    python scripts/seed_data.py

Pass --reset to overwrite existing demo accounts (this also clears any MFA
enrollment/secret they may have, so they'll re-enroll on next MFA challenge).
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config  # noqa: E402
from firebase_init import init_firebase  # noqa: E402
from services import auth_service, geo_service  # noqa: E402

DEMO_IP = "127.0.0.1"  # matches localhost, so a local test login won't trip the "unusual location" rule
TYPICAL_HOURS = [8, 20]  # 08:00-20:00 local server time is considered "normal"

DEMO_USERS = [
    {"username": "admin1", "password": "Admin@123", "role": "admin"},
    {"username": "manager1", "password": "Manager@123", "role": "manager"},
    {"username": "employee1", "password": "Employee@123", "role": "employee"},
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true", help="Overwrite existing demo accounts")
    args = parser.parse_args()

    init_firebase(Config.FIREBASE_CRED_PATH)

    location = geo_service.get_location(DEMO_IP)
    typical_location_label = location["label"]

    print(f"Seeding demo users with typical_ip={DEMO_IP}, typical_location={typical_location_label}\n")

    for u in DEMO_USERS:
        existing = auth_service.get_user(u["username"])
        if existing and not args.reset:
            print(f"- '{u['username']}' already exists, skipping (use --reset to overwrite).")
            continue

        auth_service.create_user(
            username=u["username"],
            password=u["password"],
            role=u["role"],
            typical_ip=DEMO_IP,
            typical_location=typical_location_label,
            typical_login_hours=TYPICAL_HOURS,
        )
        print(f"- Created {u['role']:<10} username='{u['username']}'  password='{u['password']}'")

    print("\nDone. These are demo credentials for local testing only - passwords are stored as "
          "salted hashes in Firestore, never in plain text.")


if __name__ == "__main__":
    main()
