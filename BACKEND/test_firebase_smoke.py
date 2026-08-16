"""
Real Firebase Authentication & Firestore End-to-End Smoke Test.

Validates the live integration against Google Cloud Firebase:
1. Real Firebase Client Authentication (Email/Password via Identity Toolkit API)
2. Real Firebase Admin SDK ID Token Verification (auth.verify_id_token)
3. Real Firestore Profile Resolution (/api/auth/me)
4. Real Firestore System Document Creation (/api/systems)
5. Real Firestore System Document Retrieval (/api/systems/<id>)
6. Live Document Cleanup

Security Policy:
- NEVER hardcodes passwords, keys, or tokens in source code.
- Uses environment variables or explicit CLI parameters for test credentials.
- Zero mock-token bypasses in production code.
- If credentials are not supplied in the environment, reports [NOT RUN] cleanly
  without falsely claiming a PASS.
"""

import sys
import os
import json
import logging
import argparse
import urllib.request
import urllib.error

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure UTF-8 stdout for Windows
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("FirebaseSmokeTest")


def get_real_firebase_id_token(email: str, password: str, api_key: str) -> dict:
    """
    Exchanges Email/Password for a real Firebase ID Token using Google Identity Toolkit REST API.
    """
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def run_smoke_test(email: str = None, password: str = None, api_key: str = None) -> int:
    print("\n==================================================================================")
    print("           Real Firebase & Firestore End-to-End Smoke Test                        ")
    print("==================================================================================\n", flush=True)

    # Read from parameter or environment variables
    test_email = (email or os.environ.get("FIREBASE_TEST_EMAIL", "")).strip()
    test_password = (password or os.environ.get("FIREBASE_TEST_PASSWORD", "")).strip()
    test_api_key = (api_key or os.environ.get("FIREBASE_WEB_API_KEY", "")).strip()

    if not test_email or not test_password or not test_api_key:
        print("[NOT RUN] Real Firebase smoke test — credentials/configuration unavailable\n")
        print("To execute live end-to-end testing against Google Cloud Firebase & Firestore:")
        print("  Option A (Environment Variables):")
        print("     $env:FIREBASE_TEST_EMAIL = 'your_test_user@domain.com'")
        print("     $env:FIREBASE_TEST_PASSWORD = 'your_password'")
        print("     $env:FIREBASE_WEB_API_KEY = 'AIzaSy...'")
        print("     python BACKEND/test_firebase_smoke.py\n")
        print("  Option B (Command-line arguments):")
        print("     python BACKEND/test_firebase_smoke.py --email user@example.com --password mypass --api-key AIzaSy...\n")
        print("  Ensure serviceAccountKey.json is present in the project root directory.\n")
        print("==================================================================================\n", flush=True)
        return 0

    try:
        from BACKEND.app import app
        from BACKEND.firebase_config import get_db

        db = get_db()
        if db is None:
            print("[FAIL] REAL Firestore — Database handle could not be initialized.")
            return 1

        print("  1. Authenticating with live Firebase Identity Platform...")
        auth_res = get_real_firebase_id_token(test_email, test_password, test_api_key)
        id_token = auth_res.get("idToken")
        real_uid = auth_res.get("localId")

        if not id_token or not real_uid:
            print("[FAIL] REAL Firebase Auth — Did not receive valid idToken from Identity Platform.")
            return 1
        print(f"[PASS] REAL Firebase Auth — Logged in as '{test_email}' (UID: {real_uid})")

        client = app.test_client()
        headers = {"Authorization": f"Bearer {id_token}"}

        print("  2. Testing live /api/auth/me with real Bearer token...")
        r_me = client.get("/api/auth/me", headers=headers)
        if r_me.status_code != 200:
            print(f"[FAIL] REAL /api/auth/me — Status {r_me.status_code}, expected 200: {r_me.get_json()}")
            return 1
        me_data = r_me.get_json() or {}
        if me_data.get("uid") != real_uid:
            print(f"[FAIL] REAL /api/auth/me — Returned UID '{me_data.get('uid')}' does not match Firebase UID '{real_uid}'")
            return 1
        print(f"[PASS] REAL /api/auth/me — Profile verified (Role: {me_data.get('role', 'none')})")

        print("  3. Creating live solar system via POST /api/systems...")
        payload = {
            "name": "Live Smoke Test Solar System",
            "location": {"lat": 26.8467, "lng": 80.9462},
            "installation_date": "2026-08-16T00:00:00Z",
            "panel_capacity_watts": 5000,
            "inverter_type": "Smoke-Test-Inverter",
            "components": [],
            "qr_code_data": "smoke-test-qr"
        }
        r_create = client.post("/api/systems", json=payload, headers=headers)
        if r_create.status_code != 201:
            print(f"[FAIL] REAL /api/systems — Status {r_create.status_code}, expected 201: {r_create.get_json()}")
            return 1

        created_system = (r_create.get_json() or {}).get("system", {})
        system_id = created_system.get("system_id")
        if not system_id or created_system.get("owner_uid") != real_uid:
            print(f"[FAIL] REAL /api/systems — Invalid system data returned: {created_system}")
            return 1
        print(f"[PASS] REAL /api/systems — Created system '{system_id}' (Owner: {created_system.get('owner_uid')})")

        print(f"  4. Retrieving live system GET /api/systems/{system_id}...")
        r_get = client.get(f"/api/systems/{system_id}", headers=headers)
        if r_get.status_code != 200:
            print(f"[FAIL] REAL system retrieval — Status {r_get.status_code}: {r_get.get_json()}")
            return 1
        print(f"[PASS] REAL system retrieval — Successfully fetched '{system_id}'")

        print(f"  5. Cleaning up smoke test document '{system_id}' from live Firestore...")
        db.collection("systems").document(system_id).delete()
        print(f"[CLEANUP] Smoke-test system '{system_id}' deleted from Firestore.")

        print("\n==================================================================================")
        print("               Real Firebase Smoke Test: ALL CHECKS PASSED                        ")
        print("==================================================================================\n", flush=True)
        return 0

    except Exception as e:
        logger.exception("Real Firebase smoke test failed with exception")
        print(f"[FAIL] Real Firebase smoke test encountered unexpected exception: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Real Firebase & Firestore Live Smoke Test")
    parser.add_argument("--email", help="Firebase test user email", default=None)
    parser.add_argument("--password", help="Firebase test user password", default=None)
    parser.add_argument("--api-key", help="Firebase Web API key", default=None)
    args = parser.parse_args()

    exit_code = run_smoke_test(email=args.email, password=args.password, api_key=args.api_key)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
