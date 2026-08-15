"""
Comprehensive Integration & Security Testing Suite for Solar Monitoring Backend API.

Tests all REST endpoints, Chatbot queries, Authentication, and Role-Based Access Control
against a running Flask server (http://127.0.0.1:5000).

Usage:
    python BACKEND/test_backend.py                  # Standard integration & security test suite
    python BACKEND/test_backend.py --include-ingest  # Include optional POST /api/ingest write test
"""

import sys
import os
import argparse
import urllib.parse
import uuid
import requests

# Enable test environment token authorization for the test execution process
os.environ["TESTING"] = "1"

# Configure UTF-8 encoding for standard output on Windows
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_URL = "http://127.0.0.1:5000"


def run_tests(include_ingest: bool = False) -> bool:
    print("\n==================================================")
    print("Solar Backend Integration & Security Test Suite")
    print(f"Target Base URL: {BASE_URL}")
    print("==================================================\n", flush=True)

    passed_count = 0
    failed_count = 0
    test_counter = 1

    def record_result(test_label: str, passed: bool, details: str):
        nonlocal passed_count, failed_count, test_counter
        status_str = "[PASS]" if passed else "[FAIL]"
        if passed:
            passed_count += 1
        else:
            failed_count += 1
        full_label = f"{test_counter:02d}. {test_label}"
        print(f"{status_str:7s} | {full_label:<48s} | {details}", flush=True)
        test_counter += 1

    # 1. Health Check
    try:
        r = requests.get(f"{BASE_URL}/api/health", timeout=15)
        passed = (r.status_code == 200 and r.json().get("status") == "ok")
        record_result("GET /api/health", passed, f"Status: {r.status_code} | Service: {r.json().get('service')}")
    except Exception as e:
        record_result("GET /api/health", False, f"Connection Error: {e}")

    # 2. Latest Readings
    try:
        r = requests.get(f"{BASE_URL}/api/readings/latest?limit=5", timeout=15)
        passed = (r.status_code == 200 and isinstance(r.json(), list))
        record_result("GET /api/readings/latest?limit=5", passed, f"Status: {r.status_code} | Fetched {len(r.json()) if passed else 0} readings")
    except Exception as e:
        record_result("GET /api/readings/latest?limit=5", False, f"Connection Error: {e}")

    # 3. Active Alerts Query
    try:
        r = requests.get(f"{BASE_URL}/api/alerts", timeout=15)
        passed = (r.status_code == 200 and isinstance(r.json(), list))
        record_result("GET /api/alerts", passed, f"Status: {r.status_code} | Active Alerts: {len(r.json()) if passed else 0}")
    except Exception as e:
        record_result("GET /api/alerts", False, f"Connection Error: {e}")

    # 4. Trigger Analysis Engine
    try:
        r = requests.get(f"{BASE_URL}/api/analysis/run", timeout=15)
        passed = (r.status_code == 200 and r.json().get("status") == "ok")
        res = r.json() if passed else {}
        record_result("GET /api/analysis/run", passed, f"Status: {r.status_code} | PR: {res.get('latest_pr')} | Anomaly: {res.get('is_anomaly')}")
    except Exception as e:
        record_result("GET /api/analysis/run", False, f"Connection Error: {e}")

    # Chatbot Test Queries (5 through 11)
    chat_queries = [
        ("Chat: Current Power", "What is my current power generation?"),
        ("Chat: Performance Ratio", "What is my performance ratio?"),
        ("Chat: Yesterday Drop Analysis", "Why did my generation drop yesterday?"),
        ("Chat: Last 7 Days Energy Loss", "How much energy did I lose last 7 days?"),
        ("Chat: This Month Energy Loss", "How much energy did I lose this month?"),
        ("Chat: Last Month Energy Loss", "How much energy did I lose last month?"),
        ("Chat: Active Alerts", "Are there any active alerts?")
    ]

    for label, q_text in chat_queries:
        try:
            url = f"{BASE_URL}/api/chat?query={urllib.parse.quote(q_text)}"
            r = requests.get(url, timeout=15)
            passed = (r.status_code == 200 and "response" in r.json())
            resp_snippet = r.json().get("response", "").replace("\n", " ")[:60] if passed else ""
            record_result(label, passed, f"Status: {r.status_code} | Response: \"{resp_snippet}...\"")
        except Exception as e:
            record_result(label, False, f"Connection Error: {e}")

    # 12. Auth: Reject Missing Authorization Header
    try:
        r = requests.get(f"{BASE_URL}/api/auth/me", timeout=15)
        passed = (r.status_code == 401)
        record_result("Auth: Missing Authorization Header", passed, f"Status: {r.status_code} (Expected 401)")
    except Exception as e:
        record_result("Auth: Missing Authorization Header", False, f"Connection Error: {e}")

    # 13. Auth: Reject Invalid Bearer Token
    try:
        r = requests.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": "Bearer invalid-garbage-token"}, timeout=15)
        passed = (r.status_code == 401)
        record_result("Auth: Invalid Bearer Token", passed, f"Status: {r.status_code} (Expected 401)")
    except Exception as e:
        record_result("Auth: Invalid Bearer Token", False, f"Connection Error: {e}")

    # Unique test emails for current execution
    test_run_id = str(uuid.uuid4())[:8]
    owner_email = f"owner_{test_run_id}@solar.com"
    tech_email = f"tech_{test_run_id}@solar.com"
    admin_email = f"admin_{test_run_id}@solar.com"

    owner_uid, tech_uid, admin_uid = None, None, None

    # 14. Auth: Public Registration (Prevents Self-Assigned Admin Role)
    try:
        # Client requests role="admin" during public signup
        r_owner = requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": owner_email,
            "password": "password123",
            "name": "Test Owner",
            "role": "admin"
        }, timeout=15)

        if r_owner.status_code == 201:
            u_data = r_owner.json().get("user", {})
            owner_uid = u_data.get("uid")
            # Verify role was forced to 'owner' despite client requesting 'admin'
            passed = (u_data.get("role") == "owner")
            record_result("Auth: Public Registration Role Enforced", passed, f"Status: 201 | Assigned Role: '{u_data.get('role')}' (Client request 'admin' forced to 'owner')")
        else:
            record_result("Auth: Public Registration Role Enforced", False, f"Status: {r_owner.status_code}")
    except Exception as e:
        record_result("Auth: Public Registration Role Enforced", False, f"Error: {e}")

    # 15. Auth: Duplicate Email Registration Prevention (409 Conflict)
    try:
        r_dup = requests.post(f"{BASE_URL}/api/auth/register", json={
            "email": owner_email,
            "password": "password123",
            "name": "Duplicate Owner Attempt"
        }, timeout=15)
        passed = (r_dup.status_code == 409)
        record_result("Auth: Prevent Duplicate Email Registration", passed, f"Status: {r_dup.status_code} (Expected 409 Conflict)")
    except Exception as e:
        record_result("Auth: Prevent Duplicate Email Registration", False, f"Error: {e}")

    # First bootstrap an initial admin profile in Firestore for administrative user creation test
    if owner_uid:
        admin_uid = f"usr_admin_{test_run_id}"
        from BACKEND.firebase_config import get_db
        db = get_db()
        if db:
            db.collection("users").document(admin_uid).set({
                "uid": admin_uid,
                "email": admin_email,
                "name": "System Admin",
                "role": "admin",
                "created_at": "2026-08-16T00:00:00Z"
            })

    # 16. Auth: Admin User Creation (POST /api/auth/users)
    if admin_uid:
        try:
            admin_headers = {"Authorization": f"Bearer test-token-{admin_uid}"}
            r_tech = requests.post(f"{BASE_URL}/api/auth/users", json={
                "email": tech_email,
                "password": "password123",
                "name": "Test Technician",
                "role": "technician"
            }, headers=admin_headers, timeout=15)

            if r_tech.status_code == 201:
                u_tech = r_tech.json().get("user", {})
                tech_uid = u_tech.get("uid")
                passed = (u_tech.get("role") == "technician")
                record_result("Auth: Admin User Creation (Technician)", passed, f"Status: 201 | Created Technician UID: {tech_uid}")
            else:
                record_result("Auth: Admin User Creation (Technician)", False, f"Status: {r_tech.status_code}")
        except Exception as e:
            record_result("Auth: Admin User Creation (Technician)", False, f"Error: {e}")

    # 17. Auth: GET /api/auth/me Profile Verification
    if owner_uid:
        try:
            r_me = requests.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": f"Bearer test-token-{owner_uid}"}, timeout=15)
            passed = (r_me.status_code == 200 and r_me.json().get("uid") == owner_uid)
            record_result("Auth: GET /api/auth/me Profile Access", passed, f"Status: {r_me.status_code} | Authenticated: {r_me.json().get('email')}")
        except Exception as e:
            record_result("Auth: GET /api/auth/me Profile Access", False, f"Error: {e}")

    # 18. Auth: Missing Firestore Profile Rejection (403 Forbidden)
    try:
        r_missing = requests.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": "Bearer test-token-nonexistent_uid_999"}, timeout=15)
        passed = (r_missing.status_code == 403)
        record_result("Auth: Reject Missing Firestore Profile", passed, f"Status: {r_missing.status_code} (Expected 403 Forbidden)")
    except Exception as e:
        record_result("Auth: Reject Missing Firestore Profile", False, f"Error: {e}")

    # 19. Auth: Role-Based Authorization Matrix (@require_role)
    if owner_uid and tech_uid and admin_uid:
        try:
            owner_h = {"Authorization": f"Bearer test-token-{owner_uid}"}
            tech_h = {"Authorization": f"Bearer test-token-{tech_uid}"}
            admin_h = {"Authorization": f"Bearer test-token-{admin_uid}"}

            # Owner on admin-only -> 403
            r1 = requests.get(f"{BASE_URL}/api/auth/admin-only", headers=owner_h, timeout=15)
            # Technician on admin-only -> 403
            r2 = requests.get(f"{BASE_URL}/api/auth/admin-only", headers=tech_h, timeout=15)
            # Technician on tech-only -> 200
            r3 = requests.get(f"{BASE_URL}/api/auth/tech-only", headers=tech_h, timeout=15)
            # Admin on admin-only -> 200
            r4 = requests.get(f"{BASE_URL}/api/auth/admin-only", headers=admin_h, timeout=15)

            passed = (r1.status_code == 403 and r2.status_code == 403 and r3.status_code == 200 and r4.status_code == 200)
            record_result("Auth: Role Matrix Permission Enforcement", passed, f"Owner->Admin: {r1.status_code}(403), Tech->Admin: {r2.status_code}(403), Tech->Tech: {r3.status_code}(200), Admin->Admin: {r4.status_code}(200)")
        except Exception as e:
            record_result("Auth: Role Matrix Permission Enforcement", False, f"Error: {e}")

    # Optional Ingest Endpoint Test
    if include_ingest:
        try:
            sample_payload = {
                "voltage": 13.6,
                "current": 18.0,
                "power": 244.8,
                "expected_power": 270.0,
                "lux": 95000.0
            }
            r = requests.post(f"{BASE_URL}/api/ingest", json=sample_payload, timeout=15)
            passed = (r.status_code == 201)
            record_result("POST /api/ingest (Optional)", passed, f"Status: {r.status_code} | Doc ID: {r.json().get('doc_id') if passed else 'N/A'}")
        except Exception as e:
            record_result("POST /api/ingest (Optional)", False, f"Connection Error: {e}")

    print("\n==================================================")
    print("Integration & Security Test Results Summary")
    print("==================================================")
    print(f"Total Tests Run: {passed_count + failed_count}")
    print(f"Passed: {passed_count}")
    print(f"Failed: {failed_count}")
    print("==================================================\n", flush=True)

    return failed_count == 0


def main():
    parser = argparse.ArgumentParser(description="Integration & Security Testing Script for Solar Backend API")
    parser.add_argument(
        "--include-ingest",
        action="store_true",
        help="Include POST /api/ingest write test"
    )
    args = parser.parse_args()

    success = run_tests(include_ingest=args.include_ingest)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
