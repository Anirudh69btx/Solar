"""
Integration Testing Script for Solar Monitoring System Backend API.

Tests all REST endpoints on a running Flask server (http://127.0.0.1:5000).

Usage:
    python BACKEND/test_backend.py                  # Standard read/analysis/chat integration tests
    python BACKEND/test_backend.py --include-ingest  # Include POST /api/ingest validation test
"""

import sys
import os
import argparse
import urllib.parse
import requests

# Configure UTF-8 encoding for standard output on Windows
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_URL = "http://127.0.0.1:5000"


def run_tests(include_ingest: bool = False) -> bool:
    print("\n==================================================")
    print("Solar Backend Integration Test Suite")
    print(f"Target Base URL: {BASE_URL}")
    print("==================================================\n", flush=True)

    passed_count = 0
    failed_count = 0

    def record_result(test_name: str, passed: bool, details: str):
        nonlocal passed_count, failed_count
        status_str = "[PASS]" if passed else "[FAIL]"
        if passed:
            passed_count += 1
        else:
            failed_count += 1
        print(f"{status_str:7s} | {test_name:<45s} | {details}", flush=True)

    # 1. Health Check
    try:
        r = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if r.status_code == 200 and r.json().get("status") == "ok":
            record_result("1. GET /api/health", True, f"Status: 200 OK | Response: {r.json().get('status')}")
        else:
            record_result("1. GET /api/health", False, f"Status: {r.status_code} | Body: {r.text[:60]}")
    except Exception as e:
        record_result("1. GET /api/health", False, f"Connection Error: {e}")

    # 2. Latest Readings
    try:
        r = requests.get(f"{BASE_URL}/api/readings/latest?limit=5", timeout=5)
        if r.status_code == 200 and isinstance(r.json(), list):
            readings = r.json()
            record_result("2. GET /api/readings/latest?limit=5", True, f"Status: 200 OK | Fetched {len(readings)} readings")
        else:
            record_result("2. GET /api/readings/latest?limit=5", False, f"Status: {r.status_code}")
    except Exception as e:
        record_result("2. GET /api/readings/latest?limit=5", False, f"Connection Error: {e}")

    # 3. Active Alerts Query
    try:
        r = requests.get(f"{BASE_URL}/api/alerts", timeout=5)
        if r.status_code == 200 and isinstance(r.json(), list):
            alerts = r.json()
            record_result("3. GET /api/alerts", True, f"Status: 200 OK | Active Alerts: {len(alerts)}")
        else:
            record_result("3. GET /api/alerts", False, f"Status: {r.status_code}")
    except Exception as e:
        record_result("3. GET /api/alerts", False, f"Connection Error: {e}")

    # 4. Trigger Analysis Engine
    try:
        r = requests.get(f"{BASE_URL}/api/analysis/run", timeout=5)
        if r.status_code == 200 and r.json().get("status") == "ok":
            res = r.json()
            record_result("4. GET /api/analysis/run", True, f"Status: 200 OK | PR: {res.get('latest_pr')} | Anomaly: {res.get('is_anomaly')}")
        else:
            record_result("4. GET /api/analysis/run", False, f"Status: {r.status_code}")
    except Exception as e:
        record_result("4. GET /api/analysis/run", False, f"Connection Error: {e}")

    # Chatbot Test Queries
    chat_queries = [
        ("5. Chat: Current Power", "What is my current power generation?"),
        ("6. Chat: Performance Ratio", "What is my performance ratio?"),
        ("7. Chat: Yesterday Drop Analysis", "Why did my generation drop yesterday?"),
        ("8. Chat: Last 7 Days Energy Loss", "How much energy did I lose last 7 days?"),
        ("9. Chat: This Month Energy Loss", "How much energy did I lose this month?"),
        ("10. Chat: Last Month Energy Loss", "How much energy did I lose last month?"),
        ("11. Chat: Active Alerts", "Are there any active alerts?")
    ]

    for label, q_text in chat_queries:
        try:
            url = f"{BASE_URL}/api/chat?query={urllib.parse.quote(q_text)}"
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and "response" in r.json():
                resp_snippet = r.json()["response"].replace("\n", " ")[:65]
                record_result(label, True, f"Status: 200 OK | Response: \"{resp_snippet}...\"")
            else:
                record_result(label, False, f"Status: {r.status_code}")
        except Exception as e:
            record_result(label, False, f"Connection Error: {e}")

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
            r = requests.post(f"{BASE_URL}/api/ingest", json=sample_payload, timeout=5)
            if r.status_code == 201:
                res = r.json()
                record_result("12. POST /api/ingest (Optional)", True, f"Status: 201 Created | Doc ID: {res.get('doc_id')}")
            else:
                record_result("12. POST /api/ingest (Optional)", False, f"Status: {r.status_code}")
        except Exception as e:
            record_result("12. POST /api/ingest (Optional)", False, f"Connection Error: {e}")

    print("\n==================================================")
    print("Integration Test Results Summary")
    print("==================================================")
    print(f"Total Tests Run: {passed_count + failed_count}")
    print(f"Passed: {passed_count}")
    print(f"Failed: {failed_count}")
    print("==================================================\n", flush=True)

    return failed_count == 0


def main():
    parser = argparse.ArgumentParser(description="Integration Testing Script for Solar Backend API")
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
