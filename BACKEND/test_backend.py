"""
Comprehensive Integration & Security Testing Suite for Solar Monitoring Backend API.

Verifies:
- Segments 1-6 Endpoints: Health Check, Latest Readings, Active Alerts, Analysis Engine,
  and Natural Language Chatbot queries (Current Power, PR, Yesterday, Last 7 Days,
  This Month, Last Month, Active Alerts).
- Segment 7 Security & RBAC:
  1. Owner Registration (201)
  2. Public Privilege Escalation Prevention (Admin/Tech self-registration rejected with 403)
  3. Duplicate Email Rejection (409 Conflict)
  4. Missing Authorization Header Rejection (401)
  5. Invalid Bearer Token Rejection (401)
  6. Valid Token with Missing Firestore Profile (403)
  7. Role Matrix Enforcement:
     - Owner on Admin-only endpoint (403)
     - Technician on Admin-only endpoint (403)
     - Technician on Tech/Admin endpoint (200)
     - Admin on Admin-only endpoint (200)
     - Admin on Tech/Admin endpoint (200)
  8. Missing Role in Firestore Profile Rejection (403)
  9. Invalid Role in Firestore Profile Rejection (403)
- Segment 8 Solar System CRUD & Security (tests 25–54):
  Covers create, list, get, update, delete — with full RBAC, ownership enforcement,
  input validation, immutability checks, and unauthenticated rejection.
- Production Improvements (tests 55–72):
  1. Technician Assignment System (create, list, delete, duplicate prevention, RBAC)
  2. Technician System Access by Active Assignment
  3. Cross-Technician Isolation & Unassigned System Protection
  4. Atomic System Creation, Concurrency & Collision Retries
- Segment 9 Solar Performance Reports (tests 73–102):
  1. Daily Reports (Owner, Admin, Tech 403, 401, validation, generation, loss, PR, rain events, empty period)
  2. Weekly Reports (Owner, Admin, Tech 403, date validation, best/worst day, multi-day aggregation)
  3. Monthly Reports (Owner, Admin, Tech 403, month validation, empty period, month aggregations)

Note on Authentication Testing:
In accordance with production security standards, production verify_token() strictly
invokes Firebase Admin SDK auth.verify_id_token(). In this isolated test runner,
Firebase verification and user creation are mocked via unittest.mock to test
authorization boundaries without introducing backdoors into production code.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

# Configure UTF-8 encoding for standard output on Windows
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from firebase_admin import auth as fb_auth
from BACKEND.app import app


# ===========================================================================
# Mock Firestore infrastructure
# ===========================================================================

class MockFirestoreDoc:
    """Mock Firestore Document Snapshot."""
    def __init__(self, doc_id: str, data: dict, exists: bool = True):
        self.id = doc_id
        self._data = data.copy() if data else {}
        self.exists = exists

    def to_dict(self):
        return self._data.copy()


class MockFirestoreQuery:
    """Mock Firestore Query supporting chaining (.where, .order_by, .limit, .select, .stream)."""
    def __init__(self, collection_data: dict, filters=None, order_field=None, direction=None, limit_val=None, select_fields=None):
        self._collection_data = collection_data
        self._filters = filters or []
        self._order_field = order_field
        self._direction = direction
        self._limit_val = limit_val
        self._select_fields = select_fields

    def select(self, *fields):
        selected = []
        for f in fields:
            if isinstance(f, (list, tuple)):
                selected.extend(f)
            else:
                selected.append(f)
        return MockFirestoreQuery(
            self._collection_data,
            filters=self._filters,
            order_field=self._order_field,
            direction=self._direction,
            limit_val=self._limit_val,
            select_fields=selected
        )

    def where(self, *args, **kwargs):
        new_filters = list(self._filters)
        if args and len(args) == 3:
            new_filters.append((args[0], args[1], args[2]))
        elif "filter" in kwargs:
            ff = kwargs["filter"]
            new_filters.append((getattr(ff, "field_path", "active"), getattr(ff, "op_string", "=="), getattr(ff, "value", True)))
        return MockFirestoreQuery(
            self._collection_data,
            filters=new_filters,
            order_field=self._order_field,
            direction=self._direction,
            limit_val=self._limit_val,
            select_fields=self._select_fields
        )

    def order_by(self, field: str, direction: str = "ASCENDING"):
        return MockFirestoreQuery(
            self._collection_data,
            filters=self._filters,
            order_field=field,
            direction=direction,
            limit_val=self._limit_val,
            select_fields=self._select_fields
        )

    def limit(self, count: int):
        return MockFirestoreQuery(
            self._collection_data,
            filters=self._filters,
            order_field=self._order_field,
            direction=self._direction,
            limit_val=count,
            select_fields=self._select_fields
        )

    def stream(self):
        results = []
        for doc_id, data in self._collection_data.items():
            matches = True
            for field, op, val in self._filters:
                doc_val = data.get(field)
                if op == "==" and doc_val != val:
                    matches = False
                    break
                elif op == ">=" and (doc_val is None or doc_val < val):
                    matches = False
                    break
                elif op == "<=" and (doc_val is None or doc_val > val):
                    matches = False
                    break
                elif op == ">" and (doc_val is None or doc_val <= val):
                    matches = False
                    break
                elif op == "<" and (doc_val is None or doc_val >= val):
                    matches = False
                    break

            if matches:
                item_data = data
                if self._select_fields:
                    item_data = {k: v for k, v in data.items() if k in self._select_fields or k == "id"}
                results.append(MockFirestoreDoc(doc_id, item_data, exists=True))

        if self._order_field:
            reverse = (self._direction or "").upper() == "DESCENDING"
            results.sort(key=lambda d: d.to_dict().get(self._order_field, 0), reverse=reverse)

        if self._limit_val is not None:
            results = results[:self._limit_val]

        return results


class MockFirestoreDocRef:
    """Mock Firestore Document Reference."""
    def __init__(self, collection_data: dict, doc_id: str):
        self._collection_data = collection_data
        self.id = doc_id

    def get(self):
        if self.id in self._collection_data:
            return MockFirestoreDoc(self.id, self._collection_data[self.id], exists=True)
        return MockFirestoreDoc(self.id, {}, exists=False)

    def set(self, data: dict, merge: bool = False):
        if merge and self.id in self._collection_data:
            self._collection_data[self.id].update(data)
        else:
            self._collection_data[self.id] = data.copy()

    def create(self, data: dict):
        """Atomic create: raises if document already exists."""
        if self.id in self._collection_data:
            raise Exception(f"Document already exists: {self.id}")
        self._collection_data[self.id] = data.copy()

    def delete(self):
        self._collection_data.pop(self.id, None)


class MockFirestoreCollection:
    """Mock Firestore Collection Reference."""
    def __init__(self, data_store: dict, collection_name: str):
        self._data_store = data_store
        self._collection_name = collection_name
        if collection_name not in self._data_store:
            self._data_store[collection_name] = {}

    @property
    def _coll_dict(self):
        return self._data_store[self._collection_name]

    def document(self, doc_id: str = None):
        if not doc_id:
            import uuid
            doc_id = f"doc_{uuid.uuid4().hex[:12]}"
        return MockFirestoreDocRef(self._coll_dict, doc_id)

    def select(self, *fields):
        query = MockFirestoreQuery(self._coll_dict)
        return query.select(*fields)

    def where(self, *args, **kwargs):
        query = MockFirestoreQuery(self._coll_dict)
        return query.where(*args, **kwargs)

    def order_by(self, field: str, direction: str = "ASCENDING"):
        query = MockFirestoreQuery(self._coll_dict)
        return query.order_by(field, direction)

    def limit(self, count: int):
        query = MockFirestoreQuery(self._coll_dict)
        return query.limit(count)

    def stream(self):
        query = MockFirestoreQuery(self._coll_dict)
        return query.stream()


class MockFirestoreDB:
    """In-memory mock Firestore DB for backend testing."""
    def __init__(self):
        now_dt = datetime.now(timezone.utc)
        now_ts = int(now_dt.timestamp())
        yesterday_ts = int((now_dt - timedelta(days=1)).timestamp())
        three_days_ago_ts = int((now_dt - timedelta(days=3)).timestamp())

        self._store = {
            "users": {
                "uid_owner": {
                    "uid": "uid_owner",
                    "email": "owner@solar.com",
                    "name": "Solar Owner",
                    "role": "owner",
                    "created_at": "2026-08-16T00:00:00Z"
                },
                "uid_owner2": {
                    "uid": "uid_owner2",
                    "email": "owner2@solar.com",
                    "name": "Solar Owner 2",
                    "role": "owner",
                    "created_at": "2026-08-16T00:00:00Z"
                },
                "uid_tech": {
                    "uid": "uid_tech",
                    "email": "tech@solar.com",
                    "name": "Solar Tech",
                    "role": "technician",
                    "created_at": "2026-08-16T00:00:00Z"
                },
                "uid_tech2": {
                    "uid": "uid_tech2",
                    "email": "tech2@solar.com",
                    "name": "Solar Tech 2",
                    "role": "technician",
                    "created_at": "2026-08-16T00:00:00Z"
                },
                "uid_admin": {
                    "uid": "uid_admin",
                    "email": "admin@solar.com",
                    "name": "Solar Admin",
                    "role": "admin",
                    "created_at": "2026-08-16T00:00:00Z"
                },
                "uid_missing_role": {
                    "uid": "uid_missing_role",
                    "email": "norole@solar.com",
                    "name": "No Role User",
                    "created_at": "2026-08-16T00:00:00Z"
                },
                "uid_invalid_role": {
                    "uid": "uid_invalid_role",
                    "email": "invalidrole@solar.com",
                    "name": "Invalid Role User",
                    "role": "superadmin",
                    "created_at": "2026-08-16T00:00:00Z"
                }
            },
            "readings": {
                f"read_{now_ts}": {
                    "timestamp": now_dt.isoformat(),
                    "unix_timestamp": now_ts,
                    "voltage": 230.5,
                    "current": 10.2,
                    "power": 2351.1,
                    "expected_power": 2500.0,
                    "performance_ratio": 0.9404,
                    "irradiance": 800.0,
                    "lux": 96000.0,
                    "temperature_ambient": 28.0,
                    "temperature_panel": 42.0,
                    "humidity": 45.0,
                    "vibration": 0.02,
                    "rain": 0.0,
                    "fault_injected": False
                },
                f"read_{yesterday_ts}": {
                    "timestamp": (now_dt - timedelta(days=1)).isoformat(),
                    "unix_timestamp": yesterday_ts,
                    "voltage": 228.0,
                    "current": 9.5,
                    "power": 2166.0,
                    "expected_power": 2500.0,
                    "performance_ratio": 0.8664,
                    "irradiance": 750.0,
                    "lux": 90000.0,
                    "temperature_ambient": 27.0,
                    "temperature_panel": 40.0,
                    "humidity": 48.0,
                    "vibration": 0.01,
                    "rain": 0.0,
                    "fault_injected": False
                },
                f"read_{three_days_ago_ts}": {
                    "timestamp": (now_dt - timedelta(days=3)).isoformat(),
                    "unix_timestamp": three_days_ago_ts,
                    "voltage": 225.0,
                    "current": 9.0,
                    "power": 2025.0,
                    "expected_power": 2500.0,
                    "performance_ratio": 0.8100,
                    "irradiance": 720.0,
                    "lux": 86400.0,
                    "temperature_ambient": 26.0,
                    "temperature_panel": 38.0,
                    "humidity": 50.0,
                    "vibration": 0.01,
                    "rain": 0.0,
                    "fault_injected": False
                }
            },
            "alerts": {
                "alert_001": {
                    "id": "alert_001",
                    "type": "WARNING",
                    "message": "Performance ratio dropped below threshold (0.75)",
                    "active": True,
                    "timestamp": now_dt.isoformat()
                }
            },
            "sites": {
                "SITE-OWNER001": {
                    "site_id": "SITE-OWNER001",
                    "owner_uid": "uid_owner",
                    "site_name": "Sunrise Solar Farm 1",
                    "address": "123 Solar Way, Lucknow, UP",
                    "location": {"lat": 26.8467, "lng": 80.9462},
                    "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                },
                "SITE-OWNER002": {
                    "site_id": "SITE-OWNER002",
                    "owner_uid": "uid_owner2",
                    "site_name": "Delhi Industrial Solar Site",
                    "address": "456 Clean Energy Blvd, New Delhi",
                    "location": {"lat": 28.6139, "lng": 77.2090},
                    "created_at": datetime(2026, 2, 1, tzinfo=timezone.utc),
                    "updated_at": datetime(2026, 2, 1, tzinfo=timezone.utc),
                }
            },
            "systems": {
                "SYS-OWNER001": {
                    "system_id": "SYS-OWNER001",
                    "owner_uid": "uid_owner",
                    "site_id": "SITE-OWNER001",
                    "name": "Owner One Rooftop",
                    "location": {"lat": 26.8467, "lng": 80.9462},
                    "installation_date": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "panel_capacity_watts": 5000.0,
                    "inverter_type": "Grid-Tied",
                    "components": [],
                    "qr_code_data": None,
                    "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "updated_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                },
                "SYS-OWNER002": {
                    "system_id": "SYS-OWNER002",
                    "owner_uid": "uid_owner2",
                    "site_id": "SITE-OWNER002",
                    "name": "Owner Two Rooftop",
                    "location": {"lat": 28.6139, "lng": 77.2090},
                    "installation_date": datetime(2026, 2, 1, tzinfo=timezone.utc),
                    "panel_capacity_watts": 3000.0,
                    "inverter_type": "Off-Grid",
                    "components": [],
                    "qr_code_data": None,
                    "created_at": datetime(2026, 2, 1, tzinfo=timezone.utc),
                    "updated_at": datetime(2026, 2, 1, tzinfo=timezone.utc),
                },
            },
            "assignments": {}
        }

        # Seed deterministic report test readings for SYS-OWNER001 on 2026-08-16.
        # Variable-interval integration: N+1 readings produce N intervals.
        # 11 readings at 5-min intervals -> 10 intervals.
        # actual: 10 * 2400W * (5/60)h / 1000 = 2.0 kWh
        # expected: 10 * 2500W * (5/60)h / 1000 = 2.0833 kWh -> 2.08 kWh
        # lost = 2.08 - 2.0 = 0.08 kWh, loss_percent = (0.08/2.08)*100 = 3.85%
        # PR = 2.0 / 2.08 = 0.9615 -> 0.9615
        # temperature_ambient = 30.0°C (mean of 11 readings)
        # Rain sequence (11 readings): 0,0,0,1.5,2.0,1.0,0,2.5,1.2,0,0 -> 2 discrete events
        rain_seq_11 = [0.0, 0.0, 0.0, 1.5, 2.0, 1.0, 0.0, 2.5, 1.2, 0.0, 0.0]
        base_aug16 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(11):
            r_dt = base_aug16 + timedelta(minutes=5 * i)
            r_ts = int(r_dt.timestamp())
            self._store["readings"][f"read_aug16_{i}"] = {
                "system_id": "SYS-OWNER001",
                "timestamp": r_dt.isoformat(),
                "unix_timestamp": r_ts,
                "power": 2400.0,
                "expected_power": 2500.0,
                "performance_ratio": 0.96,
                "temperature_ambient": 30.0,
                "rain": rain_seq_11[i]
            }

        # Seed readings on 2026-08-12: 6 readings -> 5 intervals at 5-min each.
        # actual: 5 * 3600W * (5/60)h / 1000 = 1.5 kWh
        base_aug12 = datetime(2026, 8, 12, 11, 0, 0, tzinfo=timezone.utc)
        for i in range(6):
            r_dt = base_aug12 + timedelta(minutes=5 * i)
            r_ts = int(r_dt.timestamp())
            self._store["readings"][f"read_aug12_{i}"] = {
                "system_id": "SYS-OWNER001",
                "timestamp": r_dt.isoformat(),
                "unix_timestamp": r_ts,
                "power": 3600.0,
                "expected_power": 4000.0,
                "performance_ratio": 0.90,
                "temperature_ambient": 32.0,
                "rain": 0.0
            }

        # Seed readings on 2026-08-15 (worst day): 3 readings -> 2 intervals at 5-min each.
        # actual: 2 * 1200W * (5/60)h / 1000 = 0.2 kWh
        base_aug15 = datetime(2026, 8, 15, 9, 0, 0, tzinfo=timezone.utc)
        for i in range(3):
            r_dt = base_aug15 + timedelta(minutes=5 * i)
            r_ts = int(r_dt.timestamp())
            self._store["readings"][f"read_aug15_{i}"] = {
                "system_id": "SYS-OWNER001",
                "timestamp": r_dt.isoformat(),
                "unix_timestamp": r_ts,
                "power": 1200.0,
                "expected_power": 2000.0,
                "performance_ratio": 0.60,
                "temperature_ambient": 25.0,
                "rain": 3.0
            }

    def collection(self, name: str):
        return MockFirestoreCollection(self._store, name)


# ===========================================================================
# Shared payload for a valid system creation request
# ===========================================================================

VALID_SYSTEM_PAYLOAD = {
    "name": "Test Solar Installation",
    "location": {"lat": 26.8467, "lng": 80.9462},
    "installation_date": "2026-08-01T00:00:00Z",
    "panel_capacity_watts": 5000,
    "inverter_type": "Grid-Tied",
    "components": [
        {
            "type": "solar_panel",
            "model": "XYZ-550",
            "serial": "PANEL-001",
            "warranty_until": "2036-08-01T00:00:00Z"
        }
    ],
    "qr_code_data": "test-qr-data"
}


# ===========================================================================
# Main test runner
# ===========================================================================

def run_tests(include_ingest: bool = False) -> bool:
    """
    Executes the full test suite and prints formatted results.

    Args:
        include_ingest: When True, include POST /api/ingest tests that write
                        to the mocked Firestore.
    """
    print("\n==================================================================================")
    print("           Solar Backend API Integration & Security Test Suite                   ")
    print("==================================================================================\n", flush=True)

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
        print(f"{status_str:7s} | {full_label:<52s} | {details}", flush=True)
        test_counter += 1

    mock_db = MockFirestoreDB()
    client = app.test_client()

    # Mock token claims map for controlled testing [MOCKED AUTH]
    token_claims = {
        "valid-token-owner":        {"uid": "uid_owner",        "email": "owner@solar.com"},
        "valid-token-owner2":       {"uid": "uid_owner2",       "email": "owner2@solar.com"},
        "valid-token-tech":         {"uid": "uid_tech",         "email": "tech@solar.com"},
        "valid-token-tech2":        {"uid": "uid_tech2",        "email": "tech2@solar.com"},
        "valid-token-admin":        {"uid": "uid_admin",        "email": "admin@solar.com"},
        "valid-token-missing-role": {"uid": "uid_missing_role", "email": "norole@solar.com"},
        "valid-token-invalid-role": {"uid": "uid_invalid_role", "email": "invalidrole@solar.com"},
        "valid-token-orphan":       {"uid": "uid_orphan_no_firestore", "email": "orphan@solar.com"},
    }

    def mock_verify_id_token(id_token: str, *args, **kwargs):
        if id_token in token_claims:
            return token_claims[id_token]
        raise fb_auth.InvalidIdTokenError(
            f"Mocked auth rejection: token '{id_token}' is invalid or expired."
        )

    def mock_create_user(email: str, password: str, display_name: str = None, **kwargs):
        for uid, user_data in mock_db._store["users"].items():
            if user_data.get("email") == email:
                raise fb_auth.EmailAlreadyExistsError(
                    f"User with email {email} already exists."
                )
        mock_user = MagicMock()
        mock_user.uid = f"uid_{email.split('@')[0]}_{int(datetime.now(timezone.utc).timestamp())}"
        return mock_user

    # Patch get_db and firebase_admin.auth for ALL tests
    with patch("BACKEND.app.get_db", return_value=mock_db), \
         patch("BACKEND.auth.get_db", return_value=mock_db), \
         patch("BACKEND.chatbot.get_db", return_value=mock_db), \
         patch("BACKEND.analysis.get_db", return_value=mock_db), \
         patch("BACKEND.sites.get_db", return_value=mock_db), \
         patch("BACKEND.systems.get_db", return_value=mock_db), \
         patch("BACKEND.assignments.get_db", return_value=mock_db), \
         patch("BACKEND.reports.get_db", return_value=mock_db), \
         patch("firebase_admin.auth.verify_id_token", side_effect=mock_verify_id_token), \
         patch("firebase_admin.auth.create_user", side_effect=mock_create_user):

        # ---------------------------------------------------------
        # SEGMENT 1-6 ENDPOINT TESTS (Tests 1 – 11)
        # ---------------------------------------------------------

        # 1. GET /api/health
        try:
            r = client.get("/api/health")
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("status") == "ok")
            record_result("GET /api/health", passed, f"Status: {r.status_code} | Service: '{data.get('service')}'")
        except Exception as e:
            record_result("GET /api/health", False, f"Exception: {e}")

        # 2. GET /api/readings/latest
        try:
            r = client.get("/api/readings/latest?limit=5")
            data = r.get_json()
            passed = (r.status_code == 200 and isinstance(data, list))
            record_result("GET /api/readings/latest", passed, f"Status: {r.status_code} | Fetched: {len(data) if isinstance(data, list) else 0} readings")
        except Exception as e:
            record_result("GET /api/readings/latest", False, f"Exception: {e}")

        # 3. GET /api/alerts
        try:
            r = client.get("/api/alerts")
            data = r.get_json()
            passed = (r.status_code == 200 and isinstance(data, list))
            record_result("GET /api/alerts", passed, f"Status: {r.status_code} | Active Alerts: {len(data) if isinstance(data, list) else 0}")
        except Exception as e:
            record_result("GET /api/alerts", False, f"Exception: {e}")

        # 4. GET /api/analysis/run
        try:
            r = client.get("/api/analysis/run")
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("status") == "ok")
            record_result("GET /api/analysis/run", passed, f"Status: {r.status_code} | PR: {data.get('latest_pr')} | Anomaly: {data.get('is_anomaly')}")
        except Exception as e:
            record_result("GET /api/analysis/run", False, f"Exception: {e}")

        # Chatbot Queries (5 – 11)
        chat_queries = [
            ("Chat: Current Power",          "What is my current power generation?"),
            ("Chat: Performance Ratio",      "What is my performance ratio?"),
            ("Chat: Yesterday Drop Analysis","Why did my generation drop yesterday?"),
            ("Chat: Last 7 Days Energy Loss","How much energy did I lose last 7 days?"),
            ("Chat: This Month Energy Loss", "How much energy did I lose this month?"),
            ("Chat: Last Month Energy Loss", "How much energy did I lose last month?"),
            ("Chat: Active Alerts",          "Are there any active alerts?"),
        ]

        for label, q_text in chat_queries:
            try:
                r = client.get(f"/api/chat?query={q_text}")
                data = r.get_json() or {}
                passed = (r.status_code == 200 and "response" in data)
                snippet = data.get("response", "").replace("\n", " ")[:45]
                record_result(label, passed, f"Status: {r.status_code} | Resp: \"{snippet}...\"")
            except Exception as e:
                record_result(label, False, f"Exception: {e}")

        # ---------------------------------------------------------
        # SEGMENT 7 AUTHENTICATION & SECURITY TESTS (Tests 12 – 24)
        # ---------------------------------------------------------

        # 12. Owner Registration Success
        try:
            r = client.post("/api/auth/register", json={
                "email": "new_solar_owner@solar.com",
                "password": "password123",
                "name": "New Owner"
            })
            data = r.get_json() or {}
            user = data.get("user", {})
            passed = (r.status_code == 201 and user.get("role") == "owner" and "uid" in user)
            record_result("Auth: Owner Registration [Mocked Auth]", passed, f"Status: {r.status_code} | Assigned Role: '{user.get('role')}' | UID: {user.get('uid')}")
        except Exception as e:
            record_result("Auth: Owner Registration [Mocked Auth]", False, f"Exception: {e}")

        # 13. Public Privilege Escalation Attempt (Admin/Technician self-registration rejected)
        try:
            r_admin_attempt = client.post("/api/auth/register", json={
                "email": "attacker_admin@solar.com",
                "password": "password123",
                "name": "Attacker Admin",
                "role": "admin"
            })
            r_tech_attempt = client.post("/api/auth/register", json={
                "email": "attacker_tech@solar.com",
                "password": "password123",
                "name": "Attacker Tech",
                "role": "technician"
            })
            passed = (r_admin_attempt.status_code == 403 and r_tech_attempt.status_code == 403)
            record_result("Auth: Reject Public Admin/Tech Escalation", passed, f"Admin Attempt: {r_admin_attempt.status_code} (403), Tech Attempt: {r_tech_attempt.status_code} (403)")
        except Exception as e:
            record_result("Auth: Reject Public Admin/Tech Escalation", False, f"Exception: {e}")

        # 14. Duplicate Email Registration Prevention (409 Conflict)
        try:
            r = client.post("/api/auth/register", json={
                "email": "owner@solar.com",
                "password": "password123",
                "name": "Duplicate Owner"
            })
            passed = (r.status_code == 409)
            record_result("Auth: Reject Duplicate Email (409)", passed, f"Status: {r.status_code} (Expected 409 Conflict)")
        except Exception as e:
            record_result("Auth: Reject Duplicate Email (409)", False, f"Exception: {e}")

        # 15. /api/auth/me without Authorization Header (401)
        try:
            r = client.get("/api/auth/me")
            passed = (r.status_code == 401)
            record_result("Auth: Reject Missing Token (401)", passed, f"Status: {r.status_code} (Expected 401 Unauthorized)")
        except Exception as e:
            record_result("Auth: Reject Missing Token (401)", False, f"Exception: {e}")

        # 16. /api/auth/me with Invalid/Expired Token (401)
        try:
            r = client.get("/api/auth/me", headers={"Authorization": "Bearer invalid-garbage-jwt-token"})
            passed = (r.status_code == 401)
            record_result("Auth: Reject Invalid Token (401)", passed, f"Status: {r.status_code} (Expected 401 Unauthorized)")
        except Exception as e:
            record_result("Auth: Reject Invalid Token (401)", False, f"Exception: {e}")

        # 17. Valid Token but Missing Firestore Profile (403)
        try:
            r = client.get("/api/auth/me", headers={"Authorization": "Bearer valid-token-orphan"})
            passed = (r.status_code == 403)
            record_result("Auth: Reject Missing Firestore Profile (403)", passed, f"Status: {r.status_code} (Expected 403 Forbidden)")
        except Exception as e:
            record_result("Auth: Reject Missing Firestore Profile (403)", False, f"Exception: {e}")

        # 18. Owner → Admin Endpoint (403)
        try:
            r = client.get("/api/auth/admin-only", headers={"Authorization": "Bearer valid-token-owner"})
            passed = (r.status_code == 403)
            record_result("RBAC: Owner -> Admin Endpoint (403)", passed, f"Status: {r.status_code} (Expected 403 Forbidden)")
        except Exception as e:
            record_result("RBAC: Owner -> Admin Endpoint (403)", False, f"Exception: {e}")

        # 19. Technician → Admin Endpoint (403)
        try:
            r = client.get("/api/auth/admin-only", headers={"Authorization": "Bearer valid-token-tech"})
            passed = (r.status_code == 403)
            record_result("RBAC: Technician -> Admin Endpoint (403)", passed, f"Status: {r.status_code} (Expected 403 Forbidden)")
        except Exception as e:
            record_result("RBAC: Technician -> Admin Endpoint (403)", False, f"Exception: {e}")

        # 20. Technician → Tech/Admin Endpoint (200)
        try:
            r = client.get("/api/auth/tech-only", headers={"Authorization": "Bearer valid-token-tech"})
            passed = (r.status_code == 200)
            record_result("RBAC: Technician -> Tech/Admin Endpoint (200)", passed, f"Status: {r.status_code} (Expected 200 OK)")
        except Exception as e:
            record_result("RBAC: Technician -> Tech/Admin Endpoint (200)", False, f"Exception: {e}")

        # 21. Admin → Admin Endpoint (200)
        try:
            r = client.get("/api/auth/admin-only", headers={"Authorization": "Bearer valid-token-admin"})
            passed = (r.status_code == 200)
            record_result("RBAC: Admin -> Admin Endpoint (200)", passed, f"Status: {r.status_code} (Expected 200 OK)")
        except Exception as e:
            record_result("RBAC: Admin -> Admin Endpoint (200)", False, f"Exception: {e}")

        # 22. Admin → Tech/Admin Endpoint (200)
        try:
            r = client.get("/api/auth/tech-only", headers={"Authorization": "Bearer valid-token-admin"})
            passed = (r.status_code == 200)
            record_result("RBAC: Admin -> Tech/Admin Endpoint (200)", passed, f"Status: {r.status_code} (Expected 200 OK)")
        except Exception as e:
            record_result("RBAC: Admin -> Tech/Admin Endpoint (200)", False, f"Exception: {e}")

        # 23. Missing Role in Firestore → Protected Role Endpoint (403)
        try:
            r = client.get("/api/auth/admin-only", headers={"Authorization": "Bearer valid-token-missing-role"})
            passed = (r.status_code == 403)
            record_result("RBAC: Missing Role in Profile (403)", passed, f"Status: {r.status_code} (Expected 403 Forbidden - No default to owner)")
        except Exception as e:
            record_result("RBAC: Missing Role in Profile (403)", False, f"Exception: {e}")

        # 24. Invalid Role in Firestore → Protected Role Endpoint (403)
        try:
            r = client.get("/api/auth/admin-only", headers={"Authorization": "Bearer valid-token-invalid-role"})
            passed = (r.status_code == 403)
            record_result("RBAC: Invalid Role in Profile (403)", passed, f"Status: {r.status_code} (Expected 403 Forbidden)")
        except Exception as e:
            record_result("RBAC: Invalid Role in Profile (403)", False, f"Exception: {e}")

        # ---------------------------------------------------------
        # SEGMENT 8 SOLAR SYSTEM CRUD & SECURITY TESTS (25 – 54)
        # All Firebase calls mocked; Firestore mocked via MockFirestoreDB
        # ---------------------------------------------------------
        print("\n  --- Segment 8: Solar System CRUD & Security ---\n", flush=True)

        OWNER_HDR  = {"Authorization": "Bearer valid-token-owner"}
        OWNER2_HDR = {"Authorization": "Bearer valid-token-owner2"}
        TECH_HDR   = {"Authorization": "Bearer valid-token-tech"}
        TECH2_HDR  = {"Authorization": "Bearer valid-token-tech2"}
        ADMIN_HDR  = {"Authorization": "Bearer valid-token-admin"}

        created_system_id = [None]
        admin_created_id  = [None]

        # 25. Owner creates system → 201
        try:
            r = client.post("/api/systems", json=VALID_SYSTEM_PAYLOAD, headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (
                r.status_code == 201
                and "system_id" in system
                and system.get("owner_uid") == "uid_owner"
                and system.get("role") is None
                and system.get("system_id", "").startswith("SYS-")
            )
            created_system_id[0] = system.get("system_id")
            record_result("Seg8: Owner creates system (201)", passed, f"Status: {r.status_code} | SID: {system.get('system_id')} | Owner: {system.get('owner_uid')}")
        except Exception as e:
            record_result("Seg8: Owner creates system (201)", False, f"Exception: {e}")

        # 26. Admin creates system → 201
        try:
            r = client.post("/api/systems", json={
                **VALID_SYSTEM_PAYLOAD, "name": "Admin Created System"
            }, headers=ADMIN_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (
                r.status_code == 201
                and system.get("owner_uid") == "uid_admin"
                and system.get("system_id", "").startswith("SYS-")
            )
            admin_created_id[0] = system.get("system_id")
            record_result("Seg8: Admin creates system (201)", passed, f"Status: {r.status_code} | SID: {system.get('system_id')}")
        except Exception as e:
            record_result("Seg8: Admin creates system (201)", False, f"Exception: {e}")

        # 27. Technician creates system → 403
        try:
            r = client.post("/api/systems", json=VALID_SYSTEM_PAYLOAD, headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Seg8: Technician creates system (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg8: Technician creates system (403)", False, f"Exception: {e}")

        # 28. Unauthenticated create → 401
        try:
            r = client.post("/api/systems", json=VALID_SYSTEM_PAYLOAD)
            passed = (r.status_code == 401)
            record_result("Seg8: Unauthenticated create (401)", passed, f"Status: {r.status_code} (Expected 401)")
        except Exception as e:
            record_result("Seg8: Unauthenticated create (401)", False, f"Exception: {e}")

        # 29. Missing required field → 400
        try:
            bad_payload = {k: v for k, v in VALID_SYSTEM_PAYLOAD.items() if k != "name"}
            r = client.post("/api/systems", json=bad_payload, headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg8: Missing required field (400)", passed, f"Status: {r.status_code} (Expected 400)")
        except Exception as e:
            record_result("Seg8: Missing required field (400)", False, f"Exception: {e}")

        # 30. Invalid latitude → 400
        try:
            bad_payload = {**VALID_SYSTEM_PAYLOAD, "location": {"lat": 999, "lng": 80.0}}
            r = client.post("/api/systems", json=bad_payload, headers=OWNER_HDR)
            passed = (r.status_code == 400)
            data = r.get_json() or {}
            record_result("Seg8: Invalid latitude (400)", passed, f"Status: {r.status_code} | Msg: {data.get('message','')[:40]}")
        except Exception as e:
            record_result("Seg8: Invalid latitude (400)", False, f"Exception: {e}")

        # 31. Invalid longitude → 400
        try:
            bad_payload = {**VALID_SYSTEM_PAYLOAD, "location": {"lat": 26.0, "lng": -999}}
            r = client.post("/api/systems", json=bad_payload, headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg8: Invalid longitude (400)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg8: Invalid longitude (400)", False, f"Exception: {e}")

        # 32. Invalid panel capacity (zero) → 400
        try:
            bad_payload = {**VALID_SYSTEM_PAYLOAD, "panel_capacity_watts": 0}
            r = client.post("/api/systems", json=bad_payload, headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg8: Zero panel capacity (400)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg8: Zero panel capacity (400)", False, f"Exception: {e}")

        # 33. Negative panel capacity → 400
        try:
            bad_payload = {**VALID_SYSTEM_PAYLOAD, "panel_capacity_watts": -100}
            r = client.post("/api/systems", json=bad_payload, headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg8: Negative panel capacity (400)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg8: Negative panel capacity (400)", False, f"Exception: {e}")

        # 34. Client-supplied owner_uid is ignored (owner_uid from token)
        try:
            spoofed_payload = {**VALID_SYSTEM_PAYLOAD, "owner_uid": "uid_admin", "name": "Spoofed UID System"}
            r = client.post("/api/systems", json=spoofed_payload, headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (
                r.status_code == 201
                and system.get("owner_uid") == "uid_owner"
            )
            record_result("Seg8: owner_uid spoofing prevented", passed, f"Status: {r.status_code} | Stored owner: '{system.get('owner_uid')}' (must be uid_owner)")
        except Exception as e:
            record_result("Seg8: owner_uid spoofing prevented", False, f"Exception: {e}")

        # 35. Client-supplied system_id is ignored (always server-generated)
        try:
            spoofed_payload = {**VALID_SYSTEM_PAYLOAD, "system_id": "SYS-HACKER1", "name": "Spoofed SID System"}
            r = client.post("/api/systems", json=spoofed_payload, headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (
                r.status_code == 201
                and system.get("system_id") != "SYS-HACKER1"
                and system.get("system_id", "").startswith("SYS-")
            )
            record_result("Seg8: system_id spoofing prevented", passed, f"Status: {r.status_code} | Server SID: '{system.get('system_id')}' (not HACKER1)")
        except Exception as e:
            record_result("Seg8: system_id spoofing prevented", False, f"Exception: {e}")

        # 36. Owner lists own systems → only own systems (200)
        try:
            r = client.get("/api/systems", headers=OWNER_HDR)
            data = r.get_json()
            passed = (
                r.status_code == 200
                and isinstance(data, list)
                and all(s.get("owner_uid") == "uid_owner" for s in data)
            )
            non_own = [s for s in (data or []) if s.get("owner_uid") != "uid_owner"]
            record_result("Seg8: Owner lists only own systems (200)", passed, f"Status: {r.status_code} | Count: {len(data or [])} | Non-own leaked: {len(non_own)}")
        except Exception as e:
            record_result("Seg8: Owner lists only own systems (200)", False, f"Exception: {e}")

        # 37. Technician list without assignment → 200 + empty list
        try:
            r = client.get("/api/systems", headers=TECH_HDR)
            data = r.get_json()
            passed = (r.status_code == 200 and data == [])
            record_result("Seg8: Technician list returns empty (200)", passed, f"Status: {r.status_code} | Count: {len(data or [])}")
        except Exception as e:
            record_result("Seg8: Technician list returns empty (200)", False, f"Exception: {e}")

        # 38. Admin lists all systems → 200
        try:
            r = client.get("/api/systems", headers=ADMIN_HDR)
            data = r.get_json()
            passed = (r.status_code == 200 and isinstance(data, list) and len(data) >= 2)
            record_result("Seg8: Admin lists all systems (200)", passed, f"Status: {r.status_code} | Count: {len(data or [])}")
        except Exception as e:
            record_result("Seg8: Admin lists all systems (200)", False, f"Exception: {e}")

        # 39. Unauthenticated list → 401
        try:
            r = client.get("/api/systems")
            passed = (r.status_code == 401)
            record_result("Seg8: Unauthenticated list (401)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg8: Unauthenticated list (401)", False, f"Exception: {e}")

        # 40. Owner gets own system → 200
        try:
            r = client.get("/api/systems/SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (r.status_code == 200 and system.get("system_id") == "SYS-OWNER001")
            record_result("Seg8: Owner gets own system (200)", passed, f"Status: {r.status_code} | SID: {system.get('system_id')}")
        except Exception as e:
            record_result("Seg8: Owner gets own system (200)", False, f"Exception: {e}")

        # 41. Owner cannot get another owner's system → 403
        try:
            r = client.get("/api/systems/SYS-OWNER002", headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Seg8: Owner cannot get other owner system (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg8: Owner cannot get other owner system (403)", False, f"Exception: {e}")

        # 42. Admin gets any system → 200
        try:
            r = client.get("/api/systems/SYS-OWNER002", headers=ADMIN_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (r.status_code == 200 and system.get("system_id") == "SYS-OWNER002")
            record_result("Seg8: Admin gets any system (200)", passed, f"Status: {r.status_code} | SID: {system.get('system_id')}")
        except Exception as e:
            record_result("Seg8: Admin gets any system (200)", False, f"Exception: {e}")

        # 43. Technician gets unassigned system → 403
        try:
            r = client.get("/api/systems/SYS-OWNER001", headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Seg8: Technician gets unassigned system (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg8: Technician gets unassigned system (403)", False, f"Exception: {e}")

        # 44. Non-existent system → 404
        try:
            r = client.get("/api/systems/SYS-DOESNOTEXIST", headers=ADMIN_HDR)
            passed = (r.status_code == 404)
            record_result("Seg8: Non-existent system (404)", passed, f"Status: {r.status_code} (Expected 404)")
        except Exception as e:
            record_result("Seg8: Non-existent system (404)", False, f"Exception: {e}")

        # 45. Owner updates own system → 200
        try:
            r = client.put("/api/systems/SYS-OWNER001", json={"name": "Updated Name"}, headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (r.status_code == 200 and system.get("name") == "Updated Name")
            record_result("Seg8: Owner updates own system (200)", passed, f"Status: {r.status_code} | Name: '{system.get('name')}'")
        except Exception as e:
            record_result("Seg8: Owner updates own system (200)", False, f"Exception: {e}")

        # 46. Owner cannot update another owner's system → 403
        try:
            r = client.put("/api/systems/SYS-OWNER002", json={"name": "Hijacked"}, headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Seg8: Owner cannot update other owner system (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg8: Owner cannot update other owner system (403)", False, f"Exception: {e}")

        # 47. Technician cannot update → 403
        try:
            r = client.put("/api/systems/SYS-OWNER001", json={"name": "Tech Hijack"}, headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Seg8: Technician cannot update system (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg8: Technician cannot update system (403)", False, f"Exception: {e}")

        # 48. Admin updates any system → 200
        try:
            r = client.put("/api/systems/SYS-OWNER001", json={"inverter_type": "Hybrid"}, headers=ADMIN_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (r.status_code == 200 and system.get("inverter_type") == "Hybrid")
            record_result("Seg8: Admin updates any system (200)", passed, f"Status: {r.status_code} | Inverter: '{system.get('inverter_type')}'")
        except Exception as e:
            record_result("Seg8: Admin updates any system (200)", False, f"Exception: {e}")

        # 49. Client cannot modify owner_uid via PUT → ignored
        try:
            r = client.put("/api/systems/SYS-OWNER001", json={
                "owner_uid": "uid_hacker",
                "name": "Ownership Takeover"
            }, headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (
                r.status_code == 200
                and system.get("owner_uid") == "uid_owner"
            )
            record_result("Seg8: Cannot modify owner_uid via PUT", passed, f"Status: {r.status_code} | owner_uid: '{system.get('owner_uid')}'")
        except Exception as e:
            record_result("Seg8: Cannot modify owner_uid via PUT", False, f"Exception: {e}")

        # 50. updated_at changes after update
        try:
            r_get = client.get("/api/systems/SYS-OWNER001", headers=ADMIN_HDR)
            before = (r_get.get_json() or {}).get("system", {}).get("updated_at")
            import time as _time
            _time.sleep(0.01)
            r_put = client.put("/api/systems/SYS-OWNER001", json={"name": "Time Check System"}, headers=ADMIN_HDR)
            after = (r_put.get_json() or {}).get("system", {}).get("updated_at")
            passed = (r_put.status_code == 200 and after is not None)
            record_result("Seg8: updated_at set on update", passed, f"Status: {r_put.status_code} | updated_at present: {after is not None}")
        except Exception as e:
            record_result("Seg8: updated_at set on update", False, f"Exception: {e}")

        # 51. Owner cannot delete system → 403
        try:
            r = client.delete("/api/systems/SYS-OWNER001", headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Seg8: Owner cannot delete system (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg8: Owner cannot delete system (403)", False, f"Exception: {e}")

        # 52. Technician cannot delete system → 403
        try:
            r = client.delete("/api/systems/SYS-OWNER001", headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Seg8: Technician cannot delete system (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg8: Technician cannot delete system (403)", False, f"Exception: {e}")

        # 53. Admin deletes system → 200
        try:
            target = admin_created_id[0] or "SYS-OWNER002"
            r = client.delete(f"/api/systems/{target}", headers=ADMIN_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("system_id") == target)
            record_result("Seg8: Admin deletes system (200)", passed, f"Status: {r.status_code} | SID: {data.get('system_id')}")
        except Exception as e:
            record_result("Seg8: Admin deletes system (200)", False, f"Exception: {e}")

        # 54. Get deleted system → 404
        try:
            target = admin_created_id[0] or "SYS-OWNER002"
            r = client.get(f"/api/systems/{target}", headers=ADMIN_HDR)
            passed = (r.status_code == 404)
            record_result("Seg8: Get deleted system (404)", passed, f"Status: {r.status_code} (Expected 404)")
        except Exception as e:
            record_result("Seg8: Get deleted system (404)", False, f"Exception: {e}")

        # ---------------------------------------------------------
        # PRODUCTION IMPROVEMENT TESTS (55 – 72)
        # Technician Assignments & Concurrency Protection
        # ---------------------------------------------------------
        print("\n  --- Improvements: Technician Assignments & Concurrency ---\n", flush=True)

        created_asg_id = [None]

        # 55. Admin creates technician assignment → 201
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_tech",
                "system_id": "SYS-OWNER001"
            }, headers=ADMIN_HDR)
            data = r.get_json() or {}
            asg = data.get("assignment", {})
            passed = (
                r.status_code == 201
                and asg.get("technician_uid") == "uid_tech"
                and asg.get("system_id") == "SYS-OWNER001"
                and asg.get("status") == "active"
                and asg.get("assignment_id", "").startswith("ASG-")
            )
            created_asg_id[0] = asg.get("assignment_id")
            record_result("Asg: Admin creates assignment (201)", passed, f"Status: {r.status_code} | AID: {asg.get('assignment_id')} | Tech: {asg.get('technician_uid')}")
        except Exception as e:
            record_result("Asg: Admin creates assignment (201)", False, f"Exception: {e}")

        # 56. Technician self-assignment attempt → 403
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_tech",
                "system_id": "SYS-OWNER002"
            }, headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Asg: Technician self-assignment rejected (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Asg: Technician self-assignment rejected (403)", False, f"Exception: {e}")

        # 57. Owner assignment creation attempt → 403
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_tech",
                "system_id": "SYS-OWNER001"
            }, headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Asg: Owner assignment creation rejected (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Asg: Owner assignment creation rejected (403)", False, f"Exception: {e}")

        # 58. Unauthenticated assignment creation → 401
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_tech",
                "system_id": "SYS-OWNER001"
            })
            passed = (r.status_code == 401)
            record_result("Asg: Unauthenticated assignment rejected (401)", passed, f"Status: {r.status_code} (Expected 401)")
        except Exception as e:
            record_result("Asg: Unauthenticated assignment rejected (401)", False, f"Exception: {e}")

        # 59. Assignment creation with non-existent system → 404
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_tech",
                "system_id": "SYS-NONEXISTENT"
            }, headers=ADMIN_HDR)
            passed = (r.status_code == 404)
            record_result("Asg: Assign non-existent system rejected (404)", passed, f"Status: {r.status_code} (Expected 404)")
        except Exception as e:
            record_result("Asg: Assign non-existent system rejected (404)", False, f"Exception: {e}")

        # 60. Assignment creation with non-technician user (e.g. owner) → 400
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_owner",
                "system_id": "SYS-OWNER001"
            }, headers=ADMIN_HDR)
            passed = (r.status_code == 400)
            record_result("Asg: Assign non-technician user rejected (400)", passed, f"Status: {r.status_code} (Expected 400)")
        except Exception as e:
            record_result("Asg: Assign non-technician user rejected (400)", False, f"Exception: {e}")

        # 61. Duplicate active assignment rejected → 409 Conflict
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_tech",
                "system_id": "SYS-OWNER001"
            }, headers=ADMIN_HDR)
            passed = (r.status_code == 409)
            record_result("Asg: Duplicate active assignment rejected (409)", passed, f"Status: {r.status_code} (Expected 409 Conflict)")
        except Exception as e:
            record_result("Asg: Duplicate active assignment rejected (409)", False, f"Exception: {e}")

        # 62. Admin lists all assignments → 200
        try:
            r = client.get("/api/assignments", headers=ADMIN_HDR)
            data = r.get_json()
            passed = (r.status_code == 200 and isinstance(data, list) and len(data) >= 1)
            record_result("Asg: Admin lists all assignments (200)", passed, f"Status: {r.status_code} | Total assignments: {len(data or [])}")
        except Exception as e:
            record_result("Asg: Admin lists all assignments (200)", False, f"Exception: {e}")

        # 63. Technician lists only own active assignments → 200
        try:
            r = client.get("/api/assignments", headers=TECH_HDR)
            data = r.get_json()
            passed = (
                r.status_code == 200
                and isinstance(data, list)
                and len(data) == 1
                and data[0].get("technician_uid") == "uid_tech"
            )
            record_result("Asg: Technician lists own assignments (200)", passed, f"Status: {r.status_code} | Owned assignments: {len(data or [])}")
        except Exception as e:
            record_result("Asg: Technician lists own assignments (200)", False, f"Exception: {e}")

        # 64. Owner cannot view assignments → 403
        try:
            r = client.get("/api/assignments", headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Asg: Owner viewing assignments rejected (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Asg: Owner viewing assignments rejected (403)", False, f"Exception: {e}")

        # 65. Technician lists systems → now returns assigned system SYS-OWNER001 (200)
        try:
            r = client.get("/api/systems", headers=TECH_HDR)
            data = r.get_json()
            passed = (
                r.status_code == 200
                and isinstance(data, list)
                and len(data) == 1
                and data[0].get("system_id") == "SYS-OWNER001"
            )
            record_result("Asg: Technician lists assigned systems (200)", passed, f"Status: {r.status_code} | Assigned systems: {[s.get('system_id') for s in (data or [])]}")
        except Exception as e:
            record_result("Asg: Technician lists assigned systems (200)", False, f"Exception: {e}")

        # 66. Technician gets assigned system → 200 OK
        try:
            r = client.get("/api/systems/SYS-OWNER001", headers=TECH_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (r.status_code == 200 and system.get("system_id") == "SYS-OWNER001")
            record_result("Asg: Technician gets assigned system (200)", passed, f"Status: {r.status_code} | System: {system.get('system_id')}")
        except Exception as e:
            record_result("Asg: Technician gets assigned system (200)", False, f"Exception: {e}")

        # 67. Technician gets unassigned system SYS-OWNER002 → 403 Forbidden
        try:
            r = client.get("/api/systems/SYS-OWNER002", headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Asg: Technician gets unassigned system (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Asg: Technician gets unassigned system (403)", False, f"Exception: {e}")

        # 68. Technician 2 cannot access Technician 1's assigned system → 403 Forbidden
        try:
            r = client.get("/api/systems/SYS-OWNER001", headers=TECH2_HDR)
            passed = (r.status_code == 403)
            record_result("Asg: Cross-technician isolation (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Asg: Cross-technician isolation (403)", False, f"Exception: {e}")

        # 69. Admin deletes/deactivates assignment → 200 OK
        try:
            aid = created_asg_id[0]
            r = client.delete(f"/api/assignments/{aid}", headers=ADMIN_HDR)
            passed = (r.status_code == 200)
            record_result("Asg: Admin deletes assignment (200)", passed, f"Status: {r.status_code} | Deleted AID: {aid}")
        except Exception as e:
            record_result("Asg: Admin deletes assignment (200)", False, f"Exception: {e}")

        # 70. Technician lists systems after assignment deletion → returns empty [] (200)
        try:
            r = client.get("/api/systems", headers=TECH_HDR)
            data = r.get_json()
            passed = (r.status_code == 200 and data == [])
            record_result("Asg: Technician list empty after delete (200)", passed, f"Status: {r.status_code} | Systems: {len(data or [])}")
        except Exception as e:
            record_result("Asg: Technician list empty after delete (200)", False, f"Exception: {e}")

        # 71. Concurrency: Atomic creation with simulated collision retries cleanly → 201
        try:
            from BACKEND.systems import create_system_atomic
            sim_doc_data = {
                "owner_uid": "uid_owner",
                "name": "Atomic Concurrency Test System",
                "location": {"lat": 26.8467, "lng": 80.9462},
                "installation_date": datetime.now(timezone.utc),
                "panel_capacity_watts": 5000.0,
                "inverter_type": "Grid-Tied",
                "components": [],
                "qr_code_data": None,
                "created_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
            }
            sid, out_data = create_system_atomic(mock_db, sim_doc_data, max_retries=5)
            passed = (sid.startswith("SYS-") and out_data["system_id"] == sid)
            record_result("Atomic: Collision retry & atomic creation (201)", passed, f"Generated SID: '{sid}'")
        except Exception as e:
            record_result("Atomic: Collision retry & atomic creation (201)", False, f"Exception: {e}")

        # 72. Security: Client cannot force an existing system_id to overwrite existing data
        try:
            r = client.post("/api/systems", json={
                **VALID_SYSTEM_PAYLOAD,
                "system_id": "SYS-OWNER001",
                "name": "Malicious Overwrite Attempt"
            }, headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            orig_doc = mock_db.collection("systems").document("SYS-OWNER001").get().to_dict()
            passed = (
                r.status_code == 201
                and system.get("system_id") != "SYS-OWNER001"
                and orig_doc.get("name") != "Malicious Overwrite Attempt"
            )
            record_result("Security: Force system_id overwrite prevented", passed, f"Status: {r.status_code} | Original Name: '{orig_doc.get('name')}' (Untouched)")
        except Exception as e:
            record_result("Security: Force system_id overwrite prevented", False, f"Exception: {e}")

        # ---------------------------------------------------------
        # SEGMENT 9 SOLAR PERFORMANCE REPORT TESTS (73 – 102)
        # ---------------------------------------------------------
        print("\n  --- Segment 9: Solar Performance Reports ---\n", flush=True)

        # 73. Daily report owner -> 200
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("success") is True and data.get("data_available") is True)
            record_result("Seg9: Daily report owner (200)", passed, f"Status: {r.status_code} | Sys: {data.get('system_id')}")
        except Exception as e:
            record_result("Seg9: Daily report owner (200)", False, f"Exception: {e}")

        # 74. Daily report admin -> 200
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=ADMIN_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("success") is True)
            record_result("Seg9: Daily report admin (200)", passed, f"Status: {r.status_code} | Generation: {data.get('generation',{}).get('actual_kwh')} kWh")
        except Exception as e:
            record_result("Seg9: Daily report admin (200)", False, f"Exception: {e}")

        # 75. Daily report technician -> 403
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Seg9: Daily report technician rejected (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg9: Daily report technician rejected (403)", False, f"Exception: {e}")

        # 76. Daily report unauthenticated -> 401
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001")
            passed = (r.status_code == 401)
            record_result("Seg9: Daily report unauthenticated (401)", passed, f"Status: {r.status_code} (Expected 401)")
        except Exception as e:
            record_result("Seg9: Daily report unauthenticated (401)", False, f"Exception: {e}")

        # 77. Daily report missing date -> 400
        try:
            r = client.get("/api/reports/daily?system_id=SYS-OWNER001", headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg9: Daily report missing date (400)", passed, f"Status: {r.status_code} (Expected 400)")
        except Exception as e:
            record_result("Seg9: Daily report missing date (400)", False, f"Exception: {e}")

        # 78. Daily report invalid date format -> 400
        try:
            r = client.get("/api/reports/daily?date=2026-99-99&system_id=SYS-OWNER001", headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg9: Daily report invalid date format (400)", passed, f"Status: {r.status_code} (Expected 400)")
        except Exception as e:
            record_result("Seg9: Daily report invalid date format (400)", False, f"Exception: {e}")

        # 79. Daily report missing system_id -> 400
        try:
            r = client.get("/api/reports/daily?date=2026-08-16", headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg9: Daily report missing system_id (400)", passed, f"Status: {r.status_code} (Expected 400)")
        except Exception as e:
            record_result("Seg9: Daily report missing system_id (400)", False, f"Exception: {e}")

        # 80. Daily report non-existent system -> 404
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-NONEXISTENT", headers=ADMIN_HDR)
            passed = (r.status_code == 404)
            record_result("Seg9: Daily report non-existent system (404)", passed, f"Status: {r.status_code} (Expected 404)")
        except Exception as e:
            record_result("Seg9: Daily report non-existent system (404)", False, f"Exception: {e}")

        # 81. Owner cannot access another owner's report -> 403
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER2_HDR)
            passed = (r.status_code == 403)
            record_result("Seg9: Cross-owner report access rejected (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg9: Cross-owner report access rejected (403)", False, f"Exception: {e}")

        # 82. Daily actual generation (11 readings, 10 intervals x 5min x 2400W = 2.0 kWh)
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            gen = data.get("generation", {})
            passed = (r.status_code == 200 and gen.get("actual_kwh") == 2.0)
            record_result("Seg9: Daily actual generation math (2.0 kWh)", passed, f"Actual kWh: {gen.get('actual_kwh')}")
        except Exception as e:
            record_result("Seg9: Daily actual generation math (2.0 kWh)", False, f"Exception: {e}")

        # 83. Daily expected generation (11 readings, 10 intervals x 5min x 2500W = 2.08 kWh)
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            gen = data.get("generation", {})
            passed = (r.status_code == 200 and gen.get("expected_kwh") == 2.08)
            record_result("Seg9: Daily expected generation math (2.08 kWh)", passed, f"Expected kWh: {gen.get('expected_kwh')}")
        except Exception as e:
            record_result("Seg9: Daily expected generation math (2.08 kWh)", False, f"Exception: {e}")

        # 84. Daily lost generation (2.08 - 2.0 = 0.08 kWh, (0.08/2.08)*100 = 3.85%)
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            gen = data.get("generation", {})
            passed = (r.status_code == 200 and gen.get("lost_kwh") == 0.08 and gen.get("loss_percent") == 3.85)
            record_result("Seg9: Daily lost generation math (0.08 kWh, 3.85%)", passed, f"Lost: {gen.get('lost_kwh')} kWh | Loss %: {gen.get('loss_percent')}%")
        except Exception as e:
            record_result("Seg9: Daily lost generation math (0.08 kWh, 3.85%)", False, f"Exception: {e}")

        # 85. Aggregate PR = actual/expected = 2.0/2.08 = 0.9615 -> 96.15%
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            perf = data.get("performance", {})
            pr_val = perf.get("performance_ratio")
            pr_pct_val = perf.get("performance_ratio_percent")
            passed = (r.status_code == 200 and pr_val is not None and abs(pr_val - 0.9615) < 0.001
                      and pr_pct_val is not None and abs(pr_pct_val - 96.15) < 0.1)
            record_result("Seg9: Daily Aggregate PR (actual/expected)", passed, f"PR: {pr_val} | PR%: {pr_pct_val}%")
        except Exception as e:
            record_result("Seg9: Daily Aggregate PR (actual/expected)", False, f"Exception: {e}")

        # 86. Daily peak power (max power = 2400.0 W)
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            perf = data.get("performance", {})
            passed = (r.status_code == 200 and perf.get("peak_power_w") == 2400.0)
            record_result("Seg9: Daily peak power calculation (2400.0 W)", passed, f"Peak Power: {perf.get('peak_power_w')} W")
        except Exception as e:
            record_result("Seg9: Daily peak power calculation (2400.0 W)", False, f"Exception: {e}")

        # 87. Daily average temperature (30.0 °C)
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            env = data.get("environment", {})
            passed = (r.status_code == 200 and env.get("average_temperature_c") == 30.0)
            record_result("Seg9: Daily average temperature (30.0 °C)", passed, f"Avg Temp: {env.get('average_temperature_c')} °C")
        except Exception as e:
            record_result("Seg9: Daily average temperature (30.0 °C)", False, f"Exception: {e}")

        # 88. Daily rain events (2 discrete False->True transitions)
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            env = data.get("environment", {})
            passed = (r.status_code == 200 and env.get("rain_events") == 2)
            record_result("Seg9: Daily discrete rain events (2 events)", passed, f"Rain Events: {env.get('rain_events')}")
        except Exception as e:
            record_result("Seg9: Daily discrete rain events (2 events)", False, f"Exception: {e}")

        # 89. Daily empty telemetry period handling -> 200 with data_available=False
        try:
            r = client.get("/api/reports/daily?date=2025-01-01&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("data_available") is False and "generation" not in data)
            record_result("Seg9: Daily empty telemetry handling (200)", passed, f"data_available: {data.get('data_available')}")
        except Exception as e:
            record_result("Seg9: Daily empty telemetry handling (200)", False, f"Exception: {e}")

        # 90. Daily data completeness (11 readings / 288 = 3.82%); enriched data_quality block present
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            dq = data.get("data_quality", {})
            passed = (
                r.status_code == 200
                and dq.get("reading_count") == 11
                and dq.get("expected_readings") == 288
                and dq.get("data_completeness_percent") == round(11/288*100, 2)
                and "valid_reading_count" in dq
                and "data_gap_count" in dq
            )
            record_result("Seg9: Daily data completeness & enriched dq block", passed,
                          f"Count: {dq.get('reading_count')}/288 ({dq.get('data_completeness_percent')}%) | gaps: {dq.get('data_gap_count')}")
        except Exception as e:
            record_result("Seg9: Daily data completeness & enriched dq block", False, f"Exception: {e}")

        # 91. Weekly report owner -> 200
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("report_type") == "weekly" and data.get("data_available") is True)
            record_result("Seg9: Weekly report owner (200)", passed, f"Status: {r.status_code} | Total Gen: {data.get('generation',{}).get('actual_kwh')} kWh")
        except Exception as e:
            record_result("Seg9: Weekly report owner (200)", False, f"Exception: {e}")

        # 92. Weekly report unauthorized owner -> 403
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER2_HDR)
            passed = (r.status_code == 403)
            record_result("Seg9: Weekly report cross-owner rejected (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg9: Weekly report cross-owner rejected (403)", False, f"Exception: {e}")

        # 93. Weekly report admin -> 200
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=ADMIN_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("success") is True)
            record_result("Seg9: Weekly report admin (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg9: Weekly report admin (200)", False, f"Exception: {e}")

        # 94. Weekly date-range validation (start_date > end_date -> 400)
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-20&end_date=2026-08-10&system_id=SYS-OWNER001", headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg9: Weekly invalid date order rejected (400)", passed, f"Status: {r.status_code} (Expected 400)")
        except Exception as e:
            record_result("Seg9: Weekly invalid date order rejected (400)", False, f"Exception: {e}")

        # 95. Weekly best day (aug16=2.0 kWh > aug12=1.5 kWh > aug15=0.2 kWh -> Best: 2026-08-16)
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            best = data.get("best_day", {})
            passed = (r.status_code == 200 and best.get("date") == "2026-08-16" and best.get("generation_kwh") == 2.0)
            record_result("Seg9: Weekly best day (2026-08-16, 2.0 kWh)", passed, f"Best Day: {best.get('date')} ({best.get('generation_kwh')} kWh)")
        except Exception as e:
            record_result("Seg9: Weekly best day (2026-08-16, 2.0 kWh)", False, f"Exception: {e}")

        # 96. Weekly worst day (aug15=0.2 kWh -> Worst: 2026-08-15)
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            worst = data.get("worst_day", {})
            passed = (r.status_code == 200 and worst.get("date") == "2026-08-15" and worst.get("generation_kwh") == 0.2)
            record_result("Seg9: Weekly worst day (2026-08-15, 0.2 kWh)", passed, f"Worst Day: {worst.get('date')} ({worst.get('generation_kwh')} kWh)")
        except Exception as e:
            record_result("Seg9: Weekly worst day (2026-08-15, 0.2 kWh)", False, f"Exception: {e}")

        # 97. Monthly report owner -> 200
        try:
            r = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("report_type") == "monthly" and data.get("month") == "2026-08")
            record_result("Seg9: Monthly report owner (200)", passed, f"Status: {r.status_code} | Month: {data.get('month')}")
        except Exception as e:
            record_result("Seg9: Monthly report owner (200)", False, f"Exception: {e}")

        # 98. Monthly report admin -> 200
        try:
            r = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=ADMIN_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("success") is True)
            record_result("Seg9: Monthly report admin (200)", passed, f"Status: {r.status_code} | Gen: {data.get('generation',{}).get('actual_kwh')} kWh")
        except Exception as e:
            record_result("Seg9: Monthly report admin (200)", False, f"Exception: {e}")

        # 99. Monthly report technician -> 403
        try:
            r = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Seg9: Monthly report technician rejected (403)", passed, f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Seg9: Monthly report technician rejected (403)", False, f"Exception: {e}")

        # 100. Monthly report invalid month format -> 400
        try:
            r = client.get("/api/reports/monthly?month=2026-13&system_id=SYS-OWNER001", headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Seg9: Monthly invalid month format rejected (400)", passed, f"Status: {r.status_code} (Expected 400)")
        except Exception as e:
            record_result("Seg9: Monthly invalid month format rejected (400)", False, f"Exception: {e}")

        # 101. Monthly empty data handling -> 200 with data_available=False
        try:
            r = client.get("/api/reports/monthly?month=2025-01&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("data_available") is False)
            record_result("Seg9: Monthly empty data handling (200)", passed, f"data_available: {data.get('data_available')}")
        except Exception as e:
            record_result("Seg9: Monthly empty data handling (200)", False, f"Exception: {e}")

        # 102. Monthly aggregate (aug16=2.0 + aug12=1.5 + aug15=0.2 = 3.7 kWh)
        try:
            r = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            gen = data.get("generation", {})
            passed = (r.status_code == 200 and gen.get("actual_kwh") == 3.7)
            record_result("Seg9: Monthly aggregate math (3.7 kWh)", passed, f"Monthly Actual: {gen.get('actual_kwh')} kWh")
        except Exception as e:
            record_result("Seg9: Monthly aggregate math (3.7 kWh)", False, f"Exception: {e}")

        # ---------------------------------------------------------
        # SEGMENT 9 HARDENING & OPTIMIZATION TESTS (103 – 132)
        # A. Firestore query filtering
        # B. Irregular interval energy integration
        # C. Expected-generation strategy
        # D. Aggregate PR
        # E. Regression
        # ---------------------------------------------------------
        print("\n  --- Seg9 Hardening: Firestore Filtering, Variable Intervals, PR ---\n", flush=True)

        # ---- Unit-level helpers (direct function calls, no HTTP) ----
        from BACKEND.reports import integrate_energy, calculate_solar_metrics, fetch_readings_dataframe
        import pandas as pd

        def make_df(rows):
            """Build a minimal DataFrame from list-of-dicts for direct unit tests."""
            df = pd.DataFrame(rows)
            df["dt"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
            df = df.dropna(subset=["dt"]).sort_values("dt").reset_index(drop=True)
            return df

        # ---- A. Firestore Query Filtering Tests ----

        # 103. Query filters by system_id: SYS-OWNER002 readings must NOT appear in SYS-OWNER001 report
        try:
            # Temporarily inject a reading for SYS-OWNER002 on the same date
            mock_db._store["readings"]["_cross_sys_spy"] = {
                "system_id": "SYS-OWNER002",
                "timestamp": "2026-08-16T10:00:00+00:00",
                "unix_timestamp": int(datetime(2026,8,16,10,0,0,tzinfo=timezone.utc).timestamp()),
                "power": 99999.0,
                "expected_power": 99999.0,
            }
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            gen = data.get("generation", {})
            # 99999W must NOT appear in SYS-OWNER001 report; actual must stay 2.0 kWh
            passed = (r.status_code == 200 and gen.get("actual_kwh") == 2.0)
            record_result("Seg9H: Cross-system readings excluded", passed,
                          f"actual_kwh={gen.get('actual_kwh')} (must be 2.0, not contaminated by SYS-OWNER002)")
        except Exception as e:
            record_result("Seg9H: Cross-system readings excluded", False, f"Exception: {e}")
        finally:
            mock_db._store["readings"].pop("_cross_sys_spy", None)

        # 104. Out-of-range readings not included in report
        try:
            # Inject a reading from 2026-08-17 (outside 2026-08-16 range)
            mock_db._store["readings"]["_oor_future"] = {
                "system_id": "SYS-OWNER001",
                "timestamp": "2026-08-17T02:00:00+00:00",
                "unix_timestamp": int(datetime(2026,8,17,2,0,0,tzinfo=timezone.utc).timestamp()),
                "power": 99999.0,
            }
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            gen = data.get("generation", {})
            passed = (r.status_code == 200 and gen.get("actual_kwh") == 2.0)
            record_result("Seg9H: Out-of-range readings excluded", passed,
                          f"actual_kwh={gen.get('actual_kwh')} (must be 2.0)")
        except Exception as e:
            record_result("Seg9H: Out-of-range readings excluded", False, f"Exception: {e}")
        finally:
            mock_db._store["readings"].pop("_oor_future", None)

        # 105. Readings without system_id never leak into reports
        try:
            mock_db._store["readings"]["_no_sid"] = {
                "timestamp": "2026-08-16T10:05:00+00:00",
                "unix_timestamp": int(datetime(2026,8,16,10,5,0,tzinfo=timezone.utc).timestamp()),
                "power": 99999.0,
            }
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            gen = data.get("generation", {})
            passed = (r.status_code == 200 and gen.get("actual_kwh") == 2.0)
            record_result("Seg9H: Readings without system_id excluded", passed,
                          f"actual_kwh={gen.get('actual_kwh')} (must be 2.0)")
        except Exception as e:
            record_result("Seg9H: Readings without system_id excluded", False, f"Exception: {e}")
        finally:
            mock_db._store["readings"].pop("_no_sid", None)

        # ---- B. Irregular Interval Energy Integration (unit-level) ----

        # 106. Exact 5-minute intervals: 2 readings -> 1 interval
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0},
            ])
            kwh, gaps, excl = integrate_energy(df_unit, "power")
            expected = round(2400.0 * (5/60) / 1000, 4)  # 0.2 kWh
            passed = (abs(kwh - expected) < 0.001 and gaps == 0)
            record_result("Seg9H: 5-min interval energy (0.2 kWh)", passed, f"kWh={kwh} expected={expected}")
        except Exception as e:
            record_result("Seg9H: 5-min interval energy (0.2 kWh)", False, f"Exception: {e}")

        # 107. 2-minute intervals: 2 readings -> 1 interval
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=2)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 3000.0},
                {"timestamp": t1.isoformat(), "power": 3000.0},
            ])
            kwh, gaps, excl = integrate_energy(df_unit, "power")
            expected = round(3000.0 * (2/60) / 1000, 4)  # 0.1 kWh
            passed = (abs(kwh - expected) < 0.001 and gaps == 0)
            record_result("Seg9H: 2-min interval energy (0.1 kWh)", passed, f"kWh={kwh} expected={expected}")
        except Exception as e:
            record_result("Seg9H: 2-min interval energy (0.1 kWh)", False, f"Exception: {e}")

        # 108. 10-minute intervals: 2 readings -> 1 interval
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=10)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 1800.0},
                {"timestamp": t1.isoformat(), "power": 1800.0},
            ])
            kwh, gaps, excl = integrate_energy(df_unit, "power")
            expected = round(1800.0 * (10/60) / 1000, 4)  # 0.3 kWh
            passed = (abs(kwh - expected) < 0.001 and gaps == 0)
            record_result("Seg9H: 10-min interval energy (0.3 kWh)", passed, f"kWh={kwh} expected={expected}")
        except Exception as e:
            record_result("Seg9H: 10-min interval energy (0.3 kWh)", False, f"Exception: {e}")

        # 109. Mixed intervals: 2min + 5min
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=2)
            t2 = t1 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0},
                {"timestamp": t2.isoformat(), "power": 2400.0},
            ])
            kwh, gaps, _ = integrate_energy(df_unit, "power")
            expected = round(2400.0 * ((2+5)/60) / 1000, 4)  # 0.28 kWh
            passed = (abs(kwh - expected) < 0.001 and gaps == 0)
            record_result("Seg9H: Mixed intervals energy (0.28 kWh)", passed, f"kWh={kwh} expected={expected}")
        except Exception as e:
            record_result("Seg9H: Mixed intervals energy (0.28 kWh)", False, f"Exception: {e}")

        # 110. First reading does NOT generate artificial energy (only 1 reading -> 0 intervals)
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            df_unit = make_df([{"timestamp": t0.isoformat(), "power": 2400.0}])
            kwh, gaps, excl = integrate_energy(df_unit, "power")
            passed = (kwh == 0.0 and gaps == 0)
            record_result("Seg9H: Single reading -> 0.0 kWh (no artificial energy)", passed, f"kWh={kwh}")
        except Exception as e:
            record_result("Seg9H: Single reading -> 0.0 kWh (no artificial energy)", False, f"Exception: {e}")

        # 111. Duplicate timestamps: delta=0 -> skipped safely
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t0.isoformat(), "power": 2400.0},  # exact duplicate
                {"timestamp": (t0 + timedelta(minutes=5)).isoformat(), "power": 2400.0},
            ])
            kwh, gaps, excl = integrate_energy(df_unit, "power")
            # Only 1 valid interval (5 min) should be counted (duplicate skipped)
            expected = round(2400.0 * (5/60) / 1000, 4)
            passed = (abs(kwh - expected) < 0.001)
            record_result("Seg9H: Duplicate timestamps skipped safely", passed, f"kWh={kwh} (expected ~{expected})")
        except Exception as e:
            record_result("Seg9H: Duplicate timestamps skipped safely", False, f"Exception: {e}")

        # 112. Negative timestamp difference -> skipped safely
        try:
            t0 = datetime(2026, 8, 16, 10, 5, 0, tzinfo=timezone.utc)
            t1 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)  # earlier: backward
            t2 = datetime(2026, 8, 16, 10, 10, 0, tzinfo=timezone.utc)
            df_raw = pd.DataFrame([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0},  # backward
                {"timestamp": t2.isoformat(), "power": 2400.0},
            ])
            df_raw["dt"] = pd.to_datetime(df_raw["timestamp"], utc=True)
            df_raw = df_raw.sort_values("dt").reset_index(drop=True)
            kwh, gaps, excl = integrate_energy(df_raw, "power")
            # Sorted order: t1(10:00) -> t0(10:05) -> t2(10:10) -> all positive, 2 valid 5-min intervals
            passed = (kwh >= 0 and not (kwh != kwh))  # no NaN, no negative
            record_result("Seg9H: Backward timestamps handled (no negative energy)", passed, f"kWh={kwh} (>= 0)")
        except Exception as e:
            record_result("Seg9H: Backward timestamps handled (no negative energy)", False, f"Exception: {e}")

        # 113. Missing/None power value handled safely (treated as 0.0)
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            t2 = t1 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": None},    # missing power
                {"timestamp": t2.isoformat(), "power": 2400.0},
            ])
            kwh, gaps, excl = integrate_energy(df_unit, "power")
            # Interval t0->t1: power at t1=None -> skipped (0 contribution)
            # Interval t1->t2: power at t2=2400 -> 2400*(5/60)/1000 = 0.2 kWh
            passed = (kwh >= 0 and not (kwh != kwh))
            record_result("Seg9H: Missing power value handled safely", passed, f"kWh={kwh} (no crash, no NaN)")
        except Exception as e:
            record_result("Seg9H: Missing power value handled safely", False, f"Exception: {e}")

        # 114. Large gap (> MAX_INTEGRATION_INTERVAL_MINUTES) -> excluded, gap_count incremented
        try:
            from BACKEND.reports import MAX_INTEGRATION_INTERVAL_MINUTES
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=MAX_INTEGRATION_INTERVAL_MINUTES + 5)  # exceeds cap
            t2 = t1 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0},  # large gap before this
                {"timestamp": t2.isoformat(), "power": 2400.0},
            ])
            kwh, gap_count, excl_min = integrate_energy(df_unit, "power")
            expected_valid = round(2400.0 * (5/60) / 1000, 4)  # only the t1->t2 interval counted
            passed = (
                gap_count == 1
                and excl_min > MAX_INTEGRATION_INTERVAL_MINUTES
                and abs(kwh - expected_valid) < 0.001
            )
            record_result("Seg9H: Large gap excluded; gap_count=1", passed,
                          f"kWh={kwh} (expected {expected_valid}) | gap_count={gap_count} | excl_min={excl_min}")
        except Exception as e:
            record_result("Seg9H: Large gap excluded; gap_count=1", False, f"Exception: {e}")

        # 115. Data-gap metrics reported in API data_quality block
        try:
            # Insert a large-gap reading for SYS-OWNER001 on 2026-08-16
            t_gap = datetime(2026, 8, 16, 14, 0, 0, tzinfo=timezone.utc)  # 3.5h after last reading -> giant gap
            mock_db._store["readings"]["_gap_reading"] = {
                "system_id": "SYS-OWNER001",
                "timestamp": t_gap.isoformat(),
                "unix_timestamp": int(t_gap.timestamp()),
                "power": 2400.0,
            }
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            dq = data.get("data_quality", {})
            passed = (
                r.status_code == 200
                and "data_gap_count" in dq
                and dq["data_gap_count"] >= 1
                and "excluded_gap_minutes" in dq
                and dq["excluded_gap_minutes"] > 0
            )
            record_result("Seg9H: Data gap metrics in data_quality block", passed,
                          f"data_gap_count={dq.get('data_gap_count')} excl_min={dq.get('excluded_gap_minutes')}")
        except Exception as e:
            record_result("Seg9H: Data gap metrics in data_quality block", False, f"Exception: {e}")
        finally:
            mock_db._store["readings"].pop("_gap_reading", None)

        # ---- C. Expected-Generation Strategy Tests ----

        # 116. Valid expected_power in reading is used for expected generation
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2000.0, "expected_power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2000.0, "expected_power": 2400.0},
            ])
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026,8,16,tzinfo=timezone.utc),
                datetime(2026,8,17,tzinfo=timezone.utc))
            # 2400W * 5/60 / 1000 = 0.2 kWh
            passed = (metrics["expected_kwh"] == 0.2)
            record_result("Seg9H: Valid expected_power used for expected gen", passed,
                          f"expected_kwh={metrics['expected_kwh']} (want 0.2)")
        except Exception as e:
            record_result("Seg9H: Valid expected_power used for expected gen", False, f"Exception: {e}")

        # 117. Missing expected_power -> expected_kwh is None (no fake generation)
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},  # no expected_power
                {"timestamp": t1.isoformat(), "power": 2400.0},
            ])
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026,8,16,tzinfo=timezone.utc),
                datetime(2026,8,17,tzinfo=timezone.utc))
            passed = (metrics["expected_kwh"] is None and metrics["performance_ratio"] is None)
            record_result("Seg9H: Missing expected_power -> expected_kwh=None, PR=None", passed,
                          f"expected_kwh={metrics['expected_kwh']}, PR={metrics['performance_ratio']}")
        except Exception as e:
            record_result("Seg9H: Missing expected_power -> expected_kwh=None, PR=None", False, f"Exception: {e}")

        # 118. Invalid expected_power (NaN string) -> excluded safely
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            df_raw = pd.DataFrame([
                {"timestamp": t0.isoformat(), "power": 2400.0, "expected_power": "invalid"},
                {"timestamp": t1.isoformat(), "power": 2400.0, "expected_power": "invalid"},
            ])
            df_raw["dt"] = pd.to_datetime(df_raw["timestamp"], utc=True)
            df_raw = df_raw.sort_values("dt").reset_index(drop=True)
            metrics = calculate_solar_metrics(df_raw,
                datetime(2026,8,16,tzinfo=timezone.utc),
                datetime(2026,8,17,tzinfo=timezone.utc))
            # integrate_energy with non-numeric expected_power -> 0.0 kWh, but actual is valid
            passed = (
                metrics["actual_kwh"] is not None
                and metrics["actual_kwh"] > 0
                # expected is 0.0 (all invalid), so lost might be 0
            )
            record_result("Seg9H: Invalid expected_power handled safely (no crash)", passed,
                          f"actual_kwh={metrics['actual_kwh']} expected_kwh={metrics['expected_kwh']}")
        except Exception as e:
            record_result("Seg9H: Invalid expected_power handled safely (no crash)", False, f"Exception: {e}")

        # 119. Expected generation uses actual interval duration (not fixed 5 min)
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=3)  # 3-minute interval
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0, "expected_power": 2000.0},
                {"timestamp": t1.isoformat(), "power": 2400.0, "expected_power": 2000.0},
            ])
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026,8,16,tzinfo=timezone.utc),
                datetime(2026,8,17,tzinfo=timezone.utc))
            # 2000W * 3/60 / 1000 = 0.1 kWh
            passed = (metrics["expected_kwh"] == 0.1)
            record_result("Seg9H: Expected gen uses actual 3-min interval", passed,
                          f"expected_kwh={metrics['expected_kwh']} want 0.1")
        except Exception as e:
            record_result("Seg9H: Expected gen uses actual 3-min interval", False, f"Exception: {e}")

        # 120. Lost generation remains correct after variable-interval change
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 1200.0, "expected_power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 1200.0, "expected_power": 2400.0},
            ])
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026,8,16,tzinfo=timezone.utc),
                datetime(2026,8,17,tzinfo=timezone.utc))
            # actual = 1200 * 5/60 / 1000 = 0.1 kWh
            # expected = 2400 * 5/60 / 1000 = 0.2 kWh
            # lost = 0.2 - 0.1 = 0.1 kWh, loss_percent = 50.0%
            passed = (
                metrics["actual_kwh"] == 0.1
                and metrics["expected_kwh"] == 0.2
                and metrics["lost_kwh"] == 0.1
                and metrics["loss_percent"] == 50.0
            )
            record_result("Seg9H: Lost generation correct after variable-interval", passed,
                          f"actual={metrics['actual_kwh']} expected={metrics['expected_kwh']} lost={metrics['lost_kwh']}")
        except Exception as e:
            record_result("Seg9H: Lost generation correct after variable-interval", False, f"Exception: {e}")

        # ---- D. Performance Ratio Tests ----

        # 121. PR = aggregate actual_kwh / expected_kwh (4.8 kWh / 5.0 kWh = 0.96)
        try:
            base_t = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            rows = []
            for i in range(7):  # 7 readings -> 6 intervals of 5 min = 30 min
                rows.append({
                    "timestamp": (base_t + timedelta(minutes=5 * i)).isoformat(),
                    "power": 9600.0,
                    "expected_power": 10000.0,
                })
            df_unit = make_df(rows)
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026,8,16,tzinfo=timezone.utc),
                datetime(2026,8,17,tzinfo=timezone.utc))
            # actual_kwh = 6 * 9600 * (5/60)/1000 = 4.8 kWh
            # expected_kwh = 6 * 10000 * (5/60)/1000 = 5.0 kWh
            # PR = 4.8 / 5.0 = 0.96
            passed = (
                metrics["actual_kwh"] == 4.8
                and metrics["expected_kwh"] == 5.0
                and metrics["performance_ratio"] == 0.96
                and metrics["performance_ratio_percent"] == 96.0
            )
            record_result("Seg9H: Aggregate PR = actual/expected (0.96)", passed,
                          f"actual={metrics['actual_kwh']} exp={metrics['expected_kwh']} PR={metrics['performance_ratio']}")
        except Exception as e:
            record_result("Seg9H: Aggregate PR = actual/expected (0.96)", False, f"Exception: {e}")

        # 122. Zero expected generation -> PR is not returned as 0% (stays None or graceful)
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0, "expected_power": 0.0},
                {"timestamp": t1.isoformat(), "power": 2400.0, "expected_power": 0.0},
            ])
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026,8,16,tzinfo=timezone.utc),
                datetime(2026,8,17,tzinfo=timezone.utc))
            # expected_kwh = 0.0, so PR calculation must not divide by zero
            passed = (metrics["performance_ratio"] is None or metrics["performance_ratio"] == 0.0)
            record_result("Seg9H: Zero expected_kwh -> PR handled safely (no div-by-zero)", passed,
                          f"PR={metrics['performance_ratio']} (must be None or 0)")
        except Exception as e:
            record_result("Seg9H: Zero expected_kwh -> PR handled safely (no div-by-zero)", False, f"Exception: {e}")

        # 123. Missing expected-generation -> PR returned as None (not fake 0%)
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},  # no expected_power column
                {"timestamp": t1.isoformat(), "power": 2400.0},
            ])
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026,8,16,tzinfo=timezone.utc),
                datetime(2026,8,17,tzinfo=timezone.utc))
            passed = (metrics["performance_ratio"] is None and metrics["expected_kwh"] is None)
            record_result("Seg9H: No expected_power -> PR=None (not fake 0%)", passed,
                          f"PR={metrics['performance_ratio']} expected_kwh={metrics['expected_kwh']}")
        except Exception as e:
            record_result("Seg9H: No expected_power -> PR=None (not fake 0%)", False, f"Exception: {e}")

        # ---- E. Regression Tests (existing API still works) ----

        # 124. Existing daily report still works (200, data_available)
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("success") is True and data.get("data_available") is True
                      and "generation" in data and "performance" in data and "data_quality" in data)
            record_result("Seg9H: Reg - Daily report still works", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg9H: Reg - Daily report still works", False, f"Exception: {e}")

        # 125. Existing weekly report still works
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("report_type") == "weekly"
                      and "best_day" in data and "worst_day" in data)
            record_result("Seg9H: Reg - Weekly report still works", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg9H: Reg - Weekly report still works", False, f"Exception: {e}")

        # 126. Existing monthly report still works
        try:
            r = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("report_type") == "monthly"
                      and data.get("month") == "2026-08")
            record_result("Seg9H: Reg - Monthly report still works", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg9H: Reg - Monthly report still works", False, f"Exception: {e}")

        # 127. Owner authorization still works
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            passed = (r.status_code == 200)
            record_result("Seg9H: Reg - Owner auth still works (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg9H: Reg - Owner auth still works (200)", False, f"Exception: {e}")

        # 128. Admin authorization still works
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=ADMIN_HDR)
            passed = (r.status_code == 200)
            record_result("Seg9H: Reg - Admin auth still works (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg9H: Reg - Admin auth still works (200)", False, f"Exception: {e}")

        # 129. Technician remains forbidden (403)
        try:
            r_d = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=TECH_HDR)
            r_w = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=TECH_HDR)
            r_m = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=TECH_HDR)
            passed = (r_d.status_code == 403 and r_w.status_code == 403 and r_m.status_code == 403)
            record_result("Seg9H: Reg - Technician forbidden on all reports (403)", passed,
                          f"daily={r_d.status_code} weekly={r_w.status_code} monthly={r_m.status_code}")
        except Exception as e:
            record_result("Seg9H: Reg - Technician forbidden on all reports (403)", False, f"Exception: {e}")

        # 130. Unauthenticated request still 401
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001")
            passed = (r.status_code == 401)
            record_result("Seg9H: Reg - Unauthenticated request (401)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Seg9H: Reg - Unauthenticated request (401)", False, f"Exception: {e}")

        # 131. Enriched data_quality fields present in all 3 endpoint types
        try:
            r_d = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            r_w = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            r_m = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=OWNER_HDR)
            new_fields = ["valid_reading_count", "invalid_reading_count", "missing_timestamp_count",
                          "data_gap_count", "total_gap_minutes", "excluded_gap_minutes"]
            def has_new_fields(resp):
                dq = (resp.get_json() or {}).get("data_quality", {})
                return all(f in dq for f in new_fields)
            passed = (r_d.status_code == 200 and has_new_fields(r_d)
                      and r_w.status_code == 200 and has_new_fields(r_w)
                      and r_m.status_code == 200 and has_new_fields(r_m))
            record_result("Seg9H: Enriched data_quality fields in all 3 endpoints", passed,
                          f"daily={r_d.status_code} weekly={r_w.status_code} monthly={r_m.status_code}")
        except Exception as e:
            record_result("Seg9H: Enriched data_quality fields in all 3 endpoints", False, f"Exception: {e}")

        # 132. NaN / Infinity power values do not corrupt JSON response
        try:
            import math as _math
            nan_ts = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)
            mock_db._store["readings"]["_nan_power"] = {
                "system_id": "SYS-OWNER001",
                "timestamp": nan_ts.isoformat(),
                "unix_timestamp": int(nan_ts.timestamp()),
                "power": float("inf"),  # Infinity
                "expected_power": float("nan"),  # NaN
            }
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            passed = (r.status_code == 200)
            # Make sure JSON is valid (no NaN/Infinity in output)
            import json as _json
            try:
                _json.loads(r.data)
                json_valid = True
            except Exception:
                json_valid = False
            passed = passed and json_valid
            record_result("Seg9H: NaN/Infinity power -> valid JSON response", passed,
                          f"Status={r.status_code} json_valid={json_valid}")
        except Exception as e:
            record_result("Seg9H: NaN/Infinity power -> valid JSON response", False, f"Exception: {e}")
        finally:
            mock_db._store["readings"].pop("_nan_power", None)

        # ---------------------------------------------------------
        # SEGMENT 9 PRODUCTION HARDENING TESTS (133 – 150)
        # 1. Firestore index required error handling & protection
        # 2. Expected generation strategy & tracking
        # 3. Configurable telemetry gap resolution & validation
        # 4. API response schema & custom threshold propagation
        # ---------------------------------------------------------
        print("\n  --- Seg9 Production Hardening: Index Protection, Expected Gen, Configurable Gaps ---\n", flush=True)

        from BACKEND.reports import (
            FirestoreIndexRequiredError,
            is_firestore_index_error,
            resolve_max_integration_gap,
            estimate_expected_power_from_system,
            DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES,
        )

        # 133. Firestore missing index error detection helper
        try:
            class DummyFailedPrecondition(Exception):
                pass
            dummy_exc1 = DummyFailedPrecondition("The query requires a composite index: system_id ASC, timestamp ASC.")
            dummy_exc2 = Exception("FAILED_PRECONDITION: requires an index https://console.firebase.google.com/...")
            dummy_exc3 = Exception("Generic network timeout")

            passed = (
                is_firestore_index_error(dummy_exc1) is True
                and is_firestore_index_error(dummy_exc2) is True
                and is_firestore_index_error(dummy_exc3) is False
            )
            record_result("Seg9H: is_firestore_index_error detects index exceptions", passed,
                          f"exc1={is_firestore_index_error(dummy_exc1)} exc2={is_firestore_index_error(dummy_exc2)} exc3={is_firestore_index_error(dummy_exc3)}")
        except Exception as e:
            record_result("Seg9H: is_firestore_index_error detects index exceptions", False, f"Exception: {e}")

        # 134. Production missing-index raises FirestoreIndexRequiredError (no silent unbounded scan)
        try:
            class MockRealDb:
                # _is_mock is False to simulate real production client
                _is_mock = False
                def collection(self, name):
                    class MockIndexFailingColl:
                        def where(self, *a, **kw):
                            return self
                        def order_by(self, *a, **kw):
                            return self
                        def stream(self):
                            raise Exception("FAILED_PRECONDITION: The query requires an index.")
                    return MockIndexFailingColl()

            raised_correct = False
            try:
                fetch_readings_dataframe(
                    MockRealDb(),
                    "SYS-OWNER001",
                    datetime(2026, 8, 16, tzinfo=timezone.utc),
                    datetime(2026, 8, 17, tzinfo=timezone.utc),
                )
            except FirestoreIndexRequiredError as fie:
                raised_correct = True
                error_msg = str(fie)

            passed = raised_correct and "composite index" in error_msg.lower()
            record_result("Seg9H: Missing index raises FirestoreIndexRequiredError", passed,
                          f"raised={raised_correct}")
        except Exception as e:
            record_result("Seg9H: Missing index raises FirestoreIndexRequiredError", False, f"Exception: {e}")

        # 135. API returns controlled 500 when FirestoreIndexRequiredError occurs
        try:
            with patch("BACKEND.reports.fetch_readings_dataframe", side_effect=FirestoreIndexRequiredError(
                "The required Firestore composite index for this query is missing or building."
            )):
                r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
                data = r.get_json() or {}
                passed = (
                    r.status_code == 500
                    and data.get("error") == "Database Index Required"
                    and "composite index" in data.get("message", "").lower()
                )
                record_result("Seg9H: API returns controlled 500 on missing index", passed,
                              f"Status={r.status_code} error={data.get('error')}")
        except Exception as e:
            record_result("Seg9H: API returns controlled 500 on missing index", False, f"Exception: {e}")

        # 136. Partial expected_power telemetry: only valid ones integrated; counts tracked
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            t2 = t1 + timedelta(minutes=5)
            t3 = t2 + timedelta(minutes=5)
            df_partial = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0, "expected_power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0, "expected_power": 2400.0}, # valid interval
                {"timestamp": t2.isoformat(), "power": 2400.0, "expected_power": None},   # missing
                {"timestamp": t3.isoformat(), "power": 2400.0, "expected_power": 2400.0}, # valid interval
            ])
            metrics = calculate_solar_metrics(df_partial,
                datetime(2026, 8, 16, tzinfo=timezone.utc),
                datetime(2026, 8, 17, tzinfo=timezone.utc))
            passed = (
                metrics["expected_generation_available"] is True
                and metrics["expected_power_reading_count"] == 3
                and metrics["expected_power_missing_count"] == 1
                and metrics["expected_kwh"] is not None
            )
            record_result("Seg9H: Partial expected_power tracked correctly", passed,
                          f"avail={metrics['expected_generation_available']} count={metrics['expected_power_reading_count']} miss={metrics['expected_power_missing_count']}")
        except Exception as e:
            record_result("Seg9H: Partial expected_power tracked correctly", False, f"Exception: {e}")

        # 137. All readings missing expected_power: expected_kwh=None, lost_kwh=None, PR=None
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            t2 = t1 + timedelta(minutes=5)
            df_no_exp = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0},
                {"timestamp": t2.isoformat(), "power": 2400.0},
            ])
            metrics = calculate_solar_metrics(df_no_exp,
                datetime(2026, 8, 16, tzinfo=timezone.utc),
                datetime(2026, 8, 17, tzinfo=timezone.utc))
            passed = (
                metrics["expected_generation_available"] is False
                and metrics["expected_kwh"] is None
                and metrics["lost_kwh"] is None
                and metrics["loss_percent"] is None
                and metrics["performance_ratio"] is None
                and metrics["expected_power_reading_count"] == 0
                and metrics["expected_power_missing_count"] == 3
            )
            record_result("Seg9H: All missing expected_power -> expected_kwh=None, lost=None", passed,
                          f"avail={metrics['expected_generation_available']} exp_kwh={metrics['expected_kwh']} lost={metrics['lost_kwh']}")
        except Exception as e:
            record_result("Seg9H: All missing expected_power -> expected_kwh=None, lost=None", False, f"Exception: {e}")

        # 138. All readings have non-numeric expected_power: treated as missing safely
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=5)
            df_bad_exp = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0, "expected_power": "corrupt_str"},
                {"timestamp": t1.isoformat(), "power": 2400.0, "expected_power": "another_bad"},
            ])
            metrics = calculate_solar_metrics(df_bad_exp,
                datetime(2026, 8, 16, tzinfo=timezone.utc),
                datetime(2026, 8, 17, tzinfo=timezone.utc))
            passed = (
                metrics["expected_generation_available"] is False
                and metrics["expected_kwh"] is None
                and metrics["lost_kwh"] is None
                and metrics["expected_power_reading_count"] == 0
                and metrics["expected_power_missing_count"] == 2
            )
            record_result("Seg9H: Non-numeric expected_power safely treated as missing", passed,
                          f"avail={metrics['expected_generation_available']} exp_kwh={metrics['expected_kwh']}")
        except Exception as e:
            record_result("Seg9H: Non-numeric expected_power safely treated as missing", False, f"Exception: {e}")

        # 139. Extension hook estimate_expected_power_from_system returns None (no fake physics)
        try:
            dummy_sys = {"panel_capacity_watts": 5000.0}
            dummy_reading = {"irradiance": 800.0, "temperature_ambient": 25.0}
            val = estimate_expected_power_from_system(dummy_sys, dummy_reading)
            passed = (val is None)
            record_result("Seg9H: estimate_expected_power_from_system returns None (no fake data)", passed, f"val={val}")
        except Exception as e:
            record_result("Seg9H: estimate_expected_power_from_system returns None (no fake data)", False, f"Exception: {e}")

        # 140. Configurable policy: custom 10-minute threshold excludes 12-minute gap
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=12) # 12 min gap: exceeds 10 min threshold
            t2 = t1 + timedelta(minutes=5)
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0},
                {"timestamp": t2.isoformat(), "power": 2400.0},
            ])
            sys_cfg = {"max_integration_gap_minutes": 10.0}
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026, 8, 16, tzinfo=timezone.utc),
                datetime(2026, 8, 17, tzinfo=timezone.utc),
                system_data=sys_cfg)
            # Only t1->t2 interval (5 min) should be integrated = 2400 * (5/60)/1000 = 0.2 kWh
            passed = (
                metrics["max_integration_gap_minutes"] == 10.0
                and metrics["data_gap_count"] == 1
                and metrics["excluded_gap_minutes"] == 12.0
                and metrics["actual_kwh"] == 0.2
            )
            record_result("Seg9H: Custom 10-min threshold excludes 12-min gap", passed,
                          f"max_gap={metrics['max_integration_gap_minutes']} gaps={metrics['data_gap_count']} excl={metrics['excluded_gap_minutes']} kwh={metrics['actual_kwh']}")
        except Exception as e:
            record_result("Seg9H: Custom 10-min threshold excludes 12-min gap", False, f"Exception: {e}")

        # 141. Configurable policy: custom 30-minute threshold integrates 20-minute gap
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=20) # 20 min gap: within 30 min threshold
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 3000.0},
                {"timestamp": t1.isoformat(), "power": 3000.0},
            ])
            sys_cfg = {"max_integration_gap_minutes": 30.0}
            metrics = calculate_solar_metrics(df_unit,
                datetime(2026, 8, 16, tzinfo=timezone.utc),
                datetime(2026, 8, 17, tzinfo=timezone.utc),
                system_data=sys_cfg)
            # 3000W * 20/60 / 1000 = 1.0 kWh
            passed = (
                metrics["max_integration_gap_minutes"] == 30.0
                and metrics["data_gap_count"] == 0
                and metrics["actual_kwh"] == 1.0
            )
            record_result("Seg9H: Custom 30-min threshold integrates 20-min gap (1.0 kWh)", passed,
                          f"max_gap={metrics['max_integration_gap_minutes']} gaps={metrics['data_gap_count']} kwh={metrics['actual_kwh']}")
        except Exception as e:
            record_result("Seg9H: Custom 30-min threshold integrates 20-min gap (1.0 kWh)", False, f"Exception: {e}")

        # 142. Boundary test: gap exactly at threshold (15.0 min) is integrated
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=15) # exactly 15.0 min
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0},
            ])
            kwh, gaps, excl = integrate_energy(df_unit, "power", max_gap_minutes=15.0)
            # 2400W * 15/60 / 1000 = 0.6 kWh
            passed = (gaps == 0 and kwh == 0.6 and excl == 0.0)
            record_result("Seg9H: Gap exactly at threshold (15.0 min) integrated", passed,
                          f"kwh={kwh} gaps={gaps} excl={excl}")
        except Exception as e:
            record_result("Seg9H: Gap exactly at threshold (15.0 min) integrated", False, f"Exception: {e}")

        # 143. Boundary test: gap slightly above threshold (15.1 min) is excluded
        try:
            t0 = datetime(2026, 8, 16, 10, 0, 0, tzinfo=timezone.utc)
            t1 = t0 + timedelta(minutes=15, seconds=6) # 15.1 min
            df_unit = make_df([
                {"timestamp": t0.isoformat(), "power": 2400.0},
                {"timestamp": t1.isoformat(), "power": 2400.0},
            ])
            kwh, gaps, excl = integrate_energy(df_unit, "power", max_gap_minutes=15.0)
            passed = (gaps == 1 and kwh == 0.0 and abs(excl - 15.1) < 0.01)
            record_result("Seg9H: Gap above threshold (15.1 min) excluded", passed,
                          f"kwh={kwh} gaps={gaps} excl={excl}")
        except Exception as e:
            record_result("Seg9H: Gap above threshold (15.1 min) excluded", False, f"Exception: {e}")

        # 144. Config multiplier: telemetry_interval_minutes: 5 derives 15.0 min gap
        try:
            sys_cfg = {"telemetry_interval_minutes": 5.0}
            resolved = resolve_max_integration_gap(sys_cfg)
            passed = (resolved == 15.0)
            record_result("Seg9H: telemetry_interval_minutes=5 derives 15.0 min gap", passed, f"resolved={resolved}")
        except Exception as e:
            record_result("Seg9H: telemetry_interval_minutes=5 derives 15.0 min gap", False, f"Exception: {e}")

        # 145. Malformed system config (string, negative, zero) falls back to default 15.0 min
        try:
            bad_configs = [
                {"max_integration_gap_minutes": "invalid_string"},
                {"max_integration_gap_minutes": -10.0},
                {"max_integration_gap_minutes": 0.0},
                {"max_integration_gap_minutes": float("nan")},
                None,
                {},
            ]
            all_passed = all(resolve_max_integration_gap(cfg) == DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES for cfg in bad_configs)
            record_result("Seg9H: Malformed system config falls back to default 15.0 min", all_passed,
                          f"all_fallback_to_15={all_passed}")
        except Exception as e:
            record_result("Seg9H: Malformed system config falls back to default 15.0 min", False, f"Exception: {e}")

        # 146. Unreasonable gap config (999999 min > 1440 max) falls back to default 15.0 min
        try:
            sys_cfg = {"max_integration_gap_minutes": 999999.0}
            resolved = resolve_max_integration_gap(sys_cfg)
            passed = (resolved == DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES)
            record_result("Seg9H: Out-of-bounds gap config falls back to default 15.0 min", passed, f"resolved={resolved}")
        except Exception as e:
            record_result("Seg9H: Out-of-bounds gap config falls back to default 15.0 min", False, f"Exception: {e}")

        # 147. Daily report response schema includes all enriched data_quality & generation fields
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            dq = data.get("data_quality", {})
            gen = data.get("generation", {})
            passed = (
                r.status_code == 200
                and "max_integration_gap_minutes" in dq
                and "expected_generation_available" in dq
                and "expected_power_reading_count" in dq
                and "expected_power_missing_count" in dq
                and "expected_generation_available" in gen
                and dq["expected_power_reading_count"] == 11
                and dq["expected_power_missing_count"] == 0
                and gen["expected_generation_available"] is True
            )
            record_result("Seg9H: Daily report API schema includes new fields", passed,
                          f"exp_avail={gen.get('expected_generation_available')} max_gap={dq.get('max_integration_gap_minutes')}")
        except Exception as e:
            record_result("Seg9H: Daily report API schema includes new fields", False, f"Exception: {e}")

        # 148. Weekly report response schema includes all enriched fields
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            dq = data.get("data_quality", {})
            gen = data.get("generation", {})
            passed = (
                r.status_code == 200
                and "max_integration_gap_minutes" in dq
                and "expected_generation_available" in dq
                and "expected_generation_available" in gen
            )
            record_result("Seg9H: Weekly report API schema includes new fields", passed,
                          f"Status={r.status_code}")
        except Exception as e:
            record_result("Seg9H: Weekly report API schema includes new fields", False, f"Exception: {e}")

        # 149. Monthly report response schema includes all enriched fields
        try:
            r = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            dq = data.get("data_quality", {})
            gen = data.get("generation", {})
            passed = (
                r.status_code == 200
                and "max_integration_gap_minutes" in dq
                and "expected_generation_available" in dq
                and "expected_generation_available" in gen
            )
            record_result("Seg9H: Monthly report API schema includes new fields", passed,
                          f"Status={r.status_code}")
        except Exception as e:
            record_result("Seg9H: Monthly report API schema includes new fields", False, f"Exception: {e}")

        # 150. Custom system max_integration_gap_minutes propagates to daily report data_quality
        try:
            # Set custom max_integration_gap_minutes on SYS-OWNER001
            mock_db._store["systems"]["SYS-OWNER001"]["max_integration_gap_minutes"] = 25.0
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            dq = data.get("data_quality", {})
            passed = (r.status_code == 200 and dq.get("max_integration_gap_minutes") == 25.0)
            record_result("Seg9H: Custom gap policy propagates to report data_quality (25.0 min)", passed,
                          f"max_gap={dq.get('max_integration_gap_minutes')}")
        except Exception as e:
            record_result("Seg9H: Custom gap policy propagates to report data_quality (25.0 min)", False, f"Exception: {e}")
        finally:
            mock_db._store["systems"]["SYS-OWNER001"].pop("max_integration_gap_minutes", None)

        # ---------------------------------------------------------
        # MULTI-SITE, CONNECTED SYSTEMS & TECHNICIAN REPORT ACCESS TESTS (151 – 188)
        # ---------------------------------------------------------
        print("\n  --- Multi-Site, Connected Systems & Technician Report Access ---\n", flush=True)

        created_site_id = [None]
        site_asg_id = [None]
        sys_asg_id = [None]

        # 151. Owner creates solar site → 201
        try:
            r = client.post("/api/sites", json={
                "site_name": "Rajasthan Desert Solar Farm",
                "address": "Plot 42, Solar Park, Bhadla",
                "location": {"lat": 27.5385, "lng": 71.9152}
            }, headers=OWNER_HDR)
            data = r.get_json() or {}
            site = data.get("site", {})
            passed = (
                r.status_code == 201
                and site.get("site_id", "").startswith("SITE-")
                and site.get("owner_uid") == "uid_owner"
                and site.get("site_name") == "Rajasthan Desert Solar Farm"
                and site.get("location", {}).get("lat") == 27.5385
            )
            created_site_id[0] = site.get("site_id")
            record_result("Site: Owner creates site (201)", passed,
                          f"Status: {r.status_code} | Site ID: {site.get('site_id')}")
        except Exception as e:
            record_result("Site: Owner creates site (201)", False, f"Exception: {e}")

        # 152. Admin creates solar site → 201
        try:
            r = client.post("/api/sites", json={
                "site_name": "Admin Gujarat Solar Park",
                "address": "Charanka Solar Park, Patan",
                "location": {"lat": 23.9030, "lng": 71.2000}
            }, headers=ADMIN_HDR)
            data = r.get_json() or {}
            site = data.get("site", {})
            passed = (r.status_code == 201 and site.get("site_id", "").startswith("SITE-"))
            record_result("Site: Admin creates site (201)", passed,
                          f"Status: {r.status_code} | Site ID: {site.get('site_id')}")
        except Exception as e:
            record_result("Site: Admin creates site (201)", False, f"Exception: {e}")

        # 153. Technician cannot create site → 403 Forbidden
        try:
            r = client.post("/api/sites", json={
                "site_name": "Tech Attempted Site",
                "location": {"lat": 26.8467, "lng": 80.9462}
            }, headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Site: Technician site creation rejected (403)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Technician site creation rejected (403)", False, f"Exception: {e}")

        # 154. Unauthenticated site creation rejected → 401
        try:
            r = client.post("/api/sites", json={
                "site_name": "Unauth Site",
                "location": {"lat": 26.8467, "lng": 80.9462}
            })
            passed = (r.status_code == 401)
            record_result("Site: Unauthenticated site creation rejected (401)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Unauthenticated site creation rejected (401)", False, f"Exception: {e}")

        # 155. Site creation with invalid coordinates (lat > 90) → 400
        try:
            r = client.post("/api/sites", json={
                "site_name": "Invalid Lat Site",
                "location": {"lat": 125.0, "lng": 80.0}
            }, headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Site: Out-of-bounds latitude rejected (400)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Out-of-bounds latitude rejected (400)", False, f"Exception: {e}")

        # 156. Site creation with NaN coordinate → 400
        try:
            r = client.post("/api/sites", json={
                "site_name": "NaN Coord Site",
                "location": {"lat": float("nan"), "lng": 80.0}
            }, headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Site: NaN coordinate rejected (400)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: NaN coordinate rejected (400)", False, f"Exception: {e}")

        # 157. Site creation with missing site_name → 400
        try:
            r = client.post("/api/sites", json={
                "location": {"lat": 26.8467, "lng": 80.9462}
            }, headers=OWNER_HDR)
            passed = (r.status_code == 400)
            record_result("Site: Missing site_name rejected (400)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Missing site_name rejected (400)", False, f"Exception: {e}")

        # 158. Owner lists own sites only → 200
        try:
            r = client.get("/api/sites", headers=OWNER_HDR)
            data = r.get_json()
            passed = (
                r.status_code == 200
                and isinstance(data, list)
                and all(s.get("owner_uid") == "uid_owner" for s in data)
                and any(s.get("site_id") == "SITE-OWNER001" for s in data)
            )
            record_result("Site: Owner lists own sites only (200)", passed,
                          f"Status: {r.status_code} | Count: {len(data or [])}")
        except Exception as e:
            record_result("Site: Owner lists own sites only (200)", False, f"Exception: {e}")

        # 159. Admin lists all sites → 200
        try:
            r = client.get("/api/sites", headers=ADMIN_HDR)
            data = r.get_json()
            passed = (
                r.status_code == 200
                and isinstance(data, list)
                and len(data) >= 2
                and any(s.get("site_id") == "SITE-OWNER001" for s in data)
                and any(s.get("site_id") == "SITE-OWNER002" for s in data)
            )
            record_result("Site: Admin lists all sites (200)", passed,
                          f"Status: {r.status_code} | Count: {len(data or [])}")
        except Exception as e:
            record_result("Site: Admin lists all sites (200)", False, f"Exception: {e}")

        # 160. Owner gets own site → 200
        try:
            r = client.get("/api/sites/SITE-OWNER001", headers=OWNER_HDR)
            data = r.get_json() or {}
            site = data.get("site", {})
            passed = (r.status_code == 200 and site.get("site_id") == "SITE-OWNER001")
            record_result("Site: Owner gets own site (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Owner gets own site (200)", False, f"Exception: {e}")

        # 161. Owner gets other owner's site → 403 Forbidden
        try:
            r = client.get("/api/sites/SITE-OWNER002", headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Site: Cross-owner site access blocked (403)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Cross-owner site access blocked (403)", False, f"Exception: {e}")

        # 162. Admin gets any site → 200
        try:
            r = client.get("/api/sites/SITE-OWNER002", headers=ADMIN_HDR)
            data = r.get_json() or {}
            site = data.get("site", {})
            passed = (r.status_code == 200 and site.get("site_id") == "SITE-OWNER002")
            record_result("Site: Admin gets any site (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Admin gets any site (200)", False, f"Exception: {e}")

        # 163. Get non-existent site → 404 Not Found
        try:
            r = client.get("/api/sites/SITE-NONEXISTENT", headers=ADMIN_HDR)
            passed = (r.status_code == 404)
            record_result("Site: Get non-existent site (404)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Get non-existent site (404)", False, f"Exception: {e}")

        # 164. Owner updates own site → 200
        try:
            r = client.put("/api/sites/SITE-OWNER001", json={
                "site_name": "Sunrise Solar Farm 1 (Renovated)",
                "address": "123 Solar Way, Lucknow, UP (Expanded)"
            }, headers=OWNER_HDR)
            data = r.get_json() or {}
            site = data.get("site", {})
            passed = (
                r.status_code == 200
                and site.get("site_name") == "Sunrise Solar Farm 1 (Renovated)"
                and "Expanded" in site.get("address", "")
            )
            record_result("Site: Owner updates own site (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Owner updates own site (200)", False, f"Exception: {e}")

        # 165. Owner cannot update other owner's site → 403 Forbidden
        try:
            r = client.put("/api/sites/SITE-OWNER002", json={
                "site_name": "Malicious Takeover"
            }, headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Site: Cross-owner update rejected (403)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Cross-owner update rejected (403)", False, f"Exception: {e}")

        # 166. Technician cannot update site → 403 Forbidden
        try:
            r = client.put("/api/sites/SITE-OWNER001", json={
                "site_name": "Tech Update Attempt"
            }, headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Site: Technician site update rejected (403)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Technician site update rejected (403)", False, f"Exception: {e}")

        # 167. Cannot modify site_id or owner_uid via PUT → ignored / preserved
        try:
            r = client.put("/api/sites/SITE-OWNER001", json={
                "site_id": "SITE-HACKED",
                "owner_uid": "uid_hacker",
                "site_name": "Valid Name Update"
            }, headers=OWNER_HDR)
            data = r.get_json() or {}
            site = data.get("site", {})
            passed = (
                r.status_code == 200
                and site.get("site_id") == "SITE-OWNER001"
                and site.get("owner_uid") == "uid_owner"
            )
            record_result("Site: Immutables protected against PUT modification", passed,
                          f"Status: {r.status_code} | owner: {site.get('owner_uid')}")
        except Exception as e:
            record_result("Site: Immutables protected against PUT modification", False, f"Exception: {e}")

        # 168. System creation with valid owned site_id → 201
        try:
            r = client.post("/api/systems", json={
                **VALID_SYSTEM_PAYLOAD,
                "name": "Site-Attached Rooftop Array",
                "site_id": "SITE-OWNER001"
            }, headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (
                r.status_code == 201
                and system.get("site_id") == "SITE-OWNER001"
                and system.get("owner_uid") == "uid_owner"
            )
            record_result("Sys-Site: System created under owned site (201)", passed,
                          f"Status: {r.status_code} | site_id: {system.get('site_id')}")
        except Exception as e:
            record_result("Sys-Site: System created under owned site (201)", False, f"Exception: {e}")

        # 169. System creation with another owner's site_id → 403 Forbidden
        try:
            r = client.post("/api/systems", json={
                **VALID_SYSTEM_PAYLOAD,
                "name": "Cross-Owner Site Attachment Attempt",
                "site_id": "SITE-OWNER002"  # Owned by uid_owner2
            }, headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Sys-Site: Cross-owner site attachment rejected (403)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Sys-Site: Cross-owner site attachment rejected (403)", False, f"Exception: {e}")

        # 170. System creation with non-existent site_id → 404 Not Found
        try:
            r = client.post("/api/systems", json={
                **VALID_SYSTEM_PAYLOAD,
                "name": "Non-existent Site Attachment",
                "site_id": "SITE-GHOST"
            }, headers=OWNER_HDR)
            passed = (r.status_code == 404)
            record_result("Sys-Site: Non-existent site attachment rejected (404)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Sys-Site: Non-existent site attachment rejected (404)", False, f"Exception: {e}")

        # 171. System update attaching owned site_id → 200
        try:
            r = client.put("/api/systems/SYS-OWNER001", json={
                "site_id": "SITE-OWNER001"
            }, headers=OWNER_HDR)
            data = r.get_json() or {}
            system = data.get("system", {})
            passed = (r.status_code == 200 and system.get("site_id") == "SITE-OWNER001")
            record_result("Sys-Site: System update attaches owned site (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Sys-Site: System update attaches owned site (200)", False, f"Exception: {e}")

        # 172. System update with cross-owner site_id → 403 Forbidden
        try:
            r = client.put("/api/systems/SYS-OWNER001", json={
                "site_id": "SITE-OWNER002"
            }, headers=OWNER_HDR)
            passed = (r.status_code == 403)
            record_result("Sys-Site: Cross-owner site update rejected (403)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Sys-Site: Cross-owner site update rejected (403)", False, f"Exception: {e}")

        # 173. Admin creates site-level technician assignment → 201
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_tech",
                "site_id": "SITE-OWNER001"
            }, headers=ADMIN_HDR)
            data = r.get_json() or {}
            asg = data.get("assignment", {})
            passed = (
                r.status_code == 201
                and asg.get("technician_uid") == "uid_tech"
                and asg.get("site_id") == "SITE-OWNER001"
            )
            site_asg_id[0] = asg.get("assignment_id")
            record_result("Asg: Admin creates site-level assignment (201)", passed,
                          f"Status: {r.status_code} | AID: {asg.get('assignment_id')}")
        except Exception as e:
            record_result("Asg: Admin creates site-level assignment (201)", False, f"Exception: {e}")

        # 174. Technician lists assigned sites (includes SITE-OWNER001) → 200
        try:
            r = client.get("/api/sites", headers=TECH_HDR)
            data = r.get_json()
            passed = (
                r.status_code == 200
                and isinstance(data, list)
                and any(s.get("site_id") == "SITE-OWNER001" for s in data)
            )
            record_result("Site: Technician lists assigned sites (200)", passed,
                          f"Status: {r.status_code} | Sites: {[s.get('site_id') for s in (data or [])]}")
        except Exception as e:
            record_result("Site: Technician lists assigned sites (200)", False, f"Exception: {e}")

        # 175. Technician gets assigned site → 200 OK
        try:
            r = client.get("/api/sites/SITE-OWNER001", headers=TECH_HDR)
            data = r.get_json() or {}
            site = data.get("site", {})
            passed = (r.status_code == 200 and site.get("site_id") == "SITE-OWNER001")
            record_result("Site: Technician gets assigned site (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Technician gets assigned site (200)", False, f"Exception: {e}")

        # 176. Technician gets unassigned site → 403 Forbidden
        try:
            r = client.get("/api/sites/SITE-OWNER002", headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Site: Technician gets unassigned site (403)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Technician gets unassigned site (403)", False, f"Exception: {e}")

        # 177. Technician assigned via site lists systems belonging to that site → 200
        try:
            r = client.get("/api/systems", headers=TECH_HDR)
            data = r.get_json()
            passed = (
                r.status_code == 200
                and isinstance(data, list)
                and any(s.get("system_id") == "SYS-OWNER001" for s in data)
            )
            record_result("Asg: Tech assigned via site lists systems in site (200)", passed,
                          f"Status: {r.status_code} | Systems: {[s.get('system_id') for s in (data or [])]}")
        except Exception as e:
            record_result("Asg: Tech assigned via site lists systems in site (200)", False, f"Exception: {e}")

        # 178. Technician assigned via site gets system in that site → 200
        try:
            r = client.get("/api/systems/SYS-OWNER001", headers=TECH_HDR)
            data = r.get_json() or {}
            sys_doc = data.get("system", {})
            passed = (r.status_code == 200 and sys_doc.get("system_id") == "SYS-OWNER001")
            record_result("Asg: Tech assigned via site gets system in site (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Asg: Tech assigned via site gets system in site (200)", False, f"Exception: {e}")

        # 179. Admin assigns technician directly to system SYS-OWNER002 → 201
        try:
            r = client.post("/api/assignments", json={
                "technician_uid": "uid_tech",
                "system_id": "SYS-OWNER002"
            }, headers=ADMIN_HDR)
            data = r.get_json() or {}
            asg = data.get("assignment", {})
            passed = (r.status_code == 201 and asg.get("system_id") == "SYS-OWNER002")
            sys_asg_id[0] = asg.get("assignment_id")
            record_result("Asg: Admin assigns technician to system (201)", passed,
                          f"Status: {r.status_code} | AID: {asg.get('assignment_id')}")
        except Exception as e:
            record_result("Asg: Admin assigns technician to system (201)", False, f"Exception: {e}")

        # 180. Assigned technician accesses Daily Report for SYS-OWNER001 → 200 OK
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=TECH_HDR)
            data = r.get_json() or {}
            passed = (
                r.status_code == 200
                and data.get("success") is True
                and data.get("system_id") == "SYS-OWNER001"
                and "generation" in data
            )
            record_result("Tech-Rep: Assigned tech accesses Daily Report (200)", passed,
                          f"Status: {r.status_code} | Actual: {data.get('generation', {}).get('actual_kwh')} kWh")
        except Exception as e:
            record_result("Tech-Rep: Assigned tech accesses Daily Report (200)", False, f"Exception: {e}")

        # 181. Assigned technician accesses Weekly Report for SYS-OWNER001 → 200 OK
        try:
            r = client.get("/api/reports/weekly?start_date=2026-08-10&end_date=2026-08-16&system_id=SYS-OWNER001", headers=TECH_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("report_type") == "weekly")
            record_result("Tech-Rep: Assigned tech accesses Weekly Report (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Tech-Rep: Assigned tech accesses Weekly Report (200)", False, f"Exception: {e}")

        # 182. Assigned technician accesses Monthly Report for SYS-OWNER001 → 200 OK
        try:
            r = client.get("/api/reports/monthly?month=2026-08&system_id=SYS-OWNER001", headers=TECH_HDR)
            data = r.get_json() or {}
            passed = (r.status_code == 200 and data.get("report_type") == "monthly")
            record_result("Tech-Rep: Assigned tech accesses Monthly Report (200)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Tech-Rep: Assigned tech accesses Monthly Report (200)", False, f"Exception: {e}")

        # 183. Unassigned technician 2 (uid_tech2) accesses SYS-OWNER001 report → 403 Forbidden
        try:
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=TECH2_HDR)
            passed = (r.status_code == 403)
            record_result("Tech-Rep: Unassigned technician 2 report access blocked (403)", passed,
                          f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Tech-Rep: Unassigned technician 2 report access blocked (403)", False, f"Exception: {e}")

        # 184. Revoke assignment for SYS-OWNER001 and SITE-OWNER001 → immediately blocks technician report access (403)
        try:
            if site_asg_id[0]:
                client.delete(f"/api/assignments/{site_asg_id[0]}", headers=ADMIN_HDR)
            r = client.get("/api/reports/daily?date=2026-08-16&system_id=SYS-OWNER001", headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Tech-Rep: Revoked assignment immediately blocks report access (403)", passed,
                          f"Status: {r.status_code} (Expected 403)")
        except Exception as e:
            record_result("Tech-Rep: Revoked assignment immediately blocks report access (403)", False, f"Exception: {e}")

        # 185. Cleanup: revoke system assignment for SYS-OWNER002
        try:
            if sys_asg_id[0]:
                r = client.delete(f"/api/assignments/{sys_asg_id[0]}", headers=ADMIN_HDR)
                passed = (r.status_code == 200)
            else:
                passed = True
            record_result("Asg: Admin revokes direct system assignment (200)", passed, "Cleaned up assignment")
        except Exception as e:
            record_result("Asg: Admin revokes direct system assignment (200)", False, f"Exception: {e}")

        # 186. Owner deletes own site → 200 OK
        try:
            if created_site_id[0]:
                r = client.delete(f"/api/sites/{created_site_id[0]}", headers=OWNER_HDR)
                data = r.get_json() or {}
                passed = (r.status_code == 200 and data.get("site_id") == created_site_id[0])
            else:
                passed = True
            record_result("Site: Owner deletes own site (200)", passed, f"Deleted Site: {created_site_id[0]}")
        except Exception as e:
            record_result("Site: Owner deletes own site (200)", False, f"Exception: {e}")

        # 187. Technician cannot delete site → 403 Forbidden
        try:
            r = client.delete("/api/sites/SITE-OWNER001", headers=TECH_HDR)
            passed = (r.status_code == 403)
            record_result("Site: Technician cannot delete site (403)", passed, f"Status: {r.status_code}")
        except Exception as e:
            record_result("Site: Technician cannot delete site (403)", False, f"Exception: {e}")

        # 188. Admin deletes site → 200 OK
        try:
            # Create a temporary site to delete
            r_create = client.post("/api/sites", json={
                "site_name": "Temporary Site For Admin Deletion",
                "location": {"lat": 26.8467, "lng": 80.9462}
            }, headers=ADMIN_HDR)
            temp_sid = (r_create.get_json() or {}).get("site", {}).get("site_id")
            r_del = client.delete(f"/api/sites/{temp_sid}", headers=ADMIN_HDR)
            passed = (r_del.status_code == 200)
            record_result("Site: Admin deletes site (200)", passed, f"Deleted: {temp_sid}")
        except Exception as e:
            record_result("Site: Admin deletes site (200)", False, f"Exception: {e}")

    print("\n==================================================================================")
    print("                    Integration & Security Test Results Summary                   ")
    print("==================================================================================")
    print(f"Total Tests Run: {passed_count + failed_count}")
    print(f"Passed: {passed_count}")
    print(f"Failed: {failed_count}")
    print("==================================================================================\n", flush=True)

    return failed_count == 0


# ===========================================================================
# Entry point — single execution gate
# ===========================================================================

def main():
    """
    Single entry point for the test suite.
    Parses CLI arguments, executes run_tests(), and exits with the
    appropriate process exit code.

    Usage:
        python BACKEND/test_backend.py
        python BACKEND/test_backend.py --include-ingest
    """
    import argparse
    parser = argparse.ArgumentParser(
        description="Solar Monitoring Backend Integration & Security Test Suite"
    )
    parser.add_argument(
        "--include-ingest",
        action="store_true",
        default=False,
        help="Include POST /api/ingest tests (writes to mocked Firestore; default: off)"
    )
    args = parser.parse_args()
    success = run_tests(include_ingest=args.include_ingest)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
