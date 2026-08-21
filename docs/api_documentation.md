# Solar Monitoring System API

## 1. Overview

The **Solar PV Monitoring System API** is a production-grade, secure RESTful backend designed for solar installation monitoring, multi-site hierarchy management, sensor telemetry ingestion, automated anomaly detection, performance analytics, machine learning regression predictions, document lifecycle management with Firebase Cloud Storage, safe QR field portal routing, and comprehensive administrative oversight.

The backend is built with **Python / Flask**, utilizes the **Firebase Admin SDK** for authentication and user identity, uses **Google Cloud Firestore** for document storage, and **Firebase Cloud Storage** for binary document assets.

---

## 2. Quick Start

### 2.1 Prerequisites
- Python 3.10+
- Virtual environment (`venv`)
- Firebase project credentials (`serviceAccountKey.json`) placed in the project root directory

### 2.2 Setup & Execution

1. **Activate Virtual Environment**:
   ```bash
   # Windows (PowerShell)
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   source venv/bin/activate
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables**:
   ```bash
   cp .env.example .env
   ```

4. **Start the Flask Backend**:
   ```bash
   python BACKEND/app.py
   ```
   The backend server starts on `http://0.0.0.0:5000` (or the configured `FLASK_PORT`).

5. **Verify Service Health**:
   ```bash
   curl -X GET http://localhost:5000/api/health
   ```
   Response:
   ```json
   {
     "service": "Solar Monitoring Backend API",
     "status": "ok",
     "timestamp": "2026-08-21T18:00:00.000000+00:00"
   }
   ```

6. **Authenticate & Call a Protected Endpoint**:
   Obtain a Firebase ID Token using your client application SDK, then supply it via the `Authorization` header:
   ```bash
   curl -X GET http://localhost:5000/api/auth/me \
     -H "Authorization: Bearer <FIREBASE_ID_TOKEN>"
   ```

---

## 3. Base URL

| Environment | Base URL |
| :--- | :--- |
| **Development** | `http://localhost:5000` |
| **Production** | `https://solar.monitoring.internal` (or configured `SOLAR_PUBLIC_BASE_URL`) |

All API routes are prefixed with `/api/`.

---

## 4. Authentication

The backend uses **Firebase Authentication** tokens (JSON Web Tokens - JWT) for identity verification.

```
Frontend / Client
      │
      ▼  1. Sign in with Firebase Client SDK (Email/Password or OAuth)
Firebase Auth
      │
      ▼  2. Generates Firebase ID Token (JWT)
Client App
      │
      ▼  3. Sends HTTP Request with `Authorization: Bearer <FIREBASE_ID_TOKEN>`
Flask Backend API (@require_auth)
      │
      ▼  4. Verifies ID Token using Firebase Admin SDK (auth.verify_id_token)
Authenticated UID
      │
      ▼  5. Fetches Firestore User Profile (/users/{uid})
Role & Permission Context Attached to `g.user` and `request.user`
```

### 4.1 Token Specification
- Header Name: `Authorization`
- Header Format: `Bearer <FIREBASE_ID_TOKEN>`
- Token Lifespan: 1 hour (auto-refreshed via Firebase Client SDK)

### 4.2 Security Rules for Credentials
- **NEVER** expose `serviceAccountKey.json`, private keys, database passwords, or Admin SDK credentials to the frontend or version control.
- Client applications must strictly authenticate via Firebase Client SDK and transmit only the ephemeral ID token to the backend.

---

## 5. Authorization / RBAC Architecture

The backend implements strict multi-layer Role-Based Access Control (RBAC) and Resource Authorization:

1. **Authentication Layer (`@require_auth`)**:
   Verifies the token signature, expiration, and revocation status via `auth.verify_id_token()`. Loads the authoritative user profile from the Firestore `users` collection. Rejects missing or invalid tokens with HTTP `401 Unauthorized`.

2. **Role Authorization Layer (`@require_role(*allowed_roles)`)**:
   Verifies that the authenticated user's server-stored `role` is in the allowed list for the target endpoint. Rejects unauthorized roles with HTTP `403 Forbidden`.

3. **Resource Authorization & Ownership Enforcement**:
   A valid role does not grant blanket access to every resource:
   - **`owner`**: Can access only resources where `owner_uid == user.uid`.
   - **`technician`**: Can access only systems and sites with an active assignment in the `assignments` collection.
   - **`admin`**: Granted full administrative oversight across all resources.

4. **Self-Registration Isolation**:
   Public self-registration (`POST /api/auth/register`) strictly allows only the `owner` role. Client attempts to register as `admin` or `technician` are rejected with HTTP `403 Forbidden` to prevent privilege escalation.

---

## 6. RBAC Matrix

| Endpoint | Anonymous | Owner | Technician | Admin |
| :--- | :---: | :---: | :---: | :---: |
| `GET /api/health` | Yes | Yes | Yes | Yes |
| `GET /api/health/ready` | Yes | Yes | Yes | Yes |
| `POST /api/ingest` | Yes | Yes | Yes | Yes |
| `GET /api/readings/latest` | Yes | Yes | Yes | Yes |
| `GET /api/alerts` | Yes | Yes | Yes | Yes |
| `GET/POST /api/analysis/run` | Yes | Yes | Yes | Yes |
| `GET /api/chat` | Yes | Yes | Yes | Yes |
| `POST /api/auth/register` | Yes (Owner only) | No | No | No |
| `POST /api/auth/users` | No | No | No | Yes |
| `GET /api/auth/me` | No | Yes | Yes | Yes |
| `POST /api/sites` | No | Yes | No (403) | Yes |
| `GET /api/sites` | No | Own sites | Assigned sites | All sites |
| `GET /api/sites/{id}` | No | Own site | Assigned site | All sites |
| `PUT /api/sites/{id}` | No | Own site | No (403) | All sites |
| `DELETE /api/sites/{id}` | No | Own site | No (403) | All sites |
| `POST /api/systems` | No | Yes | No (403) | Yes |
| `GET /api/systems` | No | Own systems | Assigned systems | All systems |
| `GET /api/systems/{id}` | No | Own system | Assigned system | All systems |
| `PUT /api/systems/{id}` | No | Own system | No (403) | All systems |
| `DELETE /api/systems/{id}` | No | No (403) | No (403) | Yes |
| `GET /api/systems/{id}/health` | No | Own system | Assigned system | All systems |
| `POST /api/assignments` | No | No (403) | No (403) | Yes |
| `GET /api/assignments` | No | No (403) | Own active | All |
| `DELETE /api/assignments/{id}` | No | No (403) | No (403) | Yes |
| `GET /api/reports/daily` | No | Own system | Assigned system | All systems |
| `GET /api/reports/weekly` | No | Own system | Assigned system | All systems |
| `GET /api/reports/monthly` | No | Own system | Assigned system | All systems |
| `POST /api/ml/train` | No | No (403) | No (403) | Yes |
| `GET /api/ml/predict` | No | Yes | Yes | Yes |
| `POST /api/documents/upload` | No | Own systems/sites | No (403) | All systems/sites |
| `GET /api/systems/{id}/documents` | No | Own system | Assigned system | All systems |
| `GET /api/sites/{id}/documents` | No | Own site | Assigned site | All sites |
| `GET /api/documents/{id}` | No | Own system/site | Assigned system/site | All systems/sites |
| `GET /api/documents/{id}/file` | No | Own system/site | Assigned system/site | All systems/sites |
| `DELETE /api/documents/{id}` | No | Own system/site | No (403) | All systems/sites |
| `GET /api/systems/{id}/qr` | No | Own system | Assigned system | All systems |
| `GET /api/qr-access/{id}` | Yes (Landing only) | Yes | Yes | Yes |
| `GET /api/qr-access/{id}/workspace`| No | Own (View-only) | Assigned (View-only) | Full Admin Redirect |
| `GET/POST /api/qr-access/{id}/route`| No | Own route | Assigned route | Admin dashboard route |
| `GET /api/admin/*` (All admin endpoints) | No | No (403) | No (403) | Yes |

---

## 7. Common Headers

### 7.1 Request Headers
- `Authorization: Bearer <FIREBASE_ID_TOKEN>` (Required for protected endpoints)
- `Content-Type: application/json` (Required for JSON payloads)
- `Content-Type: multipart/form-data` (For binary document uploads)

### 7.2 Response Headers
- `Content-Type: application/json` (or `image/png` / `application/pdf` for binary endpoints)
- `Access-Control-Allow-Origin: *` (Development) or explicit whitelist (Production)
- `Access-Control-Allow-Headers: Content-Type, Authorization`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`

---

## 8. Common Error Contract

The API standardizes error responses with structured JSON objects:

```json
{
  "error": "ErrorCategory",
  "message": "Human-readable explanation of why the request failed."
}
```

### HTTP Status Codes
| Status Code | Reason | Meaning |
| :--- | :--- | :--- |
| **`200 OK`** | Success | Request succeeded. |
| **`201 Created`** | Created | Resource successfully created. |
| **`400 Bad Request`** | Validation Error | Missing required fields, invalid JSON, or invalid parameters. |
| **`401 Unauthorized`** | Authentication Required | Missing, malformed, or expired Firebase ID token. |
| **`403 Forbidden`** | Authorization Refused | Authenticated role or identity lacks permission for resource. |
| **`404 Not Found`** | Resource Missing | Specified system, site, document, user, or report not found. |
| **`409 Conflict`** | Conflict | Duplicate entity (e.g. email already exists, duplicate active assignment). |
| **`500 Internal Error`** | Server Exception | Internal failure; technical details logged to server logs. |
| **`503 Unavailable`** | Dependency Down | Database or backing service unavailable. |

---

## 9. Date & Time Convention

- **Format**: All timestamps transmitted to or returned by the API use **ISO-8601 UTC format**: `YYYY-MM-DDTHH:MM:SSZ` or `YYYY-MM-DDTHH:MM:SS+00:00`.
- **Query Parameters**:
  - Daily reports: `date=YYYY-MM-DD`
  - Weekly reports: `start_date=YYYY-MM-DD&end_date=YYYY-MM-DD`
  - Monthly reports: `month=YYYY-MM`
- **Internal Time Handling**: Datetimes are normalized to timezone-aware UTC datetime objects before storage or comparison.

---

## 10. Pagination and Limits

### Standard Pagination (`GET /api/admin/*`, `GET /api/readings/latest`)
Endpoints returning collections support pagination query parameters:
- `page` (integer, default `1`, minimum `1`): The page index.
- `per_page` (integer, default `50`, maximum `200`): Number of items per page.

### Envelope Structure:
```json
{
  "items": [ ... ],
  "total": 144,
  "page": 1,
  "per_page": 50,
  "total_pages": 3
}
```

---

## 11. Auth APIs

### 11.1 POST /api/auth/register
- **Description**: Public registration for new system owners.
- **Authentication**: None (Public)
- **Role**: `owner` only
- **Request Body (`application/json`)**:
  ```json
  {
    "email": "owner@example.com",
    "password": "strongPassword123",
    "name": "Jane Owner",
    "role": "owner"
  }
  ```
- **Success Response (`201 Created`)**:
  ```json
  {
    "message": "User registered successfully",
    "user": {
      "uid": "fb_uid_123",
      "email": "owner@example.com",
      "name": "Jane Owner",
      "role": "owner",
      "created_at": "2026-08-21T18:00:00+00:00"
    }
  }
  ```
- **curl Example**:
  ```bash
  curl -X POST http://localhost:5000/api/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email":"owner@example.com","password":"password123","name":"Jane Doe"}'
  ```

### 11.2 POST /api/auth/users
- **Description**: Admin-only user creation endpoint.
- **Authentication**: Bearer Token
- **Role**: `admin`
- **Request Body (`application/json`)**:
  ```json
  {
    "email": "tech@example.com",
    "password": "password123",
    "name": "Bob Tech",
    "role": "technician"
  }
  ```
- **Success Response (`201 Created`)**: Status 201 with created user profile.

### 11.3 GET /api/auth/me
- **Description**: Fetches current authenticated user's Firestore profile.
- **Authentication**: Bearer Token
- **Role**: Any authenticated role
- **Success Response (`200 OK`)**:
  ```json
  {
    "uid": "uid_owner_123",
    "email": "owner@example.com",
    "name": "Jane Owner",
    "role": "owner",
    "created_at": "2026-08-21T18:00:00+00:00"
  }
  ```

### 11.4 GET /api/auth/admin-only
- **Description**: Admin role validation test route.
- **Authentication**: Bearer Token
- **Role**: `admin`
- **Success Response (`200 OK`)**: `{"message": "Welcome Admin!"}`

### 11.5 GET /api/auth/tech-only
- **Description**: Technician/Admin role validation test route.
- **Authentication**: Bearer Token
- **Role**: `technician`, `admin`
- **Success Response (`200 OK`)**: `{"message": "Welcome Technician/Admin!"}`

---

## 12. Ingest & Telemetry

### 12.1 POST /api/ingest
- **Description**: Ingests sensor reading payload, computes PR, writes to Firestore `readings` collection, and triggers analysis engine.
- **Authentication**: None (IoT Edge gateway compatible)
- **Request Body (`application/json`)**:
  | Field | Type | Required | Description |
  | :--- | :--- | :---: | :--- |
  | `voltage` | float | Yes | Bus DC voltage (Volts) |
  | `current` | float | Yes | Bus DC current (Amperes) |
  | `power` | float | Yes | Generated active power (Watts) |
  | `expected_power` | float | Yes | Expected ideal solar power (Watts) |
  | `timestamp` | string | No | ISO-8601 timestamp (default: current UTC) |
  | `irradiance` | float | No | Plane of Array irradiance (W/m²) |
  | `lux` | float | No | Ambient light illumination (Lux) |
  | `temperature_panel` | float | No | Panel surface temperature (°C) |
  | `temperature_ambient`| float | No | Ambient air temperature (°C) |
  | `humidity` | float | No | Relative humidity (%) |
  | `system_id` | string | No | Target solar system ID |
  | `site_id` | string | No | Associated solar site ID |

- **Success Response (`201 Created`)**:
  ```json
  {
    "message": "Sensor data ingested successfully",
    "doc_id": "read_1787335200",
    "data": { ... },
    "analysis": { ... }
  }
  ```

### 12.2 GET /api/readings/latest
- **Description**: Retrieves recent telemetry readings sorted newest first.
- **Authentication**: None
- **Query Params**: `limit` (integer, default 50, max 200)
- **Success Response (`200 OK`)**: Array of reading objects.

---

## 13. Alerts & Analysis Engine

### 13.1 GET /api/alerts
- **Description**: Lists active solar alerts.
- **Query Params**: `active_only` (bool, default `true`).
- **Success Response (`200 OK`)**: Array of alert objects.

### 13.2 GET/POST /api/analysis/run
- **Description**: Triggers anomaly detection and alert calculation across recent readings.
- **Success Response (`200 OK`)**:
  ```json
  {
    "status": "ok",
    "latest_pr": 0.92,
    "average_window_pr": 0.91,
    "is_anomaly": false,
    "anomalous_count": 0,
    "lost_energy_kwh": 0.0,
    "alert_active": false
  }
  ```

---

## 14. Solar Systems

### 14.1 POST /api/systems
- **Description**: Registers a new solar installation.
- **Authentication**: Bearer Token
- **Role**: `owner`, `admin`
- **Request Body (`application/json`)**:
  ```json
  {
    "name": "North Field Rooftop Array",
    "location": { "lat": 26.8467, "lng": 80.9462 },
    "installation_date": "2026-08-01T00:00:00Z",
    "panel_capacity_watts": 5000,
    "inverter_type": "SolarEdge String Inverter",
    "site_id": "SITE-AB12CD34",
    "components": [
      {
        "type": "solar_panel",
        "model": "Mono-PERC-550",
        "serial": "SN-00123",
        "warranty_until": "2036-08-01T00:00:00Z"
      }
    ]
  }
  ```
- **Success Response (`201 Created`)**:
  ```json
  {
    "message": "Solar system created successfully",
    "system": {
      "system_id": "SYS-A1B2C3D4",
      "owner_uid": "uid_owner",
      "name": "North Field Rooftop Array",
      "panel_capacity_watts": 5000,
      "created_at": "2026-08-21T18:00:00+00:00"
    }
  }
  ```

### 14.2 GET /api/systems
- **Description**: Lists accessible systems.
- **Role Permissions**: Owner sees own systems; Tech sees assigned systems; Admin sees all.

### 14.3 GET /api/systems/{system_id}
- **Description**: Retrieves single system document.

### 14.4 PUT /api/systems/{system_id}
- **Description**: Partial update of system metadata. (Technician forbidden).

### 14.5 DELETE /api/systems/{system_id}
- **Description**: Deletes solar installation. Restricted strictly to `admin`.

---

## 15. Solar Sites

### 15.1 POST /api/sites
- **Description**: Creates a solar site grouping multiple systems.
- **Role**: `owner`, `admin`
- **Request Body**: `{"site_name": "...", "location": {"lat": ..., "lng": ...}, "address": "..."}`

### 15.2 GET /api/sites
- **Description**: Lists sites accessible to authenticated user.

### 15.3 GET /api/sites/{site_id}
- **Description**: Get site details.

### 15.4 PUT /api/sites/{site_id}
- **Description**: Update site name, address, or location coordinates.

### 15.5 DELETE /api/sites/{site_id}
- **Description**: Delete site. (Owner can delete own site; Admin can delete any site).

---

## 16. Technician Assignments

### 16.1 POST /api/assignments
- **Description**: Dispatches a technician to a system or site.
- **Role**: `admin` only
- **Request Body**: `{"technician_uid": "...", "system_id": "SYS-...", "site_id": "SITE-..."}`

### 16.2 GET /api/assignments
- **Description**: Lists assignments. Admin sees all; Tech sees own; Owner -> 403 Forbidden.

### 16.3 DELETE /api/assignments/{assignment_id}
- **Description**: Revokes a technician assignment. `admin` only.

---

## 17. Solar Reports

### 17.1 GET /api/reports/daily
- **Description**: Generates daily generation (kWh), expected kWh, lost kWh, PR, and environmental metrics.
- **Parameters**: `date=YYYY-MM-DD` (required), `system_id=SYS-...` (required).
- **Success Response (`200 OK`)**:
  ```json
  {
    "success": true,
    "report_type": "daily",
    "system_id": "SYS-OWNER001",
    "period": { "date": "2026-08-21", "start": "...", "end": "..." },
    "data_available": true,
    "generation": {
      "actual_kwh": 24.5,
      "expected_kwh": 28.0,
      "lost_kwh": 3.5,
      "loss_percent": 12.5,
      "expected_generation_available": true
    },
    "performance": {
      "performance_ratio": 0.875,
      "performance_ratio_percent": 87.5,
      "peak_power_w": 4800.0
    },
    "environment": {
      "average_temperature_c": 31.5,
      "rain_events": 0
    },
    "data_quality": {
      "reading_count": 288,
      "expected_readings": 288,
      "data_completeness_percent": 100.0,
      "valid_reading_count": 288,
      "invalid_reading_count": 0,
      "data_gap_count": 0,
      "total_gap_minutes": 0.0,
      "max_integration_gap_minutes": 15.0
    }
  }
  ```

### 17.2 GET /api/reports/weekly
- **Parameters**: `start_date=YYYY-MM-DD`, `end_date=YYYY-MM-DD`, `system_id=SYS-...`.

### 17.3 GET /api/reports/monthly
- **Parameters**: `month=YYYY-MM`, `system_id=SYS-...`.

---

## 18. Machine Learning & Health

### 18.1 POST /api/ml/train
- **Description**: Trains capacity-normalized linear regression model with chronological 80/20 train/test split.
- **Role**: `admin` only.

### 18.2 GET /api/ml/predict
- **Description**: Performs inference for predicted power output (Watts).
- **Parameters**: `irradiance` (W/m²), `panel_temp` (°C), `humidity` (%), `hour_of_day` (0..23), `day_of_week` (0..6), `system_capacity_kw` (default 1.0).
- **Success Response (`200 OK`)**:
  ```json
  {
    "status": "success",
    "predicted_power": 4250.75,
    "predicted_normalized_power": 850.15,
    "system_capacity_kw": 5.0,
    "model_type": "LinearRegression",
    "model_version": 3,
    "r2": 0.985,
    "mae": 12.4
  }
  ```

### 18.3 GET /api/systems/{system_id}/health
- **Description**: Returns continuous float Solar Health Score (0–100) and discrete health status (`Excellent`, `Good`, `Warning`, `Critical`, `N/A`).
- **Success Response (`200 OK`)**:
  ```json
  {
    "system_id": "SYS-OWNER001",
    "health_score": 92.5,
    "status": "Excellent",
    "average_pr": 0.915,
    "pr_variance": 0.0012,
    "anomaly_count": 1,
    "avg_loss_percent": 6.2,
    "readings_analyzed": 100,
    "daytime_readings_analyzed": 95
  }
  ```

---

## 19. Documents & Cloud Storage

### 19.1 POST /api/documents/upload
- **Description**: Uploads document file to Firebase Cloud Storage, validates magic bytes (PDF, JPG, PNG), enforces 50MB limit, sanitizes filenames, and records metadata + audit log in Firestore.
- **Role**: `owner` (own systems/sites), `admin` (any). (Technician -> 403 Forbidden).
- **Content-Type**: `multipart/form-data` or `application/json`.
- **Allowed Types**: `invoice`, `manual`, `warranty`, `photo`, `commissioning_report`, `site_insurance`, `site_agreement`, `site_blueprint`, `site_permit`, `site_safety`, `contract`, `other`.

### 19.2 GET /api/systems/{system_id}/documents
- **Description**: Lists documents for a system with optional `?type=` and `?status=` filters.

### 19.3 GET /api/sites/{site_id}/documents
- **Description**: Lists documents for a site with `?scope=site|all|systems`.

### 19.4 GET /api/documents/{doc_id}
- **Description**: Fetches document metadata.

### 19.5 GET /api/documents/{doc_id}/file
- **Description**: Securely downloads binary file stream or retrieves signed URL.

### 19.6 DELETE /api/documents/{doc_id}
- **Description**: Deletes storage file and metadata record. (Technician forbidden).

---

## 20. QR Access Architecture

The system implements a hardened physical QR field portal architecture:

```
PHYSICAL QR SCAN ON SOLAR PANEL / INVERTER
              │
              ▼
GET /api/systems/{system_id}/qr
   Encodes: /qr-access/{system_id} (NOT /systems/{id}, NO secrets/tokens)
              │
              ▼
/qr-access/{system_id} (Public Minimal Portal Landing)
              │
              ▼
User Logs in with Firebase Authentication
              │
              ▼
Server Verifies ID Token + Server-Side Firestore Role Profile
              │
       ┌──────┴─────────────────────────┐
       ▼                                ▼
Owner / Technician                    Admin
Restricted QR Workspace               Routes to Main Application Admin Dashboard
(/qr-access/{system_id}/workspace)    (/admin/dashboard?system_id={system_id})
Strictly VIEW ONLY                    FULL Administrative Powers Retained
```

### 20.1 GET /api/systems/{system_id}/qr
- **Description**: Generates PNG or JSON QR code encoding `/qr-access/{system_id}`.

### 20.2 GET /api/qr-access/{system_id}
- **Description**: Public unauthenticated minimal portal landing.

### 20.3 GET /api/qr-access/{system_id}/workspace
- **Description**: Authenticated restricted QR workspace. Enforces server-side roles.

### 20.4 GET/POST /api/qr-access/{system_id}/route
- **Description**: Computes server-side intended vs authenticated role routing.

### Security Guarantees:
1. **Intended Role Spoofing Prevention**: Passing `?intended_role=admin` never elevates privileges. Server strictly enforces the authenticated Firestore profile role.
2. **IDOR Prevention**: Authenticated users can only access workspaces for systems they own or are actively assigned to.
3. **Admin Power Preservation**: Admins are not forced into view-only mode; they are routed with full administrative capabilities.

---

## 21. Admin Oversight

All admin endpoints require `@require_auth` and `@require_role('admin')`.

### 21.1 GET /api/admin/stats
- Platform-wide count of users, systems, sites, active alerts, assignments, and documents.

### 21.2 GET /api/admin/users
- Paginated user list with `?role=` filter.

### 21.3 GET /api/admin/users/{uid}
- Single user profile.

### 21.4 PUT /api/admin/users/{uid}
- Update user name or role (protected by zero-admin guard).

### 21.5 DELETE /api/admin/users/{uid}
- Soft-disable user account (protected by self-guard and zero-admin guard).

### 21.6 GET /api/admin/sites
- All sites platform-wide with system counts.

### 21.7 GET /api/admin/systems
- All solar systems platform-wide.

### 21.8 GET /api/admin/assignments
- All technician assignments platform-wide.

### 21.9 DELETE /api/admin/assignments/{asg_id}
- Hard-delete an assignment.

### 21.10 GET /api/admin/alerts
- All alerts platform-wide.

### 21.11 PUT /api/admin/alerts/{alert_id}
- Resolve an alert.

### 21.12 GET /api/admin/documents
- All documents platform-wide.

### 21.13 GET /api/admin/audit-log
- Paginated platform audit log.

### 21.14 GET /api/admin/readings
- Telemetry readings platform-wide.

### 21.15 GET /api/admin/reports/summary
- Platform-wide energy generation and KPI summary.

### 21.16 GET /api/admin/health
- Multi-system health scores sorted by lowest/highest score.

---

## 22. AI Chatbot

### 22.1 GET /api/chat
- **Description**: Natural language querying for solar telemetry, PR, lost generation, yesterday's performance drops, and active alerts.
- **Parameters**: `query` (string, required).
- **Supported Query Types**:
  - *"What is my current power generation?"*
  - *"What is my performance ratio?"*
  - *"Why did my generation drop yesterday?"*
  - *"How much energy did I lose last week?"*
  - *"How much energy did I lose this month?"*
  - *"Are there any active alerts?"*

---

## 23. Health & Readiness

### 23.1 GET /api/health
- **Description**: Liveness probe returning HTTP 200 if Flask process is running.

### 23.2 GET /api/health/ready
- **Description**: Readiness probe checking Firestore client connectivity (HTTP 200 when ready, HTTP 503 when disconnected).

---

## 24. Security Notes

1. **Service Account Protection**:
   - `serviceAccountKey.json` is stored strictly on the server and loaded via `Data_Base/firebase_config.py`.
   - Never send private keys or service account credentials to the client.
2. **Untrusted Client Inputs**:
   - Never trust client-supplied UID, role, or ownership claims.
   - All authorization decisions derive from verified Firebase token claims and Firestore user documents.
3. **Storage Security**:
   - All uploaded files undergo magic-byte signature inspection.
   - Path traversal sequences (`..`, `/`, `\`) in filenames are sanitized.
   - Storage paths are strictly generated server-side.
4. **CORS Security**:
   - In production, set `CORS_ORIGINS` to explicit frontend URLs. Do not use wildcard `*` in production.

---

## 25. Frontend Integration Flow & curl Examples

### 25.1 Complete User Flow (JavaScript/TypeScript Example)
```javascript
import { initializeApp } from "firebase/app";
import { getAuth, signInWithEmailAndPassword } from "firebase/auth";

const firebaseConfig = { /* client config */ };
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

// 1. Authenticate with Firebase Client SDK
const userCredential = await signInWithEmailAndPassword(auth, "owner@example.com", "password123");
const idToken = await userCredential.user.getIdToken();

// 2. Make authenticated API call
const response = await fetch("http://localhost:5000/api/systems", {
  method: "GET",
  headers: {
    "Authorization": `Bearer ${idToken}`,
    "Content-Type": "application/json"
  }
});

if (response.status === 401) {
  // Handle token expired / re-authenticate
} else if (response.status === 403) {
  // Handle unauthorized role / resource access
}

const systems = await response.json();
console.log("Accessible Systems:", systems);
```

### 25.2 curl Commands Reference

```bash
# Health Check
curl -X GET http://localhost:5000/api/health

# Readiness Check
curl -X GET http://localhost:5000/api/health/ready

# Ingest Telemetry
curl -X POST http://localhost:5000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"voltage":48.2,"current":10.5,"power":506.1,"expected_power":550.0,"system_id":"SYS-001"}'

# Query Chatbot
curl -X GET "http://localhost:5000/api/chat?query=What%20is%20my%20current%20power%20generation%3F"

# List User Systems
curl -X GET http://localhost:5000/api/systems \
  -H "Authorization: Bearer <TOKEN>"

# Get Daily Report
curl -X GET "http://localhost:5000/api/reports/daily?date=2026-08-21&system_id=SYS-OWNER001" \
  -H "Authorization: Bearer <TOKEN>"

# ML Prediction
curl -X GET "http://localhost:5000/api/ml/predict?irradiance=850&panel_temp=35&humidity=45&hour_of_day=12&day_of_week=3&system_capacity_kw=5.0" \
  -H "Authorization: Bearer <TOKEN>"

# Generate QR Code (JSON format)
curl -X GET "http://localhost:5000/api/systems/SYS-OWNER001/qr?format=json" \
  -H "Authorization: Bearer <TOKEN>"
```
