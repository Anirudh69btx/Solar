# Solar PV Monitoring System — Deployment & Local Testing Guide

This guide provides step-by-step instructions to configure, run, test, troubleshoot, and demonstrate the complete **Solar PV Monitoring System** backend, automated background scheduler, and ESP32 edge firmware.

---
## 1. Architecture Overview

```
+------------------------------------------------------------------------------------+
|                         1. EDGE TELEMETRY LAYER (SEGMENT 11)                       |
|   ESP32 DevKit + INA219 (V, I, P), DS18B20 (T_panel), BH1750 (Lux), DHT11, Rain,  |
|   SW-420 -> Local Validation -> P_exp(T), PR -> Fault Detection -> Ring Buffer     |
+------------------------------------------------------------------------------------+
                                          |
                                 HTTP POST /api/ingest
                                          v
+------------------------------------------------------------------------------------+
|                         2. BACKEND API SERVER (SEGMENTS 1–9, 13)                   |
|   Flask REST API (Port 5000)                                                       |
|   - Authentication & RBAC (Owner, Technician, Admin)                               |
|   - Solar Sites & Multi-System Registry                                            |
|   - Technician Work Assignments                                                    |
|   - Telemetry Ingestion & Real-Time Storage                                        |
|   - Daily / Weekly / Monthly Solar Analytics & Energy Integration Reports          |
|   - Natural Language AI Solar Chatbot                                              |
|   - ML Power Prediction (LinearRegression, model.pkl)          [SEGMENT 13]        |
|   - Multi-System Solar Health Score Engine                     [SEGMENT 13]        |
+------------------------------------------------------------------------------------+
                     |                                            |
              Firestore Read/Write                         Firestore Read/Write
                     v                                            v
+------------------------------------------+  +--------------------------------------+
|       3. FIRESTORE DATABASE LAYER        |  |  4. AUTOMATED SCHEDULER (SEGMENT 10) |
|   Collections:                           |  |   Standalone Background Process      |
|   - users       - sites      - systems   |  |   - 5-Minute Monitoring Cycle        |
|   - assignments - readings   - alerts    |  |   - PR < 0.70 Fault Anomaly Trigger  |
+------------------------------------------+  |   - 1-Hour Duplicate Suppression     |
                                               |   - Automatic Alert Recovery         |
                                               +--------------------------------------+
```
```

---

## 2. Project Prerequisites

### Software Requirements
- **Python**: Version `3.11` or higher
- **Git**: For source version control
- **Firebase Project**: Google Cloud Firebase project with:
  - **Firestore Database** (Native Mode)
  - **Firebase Authentication** (Email/Password Provider enabled)
- **Service Account Key**: `serviceAccountKey.json` generated from Firebase Console

### Hardware Requirements (Optional for Backend Testing)
- **Microcontroller**: ESP32 DevKit V1 (30-pin or 38-pin)
- **Sensors**: INA219 (DC Power), DS18B20 (1-Wire Temp), BH1750 (I2C Lux), DHT11 (Ambient), Rain Sensor, SW-420 (Vibration)
- *Note*: Hardware is **optional** for local testing, demoing, and CI/CD. The backend fully supports simulated telemetry and REST clients (curl/Postman).

---

## 3. Quickstart & Local Setup

### Step 1: Clone and Navigate
```bash
git clone <repository_url>
cd Solar
```

### Step 2: Create and Activate Virtual Environment
**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Verify Environment
```bash
python -c "import flask, firebase_admin, google.cloud.firestore, pandas, sklearn, joblib; print('Environment OK')"
```

---

## 4. Firebase & Firestore Configuration

### Step 1: Obtain Service Account Key
1. Open the [Firebase Console](https://console.firebase.google.com/).
2. Navigate to **Project Settings** (`⚙️`) -> **Service Accounts**.
3. Select **Firebase Admin SDK** -> Click **Generate New Private Key**.
4. Download the generated JSON file.

### Step 2: Place `serviceAccountKey.json`
Place the file directly in the project root directory:
```
Solar/
├── BACKEND/
├── Data_Base/
├── hardware/
├── serviceAccountKey.json   <-- Place file here
└── requirements.txt
```

> [!CAUTION]
> **Security Notice**: Never commit `serviceAccountKey.json` to version control. The repository's [`.gitignore`](file:///c:/Users/danny/OneDrive/Documents/coding/Solar/.gitignore) already includes `serviceAccountKey.json` and `*.json`.

### Step 3: Verify Firebase Connection
Run the database connection verification check:
```bash
python Data_Base/firebase_config.py
```
*Expected Output:*
```
[Firebase Config] Initialized Firebase App using key at: .../serviceAccountKey.json
Firestore Client initialized successfully.
```

---

## 5. Firestore Collections & Composite Indexes

### Firestore Collections Overview

| Collection | Document ID Format | Description | Key Fields |
|---|---|---|---|
| **`users`** | `UID` (from Firebase Auth) | User profile & RBAC | `uid`, `email`, `name`, `role` (`owner`, `technician`, `admin`), `created_at` |
| **`sites`** | `SITE-XXXXXXXX` | Solar facility / physical site | `site_id`, `name`, `location`, `owner_uid`, `created_at` |
| **`systems`** | `SYS-XXXXXXXX` | Solar PV installation | `system_id`, `name`, `site_id`, `owner_uid`, `capacity_kw`, `tilt_angle`, `azimuth_angle` |
| **`assignments`** | Auto ID | Technician assignment | `assignment_id`, `technician_uid`, `system_id`, `site_id`, `assigned_by`, `created_at` |
| **`readings`** | `read_<unix_timestamp>` | Ingested sensor telemetry | `unix_timestamp`, `timestamp`, `system_id`, `voltage`, `current`, `power`, `expected_power`, `performance_ratio`, `irradiance`, `temperature_panel` |
| **`alerts`** | Auto ID | Performance alerts | `system_id`, `site_id`, `type`, `severity`, `performance_ratio`, `threshold`, `status` (`active`/`resolved`), `active` (bool) |

### Required Production Composite Indexes
To ensure fast aggregation and multi-system querying without Firestore index exceptions, configure these indexes in Firebase Console (**Firestore Database** -> **Indexes** -> **Composite**):

1. **Collection**: `readings`
   - `system_id`: **Ascending**
   - `timestamp`: **Ascending**
   - Query scope: **Collection**

2. **Collection**: `readings`
   - `system_id`: **Ascending**
   - `unix_timestamp`: **Descending**
   - Query scope: **Collection**

---

## 6. Environment Variables

Create a `.env` file in the project root if overriding default parameters (optional):

| Variable | Default Value | Description | Environment |
|---|---|---|---|
| `PORT` | `5000` | HTTP port for Flask API | Dev / Prod |
| `FLASK_DEBUG` | `True` (Dev) | Flask debug mode (`False` in production) | Dev / Prod |
| `SCHEDULER_INTERVAL_MINUTES` | `5` | Background scheduler monitoring interval | Dev / Prod |
| `ALERT_THRESHOLD` | `0.70` | Performance Ratio anomaly threshold ($PR < 0.70$) | Dev / Prod |
| `DUPLICATE_ALERT_WINDOW_SECONDS` | `3600` | Duplicate active alert suppression window (1 hour) | Dev / Prod |
| `SLIDING_WINDOW_SIZE` | `5` | Sliding window count of recent readings to inspect | Dev / Prod |
| `MIN_ANOMALOUS_COUNT` | `3` | Minimum breached readings to trigger alert | Dev / Prod |

---

## 7. Seed & Synthetic Telemetry Generator

The synthetic data generator provides realistic diurnal solar curves, panel heating, and historical fault periods.

### Command 1: Backfill 30 Days of Historical Telemetry
Generates 30 days of 5-minute readings with realistic solar curves and noon degradation faults for testing daily/weekly/monthly reports:
```bash
python Data_Base/seed_fake_data.py --backfill --days 30
```

### Command 2: Stream Live Simulated Telemetry
Streams one reading every 5 seconds continuously to test real-time ingestion and the alert engine:
```bash
python Data_Base/seed_fake_data.py --live
```

---

## 8. Starting the Backend Services

The complete system uses two concurrent terminal processes.

### Terminal 1: Start Flask REST API Server
```bash
python BACKEND/app.py
```
*Server starts on `http://127.0.0.1:5000`.*

**Verify API Health:**
```bash
curl http://127.0.0.1:5000/api/health
```
*Expected Response (200 OK):*
```json
{
  "service": "Solar Monitoring Backend API",
  "status": "ok",
  "timestamp": "2026-08-17T14:30:00.000000+00:00"
}
```

### Terminal 2: Start Automated Background Scheduler
```bash
python BACKEND/scheduler.py
```
*Expected Output:*
```
============================================================
       Automated Solar Alert Scheduler started.             
       Monitoring interval: 5.0 minutes (300s).
       Alert threshold PR: < 0.70
============================================================
[INFO] Monitoring cycle started.
[INFO] Monitoring cycle completed. Systems checked: 4, Alerts created: 0, Alerts resolved: 0.
```

---

## 9. API Reference & Testing (Postman / curl)

All protected endpoints require the header:
`Authorization: Bearer <FIREBASE_ID_TOKEN>`

### 1. Authentication (`/api/auth`)

#### Public Owner Registration (201 Created)
```bash
curl -X POST http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"owner@example.com\", \"password\": \"securePassword123\", \"name\": \"Solar Owner\"}"
```

#### Admin-Only User Creation (201 Created)
```bash
curl -X POST http://127.0.0.1:5000/api/auth/users \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"tech@example.com\", \"password\": \"techPass123\", \"name\": \"Field Technician\", \"role\": \"technician\"}"
```

#### Get Current Profile (200 OK)
```bash
curl -X GET http://127.0.0.1:5000/api/auth/me \
  -H "Authorization: Bearer <USER_TOKEN>"
```

---

### 2. Multi-Site Management (`/api/sites`)

#### Create Site (201 Created)
```bash
curl -X POST http://127.0.0.1:5000/api/sites \
  -H "Authorization: Bearer <OWNER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"Green Valley Solar Farm\", \"location\": \"Building A, Rooftop\"}"
```

#### List Sites (200 OK)
```bash
curl -X GET http://127.0.0.1:5000/api/sites \
  -H "Authorization: Bearer <USER_TOKEN>"
```

---

### 3. Solar Systems (`/api/systems`)

#### Create System (201 Created)
```bash
curl -X POST http://127.0.0.1:5000/api/systems \
  -H "Authorization: Bearer <OWNER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d "{\"name\": \"Rooftop Array 1\", \"site_id\": \"SITE-XXXXXXXX\", \"capacity_kw\": 10.0, \"tilt_angle\": 25.0, \"azimuth_angle\": 180.0}"
```

#### List Accessible Systems (200 OK)
```bash
curl -X GET http://127.0.0.1:5000/api/systems \
  -H "Authorization: Bearer <USER_TOKEN>"
```

---

### 4. Technician Assignments (`/api/assignments`)

#### Assign Technician (201 Created)
```bash
curl -X POST http://127.0.0.1:5000/api/assignments \
  -H "Authorization: Bearer <OWNER_TOKEN>" \
  -H "Content-Type: application/json" \
  -d "{\"technician_uid\": \"<TECH_UID>\", \"system_id\": \"SYS-XXXXXXXX\"}"
```

#### List Assignments (200 OK)
```bash
curl -X GET http://127.0.0.1:5000/api/assignments \
  -H "Authorization: Bearer <USER_TOKEN>"
```

---

### 5. Telemetry Ingestion (`/api/ingest`)

#### Ingest Real or Simulated Telemetry (201 Created)
```bash
curl -X POST http://127.0.0.1:5000/api/ingest \
  -H "Content-Type: application/json" \
  -d "{\"system_id\": \"SYS-XXXXXXXX\", \"voltage\": 18.42, \"current\": 8.15, \"power\": 150.12, \"expected_power\": 245.50, \"performance_ratio\": 0.6115, \"lux\": 98200.0, \"temperature_panel\": 48.2, \"temperature_ambient\": 31.5, \"humidity\": 42.0}"
```

#### Query Latest Readings (200 OK)
```bash
curl -X GET "http://127.0.0.1:5000/api/readings/latest?limit=10"
```

---

### 6. Performance Reports (`/api/reports`)

#### Daily Report (200 OK)
```bash
curl -X GET "http://127.0.0.1:5000/api/reports/daily?system_id=SYS-XXXXXXXX&date=2026-08-17" \
  -H "Authorization: Bearer <USER_TOKEN>"
```

#### Weekly Report (200 OK)
```bash
curl -X GET "http://127.0.0.1:5000/api/reports/weekly?system_id=SYS-XXXXXXXX&start_date=2026-08-10" \
  -H "Authorization: Bearer <USER_TOKEN>"
```

#### Monthly Report (200 OK)
```bash
curl -X GET "http://127.0.0.1:5000/api/reports/monthly?system_id=SYS-XXXXXXXX&year=2026&month=8" \
  -H "Authorization: Bearer <USER_TOKEN>"
```

---

### 7. Alerts & Natural Language Chatbot

#### View Active Alerts (200 OK)
```bash
curl -X GET "http://127.0.0.1:5000/api/alerts?active_only=true"
```

#### Natural Language Solar Query (200 OK)
```bash
curl -X GET "http://127.0.0.1:5000/api/chat?query=What%20is%20my%20current%20solar%20power%20generation%3F"
```

---

## 10. HTTP Status Code Reference

| Status Code | Meaning | Common Cause in System |
|---|---|---|
| **200 OK** | Request succeeded | Successful GET query or report generation |
| **201 Created** | Resource created | Successful registration, site/system creation, or ingestion |
| **400 Bad Request** | Invalid input / payload | Missing required fields (`voltage`, `current`, `power`, `expected_power`) |
| **401 Unauthorized** | Missing or invalid auth | Missing or expired Firebase JWT ID token in Authorization header |
| **403 Forbidden** | Permission denied | Role violation (e.g. Technician attempting to update a system) |
| **404 Not Found** | Resource not found | Specified `system_id` or `site_id` does not exist |
| **409 Conflict** | Resource conflict | Email already registered in Firebase Auth / Firestore |
| **500 Server Error** | Internal error | Missing `serviceAccountKey.json` or database connection drop |

---

## 11. Complete End-to-End Local Test Workflow

Follow this sequence to test the entire platform end-to-end:

```
1. Register Owner Account (/api/auth/register)
      ↓
2. Log in & Obtain Firebase ID Token
      ↓
3. Create Solar Site (/api/sites)
      ↓
4. Create Solar System (/api/systems) linked to Site
      ↓
5. Ingest Healthy Telemetry (PR >= 0.70) (/api/ingest)
      ↓
6. Ingest Faulty Telemetry (PR < 0.70) (/api/ingest)
      ↓
7. Run Automated Scheduler (/api/alerts) -> Verifies Alert Created
      ↓
8. Ingest Recovery Telemetry (PR >= 0.70) -> Verifies Alert Resolved
      ↓
9. Generate Daily Report (/api/reports/daily) -> Verifies Aggregation
```

---

## 12. Hardware-Independent Testing

Physical hardware is **not required** to evaluate the backend. You can test all features using software simulation:

1. Use `Data_Base/seed_fake_data.py --live` to stream realistic solar data.
2. Use curl or Postman to test `/api/ingest`.
3. In `hardware/esp32_firmware.ino`, set `bool SIMULATION_MODE = true;` to test edge logic without physical sensors.

---

## 13. ESP32 Edge Firmware Deployment

To flash the ESP32 microcontroller:

1. Open [`hardware/esp32_firmware.ino`](file:///c:/Users/danny/OneDrive/Documents/coding/Solar/hardware/esp32_firmware.ino) in the **Arduino IDE**.
2. Install dependencies via **Library Manager**:
   - `ArduinoJson` (v6.x or v7.x)
   - `Adafruit INA219`
   - `OneWire`
   - `DallasTemperature`
   - `BH1750`
   - `DHT sensor library`
3. Edit configuration variables in `esp32_firmware.ino`:
   ```cpp
   const char* WIFI_SSID          = "YOUR_WIFI_SSID";
   const char* WIFI_PASSWORD      = "YOUR_WIFI_PASSWORD";
   const char* BACKEND_INGEST_URL = "http://<YOUR_PC_LAN_IP>:5000/api/ingest";
   const char* SYSTEM_ID          = "SYS-XXXXXXXX";
   ```
4. Select Board: **DOIT ESP32 DEVKIT V1** -> Select COM Port -> Click **Upload**.
5. Open **Serial Monitor** at `115200` baud to observe live edge telemetry.

---

## 14. Production Deployment Checklist

- [ ] **Secret Management**: `serviceAccountKey.json` stored outside the repository and injected via environment variables in production.
- [ ] **Flask Debug**: Set `FLASK_DEBUG=False` and run Flask behind a production WSGI server (e.g. **Gunicorn** or **Waitress**).
- [ ] **Process Management**: Run `BACKEND/app.py` and `BACKEND/scheduler.py` as separate managed system services (e.g., `systemd`, Docker, or PM2).
- [ ] **CORS**: Configure `CORS(app, resources={r"/api/*": {"origins": "https://yourfrontend.com"}})` in `BACKEND/app.py`.
- [ ] **Composite Indexes**: Confirm all composite indexes are marked **Enabled** in the Firestore console.
- [ ] **SSL / TLS**: Serve all backend endpoints over `HTTPS`.

---

## 15. Troubleshooting Guide

### 1. `FileNotFoundError: Could not find 'serviceAccountKey.json'`
- **Cause**: The Firebase service account key is missing.
- **Fix**: Download the private key from Firebase Console and place it in the project root as `serviceAccountKey.json`.

### 2. `401 Unauthorized` on API Calls
- **Cause**: Missing or expired Firebase ID token.
- **Fix**: Verify your authorization header format: `Authorization: Bearer <valid_token>`.

### 3. `403 Forbidden` on Updating Systems
- **Cause**: User role is `technician` (Technicians have read-only access to assigned systems; only `owner` and `admin` can update).

### 4. Firestore Query Requires Index Error
- **Cause**: Composite index missing for multi-field filtering (`system_id` + `timestamp`).
- **Fix**: Click the URL provided in the Firestore error log to create the composite index automatically in Firebase Console.

### 5. ESP32 `HTTP ERROR: Connection failed`
- **Cause**: ESP32 cannot reach the backend server over Wi-Fi.
- **Fix**:
  - Ensure ESP32 and PC are on the **same 2.4GHz Wi-Fi network**.
  - In `esp32_firmware.ino`, replace `localhost` or `127.0.0.1` with your PC's actual LAN IP address (e.g. `http://192.168.1.150:5000/api/ingest`).
  - Allow inbound traffic on port `5000` in your PC's firewall.

---

## 16. Verification & Automated Test Suite

Run the full backend integration and edge test suite:
```bash
python BACKEND/test_backend.py
```
*Expected Result:*
```
==================================================================================
                    Integration & Security Test Results Summary                   
==================================================================================
Total Tests Run: 234
Passed: 234
Failed: 0
==================================================================================
```

---

## 17. 5-Minute Hackathon Demo Script

1. **Start Backend**: `python BACKEND/app.py` in Terminal 1.
2. **Start Scheduler**: `python BACKEND/scheduler.py` in Terminal 2.
3. **Owner Journey**:
   - Register owner via `POST /api/auth/register`.
   - Create a Solar Site via `POST /api/sites`.
   - Register a Solar System via `POST /api/systems`.
4. **Demonstrate Telemetry Ingestion**:
   - Post healthy telemetry (`PR = 0.90`) via `POST /api/ingest`.
   - Post faulty telemetry (`PR = 0.55`) via `POST /api/ingest`.
5. **Show Automatic Alerting**:
   - Query `GET /api/alerts` to show the active underperformance alert created automatically by the scheduler.
6. **Generate Reports**:
   - Query `GET /api/reports/daily` to show automatic energy loss quantification.
7. **Demonstrate AI Chatbot**:
   - Query `GET /api/chat?query=How is my solar system performing?` to show data-backed natural language insights.
8. **ML Power Prediction (Segment 13)**:
   - Train model: `POST /api/ml/train` (Admin token).
   - Predict: `GET /api/ml/predict?lux=85000&panel_temp=45&humidity=40&hour_of_day=13&day_of_week=2`.
9. **Solar Health Score (Segment 13)**:
   - Query `GET /api/systems/<system_id>/health` to show live health score and status.

---

## 18. Segment 13 — ML Predictions & Solar Health Score

### Overview

Segment 13 adds machine learning-based solar power prediction and a multi-system Solar Health Score engine.

**Source File**: `BACKEND/ml_predict.py`

### Important Architectural Separation (Physical vs ML vs Actual)

- **Actual Measured Power (`power`)**: Real electrical generation ($P_{\text{actual}} = V \times I$ or direct power measurement) ingested from sensors and preserved in Firestore.
- **Physical Expected Power (`expected_power`)**: Theoretical physics/engineering model ($P_{\text{exp}} = \frac{\text{Irradiance}}{1000.0} \times P_{\text{rated\_watts}} \times \text{temp\_derating}$) computed deterministically from real irradiance ($\text{W/m}^2$) and configured plant capacity ($P_{\text{rated}}$), preserved in `/api/ingest`.
- **ML Predicted Power (`predicted_power`)**: Statistical regression prediction output by the LinearRegression model trained on environmental features (`irradiance`, `panel_temp`, `hour_of_day`, `day_of_week`, `humidity`) and scaled by `system_capacity_kw`.

These three metrics remain strictly decoupled throughout the entire stack (database, APIs, analysis, reports, and UI) and are never merged or overwritten.

### Authoritative Irradiance ($\text{W/m}^2$) vs Auxiliary Lux

- **Solar Irradiance (`irradiance` in $\text{W/m}^2$)**: The authoritative, physical input for solar calculations, expected power, Performance Ratio (PR), generation loss, and ML features.
- **Auxiliary Lux (`lux`)**: Visible-light illumination from sensors like the BH1750. In real datasets with measured irradiance, Lux is preserved separately as auxiliary telemetry and **never** fabricated.
- **Legacy Fallback**: For legacy edge devices providing only Lux, an explicit approximation fallback ($\text{Irradiance} = \text{Lux} / 120.0$) is applied if `irradiance` is omitted.

### Capacity Awareness (Capacity-Normalized Specific Power)

In solar engineering, plants range from small residential systems ($0.3\text{ kW}$) to commercial plants ($5\text{ kW}$ – $100\text{ kW}$). The model trains on capacity-normalized specific power ($\text{W/kW}$ capacity):
$$\text{normalized\_power} = \frac{\text{actual\_power\_watts}}{\text{system\_capacity\_kw}}$$
During prediction:
$$\text{predicted\_power} = \text{predicted\_normalized\_power} \times \text{system\_capacity\_kw}$$
This ensures accurate scaling across installations of arbitrary capacity.

### API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/ml/train` | Admin only (`@require_role("admin")`) | Train/retrain the capacity-normalized LinearRegression power prediction model. Atomically saves `model.pkl` with chronological 80/20 validation metrics (MAE, RMSE, R²). |
| `GET` | `/api/ml/predict` | Authenticated (`@require_auth`) | Predict solar power generation. Query params: `irradiance` (or `lux` fallback), `panel_temp`, `humidity`, `hour_of_day`, `day_of_week`, `system_capacity_kw` (optional, default: 1.0 kW). |
| `GET` | `/api/systems/<system_id>/health` | Owner / Assigned Tech / Admin | Returns Solar Health Score and status classification for a system. |

### ML Model Details

- **Algorithm**: `sklearn.linear_model.LinearRegression`
- **Features**: `irradiance` [0–2,000 W/m²], `panel_temp` [-40 to 125°C], `hour_of_day` [0–23 UTC], `day_of_week` [0–6], `humidity` [0–100%]
- **Target**: `normalized_power` (Watts per kW capacity $\ge 0$)
- **Train/Test Split**: Chronological 80/20 split (first 80% train, last 20% test) preserving time-series order and preventing temporal leakage.
- **Atomic Persistence**: Serializes bundle to `model.pkl.tmp` then atomically replaces `model.pkl` via `os.replace()`, preventing model corruption on write failures.
- **Metadata Bundle**: Contains `model_type`, `model_version: 3`, `training_source` (`"firestore"` or `"synthetic_fallback"`), `split_strategy: "chronological_80_20"`, `synthetic_data_used`, `mae`, `rmse`, `r2_score`, and `feature_names`.
- **Synthetic Fallback**: If fewer than 100 valid Firestore readings exist, the trainer generates 300 physically realistic synthetic samples across varied system capacities ($0.3\text{ kW}, 1.0\text{ kW}, 3.0\text{ kW}, 5.0\text{ kW}$) using diurnal solar curve equations with isolated local RNG instances.

### Solar Health Score Engine

Evaluates up to the latest 100 readings for a given system (`system_id`), filtering exclusively for active daytime generation (`expected_power > 10.0W`):

```
raw_health = 100.0 - (avg_loss_percent * 1.0) - (anomaly_ratio * 20.0) - (pr_variance * 200.0)
health_score = clamp(raw_health, 0.0, 100.0)
```

**Where**:
- `avg_loss_percent`: Average generation loss percentage $[0.0, 100.0]$ (e.g. $5.0$ for $5\%$ loss, $10.0$ for $10\%$ loss).
- `anomaly_ratio`: Fraction of daytime readings with $\text{PR} < 0.70$ $[0.0, 1.0]$.
- `pr_variance`: Population variance of daytime Performance Ratio values (typically $0.0$ to $\sim 0.05$).

**Status Classification (Continuous Float Boundaries)**:
| Score Range | Status | Meaning |
|-------------|--------|---------|
| `score >= 90.0` | **Excellent** | Measured healthy performance |
| `75.0 <= score < 90.0` | **Good** | Measured acceptable performance |
| `50.0 <= score < 75.0` | **Warning** | Measured degraded performance |
| `0.0 <= score < 50.0` | **Critical** | Measured severely degraded performance |
| `None` (no data) | **N/A** | Insufficient telemetry to determine health |

#### No-Data / N/A Behavior
When a solar system has no telemetry, only nighttime readings (`expected_power <= 10.0W`), or invalid data, the health engine explicitly returns `null` for `health_score` and status `"N/A"`:
```json
{
  "system_id": "SYS-NO-DATA",
  "health_score": null,
  "status": "N/A",
  "message": "Insufficient telemetry to calculate health",
  "average_pr": null,
  "pr_variance": null,
  "anomaly_count": 0,
  "anomaly_ratio": null,
  "avg_loss_percent": null,
  "readings_analyzed": 0,
  "daytime_readings_analyzed": 0
}
```
*Note*: `N/A` represents "insufficient telemetry to calculate health", fundamentally distinct from `Critical` (where valid telemetry demonstrates severe underperformance).

---

### Documented Prototype Limitations

1. **Prototype-Calibrated Health Formula Weights**: The weighting coefficients ($1.0$, $20.0$, $200.0$) are prototype operational calibration weights designed for interpretable $0\text{--}100$ demonstration scoring. They should be calibrated against historical field fault datasets before utility-scale production deployment.
2. **Synthetic Data Fallback & Evaluation Metrics**: When fewer than 100 valid readings exist, the model trains on synthetic diurnal data. The resulting evaluation metrics ($R^2 \approx 0.999$, $\text{MAE} \approx 5.7\text{W/kW}$) reflect fit to a synthetic mathematical model, NOT real-world weather prediction accuracy.
3. **Chronological 80/20 Validation**: Chronological splitting preserves time order and prevents future data leakage into training. In full production, rolling walk-forward cross-validation across seasonal cycles is recommended.
4. **Sample-Bounded Window (Last 100 Readings $\ne$ Fixed Time Window)**: Health Score queries up to the latest 100 valid readings for the selected system. The actual time span represented depends on sensor sampling frequency ($5\text{s}$ live streaming vs $5\text{min}$ intervals).
5. **Linear Model Scope**: `LinearRegression` on capacity-normalized specific power provides high explainability and rapid inference, but cannot capture non-linear complex cloud dynamics, partial array shading, or severe inverter clipping.
6. **ML Anomaly vs Confirmed Hardware Fault**: A discrepancy between actual power and ML predicted power indicates a *potential performance deviation*, not a confirmed hardware diagnosis (e.g. blown fuse or cracked cell).

---

### Testing & Validation (270 / 270 Tests Passed)

Tests 213–270 in `BACKEND/test_backend.py` (58 dedicated Segment 13 tests) validate:
- Canonical feature schema (`["irradiance", "panel_temp", "hour_of_day", "day_of_week", "humidity"]`) and capacity-normalized target
- Real irradiance ingested directly without fabricating fake Lux
- Physical expected power calculation with capacity scaling ($1\text{ kW}$ vs $5\text{ kW}$) and temperature derating ($P_{\text{exp}} \ge 0$)
- Capacity-aware ML prediction ($5\text{ kW}$ scales appropriately relative to $1\text{ kW}$)
- Column aliasing (`irradiance_w_m2`, `temperature_panel`, `panel_capacity_watts`), deduplication, UTC timezone parsing
- Linear Regression training, synthetic fallback flagging, and evaluation metrics (MAE, RMSE, $R^2$)
- Chronological 80/20 train/test split metadata preservation
- Atomic model persistence (`model.pkl.tmp` $\to$ `os.replace` $\to$ `model.pkl`) and write-failure recovery
- Prediction inference with boundary checks, type coercion, and non-negative power clamping
- Rejection of `NaN`, `Infinity`, nulls, and out-of-bounds query parameters with HTTP 400
- Formula regression tests ($0\% \to 100.0$, $5\% \to 95.0$, $10\% \to 90.0$, $15\% \to 85.0$, anomaly penalty, variance penalty, clamping)
- Continuous float boundary classification ($89.999 \to$ Good, $74.999 \to$ Warning, $49.999 \to$ Critical, None $\to$ N/A)
- Three-way state distinction (N/A vs Critical vs Excellent)
- Safe N/A response serialization (`health_score: null`) for unread and nighttime-only systems
- REST API RBAC enforcement (Admin-only training, auth-gated prediction, system-scoped health for Owner, assigned Technician, and Admin)
- Physical `expected_power` preserved untouched throughout ingestion and analysis pipelines
