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

---

## Segment 14: Document & QR Code Management Engine

Provides authenticated, RBAC-protected REST APIs for managing solar PV installation documents (invoices, technical manuals, warranties, site photos, commissioning reports), automated versioning, date-based expiry tracking, immutable audit trails, and deterministic system QR code generation.

### Firestore Collections

1. **`documents` Collection (`DOC-XXXXXXXX`)**:
   Stores individual document metadata records.
   ```json
   {
     "doc_id": "DOC-A1B2C3D4",
     "system_id": "SYS-001",
     "site_id": "SITE-001",
     "type": "warranty",
     "file_url": "https://storage.googleapis.com/solar-monitor-1200c.appspot.com/solar-documents/SITE-001/SYS-001/DOC-A1B2C3D4/v1/inverter_warranty.pdf",
     "storage_path": "solar-documents/SITE-001/SYS-001/DOC-A1B2C3D4/v1/inverter_warranty.pdf",
     "filename": "inverter_warranty.pdf",
     "format": "PDF",
     "file_size": 204800,
     "version": 1,
     "issue_date": "2026-01-15",
     "expiry_date": "2036-01-15",
     "status": "Active",
     "metadata": {
       "vendor": "SolarTech Global",
       "warranty_term_years": 10
     },
     "uploaded_by": "uid_owner",
     "uploaded_at": "2026-08-21T02:30:00.000000+00:00"
   }
   ```

2. **`document_audits` Collection (`AUD-XXXXXXXX`)**:
   Immutable, append-only audit trail for document lifecycle actions (`upload`, `view`, `download`, `delete`).
   ```json
   {
     "audit_id": "AUD-F8E7D6C5",
     "action": "download",
     "doc_id": "DOC-A1B2C3D4",
     "system_id": "SYS-001",
     "site_id": "SITE-001",
     "performed_by": "uid_tech",
     "performed_at": "2026-08-21T02:35:00.000000+00:00",
     "details": {
       "filename": "inverter_warranty.pdf"
     }
   }
   ```

---

### REST API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/documents/upload` | Owner (own system/site) / Admin | Upload file binary via `multipart/form-data` or register reference. Validates magic bytes, MIME, 50MB size limit, and system/site ownership. Generates server-controlled Storage path. |
| `GET` | `/api/systems/<system_id>/documents` | Owner / Assigned Tech / Admin | List all documents for a solar system. Supports `?type=` and `?status=` filters. Dynamically computes expiry status. |
| `GET` | `/api/sites/<site_id>/documents` | Owner / Assigned Tech / Admin | List documents for a site. Supports `?scope=site\|all\|systems`, `?type=`, `?status=`. |
| `GET` | `/api/documents/<doc_id>` | Owner / Assigned Tech / Admin | Retrieve document metadata. Verifies system/site authorization and records `VIEW` audit. |
| `GET` | `/api/documents/<doc_id>/file` | Owner / Assigned Tech / Admin | Secure file download / short-lived signed access link. Verifies authorization and records `DOWNLOAD` audit. |
| `DELETE` | `/api/documents/<doc_id>` | Owner (own system/site) / Admin | Delete document metadata and delete Cloud Storage object. Records `DELETE` audit. |
| `GET` | `/api/systems/<system_id>/qr` | Owner / Assigned Tech / Admin | Generate deterministic QR code image encoding restricted route `/qr-access/<system_id>`. |
| `GET` | `/api/qr-access/<system_id>` | Public (Unauthenticated) | QR Access Portal landing. Returns safe, minimal system identifier with zero private telemetry. |
| `GET` | `/api/qr-access/<system_id>/workspace` | Owner / Assigned Tech / Admin | Restricted field workspace with role-specific limited capabilities for the scanned system. |

---

### RBAC Authorization Matrix

| Operation | Owner | Technician | Admin |
|:---|:---:|:---:|:---:|
| **Upload Document (System or Site)** | Own systems / sites only | 403 Forbidden | Any system or site |
| **List Documents (System or Site)** | Own systems / sites only | Assigned systems / sites only | Any system or site |
| **Get Document Metadata** | Own systems / sites only | Assigned systems / sites only | Any system or site |
| **Download Document File** | Own systems / sites only | Assigned systems / sites only | Any system or site |
| **Delete Document** | Own systems / sites only | 403 Forbidden | Any system or site |
| **Generate QR Image (API)** | Own systems only | Assigned systems only | Any system |
| **Access QR Landing Portal** | Public (Safe minimal data) | Public (Safe minimal data) | Public (Safe minimal data) |
| **Access QR System Workspace** | Own system summary & docs | Assigned maintenance & read-only docs | Full management workspace |

---

### Cloud Storage Scheme & File Security

1. **Storage Path Scheme**:
   - System-level: `solar-documents/<site_id>/<system_id>/<doc_id>/v<version>/<sanitized_filename>`
   - Site-level: `solar-documents/<site_id>/SITE_LEVEL/<doc_id>/v<version>/<sanitized_filename>`
2. **File Validation & Magic Bytes**:
   - PDF: Magic bytes check `b"%PDF-"`
   - PNG: Magic bytes check `b"\x89PNG\r\n\x1a\n"`
   - JPG/JPEG: Magic bytes check `b"\xff\xd8\xff"`
   - Empty files (0 bytes) rejected with 400 Bad Request.
   - Files $> 50\text{ MB}$ rejected with 400 Bad Request.
   - Path traversal in filenames (e.g. `../../etc/passwd.pdf`) stripped and sanitized safely.
3. **Secure File Access**:
   - Storage buckets are private by default (no permanently public bucket permissions).
   - Downloads require authentication and server-side RBAC validation.
   - Generates short-lived v4 signed URLs (15-minute expiration) or streams via authenticated proxy.

---

### QR Code Architecture & Role-Based Router Model

> [!IMPORTANT]
> **Role-Based Router Architecture**:
> - **QR Generator API**: `GET /api/systems/<system_id>/qr` (Backend API used by authorized users to obtain the QR PNG image).
> - **QR Encoded Destination**: `<public_base_url>/qr-access/<system_id>` (Destination encoded INSIDE the QR code for field scanning).
>
> **QR Scan Flow & Role-Based Routing**:
> 1. Physical QR scan opens `/qr-access/<system_id>`.
> 2. The portal displays minimal public information (`system_id`, portal title, role selection options).
> 3. User selects intended role context and logs in with Firebase credentials.
> 4. **Role Selection is NOT Authorization**: The server validates the user's authentic Firebase role from their Firestore profile and checks system/site ownership or assignment. If a Technician selects "Admin", the backend returns 403 Forbidden.
> 5. **Role-Based Routing Decision**:
>    - **User / Owner**: Routed to the restricted system QR workspace (`/qr-access/<system_id>/workspace`), **strictly VIEW-ONLY** (limited summary, performance, documents, no management).
>    - **Technician**: Routed to the restricted technician QR workspace (`/qr-access/<system_id>/workspace`), **strictly VIEW-ONLY** (field maintenance, diagnostics, alerts, read-only documents, no upload/delete/edit).
>    - **Admin**: **Redirected to the Main Application Admin Dashboard** (`/admin/dashboard?system_id=<system_id>`) with **FULL EXISTING ADMIN POWERS** (system edit, document upload/delete, technician assignments, system configuration). Admin is NOT placed in the restricted view-only workspace.

---

---

## 15. Segment 15 — Admin Panel APIs Specification & Guide

### Overview
Segment 15 delivers a centralized, hardened, role-protected administrative API surface (`BACKEND/admin_panel.py`). All 16 endpoints are strictly locked down to administrators via `@require_auth` and `@require_role("admin")`.

### REST API Endpoints (Admin Only)

| Method | Endpoint | Query Params / Payload | Description |
|--------|----------|------------------------|-------------|
| `GET` | `/api/admin/stats` | — | Platform-wide overview metrics: user count by role, site count, system count, active assignments, active alerts, total documents. |
| `GET` | `/api/admin/users` | `role`, `page`, `per_page` | Paginated listing of all registered users across the platform. |
| `GET` | `/api/admin/users/<uid>` | — | Fetch single user profile by Firebase UID. |
| `PUT` | `/api/admin/users/<uid>` | `{"name": "...", "role": "..."}` | Update user name or role. Protected by zero-admin guard (cannot demote last remaining admin). |
| `DELETE` | `/api/admin/users/<uid>` | — | Soft-disable user account (`disabled: true`). Protected by self-disable guard and zero-admin guard. |
| `GET` | `/api/admin/sites` | `owner_uid`, `page`, `per_page` | Paginated listing of all solar sites with dynamically computed `system_count`. |
| `GET` | `/api/admin/systems` | `owner_uid`, `site_id`, `page`, `per_page` | Paginated listing of all solar installations platform-wide. |
| `GET` | `/api/admin/assignments` | `status`, `technician_uid`, `system_id`, `site_id`, `page`, `per_page` | Paginated listing of technician assignments across all systems and sites. |
| `DELETE` | `/api/admin/assignments/<asg_id>` | — | Hard-delete a technician assignment record. Audited to `document_audits`. |
| `GET` | `/api/admin/alerts` | `active_only`, `system_id`, `page`, `per_page` | Paginated listing of platform alerts. |
| `PUT` | `/api/admin/alerts/<alert_id>` | `{"active": false}` | Resolve alert. Sets `resolved_by` to admin UID and `resolved_at` timestamp. |
| `GET` | `/api/admin/documents` | `system_id`, `site_id`, `doc_type`, `page`, `per_page` | Paginated listing of all documents across all systems/sites. |
| `GET` | `/api/admin/audit-log` | `system_id`, `action`, `performed_by`, `page`, `per_page` | Paginated audit trail covering document lifecycle and administrative operations. |
| `GET` | `/api/admin/readings` | `system_id`, `page`, `per_page` | Paginated listing of telemetry readings across all systems (or filtered), ordered newest first. |
| `GET` | `/api/admin/reports/summary` | — | Platform-level performance & generation KPIs: total generation, expected generation, lost energy, average PR, and health. |
| `GET` | `/api/admin/health` | `sort`, `page`, `per_page` | Platform-wide health monitoring dashboard across all solar systems (sortable lowest/highest). |

### Security & Safety Guards
1. **Strict Admin Lockdown**: All endpoints require Firebase ID token with role `admin`. Non-admin requests (`owner`, `technician`) return `403 Forbidden`. Unauthenticated requests return `401 Unauthorized`.
2. **Self-Disable Guard**: Admin cannot disable their own account (`DELETE /api/admin/users/<own_uid>` -> `403 Forbidden`).
3. **Zero-Admin Guard**: Cannot demote or disable the last remaining admin on the platform (`403 Forbidden`).
4. **Immutable Audit Logging**: Administrative updates, disables, assignment deletions, and alert resolutions are logged to `document_audits`.
5. **Safe Pagination**: All list endpoints default to `page=1`, `per_page=50`, capped at `per_page=200`, with full pagination envelope (`items`, `total`, `page`, `per_page`, `total_pages`).

---

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SOLAR_PUBLIC_BASE_URL` | `https://solar.monitoring.internal` | Public frontend base URL encoded in QR payloads (e.g., `https://field.solarmonitor.com`). |
| `FIREBASE_STORAGE_BUCKET` | `<project_id>.appspot.com` | Google Cloud / Firebase Storage bucket name for solar documents. |
| `STORAGE_BUCKET_NAME` | (alias for above) | Optional fallback bucket name. |

---

### Testing & Verification (505 / 505 Tests Passed)

Execute the comprehensive test suite:
```powershell
.\venv\Scripts\python.exe BACKEND/test_backend.py --include-ingest
```

**Results**:
- **Total Tests Run**: `505`
- **Passed**: `505`
- **Failed**: `0`
- **Baseline Segments 1–13**: 275 tests (100% passing).
- **Segment 14 Baseline & Hardened**: 155 tests (100% passing).
- **Segment 15 Admin Panel APIs (Tests 431–505)**: 75 tests (100% passing) covering:
  - Admin Stats endpoint (`GET /api/admin/stats`): 200 OK, full envelope, accurate aggregation, 403 on non-admin.
  - User Management (`GET/PUT/DELETE /api/admin/users[/<uid>]`): role filtering, profile retrieval, name & role updates, zero-admin demotion prevention, self-disable protection, 404 handling, 403 RBAC enforcement.
  - Site & System Oversight (`GET /api/admin/sites`, `GET /api/admin/systems`): dynamic `system_count`, multi-owner visibility, owner/site filtering, 403 on technician/owner.
  - Assignment Management (`GET/DELETE /api/admin/assignments[/<id>]`): status/tech/system filtering, hard-deletion, audit generation, 403 RBAC enforcement.
  - Alert Management & Resolution (`GET/PUT /api/admin/alerts[/<id>]`): active/all filtering, resolution with `resolved_by`/`resolved_at` injection, empty payload validation, 403 RBAC enforcement.
  - Document & Audit Trail Oversight (`GET /api/admin/documents`, `GET /api/admin/audit-log`): cross-system document listing, action/performer/system audit log filtering, 403 RBAC enforcement.
  - Telemetry Readings (`GET /api/admin/readings`): system filtering, pagination, sorting newest first, 403 on non-admin, 401 unauthenticated.
  - Reports Summary (`GET /api/admin/reports/summary`): platform-wide generation, expected generation, lost energy, average PR, health aggregation, 403 on non-admin.
  - Health Monitoring Dashboard (`GET /api/admin/health`): multi-system health scores, `sort=lowest` and `sort=highest` sorting, pagination, 403 on non-admin.
  - Pagination Engine: standard envelopes, slice validation, boundary clamping (`MAX_PER_PAGE=200`), total pages computation.
  - Authentication Gates: unauthenticated rejection (401) on all endpoints.
  - End-to-End Administrative Integration Workflow (Test 490).
