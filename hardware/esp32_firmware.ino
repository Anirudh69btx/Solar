/*
 ====================================================================================================
  PROJECT: SMART SOLAR PV MONITORING SYSTEM — EDGE CONTROLLER FIRMWARE
  MODULE : Segment 11 — ESP32 Smart Solar Telemetry & Edge Intelligence
  TARGET : ESP32 DevKit V1 (30-pin / 38-pin) / ESP32-WROOM-32
  AUTHOR : Solar IoT Systems Engineering Team
  DATE   : 2026-08-17
 ====================================================================================================
 
  FIRMWARE ARCHITECTURE & EDGE PIPELINE:
  --------------------------------------
  1. SENSE            : Sample INA219 (V, I, P), DS18B20 (Panel °C), BH1750 (Lux),
                        DHT11 (Ambient °C, Humidity %), Rain Sensor (0/1), SW-420 (Vibration).
  2. VALIDATE         : Range-check readings, filter NaNs, detect sensor communication drops.
  3. COMPUTE METRICS  : Compute Actual Power (W), Irradiance (W/m²), Temperature-Compensated
                        Expected Power (W), Performance Ratio (PR), Variable-Interval Energy (kWh),
                        and Estimated Lost Generation (kWh).
  4. DETECT FAULTS    : Over-voltage, Over-current, Over-temperature, Performance Drop (PR < 0.70),
                        Rain Interference, Structural Vibration, and Sensor Communication Faults.
  5. PACKAGE JSON     : Build standard JSON payload matching backend 'POST /api/ingest'.
  6. TRANSMIT / BUFFER: Send via HTTP REST API. If Wi-Fi/Backend is unreachable, store in a bounded
                        offline circular buffer and automatically drain upon reconnection.

 ====================================================================================================
  REQUIRED ARDUINO LIBRARIES & INSTALLATION:
 ====================================================================================================
  Install via Arduino Library Manager (Sketch -> Include Library -> Manage Libraries):
  
  1. WiFi.h              [Built-in ESP32 Core] : Manages 802.11 b/g/n Wi-Fi station connectivity.
  2. HTTPClient.h        [Built-in ESP32 Core] : RESTful HTTP POST request client for backend ingestion.
  3. Wire.h              [Built-in ESP32 Core] : I2C master bus hardware interface (INA219, BH1750).
  4. ArduinoJson         [by Benoit Blanchon]  : Efficient memory-safe JSON serialization (v6.x / v7.x).
  5. Adafruit_INA219     [by Adafruit]         : High-side DC voltage, current (mA), and power monitor.
  6. OneWire             [by Paul Stoffregen]  : Dallas 1-Wire bit-banged protocol interface.
  7. DallasTemperature   [by Miles Burton]     : DS18B20 digital thermometer probe driver.
  8. BH1750              [by Christopher Laws] : Digital ambient light (Lux) sensor driver via I2C.
  9. DHT sensor library  [by Adafruit]         : DHT11 single-bus ambient temperature and humidity driver.
 ====================================================================================================
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <Wire.h>
#include <ArduinoJson.h>
#include <Adafruit_INA219.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <BH1750.h>
#include <DHT.h>
#include <time.h>
#include <math.h>

// ==================================================================================================
//  1. HARDWARE PIN CONFIGURATION
// ==================================================================================================
//  Pin choices avoid strapping pins (GPIO 0, 2, 12, 15) and input-only pins (GPIO 34-39) where
//  pull-ups/outputs are needed. GPIO 34 is safely used for analog rain level reading.
// ==================================================================================================
#define I2C_SDA_PIN           21    // Default ESP32 I2C SDA (INA219 & BH1750)
#define I2C_SCL_PIN           22    // Default ESP32 I2C SCL (INA219 & BH1750)
#define ONE_WIRE_BUS_PIN      4     // DS18B20 1-Wire Bus (Requires 4.7kΩ pull-up to 3.3V)
#define DHT_PIN               18    // DHT11 Single-Bus Data (Requires 10kΩ pull-up to 3.3V)
#define DHT_TYPE              DHT11 // Sensor model: DHT11
#define RAIN_DIGITAL_PIN      19    // Rain Sensor Digital Output (Active LOW: LOW = Rain detected)
#define RAIN_ANALOG_PIN       34    // Rain Sensor Analog Intensity (ADC1_CH6, Input-only safe)
#define SW420_VIBRATION_PIN   23    // SW-420 Digital Vibration Sensor (Active HIGH on shock)
#define STATUS_LED_PIN        2     // Onboard Blue Status LED (Visual Heartbeat / WiFi indication)


// ==================================================================================================
//  2. USER CONFIGURATION — SETTINGS TO CONFIGURE BEFORE FLASHING
// ==================================================================================================
// Wi-Fi Network Credentials
const char* WIFI_SSID             = "YOUR_WIFI_SSID";         // Replace with your 2.4GHz Wi-Fi SSID
const char* WIFI_PASSWORD         = "YOUR_WIFI_PASSWORD";     // Replace with your Wi-Fi Password

// Backend Solar Monitoring System API Endpoint
// If running Flask backend locally on PC, use PC's LAN IP (e.g., http://192.168.1.100:5000/api/ingest)
const char* BACKEND_INGEST_URL    = "http://192.168.1.100:5000/api/ingest";

// Unique System & Device Identifiers (Matches Firestore 'systems' Collection)
const char* SYSTEM_ID             = "SYS-OWNER001";           // Solar installation identifier
const char* DEVICE_ID             = "ESP32-SOLAR-EDGE-01";    // Edge controller hardware ID
const char* SITE_ID               = "SITE-OWNER001";          // Optional Site ID (or empty if standalone)

// Solar PV Panel Physical Specifications (STC: 1000 W/m², 25°C)
const float PANEL_RATING_WATTS    = 300.0f;                   // Nominal panel capacity in Watts
const float NOMINAL_VOLTAGE       = 12.0f;                    // Nominal system voltage (12V / 24V)
const float STC_IRRADIANCE        = 1000.0f;                  // Standard Test Conditions Irradiance (W/m²)
const float STC_TEMPERATURE_C     = 25.0f;                    // Standard Test Conditions Cell Temp (°C)
const float TEMP_COEFF_PMAX       = -0.004f;                  // Temperature power coefficient (-0.4% / °C)
const float LUX_TO_IRRADIANCE     = 120.0f;                   // Prototype factor: ~120 Lux ≈ 1 W/m² solar
const float MIN_DAYTIME_POWER_W   = 10.0f;                    // Minimum expected power to evaluate PR (Watts)

// Edge Performance & Safety Fault Thresholds
const float PR_FAULT_THRESHOLD    = 0.70f;                    // Performance Ratio < 70% triggers underperformance
const float MAX_VOLTAGE_LIMIT     = 25.0f;                    // Over-voltage threshold (Volts)
const float MAX_CURRENT_LIMIT     = 15.0f;                    // Over-current threshold (Amps)
const float MAX_PANEL_TEMP_LIMIT  = 75.0f;                    // Over-temperature threshold (°C)
const float MAX_AMBIENT_TEMP      = 60.0f;                    // Ambient over-temperature threshold (°C)

// Telemetry & Timing Settings
const unsigned long TELEMETRY_INTERVAL_MS   = 300000UL;       // Default reporting interval: 5 min (300,000 ms)
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000UL;        // Wi-Fi connection attempt timeout (15 sec)
const unsigned long HTTP_TIMEOUT_MS         = 8000UL;         // HTTP request timeout (8 sec)
const unsigned long MAX_INTEGRATION_GAP_MS  = 900000UL;       // Max gap for energy integration: 15 min (900,000 ms)
const unsigned int  MAX_HTTP_RETRIES        = 2;              // Max retry attempts per cycle

// Offline Ring Buffer Settings (Bounded memory-safe telemetry queue)
const int OFFLINE_BUFFER_CAPACITY = 20;                       // Buffer up to 20 readings during outages (~1.5 hours)

// Prototype Hardware Simulation Mode
// Set to 'true' to run and test firmware without physical sensors connected.
bool SIMULATION_MODE = false;


// ==================================================================================================
//  3. SENSOR DRIVER INSTANCES & STATE OBJECTS
// ==================================================================================================
Adafruit_INA219 ina219;
OneWire oneWire(ONE_WIRE_BUS_PIN);
DallasTemperature ds18b20(&oneWire);
BH1750 bh1750;
DHT dht(DHT_PIN, DHT_TYPE);

// Sensor Hardware Health Status
struct SensorHealth {
  bool ina219_ok   = false;
  bool bh1750_ok   = false;
  bool ds18b20_ok  = false;
  bool dht11_ok    = false;
  bool rain_ok     = false;
  bool sw420_ok    = false;
  bool any_fault   = false;
} sensorHealth;

// Raw Validated Sensor Readings
struct RawSensorData {
  float voltage           = 0.0f;  // Volts (V)
  float current           = 0.0f;  // Amperes (A)
  float raw_power         = 0.0f;  // Watts (W)
  float lux               = 0.0f;  // Lux (lx)
  float temp_panel        = 25.0f; // Panel Temperature (°C)
  float temp_ambient      = 25.0f; // Ambient Temperature (°C)
  float humidity          = 50.0f; // Relative Humidity (%)
  float rain_level        = 0.0f;  // 0.0 (Dry) to 100.0 (Heavy Rain)
  bool  rain_detected     = false; // Digital rain state
  float vibration         = 0.0f;  // 0.0 (Still) to 1.0 (Vibration trigger)
  bool  data_valid        = true;  // Flag indicating validation passed
};

// Computed Edge Solar Analytics
struct SolarMetrics {
  float actual_power      = 0.0f;  // Actual generated power (Watts)
  float irradiance        = 0.0f;  // Calculated solar irradiance (W/m²)
  float base_expected_pwr = 0.0f;  // STC unadjusted expected power (Watts)
  float temp_derate_factor= 1.0f;  // Temperature correction factor
  float expected_power    = 0.0f;  // Temperature-compensated expected power (Watts)
  float performance_ratio = 0.0f;  // PR = Actual / Expected (0.00 - 1.50)
  float interval_energy_wh= 0.0f;  // Energy generated in current interval (Wh)
  float accumulated_kwh   = 0.0f;  // Edge-tracked cumulative energy (kWh)
  float lost_power_watts  = 0.0f;  // Instantaneous power loss (Watts)
  float lost_energy_kwh   = 0.0f;  // Estimated lost energy in interval (kWh)
};

// Edge Fault Assessment
struct FaultState {
  bool  fault_detected     = false; // Overall fault boolean
  char  primary_fault[32]  = "NONE";// Primary critical fault description
  char  perf_status[16]    = "NORMAL"; // NORMAL, DEGRADED, CRITICAL, NIGHT, SENSOR_FAULT
  bool  over_voltage       = false;
  bool  over_current       = false;
  bool  over_temperature   = false;
  bool  underperformance   = false;
  bool  rain_interfering   = false;
  bool  excess_vibration   = false;
  bool  sensor_error       = false;
};

// Offline Circular Telemetry Buffer Structure
struct TelemetryRecord {
  char  json_payload[512];
  bool  is_valid = false;
};

TelemetryRecord offlineBuffer[OFFLINE_BUFFER_CAPACITY];
int bufferHead = 0;
int bufferTail = 0;
int bufferCount = 0;

// Runtime Timing State Variables
unsigned long lastTelemetryMillis   = 0;
unsigned long lastValidSampleMillis = 0;
unsigned long totalUptimeCycles     = 0;


// ==================================================================================================
//  4. SENSOR INITIALIZATION & SAFE STARTUP
// ==================================================================================================
void initializePins() {
  pinMode(STATUS_LED_PIN, OUTPUT);
  digitalWrite(STATUS_LED_PIN, LOW);

  pinMode(RAIN_DIGITAL_PIN, INPUT_PULLUP);
  pinMode(RAIN_ANALOG_PIN, INPUT);
  pinMode(SW420_VIBRATION_PIN, INPUT);
}

void initializeSensors() {
  Serial.println(F("[Hardware] Initializing I2C Bus on GPIO 21 (SDA) / GPIO 22 (SCL)..."));
  Wire.begin(I2C_SDA_PIN, I2C_SCL_PIN);
  Wire.setClock(100000); // 100 kHz Standard I2C clock

  // 1. INA219 Current & Voltage Monitor
  Serial.print(F("[Hardware] Initializing INA219 Power Monitor... "));
  if (ina219.begin()) {
    // Configure calibration (32V, 2A or 32V, 1A range for solar precision)
    ina219.setCalibration_32V_2A();
    sensorHealth.ina219_ok = true;
    Serial.println(F("OK"));
  } else {
    sensorHealth.ina219_ok = false;
    sensorHealth.any_fault = true;
    Serial.println(F("FAILED (Check I2C wiring to INA219)"));
  }

  // 2. BH1750 Ambient Light (Lux) Sensor
  Serial.print(F("[Hardware] Initializing BH1750 Ambient Light Sensor... "));
  if (bh1750.begin(BH1750::CONTINUOUS_HIGH_RES_MODE)) {
    sensorHealth.bh1750_ok = true;
    Serial.println(F("OK"));
  } else {
    sensorHealth.bh1750_ok = false;
    sensorHealth.any_fault = true;
    Serial.println(F("FAILED (Check I2C wiring to BH1750)"));
  }

  // 3. DS18B20 Solar Panel Temperature Sensor (1-Wire)
  Serial.print(F("[Hardware] Initializing DS18B20 Panel Thermometer on GPIO 4... "));
  ds18b20.begin();
  if (ds18b20.getDeviceCount() > 0) {
    ds18b20.setResolution(11); // 11-bit resolution (0.125°C precision, 375ms conversion)
    ds18b20.setWaitForConversion(true);
    sensorHealth.ds18b20_ok = true;
    Serial.print(F("OK (Devices found: "));
    Serial.print(ds18b20.getDeviceCount());
    Serial.println(F(")"));
  } else {
    sensorHealth.ds18b20_ok = false;
    sensorHealth.any_fault = true;
    Serial.println(F("FAILED (Check 4.7kΩ pull-up on GPIO 4)"));
  }

  // 4. DHT11 Ambient Temperature & Humidity Sensor
  Serial.print(F("[Hardware] Initializing DHT11 Ambient Sensor on GPIO 18... "));
  dht.begin();
  sensorHealth.dht11_ok = true; // DHT verifies on first read
  Serial.println(F("OK"));

  // 5. Rain & Vibration Sensors (Digital GPIOs)
  sensorHealth.rain_ok  = true;
  sensorHealth.sw420_ok = true;

  if (sensorHealth.any_fault) {
    Serial.println(F("[WARNING] One or more sensors failed initialization. Operating in degraded telemetry mode."));
  } else {
    Serial.println(F("[SUCCESS] All solar telemetry sensors initialized successfully."));
  }
}


// ==================================================================================================
//  5. WI-FI CONNECTIVITY & RELIABILITY
// ==================================================================================================
bool connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  Serial.print(F("[Wi-Fi] Connecting to SSID: "));
  Serial.print(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  unsigned long startAttempt = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - startAttempt) < WIFI_CONNECT_TIMEOUT_MS) {
    delay(500);
    Serial.print(F("."));
    digitalWrite(STATUS_LED_PIN, !digitalRead(STATUS_LED_PIN)); // Flash LED during connect
  }

  if (WiFi.status() == WL_CONNECTED) {
    digitalWrite(STATUS_LED_PIN, HIGH); // Solid ON when connected
    Serial.println();
    Serial.print(F("[Wi-Fi] Connected! IP Address: "));
    Serial.println(WiFi.localIP());
    Serial.print(F("[Wi-Fi] Signal Strength (RSSI): "));
    Serial.print(WiFi.RSSI());
    Serial.println(F(" dBm"));

    // Sync NTP Time if not already set
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");
    return true;
  } else {
    digitalWrite(STATUS_LED_PIN, LOW); // OFF on failure
    Serial.println();
    Serial.println(F("[Wi-Fi] Connection timed out. Running in offline/buffered mode."));
    return false;
  }
}

void maintainWiFi() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(F("[Wi-Fi] Connection lost. Attempting background reconnect..."));
    connectWiFi();
  }
}


// ==================================================================================================
//  6. SENSOR DATA ACQUISITION & VALIDATION
// ==================================================================================================
float sanitizeFloat(float val, float fallback = 0.0f) {
  if (isnan(val) || isinf(val)) return fallback;
  return val;
}

void readPhysicalSensors(RawSensorData &raw) {
  raw.data_valid = true;

  // 1. INA219 Voltage, Current, Power
  if (sensorHealth.ina219_ok) {
    float bus_v   = ina219.getBusVoltage_V();
    float shunt_v = ina219.getShuntVoltage_mV() / 1000.0f;
    float current_ma = ina219.getCurrent_mA();

    raw.voltage   = max(0.0f, bus_v + shunt_v);
    raw.current   = max(0.0f, current_ma / 1000.0f); // Convert mA to Amperes
    raw.raw_power = raw.voltage * raw.current;       // Direct P = V * I

    // Validate physical electrical bounds
    if (isnan(raw.voltage) || raw.voltage > 36.0f || isnan(raw.current) || raw.current > 30.0f) {
      raw.data_valid = false;
      sensorHealth.ina219_ok = false;
    }
  } else {
    raw.voltage   = 0.0f;
    raw.current   = 0.0f;
    raw.raw_power = 0.0f;
  }

  // 2. BH1750 Ambient Light (Lux)
  if (sensorHealth.bh1750_ok) {
    float luxVal = bh1750.readLightLevel();
    if (luxVal >= 0.0f && !isnan(luxVal) && !isinf(luxVal)) {
      raw.lux = min(120000.0f, luxVal); // Bound to maximum daylight lux
    } else {
      raw.lux = 0.0f;
    }
  } else {
    raw.lux = 0.0f;
  }

  // 3. DS18B20 Solar Panel Temperature
  if (sensorHealth.ds18b20_ok) {
    ds18b20.requestTemperatures();
    float panelT = ds18b20.getTempCByIndex(0);
    // DS18B20 returns -127.0 on disconnect, and +85.0 on power-on reset error
    if (panelT > -40.0f && panelT < 125.0f && panelT != 85.0f) {
      raw.temp_panel = panelT;
    } else {
      raw.temp_panel = 25.0f; // Fallback to standard 25°C STC
    }
  } else {
    raw.temp_panel = 25.0f;
  }

  // 4. DHT11 Ambient Temperature & Humidity
  if (sensorHealth.dht11_ok) {
    float ambT = dht.readTemperature();
    float hum  = dht.readHumidity();

    raw.temp_ambient = (!isnan(ambT) && ambT >= -20.0f && ambT <= 70.0f) ? ambT : 25.0f;
    raw.humidity     = (!isnan(hum)  && hum  >= 0.0f   && hum  <= 100.0f) ? hum  : 50.0f;
  } else {
    raw.temp_ambient = 25.0f;
    raw.humidity     = 50.0f;
  }

  // 5. Rain Sensor
  int rainDigital = digitalRead(RAIN_DIGITAL_PIN);
  int rainAnalog  = analogRead(RAIN_ANALOG_PIN); // 0 (Wet) to 4095 (Dry) on ESP32 ADC
  raw.rain_detected = (rainDigital == LOW);
  raw.rain_level    = map(constrain(4095 - rainAnalog, 0, 4095), 0, 4095, 0, 100);

  // 6. SW-420 Vibration Sensor
  int vibSample = digitalRead(SW420_VIBRATION_PIN);
  raw.vibration = (vibSample == HIGH) ? 1.0f : 0.0f;
}


// ==================================================================================================
//  7. HARDWARE SIMULATION ENGINE (TESTING WITHOUT PHYSICAL SENSORS)
// ==================================================================================================
void simulateSensorReadings(RawSensorData &raw, unsigned long simTimeSec) {
  // Compute simulated decimal hour (e.g., 6.0 to 18.0 is daylight)
  float hourOfDay = fmod((float)(simTimeSec % 86400) / 3600.0f, 24.0f);
  if (hourOfDay < 0) hourOfDay += 24.0f;

  bool isDaylight = (hourOfDay >= 6.0f && hourOfDay <= 18.0f);
  float sunFactor = 0.0f;

  if (isDaylight) {
    // Sine wave peak at solar noon (12:00 PM)
    float dayProgress = (hourOfDay - 6.0f) / 12.0f;
    sunFactor = sin(dayProgress * 3.14159265f);
  }

  // Simulated Lux & Irradiance
  raw.lux = sunFactor * 100000.0f + (random(-500, 500) / 10.0f);
  raw.lux = max(0.0f, raw.lux);

  // Ambient & Panel Heating Temperature
  raw.temp_ambient = 22.0f + (sunFactor * 12.0f) + (random(-5, 5) / 10.0f);
  raw.temp_panel   = raw.temp_ambient + (sunFactor * 22.0f) + (random(-8, 8) / 10.0f);
  raw.humidity     = max(20.0f, min(90.0f, 75.0f - (sunFactor * 35.0f)));

  // Simulated Fault Injection at 13:00 - 14:00 (Simulates soiling / cell degradation)
  bool injectFault = (hourOfDay >= 13.0f && hourOfDay < 14.0f);
  float perfMultiplier = injectFault ? 0.60f : 0.95f;

  // Expected vs Actual Power Generation
  float simExpectedPower = (raw.lux / LUX_TO_IRRADIANCE) / STC_IRRADIANCE * PANEL_RATING_WATTS;
  raw.raw_power = simExpectedPower * perfMultiplier;

  // Derive Voltage & Current from Power
  raw.voltage = (isDaylight) ? (NOMINAL_VOLTAGE * 1.45f + (random(-10, 10) / 100.0f)) : 0.0f;
  raw.current = (raw.voltage > 1.0f) ? (raw.raw_power / raw.voltage) : 0.0f;

  raw.rain_detected = false;
  raw.rain_level    = 0.0f;
  raw.vibration     = 0.0f;
  raw.data_valid    = true;
}


// ==================================================================================================
//  8. LOCAL SOLAR CALCULATIONS & VARIABLE-INTERVAL ENERGY INTEGRATION
// ==================================================================================================
void calculateSolarMetrics(
  const RawSensorData &raw,
  SolarMetrics &metrics,
  unsigned long currentMillis
) {
  // A. Actual Power (Watts)
  metrics.actual_power = max(0.0f, raw.voltage * raw.current);

  // B. Approximate Irradiance from Lux (W/m²)
  metrics.irradiance = raw.lux / LUX_TO_IRRADIANCE;

  // C. Base Expected Power at STC (Watts)
  // P_base = (Irradiance / 1000 W/m²) * Rated_Capacity
  metrics.base_expected_pwr = (metrics.irradiance / STC_IRRADIANCE) * PANEL_RATING_WATTS;

  // D. Temperature Derating Compensation
  // Solar PV cell power decreases as panel temperature rises above 25°C.
  // Derate Factor = 1.0 + (gamma * (T_panel - 25.0°C))
  float deltaTemp = raw.temp_panel - STC_TEMPERATURE_C;
  metrics.temp_derate_factor = max(0.60f, min(1.20f, 1.0f + (TEMP_COEFF_PMAX * deltaTemp)));

  // Temperature-Adjusted Expected Power
  metrics.expected_power = max(0.0f, metrics.base_expected_pwr * metrics.temp_derate_factor);

  // E. Performance Ratio (PR) Calculation
  // PR = Actual Power / Expected Power
  // Evaluated only when solar irradiance is active (> 10W expected output)
  if (metrics.expected_power > MIN_DAYTIME_POWER_W) {
    float rawPR = metrics.actual_power / metrics.expected_power;
    metrics.performance_ratio = max(0.0f, min(1.50f, rawPR));
  } else {
    metrics.performance_ratio = 0.0f; // Nighttime / low-light: PR not applicable
  }

  // F. Variable-Interval Energy Integration (kWh)
  // Energy = Power * delta_time. Does not assume rigid 5-minute time steps.
  if (lastValidSampleMillis > 0 && currentMillis >= lastValidSampleMillis) {
    unsigned long deltaMillis = currentMillis - lastValidSampleMillis;

    // Check against max integration gap policy (e.g., 15 minutes)
    if (deltaMillis >= 1000UL && deltaMillis <= MAX_INTEGRATION_GAP_MS) {
      float deltaHours = (float)deltaMillis / 3600000.0f;
      metrics.interval_energy_wh = metrics.actual_power * deltaHours;
      metrics.accumulated_kwh   += (metrics.interval_energy_wh / 1000.0f);

      // G. Lost Energy Estimation (kWh)
      if (metrics.expected_power > MIN_DAYTIME_POWER_W) {
        metrics.lost_power_watts = max(0.0f, metrics.expected_power - metrics.actual_power);
        metrics.lost_energy_kwh  = (metrics.lost_power_watts * deltaHours) / 1000.0f;
      } else {
        metrics.lost_power_watts = 0.0f;
        metrics.lost_energy_kwh  = 0.0f;
      }
    } else {
      // Delta exceeds policy gap (e.g. reboot/outage): skip accumulation for this step
      metrics.interval_energy_wh = 0.0f;
      metrics.lost_energy_kwh    = 0.0f;
      Serial.println(F("[Analytics] Sample delta exceeds gap policy. Outage interval excluded from energy integration."));
    }
  } else {
    // First sample of execution
    metrics.interval_energy_wh = 0.0f;
    metrics.lost_energy_kwh    = 0.0f;
  }

  lastValidSampleMillis = currentMillis;
}


// ==================================================================================================
//  9. IMMEDIATE LOCAL FAULT DETECTION & CLASSIFICATION
// ==================================================================================================
void detectLocalFaults(
  const RawSensorData &raw,
  const SolarMetrics &metrics,
  FaultState &faults
) {
  // Reset fault flags
  faults.fault_detected   = false;
  faults.over_voltage     = false;
  faults.over_current     = false;
  faults.over_temperature = false;
  faults.underperformance = false;
  faults.rain_interfering = false;
  faults.excess_vibration = false;
  faults.sensor_error     = false;
  strcpy(faults.primary_fault, "NONE");
  strcpy(faults.perf_status, "NORMAL");

  // 1. Critical Electrical Safety Checks
  if (raw.voltage > MAX_VOLTAGE_LIMIT) {
    faults.fault_detected = true;
    faults.over_voltage   = true;
    strcpy(faults.primary_fault, "OVER_VOLTAGE");
    strcpy(faults.perf_status, "CRITICAL");
  }

  if (raw.current > MAX_CURRENT_LIMIT) {
    faults.fault_detected = true;
    faults.over_current   = true;
    strcpy(faults.primary_fault, "OVER_CURRENT");
    strcpy(faults.perf_status, "CRITICAL");
  }

  // 2. Thermal Safety Check
  if (raw.temp_panel > MAX_PANEL_TEMP_LIMIT) {
    faults.fault_detected    = true;
    faults.over_temperature  = true;
    if (strcmp(faults.primary_fault, "NONE") == 0) {
      strcpy(faults.primary_fault, "OVER_TEMPERATURE");
      strcpy(faults.perf_status, "CRITICAL");
    }
  }

  // 3. Sensor Communication Check
  if (sensorHealth.any_fault || !raw.data_valid) {
    faults.fault_detected = true;
    faults.sensor_error   = true;
    if (strcmp(faults.primary_fault, "NONE") == 0) {
      strcpy(faults.primary_fault, "SENSOR_FAULT");
      strcpy(faults.perf_status, "SENSOR_ERROR");
    }
  }

  // 4. Environmental Interference Checks
  if (raw.rain_detected || raw.rain_level > 20.0f) {
    faults.rain_interfering = true;
  }

  if (raw.vibration > 0.5f) {
    faults.excess_vibration = true;
  }

  // 5. Performance Drop Check (Segment 10 & 11 Threshold: PR < 0.70)
  if (metrics.expected_power > MIN_DAYTIME_POWER_W) {
    if (metrics.performance_ratio < PR_FAULT_THRESHOLD) {
      faults.fault_detected    = true;
      faults.underperformance  = true;
      if (strcmp(faults.primary_fault, "NONE") == 0) {
        strcpy(faults.primary_fault, "UNDERPERFORMANCE");
        strcpy(faults.perf_status, (metrics.performance_ratio < 0.50f) ? "CRITICAL" : "DEGRADED");
      }
    }
  } else {
    // Low sunlight / night period
    if (strcmp(faults.perf_status, "NORMAL") == 0) {
      strcpy(faults.perf_status, "NIGHT");
    }
  }
}


// ==================================================================================================
//  10. JSON TELEMETRY SERIALIZATION (COMPATIBLE WITH POST /api/ingest)
// ==================================================================================================
String serializeTelemetry(
  const RawSensorData &raw,
  const SolarMetrics &metrics,
  const FaultState &faults,
  unsigned long unixTimestamp
) {
  // Allocate static JSON document buffer (memory-safe on ESP32 heap)
  StaticJsonDocument<768> doc;

  // Primary System & Ingest Identifiers
  doc["system_id"]            = SYSTEM_ID;
  doc["device_id"]            = DEVICE_ID;
  if (strlen(SITE_ID) > 0) {
    doc["site_id"]            = SITE_ID;
  }
  doc["unix_timestamp"]       = unixTimestamp;

  // Electrical Telemetry (Required by /api/ingest)
  doc["voltage"]              = serialized(String(raw.voltage, 2));
  doc["current"]              = serialized(String(raw.current, 2));
  doc["power"]                = serialized(String(metrics.actual_power, 2));
  doc["expected_power"]       = serialized(String(metrics.expected_power, 2));
  doc["performance_ratio"]    = serialized(String(metrics.performance_ratio, 4));

  // Environmental Telemetry
  doc["irradiance"]           = serialized(String(metrics.irradiance, 2));
  doc["lux"]                  = serialized(String(raw.lux, 2));
  doc["temperature_panel"]    = serialized(String(raw.temp_panel, 1));
  doc["temperature_ambient"]  = serialized(String(raw.temp_ambient, 1));
  doc["humidity"]             = serialized(String(raw.humidity, 1));
  doc["rain"]                 = raw.rain_detected ? 1.0 : (raw.rain_level / 100.0);
  doc["vibration"]            = serialized(String(raw.vibration, 3));

  // Edge Analytics & Fault Telemetry
  doc["energy"]               = serialized(String(metrics.accumulated_kwh, 4));
  doc["lost_generation"]      = serialized(String(metrics.lost_energy_kwh, 4));
  doc["fault_detected"]       = faults.fault_detected;
  doc["fault_type"]           = faults.primary_fault;
  doc["performance_status"]   = faults.perf_status;
  doc["data_valid"]           = raw.data_valid;
  doc["sensor_fault"]         = sensorHealth.any_fault;
  doc["fault_injected"]       = false;

  String output;
  serializeJson(doc, output);
  return output;
}


// ==================================================================================================
//  11. OFFLINE TELEMETRY RING BUFFER
// ==================================================================================================
void bufferTelemetryRecord(const String &jsonStr) {
  if (jsonStr.length() >= sizeof(offlineBuffer[0].json_payload)) {
    Serial.println(F("[Buffer ERROR] Telemetry payload exceeds buffer slot capacity. Dropping."));
    return;
  }

  // Copy payload to head slot
  strncpy(offlineBuffer[bufferHead].json_payload, jsonStr.c_str(), sizeof(offlineBuffer[bufferHead].json_payload) - 1);
  offlineBuffer[bufferHead].json_payload[sizeof(offlineBuffer[bufferHead].json_payload) - 1] = '\0';
  offlineBuffer[bufferHead].is_valid = true;

  bufferHead = (bufferHead + 1) % OFFLINE_BUFFER_CAPACITY;

  if (bufferCount < OFFLINE_BUFFER_CAPACITY) {
    bufferCount++;
  } else {
    // Buffer full: advance tail, overwriting oldest record (circular buffer policy)
    bufferTail = (bufferTail + 1) % OFFLINE_BUFFER_CAPACITY;
    Serial.println(F("[Buffer WARNING] Offline buffer full. Overwriting oldest stored telemetry reading."));
  }

  Serial.print(F("[Buffer] Stored offline telemetry reading. Buffered count: "));
  Serial.print(bufferCount);
  Serial.print(F("/"));
  Serial.println(OFFLINE_BUFFER_CAPACITY);
}

void drainOfflineBuffer() {
  if (bufferCount == 0 || WiFi.status() != WL_CONNECTED) {
    return;
  }

  Serial.print(F("[Buffer] Draining "));
  Serial.print(bufferCount);
  Serial.println(F(" offline telemetry records to backend..."));

  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);

  while (bufferCount > 0 && WiFi.status() == WL_CONNECTED) {
    if (!offlineBuffer[bufferTail].is_valid) {
      bufferTail = (bufferTail + 1) % OFFLINE_BUFFER_CAPACITY;
      bufferCount--;
      continue;
    }

    http.begin(BACKEND_INGEST_URL);
    http.addHeader("Content-Type", "application/json");

    int httpCode = http.POST((uint8_t*)offlineBuffer[bufferTail].json_payload, strlen(offlineBuffer[bufferTail].json_payload));

    if (httpCode == 200 || httpCode == 201) {
      offlineBuffer[bufferTail].is_valid = false;
      bufferTail = (bufferTail + 1) % OFFLINE_BUFFER_CAPACITY;
      bufferCount--;
      Serial.print(F("[Buffer] Successfully uploaded buffered record. Remaining: "));
      Serial.println(bufferCount);
    } else {
      Serial.print(F("[Buffer ERROR] Failed to upload buffered record. HTTP Code: "));
      Serial.println(httpCode);
      http.end();
      break; // Abort drain cycle until next loop
    }
    http.end();
    delay(100); // Small inter-packet spacing
  }
}


// ==================================================================================================
//  12. HTTP TRANSMISSION TO BACKEND /api/ingest
// ==================================================================================================
bool sendTelemetry(const String &jsonPayload) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(F("[HTTP] Wi-Fi unavailable. Buffering telemetry record."));
    bufferTelemetryRecord(jsonPayload);
    return false;
  }

  // Drain any previously buffered records first to maintain chronological order
  drainOfflineBuffer();

  HTTPClient http;
  http.setTimeout(HTTP_TIMEOUT_MS);
  http.begin(BACKEND_INGEST_URL);
  http.addHeader("Content-Type", "application/json");

  Serial.print(F("[HTTP] POST "));
  Serial.println(BACKEND_INGEST_URL);

  int httpCode = http.POST(jsonPayload);

  if (httpCode == 200 || httpCode == 201) {
    String response = http.getString();
    Serial.print(F("[HTTP SUCCESS] Status "));
    Serial.print(httpCode);
    Serial.print(F(" | Response: "));
    Serial.println(response);
    http.end();
    return true;
  } else if (httpCode > 0) {
    Serial.print(F("[HTTP ERROR] Backend returned status code: "));
    Serial.println(httpCode);
    bufferTelemetryRecord(jsonPayload);
    http.end();
    return false;
  } else {
    Serial.print(F("[HTTP ERROR] Connection failed: "));
    Serial.println(http.errorToString(httpCode).c_str());
    bufferTelemetryRecord(jsonPayload);
    http.end();
    return false;
  }
}


// ==================================================================================================
//  13. SERIAL MONITOR DIAGNOSTIC LOGGING
// ==================================================================================================
void printDiagnosticDashboard(
  const RawSensorData &raw,
  const SolarMetrics &metrics,
  const FaultState &faults,
  unsigned long nowSec
) {
  Serial.println();
  Serial.println(F("================================================================================"));
  Serial.print(F(" SOLAR EDGE TELEMETRY REPORT | System: "));
  Serial.print(SYSTEM_ID);
  Serial.print(F(" | Device: "));
  Serial.print(DEVICE_ID);
  Serial.print(F(" | Time: "));
  Serial.println(nowSec);
  Serial.println(F("--------------------------------------------------------------------------------"));
  Serial.print(F(" Voltage      : ")); Serial.print(raw.voltage, 2); Serial.print(F(" V      | Panel Temp   : ")); Serial.print(raw.temp_panel, 1); Serial.println(F(" °C"));
  Serial.print(F(" Current      : ")); Serial.print(raw.current, 2); Serial.print(F(" A      | Ambient Temp : ")); Serial.print(raw.temp_ambient, 1); Serial.println(F(" °C"));
  Serial.print(F(" Actual Power : ")); Serial.print(metrics.actual_power, 2); Serial.print(F(" W    | Humidity     : ")); Serial.print(raw.humidity, 1); Serial.println(F(" %"));
  Serial.print(F(" Expected Pwr : ")); Serial.print(metrics.expected_power, 2); Serial.print(F(" W    | Irradiance   : ")); Serial.print(metrics.irradiance, 1); Serial.println(F(" W/m²"));
  Serial.print(F(" Perf Ratio   : ")); Serial.print(metrics.performance_ratio, 4); Serial.print(F("        | Lux          : ")); Serial.print(raw.lux, 1); Serial.println(F(" lx"));
  Serial.print(F(" Cumulative E : ")); Serial.print(metrics.accumulated_kwh, 4); Serial.print(F(" kWh   | Lost Energy  : ")); Serial.print(metrics.lost_energy_kwh, 4); Serial.println(F(" kWh"));
  Serial.print(F(" Rain State   : ")); Serial.print(raw.rain_detected ? F("RAIN DETECTED") : F("DRY"));
  Serial.print(F("         | Vibration    : ")); Serial.println(raw.vibration > 0.5f ? F("SHOCK DETECTED") : F("STABLE"));
  Serial.println(F("--------------------------------------------------------------------------------"));
  Serial.print(F(" Fault Status : ")); Serial.print(faults.fault_detected ? F("[!] FAULT DETECTED") : F("[OK] NORMAL"));
  Serial.print(F(" | Primary Fault : ")); Serial.println(faults.primary_fault);
  Serial.print(F(" Perf Status  : ")); Serial.println(faults.perf_status);
  Serial.println(F("================================================================================"));
}


// ==================================================================================================
//  14. ARDUINO SETUP ENTRYPOINT
// ==================================================================================================
void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println(F("================================================================================"));
  Serial.println(F("       ESP32 SMART SOLAR PV EDGE CONTROLLER FIRMWARE (SEGMENT 11)              "));
  Serial.println(F("================================================================================"));
  Serial.print(F(" System ID       : ")); Serial.println(SYSTEM_ID);
  Serial.print(F(" Device ID       : ")); Serial.println(DEVICE_ID);
  Serial.print(F(" Panel Rating    : ")); Serial.print(PANEL_RATING_WATTS); Serial.println(F(" Watts"));
  Serial.print(F(" Ingest URL      : ")); Serial.println(BACKEND_INGEST_URL);
  Serial.print(F(" Sample Interval : ")); Serial.print(TELEMETRY_INTERVAL_MS / 1000); Serial.println(F(" seconds"));
  Serial.print(F(" Simulation Mode : ")); Serial.println(SIMULATION_MODE ? F("ENABLED") : F("DISABLED (Physical Sensors Active)"));
  Serial.println(F("================================================================================"));

  initializePins();

  if (!SIMULATION_MODE) {
    initializeSensors();
  }

  // Attempt initial Wi-Fi connection
  connectWiFi();

  lastTelemetryMillis = millis() - TELEMETRY_INTERVAL_MS; // Force immediate first reading
}


// ==================================================================================================
//  15. ARDUINO MAIN MEASUREMENT LOOP
// ==================================================================================================
void loop() {
  unsigned long currentMillis = millis();

  // Keep Wi-Fi connection alive
  maintainWiFi();

  // Periodic Telemetry Transmission Cycle
  if (currentMillis - lastTelemetryMillis >= TELEMETRY_INTERVAL_MS) {
    lastTelemetryMillis = currentMillis;
    totalUptimeCycles++;

    // 1. Obtain UTC Timestamp (from NTP or fallback epoch counter)
    time_t nowSec;
    time(&nowSec);
    if (nowSec < 100000) {
      nowSec = 1787054400 + (totalUptimeCycles * (TELEMETRY_INTERVAL_MS / 1000)); // Reasonable fallback timestamp
    }

    // 2. Read Sensors (Physical or Simulated)
    RawSensorData raw;
    if (SIMULATION_MODE) {
      simulateSensorReadings(raw, (unsigned long)nowSec);
    } else {
      readPhysicalSensors(raw);
    }

    // 3. Compute Edge Solar Metrics
    SolarMetrics metrics;
    calculateSolarMetrics(raw, metrics, currentMillis);

    // 4. Detect Immediate Edge Faults
    FaultState faults;
    detectLocalFaults(raw, metrics, faults);

    // 5. Print Diagnostic Console Dashboard
    printDiagnosticDashboard(raw, metrics, faults, (unsigned long)nowSec);

    // 6. Build and Send JSON Telemetry Payload
    String jsonPayload = serializeTelemetry(raw, metrics, faults, (unsigned long)nowSec);
    sendTelemetry(jsonPayload);
  }

  // Yield execution to allow ESP32 background tasks (Wi-Fi stack, FreeRTOS scheduler)
  delay(50);
}
