"""
Machine Learning Solar Power Prediction & Solar Health Score Engine -- Segment 13.

IMPORTANT DESIGN SEPARATION:
    expected_power  = physical/engineering model based on authoritative solar irradiance (W/m2),
                      system capacity (kW/W), and temperature derating factor.
                      Computed deterministically and preserved in Firestore by /api/ingest.
    predicted_power = ML statistical regression prediction output by this module only.
    actual_power    = Real measured electrical power (V x I or direct power telemetry).
    These three concepts are fundamentally distinct and must NEVER be merged or overwritten.

Authoritative Solar Measurement (Irradiance vs Lux):
    - Canonical solar radiation metric is IRRADIANCE (W/m2).
    - Lux (visible-light illumination) is an auxiliary environmental measurement.
    - Real datasets with irradiance are ingested directly without fabricating fake Lux.
    - Legacy devices supplying only Lux use an explicit approximation fallback (irradiance = lux / 120.0).

Capacity Awareness (Option A: Capacity-Normalized Specific Power):
    - In solar engineering, power is normalized by capacity (normalized_power = power_watts / capacity_kw).
    - The ML model learns the environmental transfer function (irradiance + temp + time + humidity -> W/kW).
    - Predicted power scales accurately for any system (0.3 kW, 1 kW, 5 kW, 100 kW):
      predicted_power = predicted_normalized_power * system_capacity_kw

Architecture:
    1. Feature Extraction & Cleaning (prepare_features_from_readings)
       - Features: irradiance (W/m2), panel_temp (degC), hour_of_day (UTC),
         day_of_week (0=Mon), humidity (%)
       - Target: normalized_power (Watts per kW capacity)
       - Timezone: all timestamps parsed as UTC
       - Deduplication: enabled to prevent bias from repeated seeds

    2. Model Training (train_model)
       - Algorithm: sklearn LinearRegression
       - Split: 80/20 Chronological split (first 80% train, last 20% test) to prevent temporal leakage
       - Atomic write: model.pkl.tmp -> os.replace() -> model.pkl
       - Synthetic fallback when Firestore readings < 100 (explicitly flagged in metadata)

    3. Power Prediction (predict_power)
       - Strict input validation and physical bounds enforcement
       - Real irradiance preferred (supports lux approximation fallback if irradiance omitted)
       - Capacity-aware prediction (scales by system_capacity_kw, default 1.0 kW)
       - Returns non-negative predicted_power (clamped at 0.0 W)

    4. Solar Health Score (calculate_health_score)
       - Per-system isolation via system_id Firestore filter
       - Analyzes up to the latest 100 valid daytime readings (expected_power > 10 W)
       - Standardized formula:
           raw_health = 100.0 - (avg_loss_percent * 1.0) - (anomaly_ratio * 20.0) - (pr_variance * 200.0)
           health_score = clamp(raw_health, 0.0, 100.0)
       - Status from continuous float (NEVER rounded):
           >= 90.0       -> "Excellent" (measured healthy performance)
           >= 75.0       -> "Good"      (measured acceptable performance)
           >= 50.0       -> "Warning"   (measured degraded performance)
           < 50.0        -> "Critical"  (measured severely degraded performance)
           No Data / Insufficient Telemetry -> "N/A" (health_score = null)

    5. Flask Blueprint (ml_bp)
       - POST /api/ml/train            -- Admin only
       - GET  /api/ml/predict          -- Authenticated (any role)
       - GET  /api/systems/<id>/health -- Owner/assigned Technician/Admin
"""

import os
import sys
import math
import random
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Union, Optional

import numpy as np
import pandas as pd
import joblib
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score

from flask import Blueprint, request, jsonify, g
from google.cloud.firestore import FieldFilter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db
from BACKEND.auth import require_auth, require_role
from BACKEND.systems import can_read_system, COLLECTION_SYSTEMS

logger = logging.getLogger(__name__)

ml_bp = Blueprint("ml", __name__)

# ---------------------------------------------------------------------------
# Module-Level Constants
# ---------------------------------------------------------------------------
FEATURE_NAMES: List[str] = [
    "irradiance",
    "panel_temp",
    "hour_of_day",
    "day_of_week",
    "humidity",
]
TARGET_NAME: str = "normalized_power"
MODEL_FILENAME: str = "model.pkl"
MODEL_VERSION: int = 3          # v3: Irradiance-first, capacity-normalized, chronological split
PR_THRESHOLD: float = 0.70
MIN_TRAINING_SAMPLES: int = 100
MIN_DAYTIME_EXPECTED_POWER: float = 10.0
COLLECTION_READINGS: str = "readings"

# Health score prototype calibration coefficients:
_HS_LOSS_COEFF: float = 1.0
_HS_ANOMALY_COEFF: float = 20.0
_HS_VARIANCE_COEFF: float = 200.0


def get_model_path() -> str:
    """Returns absolute path to model.pkl inside BACKEND/ directory."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), MODEL_FILENAME)


def _get_tmp_model_path() -> str:
    """Returns path to temporary write target for atomic model replacement."""
    return get_model_path() + ".tmp"


# ---------------------------------------------------------------------------
# Physical Solar Model (Deterministic Expected Power Calculation)
# ---------------------------------------------------------------------------
def calculate_expected_power(
    irradiance: float,
    system_capacity_kw: float = 1.0,
    panel_temp: float = 25.0,
    temp_coefficient: float = 0.004,
) -> float:
    """
    Deterministic physical solar PV expected power calculation.

    Formula:
        P_expected (Watts) = (G / 1000.0) * (P_rated_kw * 1000.0) * temp_derating
        temp_derating = max(0.0, 1.0 - temp_coefficient * (panel_temp - 25.0))

    Parameters:
        irradiance (float): Solar irradiance G in W/m2 [0, 2000].
        system_capacity_kw (float): System nameplate DC rating in kW (> 0).
        panel_temp (float): Panel surface temperature in degC.
        temp_coefficient (float): Power temperature coefficient (-0.4%/degC = 0.004).

    Returns:
        float: Expected generation in Watts, guaranteed non-negative.
    """
    if irradiance <= 0.0 or system_capacity_kw <= 0.0:
        return 0.0

    rated_watts = system_capacity_kw * 1000.0
    irradiance_factor = irradiance / 1000.0
    temp_derating = max(0.0, 1.0 - temp_coefficient * (panel_temp - 25.0))

    expected_w = irradiance_factor * rated_watts * temp_derating
    return max(0.0, round(float(expected_w), 2))


# ---------------------------------------------------------------------------
# Feature Extraction & Data Cleaning
# ---------------------------------------------------------------------------
def prepare_features_from_readings(
    readings_data: Union[List[Dict[str, Any]], pd.DataFrame]
) -> pd.DataFrame:
    """
    Validates and extracts ML features + capacity-normalized target from raw Firestore telemetry or real CSV data.

    Supported field aliases:
        irradiance         <- 'irradiance' (preferred, W/m2)
                           <- 'irradiance_w_m2' / 'poa_irradiance' (real dataset columns)
                           <- derived from 'lux' / 120.0 (approximation fallback for legacy devices)
        panel_temp         <- 'panel_temp' (preferred)
                           <- 'temperature_panel' / 'temp_panel' / 'module_temperature'
        humidity           <- 'humidity' / 'relative_humidity'
        system_capacity_kw <- 'system_capacity_kw'
                           <- derived from 'panel_capacity_watts' / 1000.0
                           <- default: 1.0 kW if capacity is omitted
        hour_of_day        <- 'hour_of_day' or derived from 'unix_timestamp' / 'timestamp' (UTC)
        day_of_week        <- 'day_of_week' or derived from same timestamp sources (0=Mon, 6=Sun)

    Physical bounds:
        irradiance [0, 2000] W/m2, panel_temp [-40, 125] degC, humidity [0, 100] %,
        hour_of_day [0, 23], day_of_week [0, 6], power [0, inf)
    """
    if isinstance(readings_data, pd.DataFrame):
        df = readings_data.copy()
    elif isinstance(readings_data, list):
        if not readings_data:
            return pd.DataFrame(columns=FEATURE_NAMES + [TARGET_NAME])
        df = pd.DataFrame(readings_data)
    else:
        return pd.DataFrame(columns=FEATURE_NAMES + [TARGET_NAME])

    if df.empty:
        return pd.DataFrame(columns=FEATURE_NAMES + [TARGET_NAME])

    # 1. Alias: irradiance (W/m2)
    if "irradiance" not in df.columns:
        if "irradiance_w_m2" in df.columns:
            df["irradiance"] = df["irradiance_w_m2"]
        elif "poa_irradiance" in df.columns:
            df["irradiance"] = df["poa_irradiance"]
        elif "lux" in df.columns:
            df["irradiance"] = pd.to_numeric(df["lux"], errors="coerce") / 120.0

    # 2. Alias: temperature_panel -> panel_temp
    if "panel_temp" not in df.columns:
        if "temperature_panel" in df.columns:
            df["panel_temp"] = df["temperature_panel"]
        elif "temp_panel" in df.columns:
            df["panel_temp"] = df["temp_panel"]
        elif "module_temperature" in df.columns:
            df["panel_temp"] = df["module_temperature"]

    # 3. Alias: humidity
    if "humidity" not in df.columns and "relative_humidity" in df.columns:
        df["humidity"] = df["relative_humidity"]

    # 4. Capacity handling for target normalization
    if "system_capacity_kw" not in df.columns:
        if "panel_capacity_watts" in df.columns:
            df["system_capacity_kw"] = pd.to_numeric(df["panel_capacity_watts"], errors="coerce") / 1000.0
        elif "capacity_kw" in df.columns:
            df["system_capacity_kw"] = df["capacity_kw"]
        else:
            df["system_capacity_kw"] = 1.0

    # 5. Alias: power target
    if "power" not in df.columns:
        if "power_w" in df.columns:
            df["power"] = df["power_w"]
        elif "actual_power" in df.columns:
            df["power"] = df["actual_power"]

    # 6. Derive hour_of_day and day_of_week from timestamps (UTC)
    if "hour_of_day" not in df.columns or "day_of_week" not in df.columns:
        dts = None
        if "unix_timestamp" in df.columns and df["unix_timestamp"].notna().any():
            dts = pd.to_datetime(df["unix_timestamp"], unit="s", utc=True, errors="coerce")
        elif "timestamp" in df.columns and df["timestamp"].notna().any():
            dts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        if dts is not None:
            if "hour_of_day" not in df.columns:
                df["hour_of_day"] = dts.dt.hour
            if "day_of_week" not in df.columns:
                df["day_of_week"] = dts.dt.dayofweek

    # 7. Check required features and target exist
    for col in FEATURE_NAMES:
        if col not in df.columns:
            return pd.DataFrame(columns=FEATURE_NAMES + [TARGET_NAME])

    if "power" not in df.columns and TARGET_NAME not in df.columns:
        return pd.DataFrame(columns=FEATURE_NAMES + [TARGET_NAME])

    # 8. Numeric coercion
    clean_df = pd.DataFrame()
    try:
        clean_df["irradiance"]         = pd.to_numeric(df["irradiance"],         errors="coerce")
        clean_df["panel_temp"]         = pd.to_numeric(df["panel_temp"],         errors="coerce")
        clean_df["hour_of_day"]        = pd.to_numeric(df["hour_of_day"],        errors="coerce")
        clean_df["day_of_week"]        = pd.to_numeric(df["day_of_week"],        errors="coerce")
        clean_df["humidity"]           = pd.to_numeric(df["humidity"],           errors="coerce")
        capacity_series                = pd.to_numeric(df["system_capacity_kw"], errors="coerce").fillna(1.0)
        capacity_safe                  = capacity_series.apply(lambda c: c if (c is not None and c > 0) else 1.0)
        clean_df["system_capacity_kw"] = capacity_safe

        if "power" in df.columns:
            raw_power = pd.to_numeric(df["power"], errors="coerce")
            clean_df["power"] = raw_power
            clean_df[TARGET_NAME] = raw_power / capacity_safe
        elif TARGET_NAME in df.columns:
            clean_df[TARGET_NAME] = pd.to_numeric(df[TARGET_NAME], errors="coerce")
            clean_df["power"] = clean_df[TARGET_NAME] * capacity_safe
    except Exception as exc:
        logger.warning(f"prepare_features_from_readings: numeric coercion error: {exc}")
        return pd.DataFrame(columns=FEATURE_NAMES + [TARGET_NAME])

    # 9. Drop NaN and +-Inf
    clean_df = clean_df.dropna()
    clean_df = clean_df.replace([np.inf, -np.inf], np.nan).dropna()

    # 10. Physical boundary filtering
    valid_mask = (
        (clean_df["irradiance"]         >= 0.0)   & (clean_df["irradiance"]         <= 2000.0) &
        (clean_df["panel_temp"]         >= -40.0) & (clean_df["panel_temp"]         <= 125.0)  &
        (clean_df["humidity"]           >= 0.0)   & (clean_df["humidity"]           <= 100.0)  &
        (clean_df["hour_of_day"]        >= 0)     & (clean_df["hour_of_day"]        <= 23)     &
        (clean_df["day_of_week"]        >= 0)     & (clean_df["day_of_week"]        <= 6)      &
        (clean_df[TARGET_NAME]          >= 0.0)
    )
    clean_df = clean_df[valid_mask].reset_index(drop=True)

    # 11. Type enforcement
    clean_df["hour_of_day"] = clean_df["hour_of_day"].astype(int)
    clean_df["day_of_week"] = clean_df["day_of_week"].astype(int)

    # 12. Deduplicate
    subset_cols = [c for c in FEATURE_NAMES + [TARGET_NAME] if c in clean_df.columns]
    clean_df = clean_df.drop_duplicates(
        subset=subset_cols
    ).reset_index(drop=True)

    return clean_df


# ---------------------------------------------------------------------------
# Synthetic Training Data Fallback Generator
# ---------------------------------------------------------------------------
def generate_synthetic_training_data(n_samples: int = 300) -> pd.DataFrame:
    """
    Generates physically realistic synthetic solar telemetry with capacity-normalized specific power.
    """
    rng_py = random.Random(42)
    rng_np = np.random.default_rng(42)

    capacities = [0.3, 1.0, 3.0, 5.0]  # kW
    data: List[Dict[str, Any]] = []

    for _ in range(n_samples):
        hour        = rng_py.uniform(0.0, 24.0)
        hour_int    = int(hour) % 24
        day_of_week = rng_py.randint(0, 6)
        capacity_kw = rng_py.choice(capacities)
        is_daylight = (6.0 <= hour <= 18.0)

        if is_daylight:
            day_progress    = (hour - 6.0) / 12.0
            base_irradiance = 1000.0 * math.sin(day_progress * math.pi)
            noise           = rng_py.uniform(-0.04, 0.04) * base_irradiance
            irradiance      = max(0.0, base_irradiance + noise)

            t_arg        = max(0.0, (hour - 5.0) / 14.0)
            t_day_factor = math.sin(t_arg * math.pi) if 5.0 <= hour <= 19.0 else 0.0
            ambient_temp = 20.0 + 12.0 * t_day_factor + float(rng_np.uniform(-0.5, 0.5))
            panel_temp   = ambient_temp + (irradiance / 1000.0) * 22.0 + float(rng_np.uniform(-0.8, 0.8))
            humidity     = float(np.clip(80.0 - (irradiance / 1000.0) * 35.0 + rng_np.uniform(-2.0, 2.0), 20.0, 95.0))

            expected_pwr     = calculate_expected_power(irradiance, capacity_kw, panel_temp)
            power            = max(0.0, expected_pwr * rng_py.uniform(0.93, 0.98))
            normalized_power = power / capacity_kw
        else:
            irradiance       = 0.0
            ambient_temp     = 18.0 + float(rng_np.uniform(-1.0, 1.0))
            panel_temp       = ambient_temp
            humidity         = float(np.clip(85.0 + rng_np.uniform(-2.0, 2.0), 20.0, 95.0))
            power            = 0.0
            normalized_power = 0.0

        data.append({
            "irradiance":         round(irradiance, 2),
            "panel_temp":         round(panel_temp, 2),
            "hour_of_day":        hour_int,
            "day_of_week":        day_of_week,
            "humidity":           round(humidity, 2),
            "system_capacity_kw": capacity_kw,
            "power":              round(power, 2),
            "normalized_power":   round(normalized_power, 2),
        })

    return pd.DataFrame(data)


# ---------------------------------------------------------------------------
# Model Training & Atomic Persistence
# ---------------------------------------------------------------------------
def train_model(db=None) -> Dict[str, Any]:
    """
    Fetch telemetry, clean data, train capacity-normalized LinearRegression model, evaluate metrics,
    and ATOMICALLY persist the bundle to model.pkl.
    """
    if db is None:
        db = get_db()

    synthetic_data_used = False
    training_source     = "firestore"
    raw_readings: List[Dict[str, Any]] = []

    # 1. Fetch up to 1000 recent readings from Firestore
    if db is not None:
        try:
            docs = list(
                db.collection(COLLECTION_READINGS)
                .order_by("unix_timestamp", direction="ASCENDING")
                .limit(1000)
                .stream()
            )
            raw_readings = [d.to_dict() for d in docs if d.to_dict()]
        except Exception as exc:
            logger.warning(f"train_model: Firestore query failed ({exc}). Using synthetic fallback.")

    # 2. Clean and validate
    df = prepare_features_from_readings(raw_readings)

    # 3. Synthetic fallback
    if len(df) < MIN_TRAINING_SAMPLES:
        logger.info(
            f"train_model: {len(df)} valid readings < {MIN_TRAINING_SAMPLES}. "
            "Using synthetic fallback. Metrics describe fit to synthetic curves only."
        )
        df = generate_synthetic_training_data(n_samples=300)
        synthetic_data_used = True
        training_source     = "synthetic_fallback"

    # 4. Prepare X and y
    X = df[FEATURE_NAMES]
    y = df[TARGET_NAME]

    # 5. Chronological 80/20 split (preserves time order, prevents temporal leakage)
    split_idx = max(1, int(len(df) * 0.8))
    X_train, X_test = X.iloc[:split_idx], X.iloc[split_idx:]
    y_train, y_test = y.iloc[:split_idx], y.iloc[split_idx:]

    if len(X_test) == 0:
        X_test, y_test = X_train, y_train

    # 6. Fit
    model = LinearRegression()
    model.fit(X_train, y_train)

    # 7. Evaluate
    y_pred = model.predict(X_test)
    mae  = float(mean_absolute_error(y_test, y_pred))
    rmse = float(np.sqrt(float(mean_squared_error(y_test, y_pred))))
    r2   = float(r2_score(y_test, y_pred))

    # 8. Metadata
    metadata: Dict[str, Any] = {
        "model_type":            "LinearRegression",
        "model_version":         MODEL_VERSION,
        "feature_names":         list(FEATURE_NAMES),
        "target_name":           TARGET_NAME,
        "target_unit":           "Watts/kW",
        "trained_at":            datetime.now(timezone.utc).isoformat(),
        "training_sample_count": int(len(df)),
        "train_set_size":        int(len(X_train)),
        "test_set_size":         int(len(X_test)),
        "synthetic_data_used":   synthetic_data_used,
        "training_source":       training_source,
        "split_strategy":        "chronological_80_20",
        "split_note":            "Chronological split (first 80% train, last 20% test) to prevent temporal leakage.",
        "mae":      round(mae, 4),
        "rmse":     round(rmse, 4),
        "r2_score": round(r2, 4),
    }

    bundle = {"model": model, "metadata": metadata}

    # 9. Atomic write: tmp -> rename (preserves existing model on failure)
    model_path = get_model_path()
    tmp_path   = _get_tmp_model_path()
    try:
        joblib.dump(bundle, tmp_path)
        os.replace(tmp_path, model_path)
        logger.info(
            f"train_model: Saved {model_path} | R2={r2:.4f} MAE={mae:.4f} "
            f"source={training_source} samples={len(df)}"
        )
    except Exception as exc:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        logger.error(f"train_model: Persistence failed: {exc}")
        raise RuntimeError("Model persistence failed. Existing model was NOT modified.") from exc

    return {
        "status":     "success",
        "message":    "ML LinearRegression model trained and saved successfully.",
        "model_file": MODEL_FILENAME,
        "metadata":   metadata,
    }


# ---------------------------------------------------------------------------
# Power Prediction Inference
# ---------------------------------------------------------------------------
def predict_power(features_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Predict solar power generation (Watts) using the saved LinearRegression model.
    Scales predicted specific generation (W/kW) by system_capacity_kw (default 1.0 kW).
    """
    if not isinstance(features_dict, dict):
        raise ValueError("Input features must be a dictionary.")

    # 1. Handle Irradiance vs Lux
    irradiance = None
    if "irradiance" in features_dict and features_dict["irradiance"] is not None:
        try:
            irradiance = float(features_dict["irradiance"])
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid 'irradiance' value: {exc}")
    elif "irradiance_w_m2" in features_dict and features_dict["irradiance_w_m2"] is not None:
        try:
            irradiance = float(features_dict["irradiance_w_m2"])
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid 'irradiance_w_m2' value: {exc}")
    elif "lux" in features_dict and features_dict["lux"] is not None:
        try:
            lux_val = float(features_dict["lux"])
            if not (0.0 <= lux_val <= 150_000.0):
                raise ValueError(f"'lux' {lux_val} out of range [0, 150000].")
            irradiance = lux_val / 120.0
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid 'lux' value: {exc}")
    else:
        raise ValueError("Missing required feature field: 'irradiance' (or 'lux' approximation fallback).")

    # 2. Check remaining required fields
    required_keys = ["panel_temp", "hour_of_day", "day_of_week", "humidity"]
    missing = [f for f in required_keys if f not in features_dict or features_dict[f] is None]
    if missing:
        raise ValueError(f"Missing required feature fields: {missing}")

    # 3. Numeric conversion
    try:
        panel_temp  = float(features_dict["panel_temp"])
        humidity    = float(features_dict["humidity"])
        hour_of_day = int(float(features_dict["hour_of_day"]))
        day_of_week = int(float(features_dict["day_of_week"]))
        capacity_kw = float(features_dict.get("system_capacity_kw", 1.0))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"All feature values must be numeric: {exc}")

    # 4. Physical bounds
    if not (0.0 <= irradiance <= 2000.0):
        raise ValueError(f"'irradiance' {irradiance} out of range [0, 2000] W/m2.")
    if not (-40.0 <= panel_temp <= 125.0):
        raise ValueError(f"'panel_temp' {panel_temp} out of range [-40, 125] degC.")
    if not (0.0 <= humidity <= 100.0):
        raise ValueError(f"'humidity' {humidity} out of range [0, 100] %.")
    if not (0 <= hour_of_day <= 23):
        raise ValueError(f"'hour_of_day' {hour_of_day} must be in [0, 23].")
    if not (0 <= day_of_week <= 6):
        raise ValueError(f"'day_of_week' {day_of_week} must be in [0, 6].")
    if not (0.0 < capacity_kw <= 10000.0):
        raise ValueError(f"'system_capacity_kw' {capacity_kw} must be positive and <= 10000 kW.")

    # 5. Load model
    model_path = get_model_path()
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"'{MODEL_FILENAME}' not found. Train the model via POST /api/ml/train."
        )

    try:
        bundle = joblib.load(model_path)
    except Exception as exc:
        logger.error(f"predict_power: Failed to load {model_path}: {exc}")
        raise ValueError(f"Model file '{MODEL_FILENAME}' is corrupted or incompatible: {exc}")

    if not isinstance(bundle, dict) or "model" not in bundle:
        raise ValueError(
            f"Model file '{MODEL_FILENAME}' has invalid bundle structure. Retrain the model."
        )
    model    = bundle["model"]
    metadata = bundle.get("metadata", {})

    # Feature mismatch guard
    stored_features = metadata.get("feature_names", [])
    if stored_features and stored_features != list(FEATURE_NAMES):
        raise ValueError(
            f"Model feature mismatch: stored={stored_features}, expected={list(FEATURE_NAMES)}. "
            "Retrain via POST /api/ml/train."
        )

    # 6. Build input vector in strict FEATURE_NAMES order
    input_vector = pd.DataFrame([{
        "irradiance":  irradiance,
        "panel_temp":  panel_temp,
        "hour_of_day": hour_of_day,
        "day_of_week": day_of_week,
        "humidity":    humidity,
    }])[FEATURE_NAMES]

    raw_norm_power = float(model.predict(input_vector)[0])
    norm_power     = max(0.0, raw_norm_power)
    predicted_pw   = max(0.0, norm_power * capacity_kw)

    return {
        "status":                     "success",
        "predicted_power":            round(predicted_pw, 2),
        "predicted_normalized_power": round(norm_power, 2),
        "system_capacity_kw":         capacity_kw,
        "model_type":                 metadata.get("model_type", "LinearRegression"),
        "model_version":              metadata.get("model_version", MODEL_VERSION),
        "trained_at":                 metadata.get("trained_at"),
        "training_sample_count":      metadata.get("training_sample_count"),
        "training_samples":           metadata.get("training_sample_count"),
        "synthetic_data_used":        metadata.get("synthetic_data_used", False),
        "training_source":            metadata.get("training_source", "unknown"),
        "split_strategy":             metadata.get("split_strategy", "chronological_80_20"),
        "r2_score":                   metadata.get("r2_score"),
        "mae":                        metadata.get("mae"),
        "features": {
            "irradiance":         irradiance,
            "panel_temp":         panel_temp,
            "humidity":           humidity,
            "hour_of_day":        hour_of_day,
            "day_of_week":        day_of_week,
            "system_capacity_kw": capacity_kw,
        },
    }


# ---------------------------------------------------------------------------
# Solar Health Score Calculation Engine
# ---------------------------------------------------------------------------
def _calculate_raw_health_score(
    avg_loss_percent: float, anomaly_ratio: float, pr_variance: float
) -> float:
    """
    Standardized prototype formula:
        raw_health = 100.0 - (avg_loss_percent * 1.0) - (anomaly_ratio * 20.0) - (pr_variance * 200.0)
    """
    return (
        100.0
        - (avg_loss_percent * _HS_LOSS_COEFF)
        - (anomaly_ratio * _HS_ANOMALY_COEFF)
        - (pr_variance * _HS_VARIANCE_COEFF)
    )


def _health_status_from_score(score: Optional[float]) -> str:
    """
    Map continuous float score to status string.
    """
    if score is None:
        return "N/A"
    if score >= 90.0:
        return "Excellent"
    if score >= 75.0:
        return "Good"
    if score >= 50.0:
        return "Warning"
    return "Critical"


def _health_no_data_response(
    system_id: str, message: str = "Insufficient telemetry to calculate health", readings_analyzed: int = 0
) -> Dict[str, Any]:
    """
    Explicit N/A response when no usable daytime readings are available.
    """
    return {
        "system_id":                 system_id,
        "health_score":              None,
        "status":                    "N/A",
        "message":                   message,
        "average_pr":                None,
        "pr_variance":               None,
        "anomaly_count":             0,
        "anomaly_ratio":             None,
        "avg_loss_percent":          None,
        "readings_analyzed":         readings_analyzed,
        "daytime_readings_analyzed": 0,
    }


def calculate_health_score(system_id: str, db=None) -> Dict[str, Any]:
    """
    Calculate Solar Health Score (0-100) for a specific system.
    """
    if not system_id or not isinstance(system_id, str):
        raise ValueError("'system_id' must be a non-empty string.")

    if db is None:
        db = get_db()

    if db is None:
        return _health_no_data_response(system_id, message="Database connection unavailable")

    # Query up to latest 100 readings for this system_id
    docs = []
    try:
        query = (
            db.collection(COLLECTION_READINGS)
            .where(filter=FieldFilter("system_id", "==", system_id))
            .order_by("unix_timestamp", direction="DESCENDING")
            .limit(100)
        )
        docs = list(query.stream())
    except Exception:
        try:
            query = (
                db.collection(COLLECTION_READINGS)
                .where(filter=FieldFilter("system_id", "==", system_id))
                .limit(100)
            )
            docs = list(query.stream())
            docs.sort(key=lambda d: d.to_dict().get("unix_timestamp", 0), reverse=True)
        except Exception as exc:
            logger.warning(f"calculate_health_score: query error for {system_id}: {exc}")
            docs = []

    if not docs:
        return _health_no_data_response(
            system_id, message="No historical readings found for this system", readings_analyzed=0
        )

    valid_prs:        List[float] = []
    loss_percentages: List[float] = []
    anomaly_count: int = 0
    total_readings = len(docs)

    for doc in docs:
        data = doc.to_dict() or {}
        try:
            exp_pwr = float(data.get("expected_power") or 0.0)
            act_pwr = float(data.get("power") or 0.0)
            pr_val  = float(data.get("performance_ratio") or 0.0)
        except (ValueError, TypeError):
            continue

        if exp_pwr <= MIN_DAYTIME_EXPECTED_POWER:
            continue  # nighttime / idle / unmeasurable

        valid_prs.append(pr_val)
        if pr_val < PR_THRESHOLD:
            anomaly_count += 1

        loss_pct = max(0.0, (exp_pwr - act_pwr) / exp_pwr) * 100.0
        loss_percentages.append(loss_pct)

    if not valid_prs:
        return _health_no_data_response(
            system_id,
            message="No daytime generation readings available for analysis",
            readings_analyzed=total_readings,
        )

    avg_pr        = float(np.mean(valid_prs))
    pr_var        = float(np.var(valid_prs)) if len(valid_prs) > 1 else 0.0
    avg_loss_pct  = float(np.mean(loss_percentages)) if loss_percentages else 0.0
    anomaly_ratio = anomaly_count / len(valid_prs)

    raw_health   = _calculate_raw_health_score(avg_loss_pct, anomaly_ratio, pr_var)
    health_score = max(0.0, min(100.0, raw_health))

    return {
        "system_id":                 system_id,
        "health_score":              round(health_score, 1),
        "status":                    _health_status_from_score(health_score),
        "average_pr":                round(avg_pr, 4),
        "pr_variance":               round(pr_var, 6),
        "anomaly_count":             anomaly_count,
        "anomaly_ratio":             round(anomaly_ratio, 4),
        "avg_loss_percent":          round(avg_loss_pct, 2),
        "readings_analyzed":         total_readings,
        "daytime_readings_analyzed": len(valid_prs),
    }


# ===========================================================================
# FLASK REST API ENDPOINTS
# ===========================================================================

@ml_bp.route("/api/ml/train", methods=["POST"])
@require_auth
@require_role("admin")
def api_train_model():
    """Admin-only: train/retrain the ML model. Full exceptions logged server-side only."""
    try:
        db = get_db()
        result = train_model(db=db)
        return jsonify(result), 200
    except Exception:
        logger.exception("api_train_model: Training failed.")
        return jsonify({
            "error":   "Model training failed.",
            "message": "An internal error occurred during training. Check server logs.",
        }), 500


@ml_bp.route("/api/ml/predict", methods=["GET"])
@require_auth
def api_predict_power():
    """
    Authenticated: predict solar power generation from environmental features.
    Query params: irradiance (or lux fallback), panel_temp, humidity, hour_of_day, day_of_week, system_capacity_kw (optional).
    """
    try:
        has_irradiance = "irradiance" in request.args or "irradiance_w_m2" in request.args or "lux" in request.args
        if not has_irradiance:
            return jsonify({
                "error":   "Bad Request",
                "message": "Missing required query parameter: 'irradiance' (or 'lux' fallback).",
            }), 400

        other_required = ["panel_temp", "hour_of_day", "day_of_week", "humidity"]
        missing_params = [p for p in other_required if p not in request.args]
        if missing_params:
            return jsonify({
                "error":   "Bad Request",
                "message": f"Missing required query parameters: {missing_params}",
            }), 400

        features_dict = {k: request.args.get(k) for k in request.args}
        result = predict_power(features_dict)
        return jsonify(result), 200

    except FileNotFoundError as exc:
        return jsonify({"error": "Model Not Found", "message": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"error": "Validation Error", "message": str(exc)}), 400
    except Exception:
        logger.exception("api_predict_power: Unexpected error.")
        return jsonify({
            "error":   "Prediction failed.",
            "message": "An internal error occurred. Check server logs.",
        }), 500


@ml_bp.route("/api/systems/<string:system_id>/health", methods=["GET"])
@require_auth
def api_system_health(system_id: str):
    """
    RBAC-protected: return Solar Health Score for a system.
    """
    try:
        db = get_db()
        if db is None:
            return jsonify({"error": "Database connection unavailable."}), 500

        user = g.user

        sys_doc = db.collection(COLLECTION_SYSTEMS).document(system_id).get()
        if not sys_doc.exists:
            return jsonify({
                "error":   "Not Found",
                "message": f"Solar system '{system_id}' was not found.",
            }), 404

        system_data = sys_doc.to_dict() or {}

        if not can_read_system(user, system_data, db=db):
            return jsonify({
                "error":   "Forbidden",
                "message": "You do not have permission to access health analytics for this system.",
            }), 403

        health_data = calculate_health_score(system_id=system_id, db=db)
        return jsonify(health_data), 200

    except Exception:
        logger.exception(f"api_system_health: Error for system '{system_id}'.")
        return jsonify({
            "error":   "Failed to calculate health score.",
            "message": "An internal error occurred. Check server logs.",
        }), 500