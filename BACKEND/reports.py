"""
Solar Performance Report Generation Module — Segment 9 (Hardened & Optimized).

Provides authenticated, RBAC-protected REST APIs for generating Daily, Weekly,
and Monthly solar performance reports from Firestore telemetry readings.

Endpoints:
- GET /api/reports/daily?date=YYYY-MM-DD&system_id=SYS-XXXXXXXX
- GET /api/reports/weekly?start_date=YYYY-MM-DD&end_date=YYYY-MM-DD&system_id=SYS-XXXXXXXX
- GET /api/reports/monthly?month=YYYY-MM&system_id=SYS-XXXXXXXX

Architecture & Implementation Standards:
1. Firestore-Side Filtering:
   Server-side query filtering by:
       system_id == requested_system_id
       AND timestamp >= start_datetime
       AND timestamp < end_datetime
       ORDER BY timestamp ASC

   Required Production Firestore Composite Index:
       Collection : readings
       Fields     : system_id ASC, timestamp ASC

   Index Failure Protection:
   If the required composite index is missing or building in production, the query
   explicitly detects FAILED_PRECONDITION / missing-index errors and raises
   FirestoreIndexRequiredError. It does NOT silently perform an unbounded scan of the
   collection in production. A controlled error response is returned to clients and
   actionable index details are logged on the server.

2. Variable-Interval Energy Integration:
   Computes actual time deltas between consecutive readings rather than assuming a
   fixed 5-minute slice. Configurable maximum integration gap policy:
   - Safe default: 15.0 minutes (DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES).
   - System configuration: system.max_integration_gap_minutes or system.telemetry_interval_minutes * 3.
   - Bounded and validated within [1.0, 1440.0] minutes.
   - Gaps exceeding the threshold are excluded from energy accumulation and tracked as data gaps.

3. Explicit Expected Generation Strategy:
   - Priority 1: Valid telemetry expected_power when available.
   - Priority 2: Structured extension hook for future system configuration-based modeling.
   - If expected generation data is unavailable: returns null for expected_kwh, lost_kwh,
     and performance_ratio. Never fabricates fake loss or fake PR.
   - Tracks expected_generation_available, expected_power_reading_count, and
     expected_power_missing_count.

4. Performance Ratio:
   Calculates energy-weighted aggregate PR = actual_kwh / expected_kwh.
   Division-by-zero protected; returns null when expected generation is unavailable or zero.

5. Data Quality Metrics:
   Tracks reading counts, validity, timestamp errors, data gaps, excluded minutes,
   active integration gap policy, and expected generation availability.
"""

import sys
import os
import math
import logging
from datetime import datetime, date, time, timedelta, timezone
from typing import Optional, Tuple, Dict, Any, List

from flask import Blueprint, request, jsonify, g
import pandas as pd

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db
from BACKEND.auth import require_auth, require_role

logger = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__)

COLLECTION_SYSTEMS = "systems"
COLLECTION_READINGS = "readings"

# Expected readings per day under nominal 5-minute sampling (24h * 60min / 5min)
EXPECTED_READINGS_PER_DAY = 288

# Default maximum time gap between consecutive readings that is integrated for energy.
# Intervals larger than this are treated as data gaps/outages and excluded from kWh.
DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES = 15.0
MAX_INTEGRATION_INTERVAL_MINUTES = DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES

# Minimum and maximum allowed configurable gap limits (in minutes)
MIN_CONFIGURABLE_GAP_MINUTES = 1.0
MAX_CONFIGURABLE_GAP_MINUTES = 1440.0  # 24 hours


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class FirestoreIndexRequiredError(Exception):
    """Raised when Firestore rejects a query due to a missing composite index."""
    pass


# ---------------------------------------------------------------------------
# Utility: Sanitized Floats (Prevent NaN / Infinity in JSON)
# ---------------------------------------------------------------------------

def sanitize_float(val: Any, ndigits: int = 2) -> Optional[float]:
    """
    Safely converts numeric values to float rounded to ndigits.
    Returns None if value is None, NaN, Infinity, or unparseable.
    """
    if val is None:
        return None
    try:
        f = float(val)
        if math.isnan(f) or math.isinf(f):
            return None
        return round(f, ndigits)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Utility: Date & Month Parsers
# ---------------------------------------------------------------------------

def parse_date_str(date_str: Optional[str], param_name: str = "date") -> date:
    """
    Parses a 'YYYY-MM-DD' string into a date object.

    Raises:
        ValueError: If date_str is missing or invalid.
    """
    if not date_str or not isinstance(date_str, str):
        raise ValueError(f"'{param_name}' query parameter is required.")
    try:
        return datetime.strptime(date_str.strip(), "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(f"Invalid {param_name} format. Expected YYYY-MM-DD.")


def parse_month_str(month_str: Optional[str]) -> Tuple[datetime, datetime, str]:
    """
    Parses a 'YYYY-MM' string into (start_dt, end_dt, normalized_month_str) UTC range [start, end).

    Raises:
        ValueError: If month_str is missing or invalid.
    """
    if not month_str or not isinstance(month_str, str):
        raise ValueError("'month' query parameter is required.")
    try:
        dt = datetime.strptime(month_str.strip(), "%Y-%m")
        year, month = dt.year, dt.month
        start_dt = datetime(year, month, 1, 0, 0, 0, tzinfo=timezone.utc)
        if month == 12:
            end_dt = datetime(year + 1, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        else:
            end_dt = datetime(year, month + 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        return start_dt, end_dt, f"{year:04d}-{month:02d}"
    except ValueError:
        raise ValueError("Invalid month format. Expected YYYY-MM.")


# ---------------------------------------------------------------------------
# System Access Check Helper
# ---------------------------------------------------------------------------

def verify_system_access(
    db, system_id: str, user: dict
) -> Tuple[Optional[dict], Optional[Tuple[dict, int]]]:
    """
    Verifies that the requested system exists and that the user is authorized.

    Authorization:
    - admin: allowed for any system
    - owner: allowed only if system.owner_uid == user.uid
    - technician: forbidden (403); assignment-based access is future functionality

    Returns:
        (system_doc_dict, None) if authorized
        (None, (error_response_dict, status_code)) if unauthorized/not found
    """
    if not system_id or not isinstance(system_id, str) or not system_id.strip():
        return None, ({"error": "Bad Request", "message": "'system_id' query parameter is required."}, 400)

    system_id = system_id.strip()
    system_doc_ref = db.collection(COLLECTION_SYSTEMS).document(system_id).get()

    if not system_doc_ref.exists:
        return None, ({"error": "Not Found", "message": "System not found."}, 404)

    system_data = system_doc_ref.to_dict() or {}
    system_data["system_id"] = system_id

    role = (user.get("role") or "").strip().lower()

    if role == "admin":
        return system_data, None

    if role == "owner":
        if system_data.get("owner_uid") == user.get("uid"):
            return system_data, None
        return None, ({"error": "Forbidden", "message": "You do not have access to this system."}, 403)

    if role == "technician":
        from BACKEND.assignments import is_technician_assigned_to_system
        tech_uid = user.get("uid")
        if is_technician_assigned_to_system(db, tech_uid, system_id, site_id=system_data.get("site_id")):
            return system_data, None
        return None, ({"error": "Forbidden", "message": "You are not authorized to view reports for this solar system."}, 403)

    return None, ({"error": "Forbidden", "message": "You do not have access to this system."}, 403)


# ---------------------------------------------------------------------------
# Policy: Configurable Telemetry Integration Gap Resolver
# ---------------------------------------------------------------------------

def resolve_max_integration_gap(system_data: Optional[dict]) -> float:
    """
    Resolves the maximum integration gap (in minutes) for energy calculations.

    Resolution Order:
    1. system_data["max_integration_gap_minutes"] (explicit threshold)
    2. system_data["telemetry_interval_minutes"] * 3.0 (rule-of-thumb: 3x sample interval)
    3. DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES (15.0 minutes)

    Validates that the resolved value is a finite number within [1.0, 1440.0] minutes.
    Malformed, negative, zero, or non-numeric values safely fall back to default.
    """
    if not system_data or not isinstance(system_data, dict):
        return DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES

    # 1. Check explicit max_integration_gap_minutes
    raw_gap = system_data.get("max_integration_gap_minutes")
    if raw_gap is not None:
        try:
            val = float(raw_gap)
            if not math.isnan(val) and not math.isinf(val):
                if MIN_CONFIGURABLE_GAP_MINUTES <= val <= MAX_CONFIGURABLE_GAP_MINUTES:
                    return round(val, 2)
                logger.warning(
                    "System %s max_integration_gap_minutes (%.1f) out of range [%.1f, %.1f]; using default %.1f",
                    system_data.get("system_id", "unknown"), val,
                    MIN_CONFIGURABLE_GAP_MINUTES, MAX_CONFIGURABLE_GAP_MINUTES,
                    DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES
                )
        except (ValueError, TypeError):
            logger.warning(
                "System %s has invalid non-numeric max_integration_gap_minutes: %r; using default %.1f",
                system_data.get("system_id", "unknown"), raw_gap, DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES
            )

    # 2. Check telemetry_interval_minutes multiplier
    raw_interval = system_data.get("telemetry_interval_minutes")
    if raw_interval is not None:
        try:
            interval_val = float(raw_interval)
            if not math.isnan(interval_val) and not math.isinf(interval_val) and interval_val > 0:
                derived_gap = interval_val * 3.0
                if MIN_CONFIGURABLE_GAP_MINUTES <= derived_gap <= MAX_CONFIGURABLE_GAP_MINUTES:
                    return round(derived_gap, 2)
        except (ValueError, TypeError):
            pass

    return DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES


# ---------------------------------------------------------------------------
# Extension Hook: Expected Power Estimation
# ---------------------------------------------------------------------------

def estimate_expected_power_from_system(system_data: Optional[dict], reading: dict) -> Optional[float]:
    """
    Extension hook for future physical solar performance modeling.

    A future solar performance engine can calculate expected generation from:
    - system_data["panel_capacity_watts"]
    - reading.get("irradiance") or reading.get("lux")
    - reading.get("temperature_panel") or reading.get("temperature_ambient")
    - system tilt, azimuth, inverter efficiency curves, and weather data.

    Currently returns None: no synthetic irradiance/weather data is fabricated.
    """
    return None


# ---------------------------------------------------------------------------
# Firestore Query Helper: Check Index Required Error
# ---------------------------------------------------------------------------

def is_firestore_index_error(exc: Exception) -> bool:
    """
    Determines whether an exception is a Firestore missing index / FailedPrecondition error.
    """
    exc_name = exc.__class__.__name__.lower()
    exc_str = str(exc).lower()
    if "failedprecondition" in exc_name or "failed_precondition" in exc_name:
        return True
    if "failed-precondition" in exc_str or "requires an index" in exc_str or "the query requires a composite index" in exc_str:
        return True
    return False


# ---------------------------------------------------------------------------
# Firestore Query — Server-Side Filtered Readings Fetch
#
# Production composite index required (create in Firebase Console):
#   Collection : readings
#   Fields     : system_id ASC, timestamp ASC
#
# Without this index, Firestore rejects the query with a "FAILED_PRECONDITION"
# error. In production, we explicitly detect this and raise FirestoreIndexRequiredError
# to return a controlled API error rather than executing an unbounded collection scan.
# ---------------------------------------------------------------------------

def fetch_readings_dataframe(
    db, system_id: str, start_dt: datetime, end_dt: datetime
) -> pd.DataFrame:
    """
    Fetches telemetry readings from Firestore using server-side filtering:
        system_id == system_id
        AND timestamp >= start_dt.isoformat()
        AND timestamp <  end_dt.isoformat()
        ORDER BY timestamp ASC

    Only readings for the requested system and time window are returned.
    Readings without a system_id are strictly excluded.

    Raises:
        FirestoreIndexRequiredError: If Firestore rejects the query due to a missing
                                     composite index in production.
    """
    readings_ref = db.collection(COLLECTION_READINGS)

    start_iso = start_dt.isoformat()
    end_iso = end_dt.isoformat()

    try:
        query = (
            readings_ref
            .where("system_id", "==", system_id)
            .where("timestamp", ">=", start_iso)
            .where("timestamp", "<", end_iso)
            .order_by("timestamp")
        )
        docs = query.stream()
    except Exception as exc:
        if is_firestore_index_error(exc):
            logger.error(
                "Firestore query rejected: Missing composite index on collection '%s' (system_id ASC, timestamp ASC). "
                "Technical error: %s",
                COLLECTION_READINGS, exc,
            )
            # In production: Never perform an unbounded scan. Return a clear, controlled error.
            raise FirestoreIndexRequiredError(
                "The required Firestore composite index for this query is missing or building. "
                "Please create the composite index in Firebase Console: Collection 'readings', fields (system_id ASC, timestamp ASC)."
            ) from exc

        # Development/Test mock isolation
        if getattr(db, "_is_mock", False):
            logger.info("Mock database detected; utilizing development fallback.")
            query_fallback = readings_ref.where("system_id", "==", system_id)
            docs = query_fallback.stream()
        else:
            logger.error("Firestore telemetry query failed unexpectedly: %s", exc)
            raise

    records: List[dict] = []
    for doc in docs:
        data = doc.to_dict()
        if not data or not isinstance(data, dict):
            continue
        # Strict system_id guard
        if data.get("system_id") != system_id:
            continue
        data["_doc_id"] = doc.id
        records.append(data)

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)

    # Normalize timestamp → timezone-aware UTC datetime in 'dt' column
    if "timestamp" in df.columns:
        df["dt"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    elif "unix_timestamp" in df.columns:
        df["dt"] = pd.to_datetime(df["unix_timestamp"], unit="s", utc=True, errors="coerce")
    else:
        logger.warning("Readings for system %s have no parseable timestamp field.", system_id)
        return pd.DataFrame()

    # Drop rows where timestamp parsing failed
    before = len(df)
    df = df.dropna(subset=["dt"])
    dropped = before - len(df)
    if dropped:
        logger.warning(
            "%d reading(s) for system %s dropped due to unparseable timestamp.", dropped, system_id
        )

    # Client-side half-open interval filter [start_dt, end_dt)
    mask = (df["dt"] >= start_dt) & (df["dt"] < end_dt)
    df = df.loc[mask].copy()

    # Sort chronologically
    df = df.sort_values("dt").reset_index(drop=True)

    return df


# ---------------------------------------------------------------------------
# Variable-Interval Energy Integration
# ---------------------------------------------------------------------------

def integrate_energy(
    df: pd.DataFrame,
    power_col: str,
    max_gap_minutes: float = DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES,
) -> Tuple[float, int, float]:
    """
    Integrates power (W) over actual time deltas to produce energy (kWh).

    Args:
        df             : DataFrame sorted by 'dt', containing column power_col.
        power_col      : Column name for power in Watts.
        max_gap_minutes: Maximum integration interval in minutes.

    Returns:
        (total_kwh, gap_count, total_excluded_gap_minutes)
            total_kwh                  — integrated energy in kWh
            gap_count                  — number of intervals exceeding max_gap_minutes
            total_excluded_gap_minutes — sum of gap durations excluded from kWh accumulation
    """
    if df.empty or power_col not in df.columns:
        return 0.0, 0, 0.0

    total_wh = 0.0
    gap_count = 0
    total_excluded_gap_minutes = 0.0
    max_gap_seconds = max_gap_minutes * 60.0

    timestamps = df["dt"].tolist()
    powers = pd.to_numeric(df[power_col], errors="coerce").tolist()

    for i in range(1, len(timestamps)):
        prev_ts = timestamps[i - 1]
        curr_ts = timestamps[i]

        if pd.isna(prev_ts) or pd.isna(curr_ts):
            continue

        delta_seconds = (curr_ts - prev_ts).total_seconds()

        # Skip duplicate or backward timestamps
        if delta_seconds <= 0:
            logger.warning(
                "Non-positive timestamp delta (%.1f s) between readings %d and %d; skipping.",
                delta_seconds, i - 1, i,
            )
            continue

        # Gap protection: exclude excessively large intervals
        if delta_seconds > max_gap_seconds:
            gap_count += 1
            total_excluded_gap_minutes += delta_seconds / 60.0
            logger.info(
                "Data gap of %.1f min between readings %d and %d exceeds policy threshold of %.1f min; "
                "excluded from energy integration.",
                delta_seconds / 60.0, i - 1, i, max_gap_minutes,
            )
            continue

        pwr = powers[i]
        if pwr is None or (isinstance(pwr, float) and (math.isnan(pwr) or math.isinf(pwr))):
            continue
        if pwr < 0:
            pwr = 0.0

        # Energy (Wh) = Power (W) × Time (h)
        total_wh += pwr * (delta_seconds / 3600.0)

    return round(total_wh / 1000.0, 4), gap_count, round(total_excluded_gap_minutes, 2)


# ---------------------------------------------------------------------------
# Analytics & Aggregation Engine
# ---------------------------------------------------------------------------

def calculate_solar_metrics(
    df: pd.DataFrame,
    start_dt: datetime,
    end_dt: datetime,
    system_data: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    Calculates solar performance metrics from a sorted pandas DataFrame.

    Features:
    - Variable-interval energy integration with configurable telemetry gap threshold.
    - Explicit expected-generation tracking (no fake loss / fake PR).
    - Aggregate energy PR = actual_kwh / expected_kwh.
    - Complete data-quality block preserving all existing keys and adding enriched metrics.
    """
    # Resolve configurable integration gap threshold from system configuration
    max_gap_minutes = resolve_max_integration_gap(system_data)

    duration_days = max(1.0, (end_dt - start_dt).total_seconds() / 86400.0)
    expected_readings = int(round(duration_days * EXPECTED_READINGS_PER_DAY))

    reading_count = int(len(df))
    missing_ts_count = 0
    invalid_reading_count = 0
    valid_reading_count = 0

    if reading_count == 0:
        return {
            "data_available": False,
            "reading_count": 0,
            "expected_readings": expected_readings,
            "data_completeness_percent": 0.0,
            "valid_reading_count": 0,
            "invalid_reading_count": 0,
            "missing_timestamp_count": 0,
            "data_gap_count": 0,
            "total_gap_minutes": 0.0,
            "excluded_gap_minutes": 0.0,
            "max_integration_gap_minutes": max_gap_minutes,
            "expected_generation_available": False,
            "expected_power_reading_count": 0,
            "expected_power_missing_count": 0,
        }

    # Timestamp tracking
    if "dt" in df.columns:
        missing_ts_count = int(df["dt"].isna().sum())
        valid_reading_count = reading_count - missing_ts_count
        invalid_reading_count = missing_ts_count
    else:
        missing_ts_count = reading_count
        invalid_reading_count = reading_count

    completeness_pct = sanitize_float(
        min(100.0, (reading_count / expected_readings) * 100.0) if expected_readings > 0 else 100.0,
        2,
    )

    # ------------------------------------------------------------------
    # 1. Actual Generation via variable-interval integration
    # ------------------------------------------------------------------
    actual_kwh = None
    peak_power_w = None
    gap_count = 0
    total_gap_minutes = 0.0
    excluded_gap_minutes = 0.0

    if "power" in df.columns and df["power"].notnull().any():
        raw_kwh, gap_count, excluded_gap_minutes = integrate_energy(
            df, "power", max_gap_minutes=max_gap_minutes
        )
        actual_kwh = sanitize_float(raw_kwh, 2)
        total_gap_minutes = excluded_gap_minutes

        power_series = pd.to_numeric(df["power"], errors="coerce")
        peak_val = power_series.dropna().max() if not power_series.dropna().empty else None
        peak_power_w = sanitize_float(peak_val, 2) if peak_val is not None else None

    # ------------------------------------------------------------------
    # 2. Expected Generation Strategy & Tracking
    # Priority 1: Use valid expected_power from telemetry.
    # Priority 2: Extension hook (estimate_expected_power_from_system).
    # If no valid expected_power is available:
    #   expected_kwh = None, lost_kwh = None, PR = None
    #   expected_generation_available = False
    # ------------------------------------------------------------------
    expected_kwh = None
    lost_kwh = None
    loss_percent = None
    expected_generation_available = False
    expected_power_reading_count = 0
    expected_power_missing_count = reading_count

    if "expected_power" in df.columns:
        exp_power_series = pd.to_numeric(df["expected_power"], errors="coerce")
        valid_exp_mask = exp_power_series.notnull()
        expected_power_reading_count = int(valid_exp_mask.sum())
        expected_power_missing_count = reading_count - expected_power_reading_count

        if expected_power_reading_count > 0:
            raw_exp_kwh, _, _ = integrate_energy(
                df, "expected_power", max_gap_minutes=max_gap_minutes
            )
            expected_kwh = sanitize_float(raw_exp_kwh, 2)
            expected_generation_available = True

            if expected_kwh is not None and actual_kwh is not None:
                lost_kwh = sanitize_float(max(0.0, expected_kwh - actual_kwh), 2)
                if expected_kwh > 0:
                    loss_percent = sanitize_float((lost_kwh / expected_kwh) * 100.0, 2)
                else:
                    loss_percent = 0.0

    # ------------------------------------------------------------------
    # 3. Performance Ratio — Aggregate Energy PR (actual_kwh / expected_kwh)
    # Safe against division-by-zero; returns None when expected_kwh is missing or zero.
    # ------------------------------------------------------------------
    pr = None
    pr_percent = None

    if expected_kwh is not None and expected_kwh > 0 and actual_kwh is not None:
        pr = sanitize_float(actual_kwh / expected_kwh, 4)
        pr_percent = sanitize_float(pr * 100.0, 2) if pr is not None else None

    # ------------------------------------------------------------------
    # 4. Average Temperature
    # ------------------------------------------------------------------
    avg_temp = None
    for temp_col in ["temperature", "temperature_ambient", "temperature_panel"]:
        if temp_col in df.columns and df[temp_col].notnull().any():
            temp_series = pd.to_numeric(df[temp_col], errors="coerce").dropna()
            if len(temp_series) > 0:
                avg_temp = sanitize_float(temp_series.mean(), 2)
                break

    # ------------------------------------------------------------------
    # 5. Rain Events — Discrete False → True transitions
    # ------------------------------------------------------------------
    rain_events = None
    if "rain" in df.columns and df["rain"].notnull().any():
        df_sorted = df.sort_values("dt")
        rain_numeric = pd.to_numeric(df_sorted["rain"], errors="coerce").fillna(0.0)
        is_raining = (rain_numeric > 0) | (df_sorted["rain"] == True)
        transitions = (is_raining & ~is_raining.shift(1, fill_value=False)).sum()
        rain_events = int(transitions)

    # ------------------------------------------------------------------
    # 6. Best and Worst Day (using variable-interval integration)
    # ------------------------------------------------------------------
    best_day = None
    worst_day = None
    if "power" in df.columns and "dt" in df.columns and len(df) > 0:
        df = df.copy()
        df["date_str"] = df["dt"].dt.strftime("%Y-%m-%d")

        daily_kwh_map: Dict[str, float] = {}
        for day_str, day_df in df.groupby("date_str"):
            day_df = day_df.sort_values("dt").reset_index(drop=True)
            day_kwh, _, _ = integrate_energy(day_df, "power", max_gap_minutes=max_gap_minutes)
            daily_kwh_map[day_str] = round(day_kwh, 2)

        if daily_kwh_map:
            best_date = max(daily_kwh_map, key=daily_kwh_map.__getitem__)
            worst_date = min(daily_kwh_map, key=daily_kwh_map.__getitem__)
            best_day = {"date": best_date, "generation_kwh": sanitize_float(daily_kwh_map[best_date], 2)}
            worst_day = {"date": worst_date, "generation_kwh": sanitize_float(daily_kwh_map[worst_date], 2)}

    return {
        "data_available": True,
        "actual_kwh": actual_kwh,
        "expected_kwh": expected_kwh,
        "lost_kwh": lost_kwh,
        "loss_percent": loss_percent,
        "performance_ratio": pr,
        "performance_ratio_percent": pr_percent,
        "peak_power_w": peak_power_w,
        "average_temperature_c": avg_temp,
        "rain_events": rain_events,
        # Existing data_quality fields
        "reading_count": reading_count,
        "expected_readings": expected_readings,
        "data_completeness_percent": completeness_pct,
        # Enriched data_quality & telemetry gap policy fields
        "valid_reading_count": valid_reading_count,
        "invalid_reading_count": invalid_reading_count,
        "missing_timestamp_count": missing_ts_count,
        "data_gap_count": gap_count,
        "total_gap_minutes": round(total_gap_minutes, 2),
        "excluded_gap_minutes": round(excluded_gap_minutes, 2),
        "max_integration_gap_minutes": max_gap_minutes,
        "expected_generation_available": expected_generation_available,
        "expected_power_reading_count": expected_power_reading_count,
        "expected_power_missing_count": expected_power_missing_count,
        "best_day": best_day,
        "worst_day": worst_day,
    }


# ---------------------------------------------------------------------------
# Shared: Build data_quality sub-dict for API responses
# ---------------------------------------------------------------------------

def _build_data_quality(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Returns the enriched data_quality block for API responses."""
    return {
        "reading_count": metrics["reading_count"],
        "expected_readings": metrics["expected_readings"],
        "data_completeness_percent": metrics["data_completeness_percent"],
        "valid_reading_count": metrics["valid_reading_count"],
        "invalid_reading_count": metrics["invalid_reading_count"],
        "missing_timestamp_count": metrics["missing_timestamp_count"],
        "data_gap_count": metrics["data_gap_count"],
        "total_gap_minutes": metrics["total_gap_minutes"],
        "excluded_gap_minutes": metrics["excluded_gap_minutes"],
        "max_integration_gap_minutes": metrics.get("max_integration_gap_minutes", DEFAULT_MAX_INTEGRATION_INTERVAL_MINUTES),
        "expected_generation_available": metrics.get("expected_generation_available", False),
        "expected_power_reading_count": metrics.get("expected_power_reading_count", 0),
        "expected_power_missing_count": metrics.get("expected_power_missing_count", 0),
    }


# ---------------------------------------------------------------------------
# ENDPOINT 1: GET /api/reports/daily
# ---------------------------------------------------------------------------

@reports_bp.route("/api/reports/daily", methods=["GET"])
@require_auth
def get_daily_report():
    """
    Generates a Daily Solar Performance Report.

    Query Params:
        date (str): Date in 'YYYY-MM-DD' format (Required).
        system_id (str): Solar installation system ID (Required).
    """
    try:
        date_param = request.args.get("date")
        system_id = request.args.get("system_id")

        if not date_param:
            return jsonify({"error": "Bad Request", "message": "'date' query parameter is required."}), 400

        try:
            target_date = parse_date_str(date_param, param_name="date")
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

        db = get_db()
        if db is None:
            logger.error("Database handle unavailable in get_daily_report")
            return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

        system_data, error_res = verify_system_access(db, system_id, g.user)
        if error_res:
            res_dict, status_code = error_res
            return jsonify(res_dict), status_code

        # Daily Range: [start 00:00:00 UTC, next day 00:00:00 UTC)
        start_dt = datetime.combine(target_date, time.min, tzinfo=timezone.utc)
        end_dt = start_dt + timedelta(days=1)

        df = fetch_readings_dataframe(db, system_id, start_dt, end_dt)
        metrics = calculate_solar_metrics(df, start_dt, end_dt, system_data=system_data)

        if not metrics["data_available"]:
            return jsonify({
                "success": True,
                "data_available": False,
                "report_type": "daily",
                "system_id": system_id,
                "period": {
                    "date": target_date.strftime("%Y-%m-%d"),
                    "start": start_dt.isoformat(),
                    "end": end_dt.isoformat()
                },
                "message": "No telemetry data available for this period."
            }), 200

        response = {
            "success": True,
            "report_type": "daily",
            "system_id": system_id,
            "period": {
                "date": target_date.strftime("%Y-%m-%d"),
                "start": start_dt.isoformat(),
                "end": end_dt.isoformat()
            },
            "data_available": True,
            "generation": {
                "actual_kwh": metrics["actual_kwh"],
                "expected_kwh": metrics["expected_kwh"],
                "lost_kwh": metrics["lost_kwh"],
                "loss_percent": metrics["loss_percent"],
                "expected_generation_available": metrics["expected_generation_available"],
            },
            "performance": {
                "performance_ratio": metrics["performance_ratio"],
                "performance_ratio_percent": metrics["performance_ratio_percent"],
                "peak_power_w": metrics["peak_power_w"]
            },
            "environment": {
                "average_temperature_c": metrics["average_temperature_c"],
                "rain_events": metrics["rain_events"]
            },
            "data_quality": _build_data_quality(metrics),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        return jsonify(response), 200

    except FirestoreIndexRequiredError as fie:
        logger.error("Firestore composite index required: %s", fie)
        return jsonify({
            "error": "Database Index Required",
            "message": str(fie)
        }), 500

    except Exception as e:
        logger.exception(f"Error generating daily report: {e}")
        return jsonify({"error": "Internal Server Error", "message": "Unable to generate report."}), 500


# ---------------------------------------------------------------------------
# ENDPOINT 2: GET /api/reports/weekly
# ---------------------------------------------------------------------------

@reports_bp.route("/api/reports/weekly", methods=["GET"])
@require_auth
def get_weekly_report():
    """
    Generates a Weekly / Date-Range Solar Performance Report.

    Query Params:
        start_date (str): Range start date in 'YYYY-MM-DD' format (Required).
        end_date (str): Range end date in 'YYYY-MM-DD' format (Required).
        system_id (str): Solar installation system ID (Required).
    """
    try:
        start_date_str = request.args.get("start_date")
        end_date_str = request.args.get("end_date")
        system_id = request.args.get("system_id")

        if not start_date_str:
            return jsonify({"error": "Bad Request", "message": "'start_date' query parameter is required."}), 400
        if not end_date_str:
            return jsonify({"error": "Bad Request", "message": "'end_date' query parameter is required."}), 400

        try:
            start_date_obj = parse_date_str(start_date_str, param_name="start_date")
            end_date_obj = parse_date_str(end_date_str, param_name="end_date")
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

        if start_date_obj > end_date_obj:
            return jsonify({
                "error": "Bad Request",
                "message": "'start_date' must be less than or equal to 'end_date'."
            }), 400

        db = get_db()
        if db is None:
            logger.error("Database handle unavailable in get_weekly_report")
            return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

        system_data, error_res = verify_system_access(db, system_id, g.user)
        if error_res:
            res_dict, status_code = error_res
            return jsonify(res_dict), status_code

        # Half-open interval: [start_date 00:00:00, end_date + 1 day 00:00:00)
        start_dt = datetime.combine(start_date_obj, time.min, tzinfo=timezone.utc)
        end_dt = datetime.combine(end_date_obj, time.min, tzinfo=timezone.utc) + timedelta(days=1)

        df = fetch_readings_dataframe(db, system_id, start_dt, end_dt)
        metrics = calculate_solar_metrics(df, start_dt, end_dt, system_data=system_data)

        if not metrics["data_available"]:
            return jsonify({
                "success": True,
                "data_available": False,
                "report_type": "weekly",
                "system_id": system_id,
                "period": {
                    "start_date": start_date_obj.strftime("%Y-%m-%d"),
                    "end_date": end_date_obj.strftime("%Y-%m-%d"),
                    "start": start_dt.isoformat(),
                    "end": end_dt.isoformat()
                },
                "message": "No telemetry data available for this period."
            }), 200

        response = {
            "success": True,
            "report_type": "weekly",
            "system_id": system_id,
            "period": {
                "start_date": start_date_obj.strftime("%Y-%m-%d"),
                "end_date": end_date_obj.strftime("%Y-%m-%d"),
                "start": start_dt.isoformat(),
                "end": end_dt.isoformat()
            },
            "data_available": True,
            "generation": {
                "actual_kwh": metrics["actual_kwh"],
                "expected_kwh": metrics["expected_kwh"],
                "lost_kwh": metrics["lost_kwh"],
                "loss_percent": metrics["loss_percent"],
                "expected_generation_available": metrics["expected_generation_available"],
            },
            "performance": {
                "performance_ratio": metrics["performance_ratio"],
                "performance_ratio_percent": metrics["performance_ratio_percent"],
                "peak_power_w": metrics["peak_power_w"]
            },
            "environment": {
                "average_temperature_c": metrics["average_temperature_c"],
                "rain_events": metrics["rain_events"]
            },
            "data_quality": _build_data_quality(metrics),
            "best_day": metrics["best_day"],
            "worst_day": metrics["worst_day"],
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        return jsonify(response), 200

    except FirestoreIndexRequiredError as fie:
        logger.error("Firestore composite index required: %s", fie)
        return jsonify({
            "error": "Database Index Required",
            "message": str(fie)
        }), 500

    except Exception as e:
        logger.exception(f"Error generating weekly report: {e}")
        return jsonify({"error": "Internal Server Error", "message": "Unable to generate report."}), 500


# ---------------------------------------------------------------------------
# ENDPOINT 3: GET /api/reports/monthly
# ---------------------------------------------------------------------------

@reports_bp.route("/api/reports/monthly", methods=["GET"])
@require_auth
def get_monthly_report():
    """
    Generates a Monthly Solar Performance Report.

    Query Params:
        month (str): Target month in 'YYYY-MM' format (Required).
        system_id (str): Solar installation system ID (Required).
    """
    try:
        month_param = request.args.get("month")
        system_id = request.args.get("system_id")

        if not month_param:
            return jsonify({"error": "Bad Request", "message": "'month' query parameter is required."}), 400

        try:
            start_dt, end_dt, normalized_month = parse_month_str(month_param)
        except ValueError as ve:
            return jsonify({"error": "Bad Request", "message": str(ve)}), 400

        db = get_db()
        if db is None:
            logger.error("Database handle unavailable in get_monthly_report")
            return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

        system_data, error_res = verify_system_access(db, system_id, g.user)
        if error_res:
            res_dict, status_code = error_res
            return jsonify(res_dict), status_code

        df = fetch_readings_dataframe(db, system_id, start_dt, end_dt)
        metrics = calculate_solar_metrics(df, start_dt, end_dt, system_data=system_data)

        if not metrics["data_available"]:
            return jsonify({
                "success": True,
                "data_available": False,
                "report_type": "monthly",
                "system_id": system_id,
                "month": normalized_month,
                "period": {
                    "start": start_dt.isoformat(),
                    "end": end_dt.isoformat()
                },
                "message": "No telemetry data available for this period."
            }), 200

        response = {
            "success": True,
            "report_type": "monthly",
            "system_id": system_id,
            "month": normalized_month,
            "period": {
                "start": start_dt.isoformat(),
                "end": end_dt.isoformat()
            },
            "data_available": True,
            "generation": {
                "actual_kwh": metrics["actual_kwh"],
                "expected_kwh": metrics["expected_kwh"],
                "lost_kwh": metrics["lost_kwh"],
                "loss_percent": metrics["loss_percent"],
                "expected_generation_available": metrics["expected_generation_available"],
            },
            "performance": {
                "performance_ratio": metrics["performance_ratio"],
                "performance_ratio_percent": metrics["performance_ratio_percent"],
                "peak_power_w": metrics["peak_power_w"]
            },
            "environment": {
                "average_temperature_c": metrics["average_temperature_c"],
                "rain_events": metrics["rain_events"]
            },
            "data_quality": _build_data_quality(metrics),
            "best_day": metrics["best_day"],
            "worst_day": metrics["worst_day"],
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        return jsonify(response), 200

    except FirestoreIndexRequiredError as fie:
        logger.error("Firestore composite index required: %s", fie)
        return jsonify({
            "error": "Database Index Required",
            "message": str(fie)
        }), 500

    except Exception as e:
        logger.exception(f"Error generating monthly report: {e}")
        return jsonify({"error": "Internal Server Error", "message": "Unable to generate report."}), 500
