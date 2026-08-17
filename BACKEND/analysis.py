"""
Performance Analysis & Alert Engine for Solar Monitoring System.

Contains analytics functions for:
- Computing Performance Ratio (PR)
- Quantifying Lost Energy (kWh)
- Detecting anomalies using sliding window analysis
- Generating & managing active alerts in Firestore
"""

import sys
import os
from datetime import datetime, timezone
from typing import List, Dict, Tuple, Optional

from google.cloud.firestore import FieldFilter

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db

COLLECTION_READINGS = "readings"
COLLECTION_ALERTS = "alerts"

# Thresholds
PR_THRESHOLD = 0.70          # PR below 70% is considered abnormal
MIN_EXPECTED_POWER_WATTS = 10.0  # Ignore nighttime / low light readings (<10W)
SLIDING_WINDOW_SIZE = 5      # Evaluate last 5 readings
MIN_ANOMALOUS_COUNT = 3      # At least 3 out of 5 below threshold to trigger alert


def compute_performance_ratio(actual_power: float, expected_power: float) -> float:
    """
    Computes the Performance Ratio (PR) = actual_power / expected_power.

    Args:
        actual_power (float): Actual generated power in Watts.
        expected_power (float): Expected ideal power in Watts.

    Returns:
        float: Calculated PR rounded to 4 decimal places (0.0 if expected_power < 1.0).
    """
    if expected_power < 1.0:
        return 0.0
    return round(max(0.0, actual_power / expected_power), 4)


def calculate_lost_energy(readings: List[Dict], interval_minutes: int = 5) -> float:
    """
    Calculates total energy loss in Kilowatt-Hours (kWh) over a list of telemetry readings.

    Formula:
        Lost Power (W) = max(0, expected_power - actual_power)
        Lost Energy (kWh) = sum(Lost Power * (interval_minutes / 60)) / 1000

    Args:
        readings (List[Dict]): List of sensor reading dictionaries.
        interval_minutes (int): Time duration per reading step in minutes (default: 5).

    Returns:
        float: Total lost energy in kWh rounded to 4 decimal places.
    """
    total_lost_watt_hours = 0.0
    time_factor_hours = interval_minutes / 60.0

    for reading in readings:
        exp_power = float(reading.get("expected_power", 0.0))
        act_power = float(reading.get("power", 0.0))
        
        # Calculate loss only when solar generation is expected
        if exp_power > MIN_EXPECTED_POWER_WATTS:
            power_loss_watts = max(0.0, exp_power - act_power)
            total_lost_watt_hours += power_loss_watts * time_factor_hours

    lost_kwh = total_lost_watt_hours / 1000.0
    return round(lost_kwh, 4)


def detect_anomalies(
    readings: List[Dict],
    pr_threshold: float = PR_THRESHOLD,
    min_anomalous_count: int = MIN_ANOMALOUS_COUNT
) -> Tuple[bool, float, List[Dict]]:
    """
    Detects solar performance degradation anomalies using a sliding window.

    A reading is considered anomalous if:
    1. expected_power > MIN_EXPECTED_POWER_WATTS (daytime generation period)
    2. performance_ratio < pr_threshold (PR < 0.70)

    Args:
        readings (List[Dict]): List of recent sensor readings (ordered newest first).
        pr_threshold (float): Performance ratio threshold (default: 0.70).
        min_anomalous_count (int): Minimum anomalous readings required in window (default: 3).

    Returns:
        Tuple[bool, float, List[Dict]]:
            - is_anomaly (bool): True if anomaly detected.
            - avg_pr (float): Average performance ratio of daytime readings in window.
            - anomalous_readings (List[Dict]): List of readings that breached threshold.
    """
    if not readings:
        return False, 0.0, []

    # Take the window of recent readings
    window = readings[:SLIDING_WINDOW_SIZE]
    
    # Filter daytime readings where sun generation is active
    daytime_readings = [r for r in window if float(r.get("expected_power", 0.0)) > MIN_EXPECTED_POWER_WATTS]

    if not daytime_readings:
        return False, 0.0, []

    # Find readings where PR is below threshold
    anomalous_readings = [
        r for r in daytime_readings
        if float(r.get("performance_ratio", 0.0)) < pr_threshold
    ]

    total_pr = sum(float(r.get("performance_ratio", 0.0)) for r in daytime_readings)
    avg_pr = round(total_pr / len(daytime_readings), 4)

    is_anomaly = len(anomalous_readings) >= min_anomalous_count
    return is_anomaly, avg_pr, anomalous_readings


def has_active_alert(
    db,
    alert_type: str = "performance_drop",
    system_id: Optional[str] = None,
    max_age_seconds: Optional[int] = None
) -> Optional[Dict]:
    """
    Checks if an active alert for the given type and system already exists in Firestore.

    Args:
        db: Firestore client handle.
        alert_type (str): Type of alert to query.
        system_id (str, optional): System identifier to scope the duplicate check.
        max_age_seconds (int, optional): If provided, only matches active alerts created
                                         within this time window (e.g. 3600 for 1 hour).

    Returns:
        Optional[Dict]: Active alert document dict with ID if found, else None.
    """
    try:
        alerts_ref = db.collection(COLLECTION_ALERTS)
        query = (
            alerts_ref
            .where(filter=FieldFilter("active", "==", True))
            .where(filter=FieldFilter("type", "==", alert_type))
        )
        docs = list(query.stream())

        now_ts = int(datetime.now(timezone.utc).timestamp())

        for doc in docs:
            alert_data = doc.to_dict() or {}
            alert_data["id"] = doc.id

            # If system_id is provided, ensure it matches
            if system_id is not None:
                doc_sys_id = alert_data.get("system_id")
                if doc_sys_id != system_id:
                    continue

            # If max_age_seconds is provided, verify timestamp age
            if max_age_seconds is not None:
                alert_ts = alert_data.get("unix_timestamp")
                if alert_ts is None and alert_data.get("timestamp"):
                    try:
                        alert_dt = datetime.fromisoformat(str(alert_data["timestamp"]).replace("Z", "+00:00"))
                        alert_ts = int(alert_dt.timestamp())
                    except Exception:
                        alert_ts = None

                if alert_ts is not None:
                    age_seconds = now_ts - alert_ts
                    if age_seconds > max_age_seconds:
                        # Alert is older than the duplicate suppression window
                        continue

            return alert_data

        return None
    except Exception as e:
        print(f"[Analysis ERROR] Error checking active alert: {e}", file=sys.stderr)
        return None


def create_alert(
    db,
    alert_type: str,
    message: str,
    reading_id: str,
    lost_energy_kwh: float = 0.0,
    avg_pr: float = 0.0,
    system_id: Optional[str] = None,
    site_id: Optional[str] = None,
    severity: Optional[str] = None,
    threshold: float = PR_THRESHOLD,
    max_duplicate_age_seconds: Optional[int] = 3600
) -> Tuple[str, bool]:
    """
    Creates an alert document in Firestore if no active alert of the same type already exists.

    Alert Schema:
        - timestamp (str ISO format)
        - unix_timestamp (int)
        - type (str, e.g. "performance_drop")
        - severity (str: "warning" | "critical")
        - performance_ratio (float)
        - average_pr (float)
        - threshold (float)
        - status (str: "active")
        - active (bool: True)
        - message (str)
        - reading_id (str)
        - lost_energy_kwh (float)
        - system_id (str, optional)
        - site_id (str, optional)

    Args:
        db: Firestore client handle.
        alert_type (str): Type identifier for the alert.
        message (str): Human-readable alert message.
        reading_id (str): ID of the latest anomalous reading.
        lost_energy_kwh (float): Calculated energy loss in kWh.
        avg_pr (float): Average PR during anomaly period.
        system_id (str, optional): Solar system identifier.
        site_id (str, optional): Site identifier if associated.
        severity (str, optional): Alert severity ("warning" | "critical"). Auto-derived if None.
        threshold (float): PR threshold breached (default: 0.70).
        max_duplicate_age_seconds (int, optional): Window for duplicate suppression (default: 3600s).

    Returns:
        Tuple[str, bool]: (alert_id, is_newly_created)
    """
    try:
        # Prevent duplicate alerts for the same ongoing fault episode
        existing_alert = has_active_alert(
            db=db,
            alert_type=alert_type,
            system_id=system_id,
            max_age_seconds=max_duplicate_age_seconds
        )
        if existing_alert:
            sys_info = f" for system '{system_id}'" if system_id else ""
            print(f"[Alert System] Active '{alert_type}' alert already exists ({existing_alert['id']}){sys_info}. Skipping duplicate creation.")
            return existing_alert["id"], False

        if severity is None:
            severity = "warning" if avg_pr >= 0.50 else "critical"

        now = datetime.now(timezone.utc)
        alert_doc = {
            "timestamp": now.isoformat(),
            "unix_timestamp": int(now.timestamp()),
            "type": alert_type,
            "severity": severity,
            "performance_ratio": round(avg_pr, 4),
            "average_pr": round(avg_pr, 4),
            "threshold": round(threshold, 4),
            "status": "active",
            "active": True,
            "message": message,
            "reading_id": reading_id,
            "lost_energy_kwh": round(lost_energy_kwh, 4),
            "system_id": system_id,
            "site_id": site_id
        }

        alerts_ref = db.collection(COLLECTION_ALERTS)
        new_doc_ref = alerts_ref.document()
        new_doc_ref.set(alert_doc)
        
        sys_info = f" [System: {system_id}]" if system_id else ""
        print(f"[Alert System] Created NEW active alert: {new_doc_ref.id}{sys_info} | Severity: {severity} | Message: {message}")
        return new_doc_ref.id, True

    except Exception as e:
        print(f"[Analysis ERROR] Failed to create alert: {e}", file=sys.stderr)
        raise e


def resolve_active_alerts(
    db,
    alert_type: str = "performance_drop",
    system_id: Optional[str] = None
) -> int:
    """
    Marks active alerts of a given type as resolved (active = False, status = "resolved")
    when system performance recovers.

    Args:
        db: Firestore client handle.
        alert_type (str): Alert type to resolve.
        system_id (str, optional): Solar system identifier to resolve alerts for.

    Returns:
        int: Number of resolved alerts.
    """
    try:
        alerts_ref = db.collection(COLLECTION_ALERTS)
        query = (
            alerts_ref
            .where(filter=FieldFilter("active", "==", True))
            .where(filter=FieldFilter("type", "==", alert_type))
        )
        docs = list(query.stream())
        resolved_count = 0

        for doc in docs:
            doc_data = doc.to_dict() or {}
            if system_id is not None and doc_data.get("system_id") != system_id:
                continue

            # Update document reference
            ref = getattr(doc, "reference", None)
            if ref and hasattr(ref, "update"):
                ref.update({
                    "active": False,
                    "status": "resolved",
                    "resolved_at": datetime.now(timezone.utc).isoformat()
                })
            resolved_count += 1
            sys_info = f" (system: {system_id})" if system_id else ""
            print(f"[Alert System] Resolved alert {doc.id}{sys_info} as system performance recovered.")

        return resolved_count
    except Exception as e:
        print(f"[Analysis ERROR] Failed to resolve alerts: {e}", file=sys.stderr)
        return 0


def run_analysis(db=None, window_size: int = 10) -> Dict:
    """
    Main analysis engine execution entry point.
    Fetches recent readings from Firestore, runs anomaly detection,
    quantifies energy loss, and creates or resolves alerts.

    Args:
        db (optional): Firestore client handle.
        window_size (int): Number of recent readings to inspect (default: 10).

    Returns:
        Dict: Analysis execution summary containing status, anomaly flag, PR, and alert details.
    """
    if db is None:
        db = get_db()

    if db is None:
        return {"error": "Database handle unavailable", "status": "failed"}

    try:
        # 1. Fetch latest readings from Firestore
        readings_ref = db.collection(COLLECTION_READINGS)
        query = readings_ref.order_by("unix_timestamp", direction="DESCENDING").limit(window_size)
        docs = list(query.stream())

        if not docs:
            return {"status": "ok", "message": "No readings found in collection"}

        readings = [d.to_dict() for d in docs]
        latest_reading_id = docs[0].id
        latest_reading = readings[0]

        # 2. Run Anomaly Detection
        is_anomaly, avg_pr, anomalous_readings = detect_anomalies(readings)

        # 3. Calculate Lost Energy over window
        lost_energy_kwh = calculate_lost_energy(anomalous_readings if is_anomaly else readings)

        alert_id = None
        new_alert = False

        if is_anomaly:
            msg = (
                f"Performance Degradation Detected! Average PR dropped to {avg_pr:.2f} "
                f"(Threshold: {PR_THRESHOLD}). Estimated lost generation: {lost_energy_kwh:.3f} kWh."
            )
            alert_id, new_alert = create_alert(
                db=db,
                alert_type="performance_drop",
                message=msg,
                reading_id=latest_reading_id,
                lost_energy_kwh=lost_energy_kwh,
                avg_pr=avg_pr
            )
        else:
            # If system performance is normal (PR >= 0.70), resolve active alerts
            resolve_active_alerts(db, alert_type="performance_drop")

        return {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "latest_reading_id": latest_reading_id,
            "latest_pr": float(latest_reading.get("performance_ratio", 0.0)),
            "average_window_pr": avg_pr,
            "is_anomaly": is_anomaly,
            "anomalous_count": len(anomalous_readings),
            "lost_energy_kwh": lost_energy_kwh,
            "alert_active": is_anomaly,
            "alert_id": alert_id,
            "new_alert_created": new_alert
        }

    except Exception as e:
        print(f"[Analysis ERROR] Exception in run_analysis: {e}", file=sys.stderr)
        return {
            "status": "error",
            "error": str(e)
        }


if __name__ == "__main__":
    print("--- Running Solar Performance Analysis Engine ---")
    result = run_analysis()
    print("\nAnalysis Execution Result:")
    import json
    print(json.dumps(result, indent=2))
