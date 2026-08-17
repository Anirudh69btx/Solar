"""
Automated Solar Alert Scheduler — Segment 10.

A standalone, resilient background scheduler that continuously monitors recent
telemetry from ALL registered solar systems and automatically creates alerts
when abnormal solar performance (PR < 0.70 during active generation) is detected.

Architecture:
    Scheduler Loop (Every 5 mins / configurable)
        ↓
    Run Monitoring Cycle
        ↓
    Discover Monitored Systems (Multi-System & Site-Aware)
        ↓
    Fetch Recent Telemetry per System (Bounded Query)
        ↓
    Evaluate Performance (Reuses analysis.py detect_anomalies & calculate_lost_energy)
        ↓
    PR < 0.70 ?
        ├─ YES ──> Check Duplicate Active Alert (1-Hour Suppression Window)
        │              ├─ Active < 1h  ──> Skip Creation & Log
        │              └─ No / Expired ──> Create Alert (Warning / Critical)
        │
        └─ NO  ──> Resolve Active Alert (status = "resolved", active = False)
        ↓
    Wait Configured Interval (time.sleep)
        ↓
    Next Monitoring Cycle
"""

import sys
import os
import math
import time
import logging
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from google.cloud.firestore import FieldFilter

# Ensure project root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db
from BACKEND.analysis import (
    PR_THRESHOLD,
    MIN_EXPECTED_POWER_WATTS,
    SLIDING_WINDOW_SIZE,
    MIN_ANOMALOUS_COUNT,
    detect_anomalies,
    calculate_lost_energy,
    has_active_alert,
    create_alert,
    resolve_active_alerts,
    COLLECTION_READINGS,
    COLLECTION_ALERTS,
)

COLLECTION_SYSTEMS = "systems"
COLLECTION_SITES = "sites"

# Default configuration values
DEFAULT_SCHEDULER_INTERVAL_SECONDS = 300  # 5 minutes
DEFAULT_DUPLICATE_WINDOW_SECONDS = 3600   # 1 hour
DEFAULT_READINGS_WINDOW_SIZE = 10         # Recent readings to fetch per system

# Configure module logger
logger = logging.getLogger("BACKEND.scheduler")


def _safe_float(val: Any, default: float = 0.0) -> float:
    """
    Safely converts a value to float. Returns default on None, NaN, Infinity or ValueError/TypeError.
    """
    if val is None:
        return default
    try:
        f = float(val)
        return default if (math.isnan(f) or math.isinf(f)) else f
    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Configuration Helper
# ---------------------------------------------------------------------------

def get_scheduler_config() -> Dict[str, Any]:
    """
    Loads scheduler runtime configuration from environment variables or defaults.

    Supported Environment Variables:
        - SCHEDULER_INTERVAL_SECONDS (int): Monitoring interval in seconds.
        - SCHEDULER_INTERVAL_MINUTES (int/float): Monitoring interval in minutes (fallback).
        - ALERT_THRESHOLD (float): Performance Ratio threshold (default: 0.70).
        - DUPLICATE_ALERT_WINDOW_SECONDS (int): Window to suppress duplicate alerts (default: 3600).
        - SLIDING_WINDOW_SIZE (int): Number of recent readings evaluated in anomaly detection.
        - MIN_ANOMALOUS_COUNT (int): Minimum anomalous readings required to trigger an alert.

    Returns:
        Dict[str, Any]: Parsed configuration dictionary.
    """
    # 1. Interval
    interval_sec_env = os.environ.get("SCHEDULER_INTERVAL_SECONDS")
    interval_min_env = os.environ.get("SCHEDULER_INTERVAL_MINUTES")

    if interval_sec_env:
        try:
            interval_seconds = max(1, int(float(interval_sec_env)))
        except (ValueError, TypeError):
            interval_seconds = DEFAULT_SCHEDULER_INTERVAL_SECONDS
    elif interval_min_env:
        try:
            interval_seconds = max(1, int(float(interval_min_env) * 60))
        except (ValueError, TypeError):
            interval_seconds = DEFAULT_SCHEDULER_INTERVAL_SECONDS
    else:
        interval_seconds = DEFAULT_SCHEDULER_INTERVAL_SECONDS

    # 2. Threshold
    threshold_env = os.environ.get("ALERT_THRESHOLD")
    if threshold_env:
        try:
            threshold = float(threshold_env)
        except (ValueError, TypeError):
            threshold = PR_THRESHOLD
    else:
        threshold = PR_THRESHOLD

    # 3. Duplicate Suppression Window
    dup_window_env = os.environ.get("DUPLICATE_ALERT_WINDOW_SECONDS")
    if dup_window_env:
        try:
            dup_window = max(0, int(dup_window_env))
        except (ValueError, TypeError):
            dup_window = DEFAULT_DUPLICATE_WINDOW_SECONDS
    else:
        dup_window = DEFAULT_DUPLICATE_WINDOW_SECONDS

    # 4. Window Size & Min Anomalous Count
    window_size_env = os.environ.get("SLIDING_WINDOW_SIZE")
    min_count_env = os.environ.get("MIN_ANOMALOUS_COUNT")

    try:
        window_size = int(window_size_env) if window_size_env else SLIDING_WINDOW_SIZE
    except (ValueError, TypeError):
        window_size = SLIDING_WINDOW_SIZE

    try:
        min_count = int(min_count_env) if min_count_env else MIN_ANOMALOUS_COUNT
    except (ValueError, TypeError):
        min_count = MIN_ANOMALOUS_COUNT

    return {
        "interval_seconds": interval_seconds,
        "interval_minutes": interval_seconds / 60.0,
        "alert_threshold": threshold,
        "duplicate_window_seconds": dup_window,
        "sliding_window_size": window_size,
        "min_anomalous_count": min_count,
    }


# ---------------------------------------------------------------------------
# Multi-System Discovery
# ---------------------------------------------------------------------------

def fetch_monitored_systems(db) -> List[Dict[str, Any]]:
    """
    Discovers all solar systems to monitor.
    Queries the 'systems' collection in Firestore, and cross-references recent
    telemetry in 'readings' to detect any active standalone or unregistered systems.

    Returns:
        List[Dict[str, Any]]: List of system descriptors, each containing:
            - system_id (str or None)
            - site_id (str or None)
            - name (str)
            - owner_uid (str or None)
    """
    systems_map: Dict[Optional[str], Dict[str, Any]] = {}

    # 1. Query registered systems from the 'systems' collection
    try:
        systems_ref = db.collection(COLLECTION_SYSTEMS)
        for doc in systems_ref.stream():
            data = doc.to_dict() or {}
            sys_id = data.get("system_id") or doc.id
            systems_map[sys_id] = {
                "system_id": sys_id,
                "site_id": data.get("site_id"),
                "name": data.get("name", f"System {sys_id}"),
                "owner_uid": data.get("owner_uid"),
                "source": "registered_systems"
            }
    except Exception as e:
        logger.warning(f"Unable to query '{COLLECTION_SYSTEMS}' collection: {e}")

    # 2. Check recent readings to discover systems with active telemetry
    try:
        readings_ref = db.collection(COLLECTION_READINGS)
        recent_docs = readings_ref.order_by("unix_timestamp", direction="DESCENDING").limit(50).stream()
        for doc in recent_docs:
            r_data = doc.to_dict() or {}
            r_sys_id = r_data.get("system_id")
            r_site_id = r_data.get("site_id")

            if r_sys_id not in systems_map:
                systems_map[r_sys_id] = {
                    "system_id": r_sys_id,
                    "site_id": r_site_id,
                    "name": f"System {r_sys_id}" if r_sys_id else "Standalone Solar System",
                    "owner_uid": None,
                    "source": "telemetry_discovery"
                }
            elif systems_map[r_sys_id].get("site_id") is None and r_site_id is not None:
                systems_map[r_sys_id]["site_id"] = r_site_id
    except Exception as e:
        logger.debug(f"Telemetry system discovery note: {e}")

    # 3. If no registered or identified systems found, check if standalone readings exist
    if not systems_map:
        try:
            readings_ref = db.collection(COLLECTION_READINGS)
            sample_docs = list(readings_ref.limit(1).stream())
            if sample_docs:
                systems_map[None] = {
                    "system_id": None,
                    "site_id": None,
                    "name": "Standalone Solar Installation",
                    "owner_uid": None,
                    "source": "standalone_default"
                }
        except Exception:
            pass

    return list(systems_map.values())


# ---------------------------------------------------------------------------
# Bounded Telemetry Retrieval per System
# ---------------------------------------------------------------------------

def fetch_recent_readings_for_system(
    db,
    system_id: Optional[str],
    limit: int = DEFAULT_READINGS_WINDOW_SIZE
) -> List[Dict[str, Any]]:
    """
    Fetches the most recent telemetry readings for a specific solar system.
    Uses bounded Firestore-side queries with robust in-memory fallback.

    Args:
        db: Firestore client handle.
        system_id (str, optional): The system identifier to filter by (or None for standalone).
        limit (int): Maximum number of recent readings to fetch.

    Returns:
        List[Dict[str, Any]]: List of reading dicts ordered newest first, with 'id' populated.
    """
    readings_ref = db.collection(COLLECTION_READINGS)
    readings: List[Dict[str, Any]] = []

    try:
        if system_id is not None:
            # Query with system_id filter
            try:
                query = (
                    readings_ref
                    .where(filter=FieldFilter("system_id", "==", system_id))
                    .order_by("unix_timestamp", direction="DESCENDING")
                    .limit(limit)
                )
                docs = list(query.stream())
            except Exception:
                # Fallback without order_by in case composite index is not active in dev/test
                query = (
                    readings_ref
                    .where(filter=FieldFilter("system_id", "==", system_id))
                )
                docs = list(query.stream())
        else:
            # Standalone / unassigned readings query
            try:
                query = readings_ref.order_by("unix_timestamp", direction="DESCENDING").limit(limit * 2)
                docs = list(query.stream())
            except Exception:
                docs = list(readings_ref.limit(limit * 2).stream())

        for doc in docs:
            data = doc.to_dict() or {}
            data["id"] = doc.id
            if system_id is not None:
                if data.get("system_id") == system_id:
                    readings.append(data)
            else:
                # Standalone: matches readings where system_id is None or missing
                if data.get("system_id") is None:
                    readings.append(data)

        # Sort newest first by unix_timestamp or timestamp
        def _get_sort_ts(r):
            if "unix_timestamp" in r and r["unix_timestamp"] is not None:
                try:
                    return float(r["unix_timestamp"])
                except (ValueError, TypeError):
                    pass
            if "timestamp" in r and r["timestamp"]:
                try:
                    dt = datetime.fromisoformat(str(r["timestamp"]).replace("Z", "+00:00"))
                    return dt.timestamp()
                except Exception:
                    pass
            return 0.0

        readings.sort(key=_get_sort_ts, reverse=True)
        return readings[:limit]

    except Exception as e:
        logger.error(f"Error fetching readings for system '{system_id}': {e}")
        return []


# ---------------------------------------------------------------------------
# Performance Evaluation & Alert Creation Helpers
# ---------------------------------------------------------------------------

def evaluate_system_performance(
    readings: List[Dict[str, Any]],
    threshold: float = PR_THRESHOLD,
    sliding_window_size: int = SLIDING_WINDOW_SIZE,
    min_anomalous_count: int = MIN_ANOMALOUS_COUNT
) -> Tuple[bool, float, float, List[Dict[str, Any]]]:
    """
    Evaluates telemetry using the shared analysis anomaly detection engine.

    Args:
        readings (List[Dict]): Telemetry readings ordered newest first.
        threshold (float): PR breach threshold (default: 0.70).
        sliding_window_size (int): Evaluation window size.
        min_anomalous_count (int): Minimum breach count.

    Returns:
        Tuple[bool, float, float, List[Dict]]:
            - is_anomaly (bool): True if performance drop is detected.
            - avg_pr (float): Average performance ratio across active daytime readings.
            - lost_energy_kwh (float): Estimated energy loss in kWh.
            - anomalous_readings (List[Dict]): Breached reading objects.
    """
    if not readings:
        return False, 0.0, 0.0, []

    window = readings[:sliding_window_size]

    # Filter daytime readings where sun generation is expected (> 10W)
    daytime_readings = [
        r for r in window
        if _safe_float(r.get("expected_power")) > MIN_EXPECTED_POWER_WATTS
    ]

    if not daytime_readings:
        return False, 0.0, 0.0, []

    # Identify readings where PR < threshold
    anomalous_readings = [
        r for r in daytime_readings
        if _safe_float(r.get("performance_ratio")) < threshold
    ]

    total_pr = sum(_safe_float(r.get("performance_ratio")) for r in daytime_readings)
    avg_pr = round(total_pr / len(daytime_readings), 4)

    # Dynamic minimum count if window has fewer daytime readings than default threshold
    required_breach_count = min(min_anomalous_count, len(daytime_readings))
    is_anomaly = len(anomalous_readings) >= required_breach_count

    lost_energy_kwh = calculate_lost_energy(anomalous_readings if is_anomaly else daytime_readings)

    return is_anomaly, avg_pr, lost_energy_kwh, anomalous_readings


def check_duplicate_alert(
    db,
    system_id: Optional[str],
    alert_type: str = "performance_drop",
    max_age_seconds: int = DEFAULT_DUPLICATE_WINDOW_SECONDS
) -> Optional[Dict[str, Any]]:
    """
    Checks if an active alert already exists for the given system within the duplicate suppression window.

    Duplicate Condition:
        - same system_id
        - same alert type ("performance_drop")
        - status = active (active == True)
        - alert created within the last 1 hour (max_age_seconds)

    Args:
        db: Firestore database handle.
        system_id (str, optional): System identifier.
        alert_type (str): Alert type to query.
        max_age_seconds (int): Maximum age in seconds for duplicate suppression.

    Returns:
        Optional[Dict[str, Any]]: Existing active alert if duplicate condition is met, else None.
    """
    return has_active_alert(
        db=db,
        alert_type=alert_type,
        system_id=system_id,
        max_age_seconds=max_age_seconds
    )


def create_performance_alert(
    db,
    system_id: Optional[str],
    site_id: Optional[str],
    pr: float,
    threshold: float,
    reading_id: str,
    lost_energy_kwh: float,
    message: Optional[str] = None
) -> Tuple[str, bool]:
    """
    Creates a new performance drop alert record in Firestore using the shared alert engine.

    Args:
        db: Firestore client handle.
        system_id (str, optional): System ID.
        site_id (str, optional): Associated Site ID.
        pr (float): Measured average PR.
        threshold (float): Configured threshold.
        reading_id (str): ID of anomalous reading.
        lost_energy_kwh (float): Estimated lost kWh.
        message (str, optional): Human-readable alert message.

    Returns:
        Tuple[str, bool]: (alert_id, is_newly_created)
    """
    # Classify severity
    severity = "warning" if pr >= 0.50 else "critical"

    if not message:
        sys_str = f" for system {system_id}" if system_id else ""
        message = (
            f"Solar system performance has dropped below {int(threshold * 100)}%{sys_str}. "
            f"Average PR: {pr:.2f} (Severity: {severity}). Estimated lost generation: {lost_energy_kwh:.3f} kWh."
        )

    return create_alert(
        db=db,
        alert_type="performance_drop",
        message=message,
        reading_id=reading_id,
        lost_energy_kwh=lost_energy_kwh,
        avg_pr=pr,
        system_id=system_id,
        site_id=site_id,
        severity=severity,
        threshold=threshold,
        max_duplicate_age_seconds=DEFAULT_DUPLICATE_WINDOW_SECONDS
    )


# ---------------------------------------------------------------------------
# Individual System Processor (Isolated Execution)
# ---------------------------------------------------------------------------

def process_system(
    db,
    system_info: Dict[str, Any],
    config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Monitors and evaluates a single solar system independently.
    Errors during processing of this system are caught and returned without halting other systems.

    Args:
        db: Firestore database handle.
        system_info (Dict[str, Any]): System metadata (system_id, site_id, name).
        config (Dict[str, Any]): Scheduler runtime configuration.

    Returns:
        Dict[str, Any]: Processing report for the system.
    """
    system_id = system_info.get("system_id")
    site_id = system_info.get("site_id")
    system_name = system_info.get("name", f"System {system_id}")
    threshold = config["alert_threshold"]
    sys_tag = system_id or "STANDALONE"

    report: Dict[str, Any] = {
        "system_id": system_id,
        "site_id": site_id,
        "system_name": system_name,
        "status": "ok",
        "readings_count": 0,
        "latest_pr": None,
        "is_anomaly": False,
        "alert_created": False,
        "alert_skipped": False,
        "alert_resolved": False,
        "alert_id": None,
        "error": None
    }

    try:
        # 1. Fetch recent readings
        readings = fetch_recent_readings_for_system(
            db=db,
            system_id=system_id,
            limit=config.get("sliding_window_size", SLIDING_WINDOW_SIZE) * 2
        )
        report["readings_count"] = len(readings)

        if not readings:
            logger.info(f"System {sys_tag} checked. No recent readings found.")
            return report

        latest_reading = readings[0]
        latest_reading_id = latest_reading.get("id", "unknown_reading")
        latest_pr = _safe_float(latest_reading.get("performance_ratio"))
        report["latest_pr"] = latest_pr

        # 2. Evaluate performance
        is_anomaly, avg_pr, lost_energy_kwh, anomalous_readings = evaluate_system_performance(
            readings=readings,
            threshold=threshold,
            sliding_window_size=config.get("sliding_window_size", SLIDING_WINDOW_SIZE),
            min_anomalous_count=config.get("min_anomalous_count", MIN_ANOMALOUS_COUNT)
        )
        report["is_anomaly"] = is_anomaly
        report["average_pr"] = avg_pr
        report["lost_energy_kwh"] = lost_energy_kwh

        logger.info(
            f"System {sys_tag} checked. "
            f"Readings: {len(readings)}, Latest PR: {latest_pr:.2f}, Average PR: {avg_pr:.2f}, Threshold: {threshold:.2f}"
        )

        # 3. Anomaly Handling & Duplicate Check
        if is_anomaly:
            logger.warning(
                f"Performance drop detected for system {sys_tag}! Average PR: {avg_pr:.2f} (Threshold: {threshold:.2f})"
            )

            # Check if active duplicate alert exists within the 1-hour window
            duplicate_alert = check_duplicate_alert(
                db=db,
                system_id=system_id,
                alert_type="performance_drop",
                max_age_seconds=config.get("duplicate_window_seconds", DEFAULT_DUPLICATE_WINDOW_SECONDS)
            )

            if duplicate_alert:
                logger.info(
                    f"Existing active alert found for system {sys_tag} (Alert ID: {duplicate_alert.get('id')}); "
                    "new alert creation skipped."
                )
                report["alert_skipped"] = True
                report["alert_id"] = duplicate_alert.get("id")
            else:
                # Create new alert record
                alert_id, is_new = create_performance_alert(
                    db=db,
                    system_id=system_id,
                    site_id=site_id,
                    pr=avg_pr,
                    threshold=threshold,
                    reading_id=latest_reading_id,
                    lost_energy_kwh=lost_energy_kwh
                )
                report["alert_created"] = is_new
                report["alert_id"] = alert_id
                logger.info(f"Performance-drop alert created for system {sys_tag} (Alert ID: {alert_id}).")
        else:
            # System performance is normal (PR >= threshold) -> resolve active alerts if any
            resolved_count = resolve_active_alerts(
                db=db,
                alert_type="performance_drop",
                system_id=system_id
            )
            if resolved_count > 0:
                report["alert_resolved"] = True
                logger.info(f"Resolved {resolved_count} active alert(s) for system {sys_tag} as performance recovered.")

        return report

    except Exception as exc:
        err_msg = f"Unexpected system processing error for system {sys_tag}: {exc}"
        logger.error(err_msg, exc_info=True)
        report["status"] = "error"
        report["error"] = str(exc)
        return report


# ---------------------------------------------------------------------------
# Monitoring Cycle Entry Point
# ---------------------------------------------------------------------------

def run_monitoring_cycle(
    db=None,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes a complete monitoring cycle across all registered and active solar systems.

    Flow:
        1. Obtain active Firestore DB client
        2. Discover all solar systems (multi-system + site-aware)
        3. Evaluate each system independently (isolated error handling)
        4. Detect PR < 0.70 anomalies
        5. Enforce 1-hour duplicate suppression
        6. Create or resolve alerts
        7. Summarize cycle telemetry & return metrics

    Args:
        db: Firestore client handle (optional, fetched via get_db() if None).
        config (Dict, optional): Scheduler configuration (fetched via get_scheduler_config() if None).

    Returns:
        Dict[str, Any]: Cycle summary containing execution metrics and per-system reports.
    """
    if config is None:
        config = get_scheduler_config()

    start_time = datetime.now(timezone.utc)
    logger.info("Monitoring cycle started.")

    summary: Dict[str, Any] = {
        "status": "completed",
        "timestamp": start_time.isoformat(),
        "systems_checked": 0,
        "alerts_created": 0,
        "alerts_skipped": 0,
        "alerts_resolved": 0,
        "errors_count": 0,
        "system_reports": [],
        "errors": []
    }

    try:
        if db is None:
            db = get_db()

        if db is None:
            err = "Firestore database connection handle is unavailable."
            logger.error(f"Firestore error during monitoring cycle: {err}")
            summary["status"] = "database_unavailable"
            summary["errors"].append(err)
            return summary

        # 1. Discover all monitored systems
        monitored_systems = fetch_monitored_systems(db)

        if not monitored_systems:
            logger.info("No registered systems or telemetry readings found to monitor.")
            return summary

        summary["systems_checked"] = len(monitored_systems)

        # 2. Process each system independently
        for sys_info in monitored_systems:
            sys_report = process_system(db=db, system_info=sys_info, config=config)
            summary["system_reports"].append(sys_report)

            if sys_report.get("alert_created"):
                summary["alerts_created"] += 1
            if sys_report.get("alert_skipped"):
                summary["alerts_skipped"] += 1
            if sys_report.get("alert_resolved"):
                summary["alerts_resolved"] += 1
            if sys_report.get("status") == "error":
                summary["errors_count"] += 1
                summary["errors"].append(
                    f"System {sys_info.get('system_id', 'unknown')}: {sys_report.get('error')}"
                )

        if summary["errors_count"] > 0:
            summary["status"] = "partial_success" if summary["systems_checked"] > summary["errors_count"] else "error"

        logger.info(
            f"Monitoring cycle completed. Systems checked: {summary['systems_checked']}, "
            f"Alerts created: {summary['alerts_created']}, Alerts skipped (suppressed): {summary['alerts_skipped']}, "
            f"Alerts resolved: {summary['alerts_resolved']}."
        )

        return summary

    except Exception as e:
        err_msg = f"Firestore error during monitoring cycle: {e}"
        logger.error(err_msg, exc_info=True)
        summary["status"] = "error"
        summary["errors"].append(str(e))
        return summary


# ---------------------------------------------------------------------------
# Continuous Scheduler Loop
# ---------------------------------------------------------------------------

def start_scheduler(
    interval_seconds: Optional[int] = None,
    max_cycles: Optional[int] = None,
    stop_event: Optional[threading.Event] = None,
    db=None
):
    """
    Starts and runs the continuous background monitoring loop.

    Args:
        interval_seconds (int, optional): Monitoring interval in seconds (default: from config).
        max_cycles (int, optional): Optional limit on number of cycles (used in testing).
        stop_event (threading.Event, optional): Optional event signal to stop loop cleanly.
        db (optional): Firestore client handle.
    """
    config = get_scheduler_config()
    if interval_seconds is not None:
        config["interval_seconds"] = interval_seconds
        config["interval_minutes"] = interval_seconds / 60.0

    interval = config["interval_seconds"]
    interval_min = config["interval_minutes"]

    print("============================================================")
    print("       Automated Solar Alert Scheduler started.             ")
    print(f"       Monitoring interval: {interval_min:.1f} minutes ({interval}s).")
    print(f"       Alert threshold PR: < {config['alert_threshold']:.2f}")
    print("============================================================", flush=True)

    logger.info(f"Scheduler started. Monitoring interval: {interval_min:.1f} minutes ({interval}s).")

    cycle_count = 0

    while True:
        if stop_event and stop_event.is_set():
            logger.info("Scheduler received stop signal. Terminating loop.")
            break

        if max_cycles is not None and cycle_count >= max_cycles:
            logger.info(f"Scheduler reached execution limit of {max_cycles} cycle(s). Stopping.")
            break

        try:
            run_monitoring_cycle(db=db, config=config)
        except Exception as e:
            logger.error(f"Unexpected exception during monitoring cycle: {e}", exc_info=True)

        cycle_count += 1
        if max_cycles is not None and cycle_count >= max_cycles:
            break

        # Sleep interval or wait on stop event
        if stop_event:
            interrupted = stop_event.wait(timeout=interval)
            if interrupted:
                break
        else:
            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                print("\n[Scheduler] KeyboardInterrupt received. Shutting down gracefully...", flush=True)
                logger.info("Scheduler interrupted by user. Shutting down.")
                break


# ---------------------------------------------------------------------------
# CLI Entrypoint for Standalone Execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    start_scheduler()
