"""
Fake Data Generator for Solar Monitoring System.

Simulates real-time and multi-day historical sensor telemetry from a 12V / 300W rooftop solar panel.
Includes physical correlation (irradiance, ambient/panel temp, humidity, voltage, current)
and realistic historical fault periods (e.g., 12:00 - 14:00 on yesterday & selected days).

Usage:
    python Data_Base/seed_fake_data.py --backfill --days 30  # Backfill 30 days of 5-min readings
    python Data_Base/seed_fake_data.py --live               # Stream live telemetry every 5s
"""

import sys
import os
import time
import math
import random
import argparse
from datetime import datetime, timedelta, timezone

# Configure UTF-8 encoding for standard output on Windows
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure parent directory is in path to import firebase_config
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Data_Base.firebase_config import get_db

# Constants for solar system simulation
PANEL_RATING_WATTS = 300.0  # 300W panel
NOMINAL_VOLTAGE = 12.0      # 12V system rating
SUNRISE_HOUR = 6.0         # 6:00 AM
SUNSET_HOUR = 18.0         # 6:00 PM
COLLECTION_NAME = "readings"


def generate_reading(timestamp: datetime = None, force_fault: bool = False) -> dict:
    """
    Generates a single simulated sensor reading for a given timestamp.

    Args:
        timestamp (datetime, optional): Timestamp for the reading. Defaults to current UTC time.
        force_fault (bool): If True, forces performance degradation to ~60% of expected output.

    Returns:
        dict: Sensor telemetry dictionary containing all physical metrics, expected power, PR, and fault flag.
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    # Decimal hour of the day (e.g. 13.5 for 13:30)
    hour = timestamp.hour + timestamp.minute / 60.0 + timestamp.second / 3600.0

    # 1. Rain simulation (2% probability)
    is_raining = random.random() < 0.02
    rain_val = round(random.uniform(1.2, 5.0), 2) if is_raining else 0.0

    # 2. Irradiance (W/m^2) simulation using Sine Wave (6:00 to 18:00)
    if SUNRISE_HOUR <= hour <= SUNSET_HOUR:
        day_progress = (hour - SUNRISE_HOUR) / (SUNSET_HOUR - SUNRISE_HOUR)
        base_irradiance = 1000.0 * math.sin(day_progress * math.pi)
        
        noise = random.uniform(-0.05, 0.05) * base_irradiance
        irradiance = max(0.0, base_irradiance + noise)

        if is_raining:
            irradiance *= random.uniform(0.1, 0.3)
    else:
        irradiance = 0.0

    # 3. Ambient Temperature (°C)
    temp_day_factor = math.sin(max(0.0, (hour - 5.0) / 14.0) * math.pi) if 5.0 <= hour <= 19.0 else 0.0
    ambient_temp = 20.0 + 12.0 * temp_day_factor + random.uniform(-0.5, 0.5)

    # 4. Panel Temperature (°C)
    sun_heating = (irradiance / 1000.0) * 22.0
    panel_temp = ambient_temp + sun_heating + random.uniform(-0.8, 0.8)

    # 5. Humidity (%)
    humidity = 80.0 - (irradiance / 1000.0) * 35.0 + random.uniform(-2.0, 2.0)
    humidity = max(20.0, min(95.0, humidity))

    # 6. Vibration (m/s^2)
    vibration = max(0.0, round(random.uniform(0.0, 0.05), 3))

    # 7. Expected Power (Watts)
    expected_power = (irradiance / 1000.0) * PANEL_RATING_WATTS

    # 8. Fault Condition Determination: 12:00 PM to 2:00 PM (12.0 <= hour < 14.0)
    is_fault_period = (force_fault or (12.0 <= hour < 14.0)) and expected_power > 10.0

    if force_fault and (12.0 <= hour < 14.0) and expected_power > 10.0:
        is_fault_period = True

    if is_fault_period:
        performance_factor = random.uniform(0.57, 0.63)
    else:
        temp_loss_factor = max(0.0, (panel_temp - 25.0) * 0.004)
        base_efficiency = random.uniform(0.92, 0.96) - temp_loss_factor
        performance_factor = max(0.0, base_efficiency)

    actual_power = expected_power * performance_factor if expected_power > 0 else 0.0

    # 9. Performance Ratio (PR)
    if expected_power > 1.0:
        performance_ratio = round(actual_power / expected_power, 4)
    else:
        performance_ratio = 0.0

    # 10. Voltage (V) & Current (A)
    if irradiance > 10.0:
        voltage = 12.5 + (irradiance / 1000.0) * 1.5 + random.uniform(-0.2, 0.2)
        voltage = max(10.5, min(14.5, voltage))
        current = actual_power / voltage if voltage > 0 else 0.0
    else:
        voltage = round(random.uniform(0.1, 0.8), 2)
        current = 0.0

    reading = {
        "timestamp": timestamp.isoformat(),
        "unix_timestamp": int(timestamp.timestamp()),
        "irradiance": round(irradiance, 2),
        "lux": round(irradiance * 120.0, 2),
        "temperature_ambient": round(ambient_temp, 2),
        "temperature_panel": round(panel_temp, 2),
        "humidity": round(humidity, 2),
        "rain": rain_val,
        "vibration": vibration,
        "voltage": round(voltage, 2),
        "current": round(current, 2),
        "power": round(actual_power, 2),
        "expected_power": round(expected_power, 2),
        "performance_ratio": performance_ratio,
        "fault_injected": is_fault_period
    }

    return reading


def push_reading(db, reading: dict) -> str:
    """Writes a single sensor reading document to Firestore."""
    try:
        doc_id = f"read_{reading['unix_timestamp']}"
        doc_ref = db.collection(COLLECTION_NAME).document(doc_id)
        doc_ref.set(reading)
        return doc_id
    except Exception as e:
        print(f"[Push ERROR] Failed to push reading: {e}", file=sys.stderr)
        raise e


def run_backfill(db, days: int = 30, interval_minutes: int = 5):
    """
    Generates multi-day historical simulated sensor data using batched commits.

    Args:
        db: Firestore client handle.
        days (int): Number of historical days to generate (default: 30).
        interval_minutes (int): Step interval in minutes (default: 5).
    """
    now_utc = datetime.now(timezone.utc)
    start_time = (now_utc - timedelta(days=days)).replace(hour=0, minute=0, second=0, microsecond=0)
    end_time = now_utc

    total_readings_expected = int(((end_time - start_time).total_seconds() / 60) // interval_minutes)
    
    print("\n========================================")
    print("Solar Fake Data Backfill Generator")
    print("========================================")
    print(f"Days: {days}")
    print(f"Interval: {interval_minutes} minutes")
    print(f"Expected readings: {total_readings_expected}")
    print(f"Date range: {start_time.isoformat()} -> {end_time.isoformat()}")
    print("========================================\n", flush=True)

    readings_to_write = []
    fault_count = 0
    current_time = start_time

    while current_time <= end_time:
        day_diff = (now_utc.date() - current_time.date()).days
        
        # Inject 12:00-14:00 fault on yesterday (day_diff == 1) and every 5th day
        should_fault = (day_diff == 1) or (day_diff > 0 and day_diff % 5 == 0)
        
        reading = generate_reading(current_time, force_fault=should_fault)
        if reading["fault_injected"]:
            fault_count += 1

        readings_to_write.append(reading)
        current_time += timedelta(minutes=interval_minutes)

    # Perform Batched Writes in chunks of 450 documents
    BATCH_SIZE = 450
    committed_count = 0
    total_items = len(readings_to_write)

    for i in range(0, total_items, BATCH_SIZE):
        chunk = readings_to_write[i:i + BATCH_SIZE]
        batch = db.batch()
        
        for item in chunk:
            doc_id = f"read_{item['unix_timestamp']}"
            doc_ref = db.collection(COLLECTION_NAME).document(doc_id)
            batch.set(doc_ref, item)

        batch.commit()
        committed_count += len(chunk)
        print(f"  [Progress] Committed batch {i//BATCH_SIZE + 1} | Written {committed_count}/{total_items} readings...", flush=True)

    print("\n========================================")
    print("Backfill Seeding Complete!")
    print("========================================")
    print(f"Total Written / Updated: {committed_count}")
    print(f"Total Fault Readings Injected: {fault_count}")
    print("========================================\n", flush=True)


def run_live(db, interval_seconds: int = 5):
    """Continuously generates and pushes live sensor readings to Firestore."""
    print(f"\n--- Starting Live Sensor Data Streaming (Interval: {interval_seconds}s) ---")
    print("Press Ctrl+C to stop live streaming.\n", flush=True)
    pushed_count = 0

    try:
        while True:
            reading = generate_reading()
            doc_id = push_reading(db, reading)
            pushed_count += 1

            fault_flag = " [FAULT INJECTED]" if reading["fault_injected"] else ""
            print(
                f"[{pushed_count:04d}] Live Push -> {doc_id} | "
                f"Time: {reading['timestamp'][11:19]} | "
                f"Power: {reading['power']:6.2f}W / {reading['expected_power']:6.2f}W | "
                f"PR: {reading['performance_ratio']:.2f} | "
                f"Irr: {reading['irradiance']:6.1f} W/m²{fault_flag}",
                flush=True
            )
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        print(f"\n\n[STOPPED] Live streaming stopped by user. Total pushed: {pushed_count} readings.\n", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Solar Sensor Fake Data Generator for Firestore")
    parser.add_argument(
        "--backfill",
        action="store_true",
        help="Generate historical multi-day data for Firestore"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help="Number of historical days to backfill (default: 30)"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Push one reading every 5 seconds continuously"
    )

    args = parser.parse_args()

    db = get_db()
    if db is None:
        print("❌ Could not connect to Firestore database. Exiting.", file=sys.stderr)
        sys.exit(1)

    if args.backfill or "--backfill" in sys.argv:
        run_backfill(db, days=args.days)
    elif args.live or "--live" in sys.argv:
        run_live(db)
    else:
        print("\n⚠️ No mode specified! Defaulting to --backfill --days 30.")
        run_backfill(db, days=30)


if __name__ == "__main__":
    main()
