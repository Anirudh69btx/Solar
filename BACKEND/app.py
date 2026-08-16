"""
Flask Application Entry Point for Solar Monitoring System Backend.

Exposes REST APIs for IoT sensor ingestion, latest telemetry querying,
alert notifications, and system health checks.
"""

import os
import sys
import time
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS

from google.cloud.firestore import FieldFilter

# Add project root to sys.path to enable imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db
from BACKEND.analysis import run_analysis
from BACKEND.chatbot import get_chat_response
from BACKEND.auth import auth_bp
from BACKEND.sites import sites_bp
from BACKEND.systems import systems_bp
from BACKEND.assignments import assignments_bp
from BACKEND.reports import reports_bp

# Configure backend logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Enable CORS for all routes (enables future React/Vue/Angular frontend integration)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Register Authentication Blueprint
app.register_blueprint(auth_bp)

# Register Solar Sites Blueprint (Multi-Site Management)
app.register_blueprint(sites_bp)

# Register Solar Systems Blueprint (Segment 8)
app.register_blueprint(systems_bp)

# Register Technician Assignments Blueprint
app.register_blueprint(assignments_bp)

# Register Solar Reports Blueprint (Segment 9)
app.register_blueprint(reports_bp)

COLLECTION_READINGS = "readings"
COLLECTION_ALERTS = "alerts"


@app.route("/api/health", methods=["GET"])
def health_check():
    """
    Health check endpoint.
    Returns:
        JSON response with system status and server UTC timestamp.
    """
    return jsonify({
        "status": "ok",
        "service": "Solar Monitoring Backend API",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


@app.route("/api/readings/latest", methods=["GET"])
def get_latest_readings():
    """
    Retrieves the latest readings from Firestore, ordered by timestamp descending.
    Query Params:
        limit (int, optional): Number of readings to fetch (default: 50, max: 200).

    Returns:
        JSON list of telemetry objects.
    """
    try:
        limit_param = request.args.get("limit", default=50, type=int)
        limit_val = min(max(1, limit_param), 200)

        db = get_db()
        if db is None:
            logger.error("Database connection unavailable in /api/readings/latest")
            return jsonify({"error": "Database connection unavailable"}), 500

        # Query readings collection ordered by unix_timestamp descending
        readings_ref = db.collection(COLLECTION_READINGS)
        query = readings_ref.order_by("unix_timestamp", direction="DESCENDING").limit(limit_val)
        
        docs = query.stream()
        readings = []

        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            readings.append(data)

        return jsonify(readings), 200

    except Exception as e:
        logger.exception(f"Error in /api/readings/latest: {e}")
        return jsonify({
            "error": "Failed to fetch latest readings",
            "details": str(e)
        }), 500


@app.route("/api/ingest", methods=["POST"])
def ingest_reading():
    """
    Ingests a new sensor reading JSON payload and writes it to Firestore.
    Expected Payload Fields:
        - voltage (float/int) [Required]
        - current (float/int) [Required]
        - power (float/int) [Required]
        - expected_power (float/int) [Required]
        - timestamp (str ISO format, optional)
        - irradiance or lux (float, optional)
        - temperature_ambient, temperature_panel, humidity, vibration (optional)

    Returns:
        JSON object with created document ID and status 201.
    """
    try:
        payload = request.get_json(silent=True)
        if not payload or not isinstance(payload, dict):
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        # Required numerical fields validation
        required_fields = ["voltage", "current", "power", "expected_power"]
        missing_fields = [field for field in required_fields if field not in payload]

        if missing_fields:
            return jsonify({
                "error": "Validation failed",
                "missing_required_fields": missing_fields
            }), 400

        # Type conversion & validation
        try:
            voltage = float(payload["voltage"])
            current = float(payload["current"])
            power = float(payload["power"])
            expected_power = float(payload["expected_power"])
        except (ValueError, TypeError):
            return jsonify({"error": "Fields 'voltage', 'current', 'power', and 'expected_power' must be numeric"}), 400

        # Timestamp normalization
        raw_timestamp = payload.get("timestamp")
        if raw_timestamp:
            try:
                # Validate ISO format parse
                parsed_dt = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
                timestamp_str = parsed_dt.isoformat()
                unix_ts = int(parsed_dt.timestamp())
            except ValueError:
                return jsonify({"error": "Invalid 'timestamp' format. Must be valid ISO 8601 string."}), 400
        else:
            now_dt = datetime.now(timezone.utc)
            timestamp_str = now_dt.isoformat()
            unix_ts = int(now_dt.timestamp())

        # Handle Lux / Irradiance conversion if specified
        irradiance = payload.get("irradiance")
        lux = payload.get("lux")
        if irradiance is None and lux is not None:
            try:
                irradiance = round(float(lux) / 120.0, 2)
            except (ValueError, TypeError):
                irradiance = 0.0
        elif irradiance is not None:
            try:
                irradiance = float(irradiance)
            except (ValueError, TypeError):
                irradiance = 0.0
        else:
            irradiance = 0.0

        # Performance Ratio calculation if missing
        pr = payload.get("performance_ratio")
        if pr is None:
            pr = round(power / expected_power, 4) if expected_power > 1.0 else 0.0
        else:
            pr = float(pr)

        # Assemble cleaned reading dictionary
        cleaned_reading = {
            "timestamp": timestamp_str,
            "unix_timestamp": payload.get("unix_timestamp", unix_ts),
            "voltage": round(voltage, 2),
            "current": round(current, 2),
            "power": round(power, 2),
            "expected_power": round(expected_power, 2),
            "performance_ratio": pr,
            "irradiance": round(irradiance, 2),
            "lux": round(float(lux), 2) if lux is not None else round(irradiance * 120.0, 2),
            "temperature_ambient": float(payload.get("temperature_ambient", 25.0)),
            "temperature_panel": float(payload.get("temperature_panel", 35.0)),
            "humidity": float(payload.get("humidity", 50.0)),
            "vibration": float(payload.get("vibration", 0.0)),
            "rain": float(payload.get("rain", 0.0)),
            "fault_injected": bool(payload.get("fault_injected", False))
        }

        db = get_db()
        if db is None:
            logger.error("Database connection unavailable in /api/ingest")
            return jsonify({"error": "Database connection unavailable"}), 500

        doc_id = f"read_{cleaned_reading['unix_timestamp']}"
        doc_ref = db.collection(COLLECTION_READINGS).document(doc_id)
        doc_ref.set(cleaned_reading)

        # Automatically trigger performance analysis & alert engine
        analysis_result = run_analysis(db=db)

        return jsonify({
            "message": "Sensor data ingested successfully",
            "doc_id": doc_id,
            "data": cleaned_reading,
            "analysis": analysis_result
        }), 201

    except Exception as e:
        logger.exception(f"Error in /api/ingest: {e}")
        return jsonify({
            "error": "Failed to ingest sensor data",
            "details": str(e)
        }), 500


@app.route("/api/alerts", methods=["GET"])
def get_active_alerts():
    """
    Retrieves active alerts from the Firestore 'alerts' collection.
    Query Params:
        active_only (bool, optional): If 'true' (default), returns only active alerts (active == True).

    Returns:
        JSON list of alert documents.
    """
    try:
        active_only = request.args.get("active_only", default="true").lower() in ("true", "1", "yes")

        db = get_db()
        if db is None:
            logger.error("Database connection unavailable in /api/alerts")
            return jsonify({"error": "Database connection unavailable"}), 500

        alerts_ref = db.collection(COLLECTION_ALERTS)
        
        if active_only:
            query = alerts_ref.where(filter=FieldFilter("active", "==", True))
        else:
            query = alerts_ref

        docs = query.stream()
        alerts = []

        for doc in docs:
            alert_data = doc.to_dict()
            alert_data["id"] = doc.id
            alerts.append(alert_data)

        # Sort by timestamp descending if timestamp exists
        alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return jsonify(alerts), 200

    except Exception as e:
        logger.exception(f"Error in /api/alerts: {e}")
        return jsonify({
            "error": "Failed to fetch alerts",
            "details": str(e)
        }), 500


@app.route("/api/analysis/run", methods=["POST", "GET"])
def trigger_analysis():
    """
    Triggers the performance analysis & alert engine on demand.
    Returns:
        JSON response summarizing analysis results, active alerts, and lost energy.
    """
    try:
        db = get_db()
        if db is None:
            logger.error("Database connection unavailable in /api/analysis/run")
            return jsonify({"error": "Database connection unavailable"}), 500

        result = run_analysis(db=db)
        return jsonify(result), 200

    except Exception as e:
        logger.exception(f"Error in /api/analysis/run: {e}")
        return jsonify({
            "error": "Failed to run analysis engine",
            "details": str(e)
        }), 500


@app.route("/api/chat", methods=["GET"])
def chat_endpoint():
    """
    Chatbot endpoint. Accepts 'query' parameter and returns data-backed response.
    Query Params:
        query (str): User's natural language question.

    Returns:
        JSON response with query, answer, and UTC timestamp.
    """
    try:
        user_query = request.args.get("query", default="", type=str)
        if not user_query:
            return jsonify({
                "error": "Query parameter 'query' is required. Example: /api/chat?query=What is my current power generation?"
            }), 400

        db = get_db()
        response_text = get_chat_response(query=user_query, db=db)

        return jsonify({
            "query": user_query,
            "response": response_text,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200

    except Exception as e:
        logger.exception(f"Error in /api/chat: {e}")
        return jsonify({
            "error": "Failed to process chat query",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    logger.info("Starting Solar Monitoring System Backend API Server on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)
