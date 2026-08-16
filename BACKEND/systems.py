"""
Solar System Registration & CRUD Module — Segment 8 & Multi-Site Connected.

Manages individual solar installation records stored in the Firestore
'systems' collection.  All endpoints require Firebase authentication
(Segment 7 @require_auth / @require_role decorators) and enforce strict
ownership and technician assignment based access control.

Role matrix:
                    OWNER       TECHNICIAN         ADMIN
  CREATE            YES         NO                 YES
  LIST              own only    assigned only      all
  GET               own only    assigned only      all
  UPDATE            own only    403                all
  DELETE            NO          NO                 YES
"""

import sys
import os
import logging
import math
import uuid
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, g
from google.cloud.firestore import FieldFilter

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db
from BACKEND.auth import require_auth, require_role

logger = logging.getLogger(__name__)

systems_bp = Blueprint("systems", __name__)

COLLECTION_SYSTEMS = "systems"
COLLECTION_SITES = "sites"
COLLECTION_ASSIGNMENTS = "assignments"
IMMUTABLE_FIELDS = {"system_id", "owner_uid", "created_at"}
MAX_NAME_LENGTH = 150
MAX_QR_LENGTH = 500


# ---------------------------------------------------------------------------
# Helper: ID generation
# ---------------------------------------------------------------------------

def generate_system_id(db=None, max_retries: int = 5) -> str:
    """
    Generate a collision-resistant system ID in the format SYS-XXXXXXXX.
    Uses the first 8 hex characters of a random UUID (uppercase).
    """
    for attempt in range(max_retries):
        sid = "SYS-" + uuid.uuid4().hex[:8].upper()
        if db is not None:
            doc = db.collection(COLLECTION_SYSTEMS).document(sid).get()
            if doc.exists:
                logger.warning(
                    f"System ID collision on attempt {attempt + 1}: '{sid}'. Regenerating."
                )
                continue
        return sid
    raise RuntimeError(
        f"Failed to generate a unique system ID after {max_retries} attempts."
    )


# ---------------------------------------------------------------------------
# Helper: atomic system creation
# ---------------------------------------------------------------------------

def create_system_atomic(db, doc_data: dict, max_retries: int = 5) -> tuple[str, dict]:
    """
    Atomically writes a new system document to Firestore using collision-safe creation.
    """
    for attempt in range(max_retries):
        system_id = generate_system_id()
        doc_ref = db.collection(COLLECTION_SYSTEMS).document(system_id)
        candidate_data = dict(doc_data)
        candidate_data["system_id"] = system_id

        try:
            if hasattr(doc_ref, "create"):
                doc_ref.create(candidate_data)
            else:
                existing = doc_ref.get()
                if existing.exists:
                    logger.warning(
                        f"System ID collision detected on attempt {attempt + 1}: '{system_id}'. Retrying."
                    )
                    continue
                doc_ref.set(candidate_data)
            return system_id, candidate_data
        except Exception as exc:
            exc_name = type(exc).__name__
            if "AlreadyExists" in exc_name or "Conflict" in exc_name or "already exists" in str(exc).lower():
                logger.warning(
                    f"System ID collision detected on attempt {attempt + 1} for '{system_id}': {exc}. Retrying."
                )
                continue
            raise

    raise RuntimeError(
        f"Failed to atomically create solar system after {max_retries} attempts due to ID collisions."
    )


# ---------------------------------------------------------------------------
# Helper: timestamp parsing
# ---------------------------------------------------------------------------

def parse_iso_timestamp(value: str, field_name: str = "timestamp"):
    """
    Parse an ISO-8601 string into a timezone-aware UTC datetime.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{field_name}' must be a non-empty ISO-8601 string.")
    try:
        normalized = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"'{field_name}' is not a valid ISO-8601 timestamp: '{value}'"
        ) from exc


# ---------------------------------------------------------------------------
# Helper: component validation
# ---------------------------------------------------------------------------

def validate_component(component: dict, index: int) -> dict:
    """
    Validate a single solar component dictionary.
    """
    if not isinstance(component, dict):
        raise ValueError(f"Component at index {index} must be an object/dict.")

    required_component_fields = ["type", "model", "serial"]
    for field in required_component_fields:
        val = component.get(field)
        if not val or not isinstance(val, str) or not val.strip():
            raise ValueError(
                f"Component at index {index}: '{field}' is required and must be a non-empty string."
            )

    cleaned = {
        "type": component["type"].strip(),
        "model": component["model"].strip(),
        "serial": component["serial"].strip(),
    }

    warranty_raw = component.get("warranty_until")
    if warranty_raw is not None:
        cleaned["warranty_until"] = parse_iso_timestamp(
            warranty_raw, field_name=f"components[{index}].warranty_until"
        )
    return cleaned


# ---------------------------------------------------------------------------
# Helper: full payload validation
# ---------------------------------------------------------------------------

def validate_system_payload(data: dict) -> dict:
    """
    Validate and clean the POST/PUT system request body.
    """
    cleaned = {}

    # --- name ---
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ValueError("'name' is required and must be a non-empty string.")
    name = name.strip()
    if len(name) > MAX_NAME_LENGTH:
        raise ValueError(f"'name' must not exceed {MAX_NAME_LENGTH} characters.")
    cleaned["name"] = name

    # --- location ---
    location = data.get("location")
    if not isinstance(location, dict):
        raise ValueError("'location' is required and must be an object with 'lat' and 'lng'.")

    lat = location.get("lat")
    lng = location.get("lng")

    if lat is None or lng is None:
        raise ValueError("'location.lat' and 'location.lng' are required.")

    try:
        lat = float(lat)
        lng = float(lng)
    except (ValueError, TypeError):
        raise ValueError("'location.lat' and 'location.lng' must be numeric values.")

    # Reject NaN and Infinity explicitly
    if not math.isfinite(lat):
        raise ValueError(f"'location.lat' must be a finite number. Got: {lat}")
    if not math.isfinite(lng):
        raise ValueError(f"'location.lng' must be a finite number. Got: {lng}")

    if not (-90.0 <= lat <= 90.0):
        raise ValueError(f"'location.lat' must be between -90 and 90. Got: {lat}")
    if not (-180.0 <= lng <= 180.0):
        raise ValueError(f"'location.lng' must be between -180 and 180. Got: {lng}")

    cleaned["location"] = {"lat": lat, "lng": lng}

    # --- installation_date ---
    installation_date_raw = data.get("installation_date")
    if installation_date_raw is None:
        raise ValueError("'installation_date' is required.")
    cleaned["installation_date"] = parse_iso_timestamp(
        installation_date_raw, field_name="installation_date"
    )

    # --- panel_capacity_watts ---
    panel_capacity = data.get("panel_capacity_watts")
    if panel_capacity is None:
        raise ValueError("'panel_capacity_watts' is required.")
    try:
        panel_capacity = float(panel_capacity)
    except (ValueError, TypeError):
        raise ValueError("'panel_capacity_watts' must be a numeric value.")
    if not math.isfinite(panel_capacity):
        raise ValueError("'panel_capacity_watts' must be a finite positive number.")
    if panel_capacity <= 0:
        raise ValueError("'panel_capacity_watts' must be greater than 0.")
    cleaned["panel_capacity_watts"] = panel_capacity

    # --- inverter_type ---
    inverter_type = data.get("inverter_type")
    if not isinstance(inverter_type, str) or not inverter_type.strip():
        raise ValueError("'inverter_type' is required and must be a non-empty string.")
    cleaned["inverter_type"] = inverter_type.strip()

    # --- components (optional) ---
    if "components" in data:
        components_raw = data["components"]
        if components_raw is None or not isinstance(components_raw, list):
            raise ValueError(
                "'components' must be a list/array. Use [] for no components; null is not accepted."
            )
        cleaned["components"] = [
            validate_component(c, i) for i, c in enumerate(components_raw)
        ]
    else:
        cleaned["components"] = []

    # --- qr_code_data (optional) ---
    qr_code_data = data.get("qr_code_data")
    if qr_code_data is not None:
        if not isinstance(qr_code_data, str):
            raise ValueError("'qr_code_data' must be a string if provided.")
        if len(qr_code_data) > MAX_QR_LENGTH:
            raise ValueError(f"'qr_code_data' must not exceed {MAX_QR_LENGTH} characters.")
        cleaned["qr_code_data"] = qr_code_data
    else:
        cleaned["qr_code_data"] = None

    # --- site_id (optional, connects system to site) ---
    site_id = data.get("site_id")
    if site_id is not None:
        if not isinstance(site_id, str) or not site_id.strip():
            raise ValueError("'site_id' must be a non-empty string if provided.")
        cleaned["site_id"] = site_id.strip()
    else:
        cleaned["site_id"] = None

    return cleaned


# ---------------------------------------------------------------------------
# Helper: serialization (datetime → ISO string for JSON responses)
# ---------------------------------------------------------------------------

def serialize_value(value):
    """Convert datetime objects to ISO strings for JSON serialization."""
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def serialize_system(doc_data: dict) -> dict:
    """
    Convert a Firestore system document dict into a JSON-safe dict.
    Converts datetime objects to ISO-8601 strings.
    """
    result = {}
    for key, value in doc_data.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = {k: serialize_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            serialized_list = []
            for item in value:
                if isinstance(item, dict):
                    serialized_list.append(
                        {k: serialize_value(v) for k, v in item.items()}
                    )
                else:
                    serialized_list.append(serialize_value(item))
            result[key] = serialized_list
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Helper: fetch system document (returns None if not found)
# ---------------------------------------------------------------------------

def get_system_doc(db, system_id: str):
    """
    Fetch a system document from Firestore.
    """
    doc_ref = db.collection(COLLECTION_SYSTEMS).document(system_id)
    doc = doc_ref.get()
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    data["system_id"] = system_id
    return data


# ---------------------------------------------------------------------------
# Helper: ownership / access checks
# ---------------------------------------------------------------------------

def can_read_system(user: dict, system: dict, db=None) -> bool:
    """
    Return True if the authenticated user may read the given system.

    - admin:      always True
    - owner:      True only when owner_uid matches user's UID
    - technician: True if an active assignment exists for (technician_uid, system_id)
                  OR for (technician_uid, system.site_id)
    """
    role = (user.get("role") or "").strip().lower()
    if role == "admin":
        return True
    if role == "owner":
        return system.get("owner_uid") == user.get("uid")
    if role == "technician":
        if db is None:
            db = get_db()
        if db is None:
            return False
        system_id = system.get("system_id")
        if not system_id:
            return False

        from BACKEND.assignments import is_technician_assigned_to_system
        return is_technician_assigned_to_system(
            db, user.get("uid"), system_id, site_id=system.get("site_id")
        )

    return False


def can_write_system(user: dict, system: dict) -> bool:
    """
    Return True if the authenticated user may update the given system.

    - admin:      always True
    - owner:      True only when owner_uid matches user's UID
    - technician: always False
    """
    role = (user.get("role") or "").strip().lower()
    if role == "admin":
        return True
    if role == "owner":
        return system.get("owner_uid") == user.get("uid")
    return False


# ---------------------------------------------------------------------------
# POST /api/systems  — Create a new solar system
# ---------------------------------------------------------------------------

@systems_bp.route("/api/systems", methods=["POST"])
@require_auth
def create_system():
    """
    Create a new solar installation record.

    Authorization:
        owner → allowed (creates system owned by themselves)
        admin → allowed (creates system owned by themselves)
        technician → 403
    """
    user = g.user
    role = (user.get("role") or "").strip().lower()

    if role not in ("owner", "admin"):
        return jsonify({
            "error": "Forbidden",
            "message": "Only owner and admin roles may create solar systems."
        }), 403

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Validation Error", "message": "Invalid or missing JSON payload."}), 400

    try:
        cleaned = validate_system_payload(data)
    except ValueError as ve:
        return jsonify({"error": "Validation Error", "message": str(ve)}), 400

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in create_system")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        now = datetime.now(timezone.utc)
        owner_uid = user["uid"]
        site_id = cleaned.get("site_id")

        # Validate site_id relationship if provided
        if site_id:
            site_doc = db.collection(COLLECTION_SITES).document(site_id).get()
            if not site_doc.exists:
                return jsonify({
                    "error": "Not Found",
                    "message": f"Site '{site_id}' not found."
                }), 404

            site_data = site_doc.to_dict() or {}
            # Owner can only attach system to a site they own
            if role == "owner" and site_data.get("owner_uid") != owner_uid:
                return jsonify({
                    "error": "Forbidden",
                    "message": "You cannot attach a system to another owner's site."
                }), 403

        base_doc_data = {
            "owner_uid": owner_uid,
            "site_id": site_id,
            "name": cleaned["name"],
            "location": cleaned["location"],
            "installation_date": cleaned["installation_date"],
            "panel_capacity_watts": cleaned["panel_capacity_watts"],
            "inverter_type": cleaned["inverter_type"],
            "components": cleaned["components"],
            "qr_code_data": cleaned.get("qr_code_data"),
            "created_at": now,
            "updated_at": now,
        }

        system_id, doc_data = create_system_atomic(db, base_doc_data)
        logger.info(
            f"Solar system '{system_id}' created by user '{owner_uid}' (role: {role})."
        )

        return jsonify({
            "message": "Solar system created successfully",
            "system": serialize_system(doc_data)
        }), 201

    except Exception:
        logger.exception("Failed to create solar system")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to create solar system."
        }), 500


# ---------------------------------------------------------------------------
# GET /api/systems  — List solar systems
# ---------------------------------------------------------------------------

@systems_bp.route("/api/systems", methods=["GET"])
@require_auth
def list_systems():
    """
    List solar systems accessible to the authenticated user.

    Role behavior:
        owner      → returns only their own systems (owner_uid == uid)
        technician → returns only actively assigned systems
        admin      → returns all systems
    """
    user = g.user
    role = (user.get("role") or "").strip().lower()

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in list_systems")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        systems_ref = db.collection(COLLECTION_SYSTEMS)

        if role == "technician":
            from BACKEND.assignments import get_technician_assigned_system_ids
            assigned_ids = get_technician_assigned_system_ids(db, user["uid"])

            result = []
            for sid in sorted(assigned_ids):
                sys_doc = get_system_doc(db, sid)
                if sys_doc:
                    result.append(serialize_system(sys_doc))

            return jsonify(result), 200

        elif role == "owner":
            uid = user["uid"]
            docs = systems_ref.where(
                filter=FieldFilter("owner_uid", "==", uid)
            ).stream()

        elif role == "admin":
            docs = systems_ref.stream()

        else:
            return jsonify({"error": "Forbidden", "message": "Unrecognised role."}), 403

        result = []
        for doc in docs:
            data = doc.to_dict() or {}
            data["system_id"] = doc.id
            result.append(serialize_system(data))

        return jsonify(result), 200

    except Exception:
        logger.exception("Failed to list solar systems")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to retrieve solar systems."
        }), 500


# ---------------------------------------------------------------------------
# GET /api/systems/<system_id>  — Get a single system
# ---------------------------------------------------------------------------

@systems_bp.route("/api/systems/<string:system_id>", methods=["GET"])
@require_auth
def get_system(system_id: str):
    """
    Retrieve a single solar system document by system_id.
    """
    user = g.user
    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in get_system")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        system = get_system_doc(db, system_id)
        if system is None:
            return jsonify({"error": "Not Found", "message": "Solar system not found."}), 404

        if not can_read_system(user, system, db=db):
            return jsonify({
                "error": "Forbidden",
                "message": "You are not authorized to access this solar system."
            }), 403

        return jsonify({"system": serialize_system(system)}), 200

    except Exception:
        logger.exception(f"Failed to fetch solar system '{system_id}'")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to retrieve solar system."
        }), 500


# ---------------------------------------------------------------------------
# PUT /api/systems/<system_id>  — Update a system
# ---------------------------------------------------------------------------

@systems_bp.route("/api/systems/<string:system_id>", methods=["PUT"])
@require_auth
def update_system(system_id: str):
    """
    Update an existing solar system document (partial update supported).
    """
    user = g.user
    role = (user.get("role") or "").strip().lower()

    if role == "technician":
        return jsonify({
            "error": "Forbidden",
            "message": "Technicians are not authorized to update solar systems."
        }), 403

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Validation Error", "message": "Invalid or missing JSON payload."}), 400

    for field in IMMUTABLE_FIELDS:
        data.pop(field, None)

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in update_system")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        system = get_system_doc(db, system_id)
        if system is None:
            return jsonify({"error": "Not Found", "message": "Solar system not found."}), 404

        if not can_write_system(user, system):
            return jsonify({
                "error": "Forbidden",
                "message": "You are not authorized to update this solar system."
            }), 403

        UPDATABLE_FIELDS = {
            "name", "location", "installation_date",
            "panel_capacity_watts", "inverter_type", "components", "qr_code_data", "site_id"
        }

        supplied_fields = {k for k in data if k in UPDATABLE_FIELDS}
        if not supplied_fields:
            return jsonify({
                "error": "Validation Error",
                "message": "No updatable fields provided. Updatable fields: " + ", ".join(sorted(UPDATABLE_FIELDS))
            }), 400

        # Validate site_id relationship if updated
        if "site_id" in supplied_fields and data["site_id"] is not None:
            new_site_id = str(data["site_id"]).strip()
            site_doc = db.collection(COLLECTION_SITES).document(new_site_id).get()
            if not site_doc.exists:
                return jsonify({
                    "error": "Not Found",
                    "message": f"Site '{new_site_id}' not found."
                }), 404

            site_data = site_doc.to_dict() or {}
            if role == "owner" and site_data.get("owner_uid") != user["uid"]:
                return jsonify({
                    "error": "Forbidden",
                    "message": "You cannot attach a system to another owner's site."
                }), 403

        def _existing_iso(field_name):
            val = system.get(field_name)
            if isinstance(val, datetime):
                return val.isoformat()
            return val

        merge_for_validation = {
            "name": system.get("name", ""),
            "location": system.get("location", {}),
            "installation_date": _existing_iso("installation_date"),
            "panel_capacity_watts": system.get("panel_capacity_watts", 1),
            "inverter_type": system.get("inverter_type", ""),
            "components": system.get("components", []),
            "qr_code_data": system.get("qr_code_data"),
            "site_id": system.get("site_id"),
        }
        for field in supplied_fields:
            merge_for_validation[field] = data[field]

        try:
            validated = validate_system_payload(merge_for_validation)
        except ValueError as ve:
            return jsonify({"error": "Validation Error", "message": str(ve)}), 400

        update_dict = {"updated_at": datetime.now(timezone.utc)}
        for field in supplied_fields:
            update_dict[field] = validated[field]

        doc_ref = db.collection(COLLECTION_SYSTEMS).document(system_id)
        doc_ref.set(update_dict, merge=True)

        updated_system = get_system_doc(db, system_id)
        logger.info(
            f"Solar system '{system_id}' updated by user '{user['uid']}' (role: {role})."
        )

        return jsonify({
            "message": "Solar system updated successfully",
            "system": serialize_system(updated_system)
        }), 200

    except Exception:
        logger.exception(f"Failed to update solar system '{system_id}'")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to update solar system."
        }), 500


# ---------------------------------------------------------------------------
# DELETE /api/systems/<system_id>  — Delete a system (admin only)
# ---------------------------------------------------------------------------

@systems_bp.route("/api/systems/<string:system_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_system(system_id: str):
    """
    Delete a solar system document. Admin ONLY.
    """
    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in delete_system")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        system = get_system_doc(db, system_id)
        if system is None:
            return jsonify({"error": "Not Found", "message": "Solar system not found."}), 404

        db.collection(COLLECTION_SYSTEMS).document(system_id).delete()
        logger.info(
            f"Solar system '{system_id}' deleted by admin '{g.user['uid']}'."
        )

        return jsonify({
            "message": "Solar system deleted successfully",
            "system_id": system_id
        }), 200

    except Exception:
        logger.exception(f"Failed to delete solar system '{system_id}'")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to delete solar system."
        }), 500
