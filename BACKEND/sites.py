"""
Solar Site Management Module — Multi-Site Hierarchy.

Manages physical solar installation sites stored in the Firestore 'sites' collection.
All endpoints require Firebase authentication (@require_auth / @require_role)
and enforce strict ownership and technician assignment access control.

Hierarchy:
  USER (Owner / Admin / Technician)
    ↓
  SITE (Collection: 'sites')
    ↓
  SOLAR SYSTEM (Collection: 'systems', field: 'site_id')
    ↓
  READINGS (Collection: 'readings', field: 'system_id')
    ↓
  REPORTS (APIs: Daily / Weekly / Monthly)

Role Matrix:
                    OWNER       TECHNICIAN         ADMIN
  CREATE SITE       YES         NO                 YES
  LIST SITES        own only    assigned only      all
  GET SITE          own only    assigned only      all
  UPDATE SITE       own only    403                all
  DELETE SITE       own only    403                all
"""

import sys
import os
import logging
import math
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from flask import Blueprint, request, jsonify, g
from google.cloud.firestore import FieldFilter

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db
from BACKEND.auth import require_auth, require_role

logger = logging.getLogger(__name__)

sites_bp = Blueprint("sites", __name__)

COLLECTION_SITES = "sites"
COLLECTION_SYSTEMS = "systems"
COLLECTION_ASSIGNMENTS = "assignments"

IMMUTABLE_SITE_FIELDS = {"site_id", "owner_uid", "created_at"}
MAX_SITE_NAME_LENGTH = 150
MAX_ADDRESS_LENGTH = 300


# ---------------------------------------------------------------------------
# Helper: ID Generation
# ---------------------------------------------------------------------------

def generate_site_id(db=None, max_retries: int = 5) -> str:
    """
    Generate a collision-resistant site ID in the format SITE-XXXXXXXX.
    Uses the first 8 hex characters of a random UUID (uppercase).
    """
    for attempt in range(max_retries):
        sid = "SITE-" + uuid.uuid4().hex[:8].upper()
        if db is not None:
            doc = db.collection(COLLECTION_SITES).document(sid).get()
            if doc.exists:
                logger.warning(
                    f"Site ID collision on attempt {attempt + 1}: '{sid}'. Regenerating."
                )
                continue
        return sid
    raise RuntimeError(
        f"Failed to generate a unique site ID after {max_retries} attempts."
    )


# ---------------------------------------------------------------------------
# Helper: Payload Validation
# ---------------------------------------------------------------------------

def validate_site_payload(data: dict) -> dict:
    """
    Validates payload for site creation and updates.

    Expected fields:
        - site_name (str, required, 1..150 chars)
        - address (str, optional, max 300 chars)
        - location (dict with 'lat' and 'lng', required)

    Returns:
        dict: Cleaned site data dictionary.

    Raises:
        ValueError: If validation fails.
    """
    if not isinstance(data, dict):
        raise ValueError("Payload must be a JSON object.")

    cleaned: Dict[str, Any] = {}

    # --- site_name ---
    site_name = data.get("site_name")
    if site_name is None or not isinstance(site_name, str) or not site_name.strip():
        raise ValueError("'site_name' is required and must be a non-empty string.")
    site_name_clean = site_name.strip()
    if len(site_name_clean) > MAX_SITE_NAME_LENGTH:
        raise ValueError(f"'site_name' must not exceed {MAX_SITE_NAME_LENGTH} characters.")
    cleaned["site_name"] = site_name_clean

    # --- address (optional) ---
    address = data.get("address", "")
    if address is not None:
        if not isinstance(address, str):
            raise ValueError("'address' must be a string if provided.")
        address_clean = address.strip()
        if len(address_clean) > MAX_ADDRESS_LENGTH:
            raise ValueError(f"'address' must not exceed {MAX_ADDRESS_LENGTH} characters.")
        cleaned["address"] = address_clean
    else:
        cleaned["address"] = ""

    # --- location ---
    location = data.get("location")
    if not location or not isinstance(location, dict):
        raise ValueError("'location' is required and must be an object with 'lat' and 'lng'.")

    for coord in ("lat", "lng"):
        if coord not in location:
            raise ValueError(f"'location' must contain '{coord}'.")
        raw_val = location[coord]
        try:
            val = float(raw_val)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"'location.{coord}' must be numeric.") from exc

        if math.isnan(val) or math.isinf(val):
            raise ValueError(f"'location.{coord}' must be a finite real number.")

        if coord == "lat" and not (-90.0 <= val <= 90.0):
            raise ValueError(f"'location.lat' must be between -90 and 90 degrees. Got {val}.")
        if coord == "lng" and not (-180.0 <= val <= 180.0):
            raise ValueError(f"'location.lng' must be between -180 and 180 degrees. Got {val}.")

    cleaned["location"] = {
        "lat": round(float(location["lat"]), 6),
        "lng": round(float(location["lng"]), 6),
    }

    return cleaned


# ---------------------------------------------------------------------------
# Helper: Serialization
# ---------------------------------------------------------------------------

def serialize_site(doc_data: dict) -> dict:
    """
    Convert a Firestore site document dict into a JSON-safe dict.
    Converts datetime objects to ISO-8601 strings.
    """
    result = {}
    for key, value in doc_data.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = {
                k: v.isoformat() if isinstance(v, datetime) else v
                for k, v in value.items()
            }
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Helper: Fetch Site Document
# ---------------------------------------------------------------------------

def get_site_doc(db, site_id: str) -> Optional[dict]:
    """
    Fetch a site document from Firestore by site_id.
    """
    doc_ref = db.collection(COLLECTION_SITES).document(site_id)
    doc = doc_ref.get()
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    data["site_id"] = site_id
    return data


# ---------------------------------------------------------------------------
# Helper: Access Control
# ---------------------------------------------------------------------------

def can_read_site(user: dict, site: dict, db=None) -> bool:
    """
    Return True if the authenticated user may read the given site document.

    - admin:      always True
    - owner:      True only when owner_uid matches user's UID
    - technician: True if active assignment exists for site_id or any system within this site
    """
    role = (user.get("role") or "").strip().lower()
    if role == "admin":
        return True
    if role == "owner":
        return site.get("owner_uid") == user.get("uid")
    if role == "technician":
        if db is None:
            db = get_db()
        if db is None:
            return False

        tech_uid = user.get("uid")
        site_id = site.get("site_id")
        if not site_id:
            return False

        # 1. Direct site assignment check
        site_asg = list(
            db.collection(COLLECTION_ASSIGNMENTS)
            .where(filter=FieldFilter("technician_uid", "==", tech_uid))
            .where(filter=FieldFilter("site_id", "==", site_id))
            .where(filter=FieldFilter("status", "==", "active"))
            .limit(1)
            .stream()
        )
        if site_asg:
            return True

        # 2. Check if technician is assigned to any system in this site
        tech_sys_asgs = list(
            db.collection(COLLECTION_ASSIGNMENTS)
            .where(filter=FieldFilter("technician_uid", "==", tech_uid))
            .where(filter=FieldFilter("status", "==", "active"))
            .stream()
        )
        for asg in tech_sys_asgs:
            asg_data = asg.to_dict() or {}
            sys_id = asg_data.get("system_id")
            if sys_id:
                sys_doc = db.collection(COLLECTION_SYSTEMS).document(sys_id).get()
                if sys_doc.exists:
                    s_data = sys_doc.to_dict() or {}
                    if s_data.get("site_id") == site_id:
                        return True

        return False

    return False


def can_write_site(user: dict, site: dict) -> bool:
    """
    Return True if the authenticated user may update/delete the given site.

    - admin:      always True
    - owner:      True only when owner_uid matches user's UID
    - technician: always False
    """
    role = (user.get("role") or "").strip().lower()
    if role == "admin":
        return True
    if role == "owner":
        return site.get("owner_uid") == user.get("uid")
    return False


# ---------------------------------------------------------------------------
# POST /api/sites — Create Site
# ---------------------------------------------------------------------------

@sites_bp.route("/api/sites", methods=["POST"])
@require_auth
def create_site():
    """
    Create a new solar site.

    Authorization:
        owner → allowed (creates site owned by themselves)
        admin → allowed (creates site owned by themselves or admin)
        technician → 403 Forbidden
    """
    user = g.user
    role = (user.get("role") or "").strip().lower()

    if role not in ("owner", "admin"):
        return jsonify({
            "error": "Forbidden",
            "message": "Only owner and admin roles may create solar sites."
        }), 403

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Validation Error", "message": "Invalid or missing JSON payload."}), 400

    try:
        cleaned = validate_site_payload(data)
    except ValueError as ve:
        return jsonify({"error": "Validation Error", "message": str(ve)}), 400

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in create_site")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        now = datetime.now(timezone.utc)
        site_id = generate_site_id(db=db)
        owner_uid = user["uid"]

        site_doc_data = {
            "site_id": site_id,
            "owner_uid": owner_uid,
            "site_name": cleaned["site_name"],
            "address": cleaned["address"],
            "location": cleaned["location"],
            "created_at": now,
            "updated_at": now,
        }

        db.collection(COLLECTION_SITES).document(site_id).set(site_doc_data)
        logger.info(f"Site '{site_id}' created by user '{owner_uid}' (role: {role}).")

        return jsonify({
            "message": "Solar site created successfully",
            "site": serialize_site(site_doc_data)
        }), 201

    except Exception:
        logger.exception("Failed to create solar site")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to create solar site."
        }), 500


# ---------------------------------------------------------------------------
# GET /api/sites — List Sites
# ---------------------------------------------------------------------------

@sites_bp.route("/api/sites", methods=["GET"])
@require_auth
def list_sites():
    """
    List solar sites accessible to the authenticated user.

    Role behavior:
        owner      → returns only their own sites (owner_uid == uid)
        technician → returns only assigned sites
        admin      → returns all sites
    """
    user = g.user
    role = (user.get("role") or "").strip().lower()

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in list_sites")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        sites_ref = db.collection(COLLECTION_SITES)

        if role == "owner":
            uid = user["uid"]
            docs = sites_ref.where(filter=FieldFilter("owner_uid", "==", uid)).stream()

        elif role == "admin":
            docs = sites_ref.stream()

        elif role == "technician":
            tech_uid = user["uid"]
            # 1. Direct site assignments
            asgs = db.collection(COLLECTION_ASSIGNMENTS)\
                .where(filter=FieldFilter("technician_uid", "==", tech_uid))\
                .where(filter=FieldFilter("status", "==", "active"))\
                .stream()

            assigned_site_ids = set()
            for asg in asgs:
                asg_data = asg.to_dict() or {}
                if asg_data.get("site_id"):
                    assigned_site_ids.add(asg_data["site_id"])
                elif asg_data.get("system_id"):
                    # Find site_id from system
                    sys_doc = db.collection(COLLECTION_SYSTEMS).document(asg_data["system_id"]).get()
                    if sys_doc.exists:
                        s_data = sys_doc.to_dict() or {}
                        if s_data.get("site_id"):
                            assigned_site_ids.add(s_data["site_id"])

            result = []
            for sid in sorted(assigned_site_ids):
                s_doc = get_site_doc(db, sid)
                if s_doc:
                    result.append(serialize_site(s_doc))
            return jsonify(result), 200

        else:
            return jsonify({"error": "Forbidden", "message": "Unrecognized role."}), 403

        result = []
        for doc in docs:
            data = doc.to_dict() or {}
            data["site_id"] = doc.id
            result.append(serialize_site(data))

        return jsonify(result), 200

    except Exception:
        logger.exception("Failed to list solar sites")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to retrieve solar sites."
        }), 500


# ---------------------------------------------------------------------------
# GET /api/sites/<site_id> — Get Single Site
# ---------------------------------------------------------------------------

@sites_bp.route("/api/sites/<string:site_id>", methods=["GET"])
@require_auth
def get_site(site_id: str):
    """
    Retrieve a single site by site_id.
    """
    user = g.user
    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in get_site")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        site = get_site_doc(db, site_id)
        if site is None:
            return jsonify({"error": "Not Found", "message": f"Site '{site_id}' not found."}), 404

        if not can_read_site(user, site, db=db):
            return jsonify({
                "error": "Forbidden",
                "message": "You are not authorized to access this solar site."
            }), 403

        return jsonify({"site": serialize_site(site)}), 200

    except Exception:
        logger.exception(f"Failed to fetch solar site '{site_id}'")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to retrieve solar site."
        }), 500


# ---------------------------------------------------------------------------
# PUT /api/sites/<site_id> — Update Site
# ---------------------------------------------------------------------------

@sites_bp.route("/api/sites/<string:site_id>", methods=["PUT"])
@require_auth
def update_site(site_id: str):
    """
    Update an existing site.

    Authorization:
        owner      → own sites only
        admin      → any site
        technician → 403 Forbidden
    """
    user = g.user
    role = (user.get("role") or "").strip().lower()

    if role == "technician":
        return jsonify({
            "error": "Forbidden",
            "message": "Technicians are not authorized to update solar sites."
        }), 403

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Validation Error", "message": "Invalid or missing JSON payload."}), 400

    for field in IMMUTABLE_SITE_FIELDS:
        data.pop(field, None)

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in update_site")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        site = get_site_doc(db, site_id)
        if site is None:
            return jsonify({"error": "Not Found", "message": f"Site '{site_id}' not found."}), 404

        if not can_write_site(user, site):
            return jsonify({
                "error": "Forbidden",
                "message": "You are not authorized to update this solar site."
            }), 403

        UPDATABLE_FIELDS = {"site_name", "address", "location"}
        supplied_fields = {k for k in data if k in UPDATABLE_FIELDS}
        if not supplied_fields:
            return jsonify({
                "error": "Validation Error",
                "message": "No updatable fields provided. Updatable fields: " + ", ".join(sorted(UPDATABLE_FIELDS))
            }), 400

        merge_for_validation = {
            "site_name": site.get("site_name", ""),
            "address": site.get("address", ""),
            "location": site.get("location", {}),
        }
        for field in supplied_fields:
            merge_for_validation[field] = data[field]

        try:
            validated = validate_site_payload(merge_for_validation)
        except ValueError as ve:
            return jsonify({"error": "Validation Error", "message": str(ve)}), 400

        update_dict = {"updated_at": datetime.now(timezone.utc)}
        for field in supplied_fields:
            update_dict[field] = validated[field]

        db.collection(COLLECTION_SITES).document(site_id).set(update_dict, merge=True)
        updated_site = get_site_doc(db, site_id)
        logger.info(f"Site '{site_id}' updated by user '{user['uid']}' (role: {role}).")

        return jsonify({
            "message": "Solar site updated successfully",
            "site": serialize_site(updated_site)
        }), 200

    except Exception:
        logger.exception(f"Failed to update solar site '{site_id}'")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to update solar site."
        }), 500


# ---------------------------------------------------------------------------
# DELETE /api/sites/<site_id> — Delete Site
# ---------------------------------------------------------------------------

@sites_bp.route("/api/sites/<string:site_id>", methods=["DELETE"])
@require_auth
def delete_site(site_id: str):
    """
    Delete a solar site.

    Authorization:
        owner → own sites only
        admin → any site
        technician → 403 Forbidden
    """
    user = g.user
    role = (user.get("role") or "").strip().lower()

    if role == "technician":
        return jsonify({
            "error": "Forbidden",
            "message": "Technicians are not authorized to delete solar sites."
        }), 403

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in delete_site")
        return jsonify({"error": "Internal Server Error", "message": "Database connection unavailable."}), 500

    try:
        site = get_site_doc(db, site_id)
        if site is None:
            return jsonify({"error": "Not Found", "message": f"Site '{site_id}' not found."}), 404

        if not can_write_site(user, site):
            return jsonify({
                "error": "Forbidden",
                "message": "You are not authorized to delete this solar site."
            }), 403

        db.collection(COLLECTION_SITES).document(site_id).delete()
        logger.info(f"Site '{site_id}' deleted by user '{user['uid']}' (role: {role}).")

        return jsonify({
            "message": "Solar site deleted successfully",
            "site_id": site_id
        }), 200

    except Exception:
        logger.exception(f"Failed to delete solar site '{site_id}'")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to delete solar site."
        }), 500
