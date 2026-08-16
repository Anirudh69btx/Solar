"""
Technician Assignment Management Module — Solar Monitoring System.

Manages technician assignments to solar installations and sites stored in the Firestore
'assignments' collection.

Document structure:
{
    "assignment_id": "ASG-XXXXXXXX",
    "technician_uid": "firebase-technician-uid",
    "system_id": "SYS-XXXXXXXX" (or null if site-level),
    "site_id": "SITE-XXXXXXXX" (or null if system-level),
    "assigned_by": "admin-uid",
    "status": "active",
    "assigned_at": timestamp,
    "updated_at": timestamp
}

Role permissions:
- Admin: Full management (create, list all, delete assignments).
- Technician: Read-only access to own active assignments.
- Owner: Forbidden from accessing assignments API (403).
"""

import sys
import os
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from flask import Blueprint, request, jsonify, g
from google.cloud.firestore import FieldFilter

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db
from BACKEND.auth import require_auth, require_role

logger = logging.getLogger(__name__)

assignments_bp = Blueprint("assignments", __name__)

COLLECTION_ASSIGNMENTS = "assignments"
COLLECTION_SYSTEMS = "systems"
COLLECTION_SITES = "sites"
COLLECTION_USERS = "users"


def generate_assignment_id(db=None, max_retries: int = 5) -> str:
    """
    Generate a collision-resistant assignment ID in the format ASG-XXXXXXXX.
    Uses the first 8 hex characters of a random UUID (uppercase).
    """
    for attempt in range(max_retries):
        aid = "ASG-" + uuid.uuid4().hex[:8].upper()
        if db is not None:
            doc = db.collection(COLLECTION_ASSIGNMENTS).document(aid).get()
            if doc.exists:
                logger.warning(
                    f"Assignment ID collision on attempt {attempt + 1}: '{aid}'. Regenerating."
                )
                continue
        return aid
    raise RuntimeError(
        f"Failed to generate a unique assignment ID after {max_retries} attempts."
    )


def serialize_assignment(doc_data: dict) -> dict:
    """
    Convert a Firestore assignment document dict into a JSON-safe dict.
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
# Exportable Query Helpers for Cross-Module Access Control
# ---------------------------------------------------------------------------

def is_technician_assigned_to_system(
    db, technician_uid: str, system_id: str, site_id: Optional[str] = None
) -> bool:
    """
    Checks if a technician has an active assignment for a given system or its parent site.
    """
    if not db or not technician_uid or not system_id:
        return False

    try:
        # 1. Check system-level active assignment
        asgs = list(
            db.collection(COLLECTION_ASSIGNMENTS)
            .where(filter=FieldFilter("technician_uid", "==", technician_uid))
            .where(filter=FieldFilter("system_id", "==", system_id))
            .where(filter=FieldFilter("status", "==", "active"))
            .limit(1)
            .stream()
        )
        if asgs:
            return True

        # 2. Check site-level active assignment if site_id is provided or can be looked up
        if not site_id:
            sys_doc = db.collection(COLLECTION_SYSTEMS).document(system_id).get()
            if sys_doc.exists:
                site_id = (sys_doc.to_dict() or {}).get("site_id")

        if site_id:
            site_asgs = list(
                db.collection(COLLECTION_ASSIGNMENTS)
                .where(filter=FieldFilter("technician_uid", "==", technician_uid))
                .where(filter=FieldFilter("site_id", "==", site_id))
                .where(filter=FieldFilter("status", "==", "active"))
                .limit(1)
                .stream()
            )
            if site_asgs:
                return True

        return False
    except Exception:
        logger.exception(f"Error checking technician assignment for system '{system_id}'")
        return False


def is_technician_assigned_to_site(db, technician_uid: str, site_id: str) -> bool:
    """
    Checks if a technician has an active assignment for a given site or any system in it.
    """
    if not db or not technician_uid or not site_id:
        return False

    try:
        # Direct site assignment
        asgs = list(
            db.collection(COLLECTION_ASSIGNMENTS)
            .where(filter=FieldFilter("technician_uid", "==", technician_uid))
            .where(filter=FieldFilter("site_id", "==", site_id))
            .where(filter=FieldFilter("status", "==", "active"))
            .limit(1)
            .stream()
        )
        if asgs:
            return True

        # System within site assignment
        tech_asgs = list(
            db.collection(COLLECTION_ASSIGNMENTS)
            .where(filter=FieldFilter("technician_uid", "==", technician_uid))
            .where(filter=FieldFilter("status", "==", "active"))
            .stream()
        )
        for asg in tech_asgs:
            asg_data = asg.to_dict() or {}
            sys_id = asg_data.get("system_id")
            if sys_id:
                sys_doc = db.collection(COLLECTION_SYSTEMS).document(sys_id).get()
                if sys_doc.exists:
                    if (sys_doc.to_dict() or {}).get("site_id") == site_id:
                        return True

        return False
    except Exception:
        logger.exception(f"Error checking technician assignment for site '{site_id}'")
        return False


def get_technician_assigned_system_ids(db, technician_uid: str) -> List[str]:
    """
    Returns a list of unique system IDs actively assigned to the technician.
    """
    if not db or not technician_uid:
        return []

    try:
        asgs = db.collection(COLLECTION_ASSIGNMENTS)\
            .where(filter=FieldFilter("technician_uid", "==", technician_uid))\
            .where(filter=FieldFilter("status", "==", "active"))\
            .stream()

        assigned_ids = set()
        for asg in asgs:
            asg_data = asg.to_dict() or {}
            sid = asg_data.get("system_id")
            if sid:
                assigned_ids.add(sid)
            site_id = asg_data.get("site_id")
            if site_id and not sid:
                # Find all systems belonging to this site
                site_systems = db.collection(COLLECTION_SYSTEMS)\
                    .where(filter=FieldFilter("site_id", "==", site_id))\
                    .stream()
                for s in site_systems:
                    assigned_ids.add(s.id)

        return list(assigned_ids)
    except Exception:
        logger.exception(f"Error retrieving assigned systems for technician '{technician_uid}'")
        return []


# ---------------------------------------------------------------------------
# POST /api/assignments — Create Assignment (Admin only)
# ---------------------------------------------------------------------------

@assignments_bp.route("/api/assignments", methods=["POST"])
@require_auth
@require_role("admin")
def create_assignment():
    """
    Assign a technician to a solar installation or site. Admin-only.

    Request Body:
        {
            "technician_uid": "...",
            "system_id": "..." (optional if site_id provided),
            "site_id": "..." (optional if system_id provided)
        }
    """
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({
            "error": "Validation Error",
            "message": "Invalid or missing JSON payload."
        }), 400

    technician_uid = data.get("technician_uid")
    system_id = data.get("system_id")
    site_id = data.get("site_id")

    if not technician_uid or not isinstance(technician_uid, str) or not technician_uid.strip():
        return jsonify({
            "error": "Validation Error",
            "message": "'technician_uid' is required and must be a non-empty string."
        }), 400

    if not system_id and not site_id:
        return jsonify({
            "error": "Validation Error",
            "message": "Either 'system_id' or 'site_id' (or both) must be provided."
        }), 400

    technician_uid = technician_uid.strip()
    system_id = system_id.strip() if system_id and isinstance(system_id, str) else None
    site_id = site_id.strip() if site_id and isinstance(site_id, str) else None

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in create_assignment")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Database connection unavailable."
        }), 500

    try:
        # 1. Verify technician user exists and has role == 'technician'
        user_doc = db.collection(COLLECTION_USERS).document(technician_uid).get()
        if not user_doc.exists:
            return jsonify({
                "error": "Not Found",
                "message": f"User profile for technician '{technician_uid}' not found."
            }), 404

        user_data = user_doc.to_dict() or {}
        user_role = (user_data.get("role") or "").strip().lower()
        if user_role != "technician":
            return jsonify({
                "error": "Validation Error",
                "message": f"User '{technician_uid}' has role '{user_role}', expected 'technician'."
            }), 400

        # 2. Verify referenced system exists if provided
        if system_id:
            system_doc = db.collection(COLLECTION_SYSTEMS).document(system_id).get()
            if not system_doc.exists:
                return jsonify({
                    "error": "Not Found",
                    "message": f"Solar system '{system_id}' not found."
                }), 404
            # Auto-populate site_id if available on the system and not explicitly given
            if not site_id:
                site_id = (system_doc.to_dict() or {}).get("site_id")

        # 3. Verify referenced site exists if provided
        if site_id:
            site_doc = db.collection(COLLECTION_SITES).document(site_id).get()
            if not site_doc.exists and not system_id:
                # If site_id was explicitly provided without a valid site doc, fail 404
                return jsonify({
                    "error": "Not Found",
                    "message": f"Site '{site_id}' not found."
                }), 404

        # 4. Check for existing active assignment
        if system_id:
            existing_query = db.collection(COLLECTION_ASSIGNMENTS)\
                .where(filter=FieldFilter("technician_uid", "==", technician_uid))\
                .where(filter=FieldFilter("system_id", "==", system_id))\
                .where(filter=FieldFilter("status", "==", "active"))\
                .stream()
            if list(existing_query):
                return jsonify({
                    "error": "Conflict",
                    "message": f"An active assignment already exists for technician '{technician_uid}' on system '{system_id}'."
                }), 409
        elif site_id:
            existing_query = db.collection(COLLECTION_ASSIGNMENTS)\
                .where(filter=FieldFilter("technician_uid", "==", technician_uid))\
                .where(filter=FieldFilter("site_id", "==", site_id))\
                .where(filter=FieldFilter("status", "==", "active"))\
                .stream()
            if list(existing_query):
                return jsonify({
                    "error": "Conflict",
                    "message": f"An active assignment already exists for technician '{technician_uid}' on site '{site_id}'."
                }), 409

        # 5. Create assignment
        now = datetime.now(timezone.utc)
        assignment_id = generate_assignment_id(db=db)
        admin_uid = g.user["uid"]

        assignment_data = {
            "assignment_id": assignment_id,
            "technician_uid": technician_uid,
            "system_id": system_id,
            "site_id": site_id,
            "assigned_by": admin_uid,
            "status": "active",
            "assigned_at": now,
            "updated_at": now
        }

        db.collection(COLLECTION_ASSIGNMENTS).document(assignment_id).set(assignment_data)
        logger.info(
            f"Assignment '{assignment_id}' created: technician '{technician_uid}' -> system '{system_id}' / site '{site_id}' by admin '{admin_uid}'."
        )

        return jsonify({
            "message": "Technician assigned successfully",
            "assignment": serialize_assignment(assignment_data)
        }), 201

    except Exception:
        logger.exception("Failed to create technician assignment")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to create technician assignment."
        }), 500


# ---------------------------------------------------------------------------
# GET /api/assignments — List Assignments
# ---------------------------------------------------------------------------

@assignments_bp.route("/api/assignments", methods=["GET"])
@require_auth
def list_assignments():
    """
    List technician assignments.

    Role permissions:
        - Admin: Returns all assignments (optional filtering by technician_uid, system_id, site_id, status).
        - Technician: Returns only their own active assignments.
        - Owner: 403 Forbidden.
    """
    user = g.user
    role = (user.get("role") or "").strip().lower()

    if role == "owner":
        return jsonify({
            "error": "Forbidden",
            "message": "Owners are not authorized to view technician assignments."
        }), 403

    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in list_assignments")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Database connection unavailable."
        }), 500

    try:
        assignments_ref = db.collection(COLLECTION_ASSIGNMENTS)

        if role == "technician":
            tech_uid = user["uid"]
            docs = assignments_ref\
                .where(filter=FieldFilter("technician_uid", "==", tech_uid))\
                .where(filter=FieldFilter("status", "==", "active"))\
                .stream()

        elif role == "admin":
            tech_param = request.args.get("technician_uid")
            sys_param = request.args.get("system_id")
            site_param = request.args.get("site_id")
            status_param = request.args.get("status")

            query = assignments_ref
            if tech_param:
                query = query.where(filter=FieldFilter("technician_uid", "==", tech_param.strip()))
            if sys_param:
                query = query.where(filter=FieldFilter("system_id", "==", sys_param.strip()))
            if site_param:
                query = query.where(filter=FieldFilter("site_id", "==", site_param.strip()))
            if status_param:
                query = query.where(filter=FieldFilter("status", "==", status_param.strip()))

            docs = query.stream()
        else:
            return jsonify({"error": "Forbidden", "message": "Unrecognized role."}), 403

        result = []
        for doc in docs:
            data = doc.to_dict() or {}
            data["assignment_id"] = doc.id
            result.append(serialize_assignment(data))

        return jsonify(result), 200

    except Exception:
        logger.exception("Failed to list assignments")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to retrieve assignments."
        }), 500


# ---------------------------------------------------------------------------
# DELETE /api/assignments/<assignment_id> — Delete Assignment (Admin only)
# ---------------------------------------------------------------------------

@assignments_bp.route("/api/assignments/<string:assignment_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_assignment(assignment_id: str):
    """
    Remove/delete an assignment. Admin-only.
    """
    db = get_db()
    if db is None:
        logger.error("Database handle unavailable in delete_assignment")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Database connection unavailable."
        }), 500

    try:
        doc_ref = db.collection(COLLECTION_ASSIGNMENTS).document(assignment_id)
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({
                "error": "Not Found",
                "message": f"Assignment '{assignment_id}' not found."
            }), 404

        doc_ref.delete()
        logger.info(f"Assignment '{assignment_id}' deleted by admin '{g.user['uid']}'.")

        return jsonify({
            "message": "Assignment deleted successfully",
            "assignment_id": assignment_id
        }), 200

    except Exception:
        logger.exception(f"Failed to delete assignment '{assignment_id}'")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to delete assignment."
        }), 500
