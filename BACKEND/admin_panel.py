"""
Admin Panel API Module — Segment 15.

Provides administrative oversight endpoints for the Solar PV Monitoring Platform.
All endpoints require Firebase Authentication with the 'admin' role.

Endpoints:
- GET    /api/admin/stats                   — Platform-wide overview statistics
- GET    /api/admin/users                   — List all users (paginated, filterable by role)
- GET    /api/admin/users/<uid>             — Get a single user profile
- PUT    /api/admin/users/<uid>             — Update user name or role
- DELETE /api/admin/users/<uid>             — Soft-disable a user account
- GET    /api/admin/sites                   — List all sites across all owners
- GET    /api/admin/systems                 — List all solar systems across all owners
- GET    /api/admin/assignments             — List all assignments (filterable)
- DELETE /api/admin/assignments/<asg_id>    — Hard-delete an assignment
- GET    /api/admin/alerts                  — List all alerts platform-wide
- PUT    /api/admin/alerts/<alert_id>       — Resolve or update an alert
- GET    /api/admin/documents               — List all documents across all systems/sites
- GET    /api/admin/audit-log               — Paginated document and admin action audit trail
- GET    /api/admin/readings                — List telemetry readings across all systems (paginated, filterable)
- GET    /api/admin/reports/summary         — Platform-wide performance & energy generation KPIs summary
- GET    /api/admin/health                  — Platform-wide multi-system health scores (sorted/filterable)

Role Permissions:
- Admin:      Full access to all endpoints.
- Owner:      403 Forbidden on all endpoints.
- Technician: 403 Forbidden on all endpoints.

Security Standards:
- @require_auth + @require_role("admin") on every endpoint — no bypass possible.
- Self-guard: Admin cannot disable their own account.
- Zero-admin guard: Role change or disable that would leave zero admins is rejected with 403.
- Audit trail: All destructive/privileged actions are logged to 'document_audits' collection.
- Input sanitization: All writable string fields trimmed and enum-validated before persistence.
"""

import sys
import os
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from flask import Blueprint, request, jsonify, g
from google.cloud.firestore import FieldFilter

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db
from BACKEND.auth import require_auth, require_role

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__)

# ---------------------------------------------------------------------------
# Collection Constants
# ---------------------------------------------------------------------------
COLLECTION_USERS            = "users"
COLLECTION_SITES            = "sites"
COLLECTION_SYSTEMS          = "systems"
COLLECTION_ASSIGNMENTS      = "assignments"
COLLECTION_ALERTS           = "alerts"
COLLECTION_DOCUMENTS        = "documents"
COLLECTION_DOCUMENT_AUDITS  = "document_audits"
COLLECTION_READINGS         = "readings"

VALID_ROLES    = {"owner", "technician", "admin"}
DEFAULT_PER_PAGE = 50
MAX_PER_PAGE     = 200


# ---------------------------------------------------------------------------
# Helper: Serialization
# ---------------------------------------------------------------------------

def _serialize_doc(data: dict) -> dict:
    """
    Convert a Firestore document dict into a JSON-safe dict.
    Recursively converts datetime objects to ISO-8601 strings.
    """
    result = {}
    for key, value in data.items():
        if isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, dict):
            result[key] = {
                k: v.isoformat() if isinstance(v, datetime) else v
                for k, v in value.items()
            }
        elif isinstance(value, list):
            serialized_list = []
            for item in value:
                if isinstance(item, dict):
                    serialized_list.append(
                        {k: v.isoformat() if isinstance(v, datetime) else v
                         for k, v in item.items()}
                    )
                elif isinstance(item, datetime):
                    serialized_list.append(item.isoformat())
                else:
                    serialized_list.append(item)
            result[key] = serialized_list
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Helper: Pagination
# ---------------------------------------------------------------------------

def _paginate(items: list, page: int, per_page: int) -> dict:
    """Return a paginated slice of a list with metadata envelope."""
    total = len(items)
    start = (page - 1) * per_page
    end   = start + per_page
    return {
        "items":       items[start:end],
        "total":       total,
        "page":        page,
        "per_page":    per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


def _parse_pagination_params() -> tuple:
    """Parse and clamp ?page and ?per_page query parameters."""
    try:
        page = max(1, int(request.args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = min(MAX_PER_PAGE, max(1, int(request.args.get("per_page", DEFAULT_PER_PAGE))))
    except (ValueError, TypeError):
        per_page = DEFAULT_PER_PAGE
    return page, per_page


# ---------------------------------------------------------------------------
# Helper: Admin Audit Trail
# ---------------------------------------------------------------------------

def _write_admin_audit(
    db,
    action: str,
    admin_uid: str,
    target: str,
    details: Optional[dict] = None,
) -> None:
    """
    Write an immutable admin action audit record to the 'document_audits' collection.

    Args:
        db:         Firestore database client.
        action:     Action type string (e.g. 'ADMIN_USER_DISABLE').
        admin_uid:  UID of the admin performing the action.
        target:     Identifier of the target resource (e.g. user UID, assignment ID).
        details:    Optional dict with additional context.
    """
    try:
        aud_id = "AUD-" + uuid.uuid4().hex[:8].upper()
        audit_record = {
            "audit_id":          aud_id,
            "action":            action,
            "performed_by_uid":  admin_uid,
            "performed_by_role": "admin",
            "target":            target,
            "details":           details or {},
            "timestamp":         datetime.now(timezone.utc).isoformat(),
        }
        db.collection(COLLECTION_DOCUMENT_AUDITS).document(aud_id).set(audit_record)
        logger.info(f"Admin audit written: action='{action}' target='{target}' by='{admin_uid}'")
    except Exception:
        logger.exception(
            f"Failed to write admin audit record for action '{action}' on target '{target}'"
        )


# ---------------------------------------------------------------------------
# Helper: Count admins on platform
# ---------------------------------------------------------------------------

def _count_admins(db) -> int:
    """Return the count of users with role='admin' in Firestore."""
    try:
        admins = list(
            db.collection(COLLECTION_USERS)
            .where(filter=FieldFilter("role", "==", "admin"))
            .stream()
        )
        return len(admins)
    except Exception:
        return 0


# ===========================================================================
# Endpoint 1 — GET /api/admin/stats
# ===========================================================================

@admin_bp.route("/api/admin/stats", methods=["GET"])
@require_auth
@require_role("admin")
def get_platform_stats():
    """
    Platform-wide overview statistics for the Admin Panel dashboard.

    Returns:
        {
            "total_users": int,
            "users_by_role": { "owner": int, "technician": int, "admin": int },
            "total_sites": int,
            "total_systems": int,
            "total_active_assignments": int,
            "total_active_alerts": int,
            "total_documents": int,
            "generated_at": str (ISO-8601 UTC timestamp)
        }
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        # --- Users ---
        all_users = list(db.collection(COLLECTION_USERS).stream())
        users_by_role: Dict[str, int] = {"owner": 0, "technician": 0, "admin": 0}
        for u in all_users:
            role = (u.to_dict() or {}).get("role", "").strip().lower()
            if role in users_by_role:
                users_by_role[role] += 1

        # --- Sites ---
        total_sites = len(list(db.collection(COLLECTION_SITES).stream()))

        # --- Systems ---
        total_systems = len(list(db.collection(COLLECTION_SYSTEMS).stream()))

        # --- Active Assignments ---
        active_assignments = list(
            db.collection(COLLECTION_ASSIGNMENTS)
            .where(filter=FieldFilter("status", "==", "active"))
            .stream()
        )

        # --- Active Alerts ---
        active_alerts = list(
            db.collection(COLLECTION_ALERTS)
            .where(filter=FieldFilter("active", "==", True))
            .stream()
        )

        # --- Documents ---
        total_documents = len(list(db.collection(COLLECTION_DOCUMENTS).stream()))

        return jsonify({
            "total_users":              len(all_users),
            "users_by_role":            users_by_role,
            "total_sites":              total_sites,
            "total_systems":            total_systems,
            "total_active_assignments": len(active_assignments),
            "total_active_alerts":      len(active_alerts),
            "total_documents":          total_documents,
            "generated_at":             datetime.now(timezone.utc).isoformat(),
        }), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/stats: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 2 — GET /api/admin/users
# ===========================================================================

@admin_bp.route("/api/admin/users", methods=["GET"])
@require_auth
@require_role("admin")
def list_all_users():
    """
    List all user profiles, optionally filtered by role.

    Query Params:
        role (str, optional):     Filter by role (owner / technician / admin).
        page (int, optional):     Page number (default: 1).
        per_page (int, optional): Results per page (default: 50, max: 200).

    Returns:
        Paginated envelope: { items, total, page, per_page, total_pages }
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        role_filter = (request.args.get("role") or "").strip().lower()
        page, per_page = _parse_pagination_params()

        all_users = list(db.collection(COLLECTION_USERS).stream())
        users = []
        for u in all_users:
            data = u.to_dict() or {}
            data["uid"] = u.id
            if role_filter and data.get("role", "").strip().lower() != role_filter:
                continue
            users.append(_serialize_doc(data))

        users.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify(_paginate(users, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/users: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 3 — GET /api/admin/users/<uid>
# ===========================================================================

@admin_bp.route("/api/admin/users/<uid>", methods=["GET"])
@require_auth
@require_role("admin")
def get_user_profile(uid: str):
    """
    Get a single user profile by Firebase UID.

    Returns 404 if the user does not exist in Firestore.
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        doc = db.collection(COLLECTION_USERS).document(uid).get()
        if not doc.exists:
            return jsonify({
                "error": "Not Found",
                "message": f"User '{uid}' not found."
            }), 404
        data = doc.to_dict() or {}
        data["uid"] = uid
        return jsonify(_serialize_doc(data)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/users/{uid}: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 4 — PUT /api/admin/users/<uid>
# ===========================================================================

@admin_bp.route("/api/admin/users/<uid>", methods=["PUT"])
@require_auth
@require_role("admin")
def update_user(uid: str):
    """
    Update a user's display name or role.

    Payload (all fields optional, at least one required):
        { "name": "...", "role": "owner|technician|admin" }

    Security:
    - Rejects invalid or unknown roles.
    - Zero-admin guard: Cannot demote the last remaining admin to another role.
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({
                "error": "Validation Error",
                "message": "Invalid or missing JSON payload."
            }), 400

        doc = db.collection(COLLECTION_USERS).document(uid).get()
        if not doc.exists:
            return jsonify({
                "error": "Not Found",
                "message": f"User '{uid}' not found."
            }), 404

        existing = doc.to_dict() or {}
        updates: Dict[str, Any] = {}

        # --- Name update ---
        if "name" in data:
            new_name = data["name"]
            if not isinstance(new_name, str) or not new_name.strip():
                return jsonify({
                    "error": "Validation Error",
                    "message": "'name' must be a non-empty string."
                }), 400
            updates["name"] = new_name.strip()

        # --- Role update ---
        if "role" in data:
            new_role = str(data["role"] or "").strip().lower()
            if new_role not in VALID_ROLES:
                return jsonify({
                    "error": "Validation Error",
                    "message": f"Invalid role '{new_role}'. Allowed roles: {sorted(VALID_ROLES)}"
                }), 400

            current_role = (existing.get("role") or "").strip().lower()

            # Zero-admin guard: prevent removing the last admin
            if current_role == "admin" and new_role != "admin":
                if _count_admins(db) <= 1:
                    return jsonify({
                        "error": "Forbidden",
                        "message": (
                            "Cannot demote this admin — they are the last admin on the platform. "
                            "Promote another user to admin first."
                        )
                    }), 403

            updates["role"] = new_role

        if not updates:
            return jsonify({
                "error": "Validation Error",
                "message": "No updatable fields provided. Supply 'name' or 'role'."
            }), 400

        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        db.collection(COLLECTION_USERS).document(uid).update(updates)

        admin_uid = (g.user or {}).get("uid", "unknown")
        _write_admin_audit(db, "ADMIN_USER_UPDATE", admin_uid, uid, {"updates": updates})

        updated_doc = db.collection(COLLECTION_USERS).document(uid).get()
        updated_data = (updated_doc.to_dict() or {})
        updated_data["uid"] = uid
        return jsonify({
            "message": "User updated successfully.",
            "user": _serialize_doc(updated_data),
        }), 200

    except Exception as e:
        logger.exception(f"Error in PUT /api/admin/users/{uid}: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 5 — DELETE /api/admin/users/<uid>
# ===========================================================================

@admin_bp.route("/api/admin/users/<uid>", methods=["DELETE"])
@require_auth
@require_role("admin")
def disable_user(uid: str):
    """
    Soft-disable a user account by setting 'disabled: true' in Firestore.

    Security:
    - Self-guard: An admin cannot disable their own account.
    - Zero-admin guard: Cannot disable the last remaining admin.

    Note: This is a soft-delete. The Firebase Auth account is NOT deleted;
    only the Firestore profile is marked disabled to preserve audit history.
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        admin_uid = (g.user or {}).get("uid", "")

        # Self-guard
        if uid == admin_uid:
            return jsonify({
                "error": "Forbidden",
                "message": "Administrators cannot disable their own account."
            }), 403

        doc = db.collection(COLLECTION_USERS).document(uid).get()
        if not doc.exists:
            return jsonify({
                "error": "Not Found",
                "message": f"User '{uid}' not found."
            }), 404

        existing     = doc.to_dict() or {}
        current_role = (existing.get("role") or "").strip().lower()

        # Zero-admin guard
        if current_role == "admin":
            if _count_admins(db) <= 1:
                return jsonify({
                    "error": "Forbidden",
                    "message": (
                        "Cannot disable this admin — they are the last admin on the platform."
                    )
                }), 403

        now_iso = datetime.now(timezone.utc).isoformat()
        updates = {
            "disabled":    True,
            "disabled_at": now_iso,
            "disabled_by": admin_uid,
        }
        db.collection(COLLECTION_USERS).document(uid).update(updates)
        _write_admin_audit(db, "ADMIN_USER_DISABLE", admin_uid, uid, {
            "target_role": current_role,
            "disabled_at": now_iso,
        })

        return jsonify({
            "message": f"User '{uid}' has been disabled successfully."
        }), 200

    except Exception as e:
        logger.exception(f"Error in DELETE /api/admin/users/{uid}: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 6 — GET /api/admin/sites
# ===========================================================================

@admin_bp.route("/api/admin/sites", methods=["GET"])
@require_auth
@require_role("admin")
def list_all_sites():
    """
    List all solar sites across all owners.

    Each site in the result includes a 'system_count' field — the number of
    solar systems registered under that site.

    Query Params:
        owner_uid (str, optional): Filter by owner UID.
        page (int, optional):      Page number (default: 1).
        per_page (int, optional):  Results per page (default: 50, max: 200).
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        owner_filter = (request.args.get("owner_uid") or "").strip()
        page, per_page = _parse_pagination_params()

        all_sites = list(db.collection(COLLECTION_SITES).stream())
        sites = []
        for s in all_sites:
            data = s.to_dict() or {}
            data["site_id"] = s.id
            if owner_filter and data.get("owner_uid", "") != owner_filter:
                continue
            # Count systems belonging to this site
            site_systems = list(
                db.collection(COLLECTION_SYSTEMS)
                .where(filter=FieldFilter("site_id", "==", s.id))
                .stream()
            )
            data["system_count"] = len(site_systems)
            sites.append(_serialize_doc(data))

        sites.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify(_paginate(sites, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/sites: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 7 — GET /api/admin/systems
# ===========================================================================

@admin_bp.route("/api/admin/systems", methods=["GET"])
@require_auth
@require_role("admin")
def list_all_systems():
    """
    List all solar systems across all owners.

    Query Params:
        owner_uid (str, optional): Filter by owner UID.
        site_id (str, optional):   Filter by site ID.
        page (int, optional):      Page number (default: 1).
        per_page (int, optional):  Results per page (default: 50, max: 200).
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        owner_filter = (request.args.get("owner_uid") or "").strip()
        site_filter  = (request.args.get("site_id") or "").strip()
        page, per_page = _parse_pagination_params()

        all_systems = list(db.collection(COLLECTION_SYSTEMS).stream())
        systems = []
        for s in all_systems:
            data = s.to_dict() or {}
            data["system_id"] = s.id
            if owner_filter and data.get("owner_uid", "") != owner_filter:
                continue
            if site_filter and data.get("site_id", "") != site_filter:
                continue
            systems.append(_serialize_doc(data))

        systems.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return jsonify(_paginate(systems, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/systems: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 8 — GET /api/admin/assignments
# ===========================================================================

@admin_bp.route("/api/admin/assignments", methods=["GET"])
@require_auth
@require_role("admin")
def list_all_assignments():
    """
    List all technician assignments, optionally filtered.

    Query Params:
        status (str, optional):           Filter by status: 'active', 'inactive', or 'all' (default: 'all').
        technician_uid (str, optional):   Filter by technician UID.
        system_id (str, optional):        Filter by system ID.
        site_id (str, optional):          Filter by site ID.
        page (int, optional):             Page number (default: 1).
        per_page (int, optional):         Results per page (default: 50, max: 200).
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        status_filter = (request.args.get("status") or "all").strip().lower()
        tech_filter   = (request.args.get("technician_uid") or "").strip()
        system_filter = (request.args.get("system_id") or "").strip()
        site_filter   = (request.args.get("site_id") or "").strip()
        page, per_page = _parse_pagination_params()

        all_asg = list(db.collection(COLLECTION_ASSIGNMENTS).stream())
        assignments = []
        for a in all_asg:
            data = a.to_dict() or {}
            data["assignment_id"] = a.id
            if status_filter != "all" and data.get("status", "") != status_filter:
                continue
            if tech_filter and data.get("technician_uid", "") != tech_filter:
                continue
            if system_filter and data.get("system_id", "") != system_filter:
                continue
            if site_filter and data.get("site_id", "") != site_filter:
                continue
            assignments.append(_serialize_doc(data))

        assignments.sort(key=lambda x: x.get("assigned_at", ""), reverse=True)
        return jsonify(_paginate(assignments, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/assignments: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 9 — DELETE /api/admin/assignments/<asg_id>
# ===========================================================================

@admin_bp.route("/api/admin/assignments/<asg_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_assignment(asg_id: str):
    """
    Hard-delete a technician assignment by assignment ID.

    An admin audit record is written before deletion.
    Returns 404 if the assignment does not exist.
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        doc = db.collection(COLLECTION_ASSIGNMENTS).document(asg_id).get()
        if not doc.exists:
            return jsonify({
                "error": "Not Found",
                "message": f"Assignment '{asg_id}' not found."
            }), 404

        asg_data  = doc.to_dict() or {}
        admin_uid = (g.user or {}).get("uid", "unknown")

        # Audit before deletion
        _write_admin_audit(db, "ADMIN_ASSIGNMENT_DELETE", admin_uid, asg_id, {
            "technician_uid": asg_data.get("technician_uid"),
            "system_id":      asg_data.get("system_id"),
            "site_id":        asg_data.get("site_id"),
            "status":         asg_data.get("status"),
        })

        db.collection(COLLECTION_ASSIGNMENTS).document(asg_id).delete()
        return jsonify({
            "message": f"Assignment '{asg_id}' deleted successfully."
        }), 200

    except Exception as e:
        logger.exception(f"Error in DELETE /api/admin/assignments/{asg_id}: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 10 — GET /api/admin/alerts
# ===========================================================================

@admin_bp.route("/api/admin/alerts", methods=["GET"])
@require_auth
@require_role("admin")
def list_all_alerts():
    """
    List all system alerts platform-wide.

    Query Params:
        active_only (str, optional): 'true' (default) for active alerts only, 'false' for all.
        system_id (str, optional):   Filter by system ID.
        page (int, optional):        Page number (default: 1).
        per_page (int, optional):    Results per page (default: 50, max: 200).
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        active_only_str = (request.args.get("active_only") or "true").strip().lower()
        active_only     = active_only_str in ("true", "1", "yes")
        system_filter   = (request.args.get("system_id") or "").strip()
        page, per_page  = _parse_pagination_params()

        all_alerts = list(db.collection(COLLECTION_ALERTS).stream())
        alerts = []
        for a in all_alerts:
            data = a.to_dict() or {}
            data["alert_id"] = a.id
            if active_only and not data.get("active", False):
                continue
            if system_filter and data.get("system_id", "") != system_filter:
                continue
            alerts.append(_serialize_doc(data))

        alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return jsonify(_paginate(alerts, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/alerts: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 11 — PUT /api/admin/alerts/<alert_id>
# ===========================================================================

@admin_bp.route("/api/admin/alerts/<alert_id>", methods=["PUT"])
@require_auth
@require_role("admin")
def resolve_alert(alert_id: str):
    """
    Resolve or update an alert.

    Supported payload fields:
        active (bool): Set to false to resolve the alert.

    When resolved (active set to false), the following fields are automatically set:
        - resolved_by: admin UID
        - resolved_at: ISO-8601 UTC timestamp

    Returns 400 if payload is empty or contains no updatable fields.
    Returns 404 if the alert does not exist.
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({
                "error": "Validation Error",
                "message": "Invalid or missing JSON payload."
            }), 400

        doc = db.collection(COLLECTION_ALERTS).document(alert_id).get()
        if not doc.exists:
            return jsonify({
                "error": "Not Found",
                "message": f"Alert '{alert_id}' not found."
            }), 404

        admin_uid = (g.user or {}).get("uid", "unknown")
        updates: Dict[str, Any] = {}

        if "active" in data:
            new_active = bool(data["active"])
            updates["active"] = new_active
            if not new_active:
                # Mark resolution metadata
                updates["resolved_by"] = admin_uid
                updates["resolved_at"] = datetime.now(timezone.utc).isoformat()

        if not updates:
            return jsonify({
                "error": "Validation Error",
                "message": "No updatable fields provided. Supply 'active'."
            }), 400

        db.collection(COLLECTION_ALERTS).document(alert_id).update(updates)
        _write_admin_audit(db, "ADMIN_ALERT_RESOLVE", admin_uid, alert_id, {"updates": updates})

        updated_doc  = db.collection(COLLECTION_ALERTS).document(alert_id).get()
        updated_data = updated_doc.to_dict() or {}
        updated_data["alert_id"] = alert_id
        return jsonify({
            "message": "Alert updated successfully.",
            "alert":   _serialize_doc(updated_data),
        }), 200

    except Exception as e:
        logger.exception(f"Error in PUT /api/admin/alerts/{alert_id}: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 12 — GET /api/admin/documents
# ===========================================================================

@admin_bp.route("/api/admin/documents", methods=["GET"])
@require_auth
@require_role("admin")
def list_all_documents():
    """
    List all documents across all systems and sites.

    Query Params:
        system_id (str, optional):  Filter by system ID.
        site_id (str, optional):    Filter by site ID.
        doc_type (str, optional):   Filter by document type (e.g. 'manual', 'invoice').
        page (int, optional):       Page number (default: 1).
        per_page (int, optional):   Results per page (default: 50, max: 200).
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        system_filter = (request.args.get("system_id") or "").strip()
        site_filter   = (request.args.get("site_id") or "").strip()
        type_filter   = (request.args.get("doc_type") or "").strip().lower()
        page, per_page = _parse_pagination_params()

        all_docs = list(db.collection(COLLECTION_DOCUMENTS).stream())
        documents = []
        for d in all_docs:
            data = d.to_dict() or {}
            data["doc_id"] = d.id
            if system_filter and data.get("system_id", "") != system_filter:
                continue
            if site_filter and data.get("site_id", "") != site_filter:
                continue
            if type_filter and data.get("type", "").lower() != type_filter:
                continue
            documents.append(_serialize_doc(data))

        documents.sort(key=lambda x: x.get("uploaded_at", ""), reverse=True)
        return jsonify(_paginate(documents, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/documents: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 13 — GET /api/admin/audit-log
# ===========================================================================

@admin_bp.route("/api/admin/audit-log", methods=["GET"])
@require_auth
@require_role("admin")
def get_audit_log():
    """
    Paginated audit trail covering all document lifecycle events and admin actions.

    Query Params:
        system_id (str, optional):    Filter by system ID.
        action (str, optional):       Filter by action type (e.g. UPLOAD, DELETE, VIEW,
                                      ADMIN_USER_DISABLE, ADMIN_ALERT_RESOLVE).
        performed_by (str, optional): Filter by actor UID.
        page (int, optional):         Page number (default: 1).
        per_page (int, optional):     Results per page (default: 50, max: 200).
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        system_filter    = (request.args.get("system_id") or "").strip()
        action_filter    = (request.args.get("action") or "").strip().upper()
        performer_filter = (request.args.get("performed_by") or "").strip()
        page, per_page   = _parse_pagination_params()

        all_audits = list(db.collection(COLLECTION_DOCUMENT_AUDITS).stream())
        audits = []
        for a in all_audits:
            data = a.to_dict() or {}
            data["audit_id"] = a.id

            if system_filter and data.get("system_id", "") != system_filter:
                continue
            if action_filter and data.get("action", "").upper() != action_filter:
                continue
            if performer_filter:
                # Support both 'performed_by_uid' (admin audits) and 'user_uid' (document audits)
                performer = data.get("performed_by_uid") or data.get("user_uid", "")
                if performer != performer_filter:
                    continue

            audits.append(_serialize_doc(data))

        audits.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return jsonify(_paginate(audits, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/audit-log: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 14 — GET /api/admin/readings
# ===========================================================================

@admin_bp.route("/api/admin/readings", methods=["GET"])
@require_auth
@require_role("admin")
def list_admin_readings():
    """
    List telemetry readings across all systems (or filtered by system_id), ordered newest first.

    Query Params:
        system_id (str, optional):   Filter by solar system ID.
        page (int, optional):        Page number (default: 1).
        per_page (int, optional):    Results per page (default: 50, max: 200).

    Returns:
        Paginated envelope: { items, total, page, per_page, total_pages }
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        system_filter = (request.args.get("system_id") or "").strip()
        page, per_page = _parse_pagination_params()

        readings_ref = db.collection(COLLECTION_READINGS)
        all_readings = []
        if system_filter:
            docs = list(readings_ref.where(filter=FieldFilter("system_id", "==", system_filter)).stream())
        else:
            docs = list(readings_ref.stream())

        for d in docs:
            data = d.to_dict() or {}
            data["id"] = d.id
            all_readings.append(_serialize_doc(data))

        def _sort_key(item):
            if "unix_timestamp" in item and item["unix_timestamp"] is not None:
                try:
                    return float(item["unix_timestamp"])
                except Exception:
                    pass
            ts = item.get("timestamp")
            if ts:
                try:
                    clean_ts = str(ts).replace("Z", "+00:00")
                    dt = datetime.fromisoformat(clean_ts)
                    return dt.timestamp()
                except Exception:
                    pass
            return 0.0

        all_readings.sort(key=_sort_key, reverse=True)
        return jsonify(_paginate(all_readings, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/readings: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 15 — GET /api/admin/reports/summary
# ===========================================================================

@admin_bp.route("/api/admin/reports/summary", methods=["GET"])
@require_auth
@require_role("admin")
def get_admin_reports_summary():
    """
    Platform-wide performance & generation KPIs summary report for administrators.

    Returns:
        {
            "total_users": int,
            "total_sites": int,
            "total_systems": int,
            "total_readings": int,
            "active_alerts": int,
            "average_health_score": Optional[float],
            "overall_generation": float,            # Total kWh generated across all systems
            "overall_expected_generation": float,   # Total expected kWh
            "total_lost_generation": float,         # Total lost kWh
            "average_performance_ratio": Optional[float],
            "generated_at": str (ISO-8601 UTC timestamp)
        }
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        # Entities count
        total_users = len(list(db.collection(COLLECTION_USERS).stream()))
        total_sites = len(list(db.collection(COLLECTION_SITES).stream()))
        systems_docs = list(db.collection(COLLECTION_SYSTEMS).stream())
        total_systems = len(systems_docs)

        active_alerts_docs = list(
            db.collection(COLLECTION_ALERTS)
            .where(filter=FieldFilter("active", "==", True))
            .stream()
        )
        total_active_alerts = len(active_alerts_docs)

        # Health Scores across systems
        health_scores = []
        for s in systems_docs:
            try:
                from BACKEND.ml_predict import calculate_health_score
                h = calculate_health_score(system_id=s.id, db=db)
                if h and h.get("health_score") is not None:
                    health_scores.append(float(h["health_score"]))
            except Exception as he:
                logger.warning(f"Error calculating health for system {s.id} in reports summary: {he}")

        avg_health = round(float(sum(health_scores) / len(health_scores)), 1) if health_scores else None

        # Energy & Generation aggregates across readings
        readings_docs = list(db.collection(COLLECTION_READINGS).stream())
        total_readings = len(readings_docs)

        total_actual_wh = 0.0
        total_expected_wh = 0.0
        total_lost_wh = 0.0
        valid_prs = []

        interval_hours = 5.0 / 60.0  # Nominal 5-minute sampling interval

        for r_doc in readings_docs:
            r_data = r_doc.to_dict() or {}
            try:
                act_pwr = float(r_data.get("power") or 0.0)
                exp_pwr = float(r_data.get("expected_power") or 0.0)
            except (ValueError, TypeError):
                continue

            total_actual_wh += act_pwr * interval_hours
            total_expected_wh += exp_pwr * interval_hours

            if exp_pwr > 10.0:  # Daytime threshold
                lost_w = max(0.0, exp_pwr - act_pwr)
                total_lost_wh += lost_w * interval_hours

            pr = r_data.get("performance_ratio")
            if pr is not None:
                try:
                    pr_float = float(pr)
                    if 0.0 <= pr_float <= 2.0:
                        valid_prs.append(pr_float)
                except (ValueError, TypeError):
                    pass

        overall_gen_kwh = round(total_actual_wh / 1000.0, 4)
        overall_exp_kwh = round(total_expected_wh / 1000.0, 4)
        overall_lost_kwh = round(total_lost_wh / 1000.0, 4)

        if overall_exp_kwh > 0.0:
            avg_pr = round(overall_gen_kwh / overall_exp_kwh, 4)
        elif valid_prs:
            avg_pr = round(float(sum(valid_prs) / len(valid_prs)), 4)
        else:
            avg_pr = None

        return jsonify({
            "total_users":                 total_users,
            "total_sites":                 total_sites,
            "total_systems":               total_systems,
            "total_readings":              total_readings,
            "active_alerts":               total_active_alerts,
            "average_health_score":        avg_health,
            "overall_generation":          overall_gen_kwh,
            "overall_expected_generation": overall_exp_kwh,
            "total_lost_generation":       overall_lost_kwh,
            "average_performance_ratio":   avg_pr,
            "generated_at":                datetime.now(timezone.utc).isoformat(),
        }), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/reports/summary: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500


# ===========================================================================
# Endpoint 16 — GET /api/admin/health
# ===========================================================================

@admin_bp.route("/api/admin/health", methods=["GET"])
@require_auth
@require_role("admin")
def list_admin_systems_health():
    """
    Platform-wide health monitoring dashboard across all solar systems.

    Query Params:
        sort (str, optional):      'lowest' (default, lowest score first to highlight issues),
                                   'highest', or 'name'.
        page (int, optional):      Page number (default: 1).
        per_page (int, optional):  Results per page (default: 50, max: 200).

    Returns:
        Paginated envelope: { items, total, page, per_page, total_pages }
    """
    db = get_db()
    if db is None:
        return jsonify({"error": "Database connection unavailable"}), 500

    try:
        sort_mode = (request.args.get("sort") or "lowest").strip().lower()
        page, per_page = _parse_pagination_params()

        all_systems = list(db.collection(COLLECTION_SYSTEMS).stream())
        system_health_list = []

        from BACKEND.ml_predict import calculate_health_score

        for s in all_systems:
            s_data = s.to_dict() or {}
            sys_id = s.id
            name = s_data.get("name", "Unnamed System")
            site_id = s_data.get("site_id", "")
            owner_uid = s_data.get("owner_uid", "")

            h_res = calculate_health_score(system_id=sys_id, db=db)

            entry = {
                "system_id":                 sys_id,
                "name":                      name,
                "site_id":                   site_id,
                "owner_uid":                 owner_uid,
                "health_score":              h_res.get("health_score"),
                "status":                    h_res.get("status", "N/A"),
                "average_pr":                h_res.get("average_pr"),
                "anomaly_count":             h_res.get("anomaly_count", 0),
                "avg_loss_percent":          h_res.get("avg_loss_percent"),
                "readings_analyzed":         h_res.get("readings_analyzed", 0),
                "daytime_readings_analyzed": h_res.get("daytime_readings_analyzed", 0),
            }
            system_health_list.append(entry)

        if sort_mode == "lowest":
            # Lowest health score first (None/unscored at the end)
            system_health_list.sort(key=lambda x: (x["health_score"] is None, x["health_score"] if x["health_score"] is not None else 999.0))
        elif sort_mode == "highest":
            # Highest health score first (None at the end)
            system_health_list.sort(key=lambda x: (x["health_score"] is None, -(x["health_score"] if x["health_score"] is not None else -1.0)))
        elif sort_mode == "name":
            system_health_list.sort(key=lambda x: x.get("name", "").lower())
        else:
            # Default to lowest score first
            system_health_list.sort(key=lambda x: (x["health_score"] is None, x["health_score"] if x["health_score"] is not None else 999.0))

        return jsonify(_paginate(system_health_list, page, per_page)), 200

    except Exception as e:
        logger.exception(f"Error in GET /api/admin/health: {e}")
        return jsonify({"error": "Internal Server Error", "message": str(e)}), 500

