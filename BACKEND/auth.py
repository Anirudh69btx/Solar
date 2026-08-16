"""
User Authentication & Role Management Module for Solar Monitoring System.

Features:
- Production Firebase Admin SDK authentication (Email/Password)
- ID token verification & decoding (auth.verify_id_token)
- Authentication decorator (@require_auth)
- Role-based authorization decorator (@require_role('owner', 'technician', 'admin'))
- Public Registration (POST /api/auth/register - strictly owner role only)
- Admin User Creation (POST /api/auth/users - restricted to admin role)
- User Profile Endpoint (GET /api/auth/me)
"""

import sys
import os
import logging
from functools import wraps
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, g
import firebase_admin
from firebase_admin import auth

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from BACKEND.firebase_config import get_db

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)
COLLECTION_USERS = "users"
VALID_ROLES = ["owner", "technician", "admin"]


def verify_token(id_token: str) -> dict:
    """
    Verifies a Firebase ID token string using Firebase Admin SDK.

    Args:
        id_token (str): Raw Firebase JWT ID token string.

    Returns:
        dict: Decoded token claims containing uid, email, etc.

    Raises:
        ValueError: If id_token is empty or not a string.
        auth.InvalidIdTokenError: If token is invalid or malformed.
        auth.ExpiredIdTokenError: If token has expired.
        auth.RevokedIdTokenError: If token was revoked.
        auth.CertificateFetchError: If public certs cannot be fetched.
        Exception: On other verification failures.
    """
    if not id_token or not isinstance(id_token, str):
        raise ValueError("ID token string is empty or invalid.")

    # Production verification: strictly call Firebase Admin SDK
    decoded_token = auth.verify_id_token(id_token)
    return decoded_token


def require_auth(f):
    """
    Decorator requiring a valid Firebase Bearer token in the Authorization header.
    Attaches the Firestore user profile dictionary to Flask's `g.user` and `request.user`.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({
                "error": "Unauthorized",
                "message": "Missing or malformed Authorization header. Expected format: 'Bearer <token>'"
            }), 401

        token = auth_header.split("Bearer ", 1)[1].strip()
        if not token:
            return jsonify({
                "error": "Unauthorized",
                "message": "Missing bearer token in Authorization header."
            }), 401

        try:
            decoded_token = verify_token(token)
            uid = decoded_token.get("uid")
            if not uid:
                raise ValueError("Decoded token payload contains no UID.")
        except Exception as e:
            logger.warning(f"Token verification failed: {e}")
            return jsonify({
                "error": "Unauthorized",
                "message": f"Invalid or expired Firebase ID token: {str(e)}"
            }), 401

        # Fetch user document from Firestore users collection
        db = get_db()
        if db is None:
            logger.error("Database handle unavailable in require_auth")
            return jsonify({"error": "Database connection unavailable"}), 500

        user_doc_ref = db.collection(COLLECTION_USERS).document(uid)
        doc = user_doc_ref.get()

        if not doc.exists:
            logger.warning(f"User profile document missing in Firestore for UID: {uid}")
            return jsonify({
                "error": "Forbidden",
                "message": f"User profile document not found in Firestore for UID: {uid}"
            }), 403

        user_data = doc.to_dict() or {}
        user_data["uid"] = uid

        # Attach user to request context (g.user and request.user)
        g.user = user_data
        setattr(request, "user", user_data)

        return f(*args, **kwargs)

    return decorated_function


def require_role(*allowed_roles):
    """
    Role-based authorization decorator. Must be used AFTER @require_auth.

    Usage:
        @require_auth
        @require_role('admin')
        def admin_only_endpoint(): ...

        @require_auth
        @require_role('technician', 'admin')
        def tech_or_admin_endpoint(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = getattr(g, "user", None) or getattr(request, "user", None)
            if not user or not isinstance(user, dict):
                return jsonify({
                    "error": "Unauthorized",
                    "message": "User context missing. Make sure @require_auth precedes @require_role."
                }), 401

            raw_role = user.get("role")
            if not raw_role or not isinstance(raw_role, str):
                logger.warning(f"User account {user.get('uid')} has no assigned role.")
                return jsonify({
                    "error": "Forbidden",
                    "message": "User account has no valid assigned role."
                }), 403

            user_role = raw_role.strip().lower()
            if user_role not in VALID_ROLES:
                logger.warning(f"User account {user.get('uid')} has invalid role '{user_role}'.")
                return jsonify({
                    "error": "Forbidden",
                    "message": f"User role '{user_role}' is invalid."
                }), 403

            allowed = [r.lower() for r in allowed_roles]
            if user_role not in allowed:
                return jsonify({
                    "error": "Forbidden",
                    "message": f"Role '{user_role}' is not authorized to access this resource. Allowed roles: {list(allowed_roles)}"
                }), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


@auth_bp.route("/api/auth/register", methods=["POST"])
def register_user():
    """
    Public user registration endpoint.
    Payload: {email, password, name, [role]}

    SECURITY POLICIES:
    1. Public registration is strictly allowed ONLY for the 'owner' role.
    2. If a client attempts to supply a privileged role (e.g. 'admin' or 'technician'),
       the request is rejected with HTTP 403 Forbidden.
    3. If role is omitted or empty, it defaults to 'owner'.
    4. Duplicate emails return HTTP 409 Conflict without overwriting existing profiles.
    5. Firestore profile creation is tied to successful real Firebase Auth UID.
    """
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        email = data.get("email", "").strip()
        password = data.get("password", "").strip()
        name = data.get("name", "").strip()

        # Prevent privilege escalation: public registration is restricted to 'owner'
        requested_role = data.get("role")
        if requested_role is not None:
            requested_role_str = str(requested_role).strip().lower()
            if requested_role_str != "" and requested_role_str != "owner":
                logger.warning(
                    f"Rejected public self-registration attempt with role '{requested_role}' for email '{email}'"
                )
                return jsonify({
                    "error": "Forbidden",
                    "message": "Public registration is allowed only for the owner role."
                }), 403

        role = "owner"

        if not email or not password:
            return jsonify({"error": "Fields 'email' and 'password' are required"}), 400

        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        # Check Firestore for existing email to prevent duplicates
        db = get_db()
        if db is None:
            logger.error("Database handle unavailable in register_user")
            return jsonify({"error": "Database connection unavailable"}), 500

        existing_users = list(db.collection(COLLECTION_USERS).where("email", "==", email).limit(1).stream())
        if existing_users:
            logger.warning(f"Registration conflict: email '{email}' already exists in Firestore.")
            return jsonify({
                "error": "Conflict",
                "message": "A user with this email already exists."
            }), 409

        # Create user in Firebase Authentication
        try:
            user_record = auth.create_user(
                email=email,
                password=password,
                display_name=name if name else email.split("@")[0]
            )
            uid = user_record.uid
        except auth.EmailAlreadyExistsError:
            logger.warning(f"Registration conflict: email '{email}' already exists in Firebase Auth.")
            return jsonify({
                "error": "Conflict",
                "message": "A user with this email already exists."
            }), 409
        except Exception as auth_err:
            logger.error(f"Firebase Auth user creation failed for '{email}': {auth_err}")
            return jsonify({
                "error": "Registration failed",
                "message": f"Failed to create user in Firebase Auth: {str(auth_err)}"
            }), 400

        # Create user document in Firestore 'users' collection with real UID
        user_profile = {
            "uid": uid,
            "email": email,
            "name": name if name else email.split("@")[0],
            "role": role,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        db.collection(COLLECTION_USERS).document(uid).set(user_profile)
        logger.info(f"Successfully registered owner user '{email}' with UID '{uid}'.")

        return jsonify({
            "message": "User registered successfully",
            "user": user_profile
        }), 201

    except Exception as e:
        logger.exception(f"Unexpected error in /api/auth/register: {e}")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to register user due to an internal error."
        }), 500


@auth_bp.route("/api/auth/users", methods=["POST"])
@require_auth
@require_role("admin")
def admin_create_user():
    """
    Admin-only user creation endpoint. Allows an authenticated Admin to create
    technician, admin, or owner accounts.
    Payload: {email, password, name, role}
    """
    try:
        data = request.get_json(silent=True)
        if not data or not isinstance(data, dict):
            return jsonify({"error": "Invalid or missing JSON payload"}), 400

        email = data.get("email", "").strip()
        password = data.get("password", "").strip()
        name = data.get("name", "").strip()
        role = data.get("role", "owner").strip().lower()

        if not email or not password:
            return jsonify({"error": "Fields 'email' and 'password' are required"}), 400

        if len(password) < 6:
            return jsonify({"error": "Password must be at least 6 characters long"}), 400

        if role not in VALID_ROLES:
            return jsonify({
                "error": "Bad Request",
                "message": f"Invalid role '{role}'. Allowed roles: {VALID_ROLES}"
            }), 400

        db = get_db()
        if db is None:
            logger.error("Database handle unavailable in admin_create_user")
            return jsonify({"error": "Database connection unavailable"}), 500

        existing_users = list(db.collection(COLLECTION_USERS).where("email", "==", email).limit(1).stream())
        if existing_users:
            logger.warning(f"Admin user creation conflict: email '{email}' already exists in Firestore.")
            return jsonify({
                "error": "Conflict",
                "message": "A user with this email already exists."
            }), 409

        try:
            user_record = auth.create_user(
                email=email,
                password=password,
                display_name=name if name else email.split("@")[0]
            )
            uid = user_record.uid
        except auth.EmailAlreadyExistsError:
            logger.warning(f"Admin user creation conflict: email '{email}' already exists in Firebase Auth.")
            return jsonify({
                "error": "Conflict",
                "message": "A user with this email already exists."
            }), 409
        except Exception as auth_err:
            logger.error(f"Admin create_user failed for '{email}': {auth_err}")
            return jsonify({
                "error": "Bad Request",
                "message": f"Failed to create user in Firebase Auth: {str(auth_err)}"
            }), 400

        user_profile = {
            "uid": uid,
            "email": email,
            "name": name if name else email.split("@")[0],
            "role": role,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        db.collection(COLLECTION_USERS).document(uid).set(user_profile)
        logger.info(f"Admin created user '{email}' with role '{role}' and UID '{uid}'.")

        return jsonify({
            "message": "User created successfully by admin",
            "user": user_profile
        }), 201

    except Exception as e:
        logger.exception(f"Unexpected error in /api/auth/users: {e}")
        return jsonify({
            "error": "Internal Server Error",
            "message": "Failed to create user due to an internal error."
        }), 500


@auth_bp.route("/api/auth/me", methods=["GET"])
@require_auth
def get_current_user_profile():
    """
    Returns current authenticated user profile from Firestore. Protected by @require_auth.
    """
    user = getattr(g, "user", None) or getattr(request, "user", None)
    return jsonify(user), 200


@auth_bp.route("/api/auth/admin-only", methods=["GET"])
@require_auth
@require_role("admin")
def admin_only_route():
    """Endpoint restricted to admin role."""
    user = getattr(g, "user", None) or getattr(request, "user", None)
    return jsonify({"message": f"Welcome Admin {user.get('name')}", "user": user}), 200


@auth_bp.route("/api/auth/tech-only", methods=["GET"])
@require_auth
@require_role("technician", "admin")
def tech_only_route():
    """Endpoint restricted to technician or admin roles."""
    user = getattr(g, "user", None) or getattr(request, "user", None)
    return jsonify({"message": f"Welcome Technician/Admin {user.get('name')}", "user": user}), 200
