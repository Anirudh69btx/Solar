"""
Firebase Configuration Module for Solar Monitoring System.

This module initializes the Firebase Admin SDK using serviceAccountKey.json
and exports a singleton Firestore database client ('db').
"""

import os
import sys
import firebase_admin
from firebase_admin import credentials, firestore


def _find_service_account_key() -> str:
    """
    Locates serviceAccountKey.json across common relative directory locations.

    Returns:
        str: Absolute path to serviceAccountKey.json

    Raises:
        FileNotFoundError: If serviceAccountKey.json cannot be found.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, ".."))

    candidate_paths = [
        os.path.join(project_root, "serviceAccountKey.json"),
        os.path.join(current_dir, "serviceAccountKey.json"),
        os.path.abspath("serviceAccountKey.json"),
    ]

    for path in candidate_paths:
        if os.path.exists(path):
            return path

    raise FileNotFoundError(
        "Could not find 'serviceAccountKey.json'. Please ensure it is present in the project root directory: "
        f"{project_root}"
    )


def initialize_firebase():
    """
    Initializes the Firebase Admin SDK idempotently.

    Returns:
        google.cloud.firestore.Client: Firestore client instance.
    """
    try:
        # Check if default app is already initialized to prevent app re-creation error
        if not firebase_admin._apps:
            key_path = _find_service_account_key()
            cred = credentials.Certificate(key_path)
            firebase_admin.initialize_app(cred)
            print(f"[Firebase Config] Initialized Firebase App using key at: {key_path}")
        else:
            print("[Firebase Config] Firebase App already initialized.")

        # Return Firestore client instance
        client = firestore.client()
        return client
    except Exception as e:
        print(f"[Firebase Config ERROR] Failed to initialize Firebase: {e}", file=sys.stderr)
        raise e


# Singleton database client instance
try:
    db = initialize_firebase()
except Exception:
    db = None


def get_db():
    """
    Helper function to access the active Firestore database client.

    Returns:
        google.cloud.firestore.Client: Active Firestore database handle.
    """
    global db
    if db is None:
        db = initialize_firebase()
    return db


if __name__ == "__main__":
    print("[Test] Verifying Firebase Firestore connection...")
    try:
        firestore_db = get_db()
        print(f"[Success] Successfully connected to Firestore. Client project: {firestore_db.project}")
    except Exception as err:
        print(f"[Failure] Connection test failed: {err}")
