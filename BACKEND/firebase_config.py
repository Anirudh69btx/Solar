"""
Backend bridge for Firebase configuration module.
Imports and re-exports db and get_db from Data_Base.firebase_config.
"""

import sys
import os

# Add project root to sys.path to enable Data_Base imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Data_Base.firebase_config import db, get_db

__all__ = ["db", "get_db"]
