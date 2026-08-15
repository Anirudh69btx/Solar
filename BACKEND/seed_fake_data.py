"""
Backend bridge for Solar Fake Data Generator module.
Imports and delegates execution to Data_Base.seed_fake_data.
"""

import sys
import os

# Add project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from Data_Base.seed_fake_data import main, generate_reading, push_reading, run_backfill, run_live

if __name__ == "__main__":
    main()
