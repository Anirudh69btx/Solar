"""Quick Firestore connectivity & latency test."""
import time
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

print("Testing Firestore connectivity...", flush=True)

t0 = time.time()
from BACKEND.firebase_config import get_db
db = get_db()
print(f"Init: {round(time.time()-t0, 2)}s", flush=True)

# Test 1: Single document fetch
print("\n--- Test 1: Single Document Fetch ---", flush=True)
t1 = time.time()
try:
    # Try fetching any document from readings
    docs = list(db.collection("readings").limit(1).stream())
    elapsed = round(time.time()-t1, 2)
    if docs:
        print(f"SUCCESS: Fetched 1 doc in {elapsed}s. ID: {docs[0].id}", flush=True)
    else:
        print(f"WARNING: No documents found in 'readings'. Elapsed: {elapsed}s", flush=True)
except Exception as e:
    elapsed = round(time.time()-t1, 2)
    print(f"FAILED after {elapsed}s: {e}", flush=True)

# Test 2: Ordered query with limit
print("\n--- Test 2: Ordered Query (limit=3) ---", flush=True)
t2 = time.time()
try:
    docs = list(db.collection("readings").order_by("unix_timestamp", direction="DESCENDING").limit(3).stream())
    elapsed = round(time.time()-t2, 2)
    print(f"SUCCESS: Fetched {len(docs)} docs in {elapsed}s", flush=True)
except Exception as e:
    elapsed = round(time.time()-t2, 2)
    print(f"FAILED after {elapsed}s: {e}", flush=True)

# Test 3: Collection count
print("\n--- Test 3: Users Collection ---", flush=True)
t3 = time.time()
try:
    docs = list(db.collection("users").limit(3).stream())
    elapsed = round(time.time()-t3, 2)
    print(f"SUCCESS: Fetched {len(docs)} user docs in {elapsed}s", flush=True)
except Exception as e:
    elapsed = round(time.time()-t3, 2)
    print(f"FAILED after {elapsed}s: {e}", flush=True)

print(f"\nTotal elapsed: {round(time.time()-t0, 2)}s", flush=True)
