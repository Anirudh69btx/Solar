import os
import time
import pandas as pd
import firebase_admin
from firebase_admin import credentials, firestore
from google.api_core.exceptions import (
    ResourceExhausted,
    ServiceUnavailable,
    DeadlineExceeded,
)

# ============================================================
# CONFIGURATION
# ============================================================

CSV_FILE = "solar_dataset_1year.csv"
SERVICE_ACCOUNT = "serviceAccountKey.json"
COLLECTION = "readings"

# Keep this conservative for Firebase free quota.
BATCH_SIZE = 100

# Delay between successful batches.
BATCH_DELAY_SECONDS = 2

# Retry settings.
MAX_RETRIES = 8
INITIAL_BACKOFF_SECONDS = 10
MAX_BACKOFF_SECONDS = 300

# Progress file.
PROGRESS_FILE = "firestore_upload_progress.txt"


# ============================================================
# FIREBASE INITIALIZATION
# ============================================================

if not os.path.exists(CSV_FILE):
    raise FileNotFoundError(
        f"CSV file not found: {CSV_FILE}"
    )

if not os.path.exists(SERVICE_ACCOUNT):
    raise FileNotFoundError(
        f"Firebase service account file not found: {SERVICE_ACCOUNT}"
    )

if not firebase_admin._apps:
    cred = credentials.Certificate(SERVICE_ACCOUNT)
    firebase_admin.initialize_app(cred)

db = firestore.client()


# ============================================================
# READ CSV
# ============================================================

print("Reading CSV...")

df = pd.read_csv(CSV_FILE)

print(f"Total rows found: {len(df)}")
print(f"Total columns found: {len(df.columns)}")


# ============================================================
# REQUIRED COLUMNS
# ============================================================

required_columns = [
    "timestamp",
    "system_id",
    "system_capacity_kw",
    "voltage",
    "current",
    "power",
    "irradiance",
    "lux",
    "temperature_panel",
    "temperature_ambient",
    "humidity",
    "rain",
    "vibration",
    "expected_power",
    "performance_ratio",
    "energy",
    "fault_injected",
    "fault_type",
    "weather_condition",
    "day_of_year",
    "hour_of_day",
    "day_of_week",
]

missing = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing:
    raise ValueError(
        f"Missing required columns: {missing}"
    )

print("Column validation: OK")


# ============================================================
# REMOVE EXACT DUPLICATES
# ============================================================

before = len(df)

df = df.drop_duplicates().reset_index(drop=True)

after = len(df)

print(f"Duplicate rows removed: {before - after}")
print(f"Rows remaining: {after}")


# ============================================================
# NORMALIZE TIMESTAMPS
# ============================================================

print("\nNormalizing timestamps...")

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    utc=True,
    errors="coerce"
)

invalid_timestamps = df["timestamp"].isna().sum()

if invalid_timestamps > 0:
    raise ValueError(
        f"Found {invalid_timestamps} invalid timestamps."
    )

print("Timestamp validation: OK")


# ============================================================
# FIRESTORE COLLECTION
# ============================================================

collection_ref = db.collection(COLLECTION)


# ============================================================
# DETERMINISTIC DOCUMENT ID
# ============================================================

def make_document_id(system_id, timestamp):
    """
    Same system + same timestamp always produces
    the exact same Firestore document ID.
    """

    system_id = str(system_id)

    timestamp = pd.to_datetime(
        timestamp,
        utc=True
    )

    timestamp_key = timestamp.strftime(
        "%Y%m%dT%H%M%S%fZ"
    )

    return f"{system_id}_{timestamp_key}"


# ============================================================
# LOAD EXISTING FIRESTORE DOCUMENTS
# ============================================================

print("\n==============================================")
print("SCANNING EXISTING FIRESTORE DOCUMENTS")
print("==============================================")

print(
    "Checking Firestore so already-uploaded records "
    "will NOT be uploaded again..."
)

existing_keys = set()
existing_document_ids = set()

existing_count = 0

try:

    for document in collection_ref.stream():

        existing_count += 1

        data = document.to_dict()

        # ----------------------------------------------------
        # Store document ID as strongest duplicate protection.
        # ----------------------------------------------------

        existing_document_ids.add(
            document.id
        )

        system_id = data.get("system_id")
        timestamp = data.get("timestamp")

        if system_id is None or timestamp is None:
            continue

        timestamp = pd.to_datetime(
            timestamp,
            utc=True,
            errors="coerce"
        )

        if pd.isna(timestamp):
            continue

        key = (
            str(system_id),
            timestamp.isoformat()
        )

        existing_keys.add(key)

        if existing_count % 1000 == 0:
            print(
                f"Existing documents scanned: "
                f"{existing_count}"
            )

except Exception as error:

    print("\n==============================================")
    print("FIRESTORE SCAN FAILED")
    print("==============================================")

    print(error)

    print(
        "\nNo upload will be attempted because "
        "the existing database could not be verified."
    )

    raise SystemExit(1)


print(
    f"\nExisting Firestore documents found: "
    f"{existing_count}"
)

print(
    f"Existing valid timestamp/system_id keys: "
    f"{len(existing_keys)}"
)


# ============================================================
# DETERMINE NEW RECORDS
# ============================================================

print("\n==============================================")
print("CHECKING CSV AGAINST FIRESTORE")
print("==============================================")

new_rows = []

already_exists = 0

for index, row in df.iterrows():

    system_id = str(row["system_id"])

    timestamp = row["timestamp"]

    key = (
        system_id,
        timestamp.isoformat()
    )

    document_id = make_document_id(
        system_id,
        timestamp
    )

    # --------------------------------------------------------
    # Check BOTH:
    #   1. system_id + timestamp
    #   2. deterministic document ID
    # --------------------------------------------------------

    if (
        key in existing_keys
        or document_id in existing_document_ids
    ):

        already_exists += 1

    else:

        new_rows.append(index)


print(
    f"Already existing: {already_exists}"
)

print(
    f"New records to upload: {len(new_rows)}"
)


# ============================================================
# NOTHING NEW
# ============================================================

if len(new_rows) == 0:

    print("\n==============================================")
    print("NOTHING TO UPLOAD")
    print("==============================================")

    print(
        "All CSV records already exist in Firestore."
    )

    print(
        f"Firestore documents: {existing_count}"
    )

    print(
        f"CSV rows: {len(df)}"
    )

    raise SystemExit(0)


# ============================================================
# DATA CONVERSION
# ============================================================

numeric_fields = [
    "system_capacity_kw",
    "voltage",
    "current",
    "power",
    "irradiance",
    "lux",
    "temperature_panel",
    "temperature_ambient",
    "humidity",
    "rain",
    "vibration",
    "expected_power",
    "performance_ratio",
    "energy",
    "day_of_year",
    "hour_of_day",
    "day_of_week",
]


def convert_row(row):

    data = row.to_dict()

    # --------------------------------------------------------
    # Convert NaN / NaT to None
    # --------------------------------------------------------

    cleaned = {}

    for key, value in data.items():

        if pd.isna(value):
            cleaned[key] = None

        else:
            cleaned[key] = value

    data = cleaned

    # --------------------------------------------------------
    # Timestamp
    # --------------------------------------------------------

    if data["timestamp"] is not None:

        data["timestamp"] = (
            pd.to_datetime(
                data["timestamp"],
                utc=True
            ).to_pydatetime()
        )

    # --------------------------------------------------------
    # Numeric fields
    # --------------------------------------------------------

    for field in numeric_fields:

        if data[field] is not None:

            data[field] = float(
                data[field]
            )

    # --------------------------------------------------------
    # Boolean
    # --------------------------------------------------------

    if data["fault_injected"] is not None:

        value = data["fault_injected"]

        if isinstance(value, str):

            data["fault_injected"] = (
                value.strip().lower()
                in ["true", "1", "yes"]
            )

        else:

            data["fault_injected"] = bool(value)

    return data


# ============================================================
# FIRESTORE COMMIT WITH RETRY
# ============================================================

def commit_with_retry(batch):

    backoff = INITIAL_BACKOFF_SECONDS

    for attempt in range(
        1,
        MAX_RETRIES + 1
    ):

        try:

            batch.commit()

            return True

        except (
            ResourceExhausted,
            ServiceUnavailable,
            DeadlineExceeded,
        ) as error:

            print(
                "\nFirestore temporary/quota error"
            )

            print(
                f"Attempt: "
                f"{attempt}/{MAX_RETRIES}"
            )

            print(
                f"Error: {error}"
            )

            if attempt >= MAX_RETRIES:

                print(
                    "\nMaximum retries reached."
                )

                return False

            print(
                f"Waiting {backoff} seconds "
                "before retry..."
            )

            time.sleep(backoff)

            backoff = min(
                backoff * 2,
                MAX_BACKOFF_SECONDS
            )

    return False


# ============================================================
# LOAD PROGRESS
# ============================================================

start_position = 0

if os.path.exists(PROGRESS_FILE):

    try:

        with open(
            PROGRESS_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            start_position = int(
                file.read().strip()
            )

        if (
            start_position < 0
            or start_position > len(new_rows)
        ):

            start_position = 0

        print(
            f"\nPrevious progress found: "
            f"{start_position}/{len(new_rows)}"
        )

    except Exception:

        print(
            "Invalid progress file. "
            "Starting from position 0."
        )

        start_position = 0

else:

    print(
        "\nNo previous progress file found."
    )

    print(
        "Starting from the first unprocessed record."
    )


# ============================================================
# IMPORTANT RESUME SAFETY
# ============================================================
#
# Firestore itself is the source of truth.
#
# Even if the progress file says 20,000 but Firestore
# already contains more records, those records are skipped
# because existing_keys/document IDs were checked above.
#
# Therefore it is safe to resume after:
#
#   - 429 quota error
#   - PC shutdown
#   - Ctrl+C
#   - network failure
#   - Python crash
#
# ============================================================


# ============================================================
# UPLOAD NEW RECORDS
# ============================================================

print("\n==============================================")
print("STARTING / RESUMING NEW RECORD UPLOAD")
print("==============================================")

print(
    f"Records remaining according to progress: "
    f"{len(new_rows) - start_position}"
)

print(
    f"Total new records detected: "
    f"{len(new_rows)}"
)

print(
    f"Batch size: {BATCH_SIZE}"
)

print(
    f"Delay between batches: "
    f"{BATCH_DELAY_SECONDS} seconds"
)

print()


uploaded = 0

position = start_position

total_new = len(new_rows)


while position < total_new:

    batch = db.batch()

    batch_start = position

    batch_end = min(
        position + BATCH_SIZE,
        total_new
    )

    batch_count = 0

    # ========================================================
    # BUILD BATCH
    # ========================================================

    for list_position in range(
        batch_start,
        batch_end
    ):

        dataframe_index = new_rows[
            list_position
        ]

        row = df.iloc[dataframe_index]

        data = convert_row(row)

        system_id = str(
            data["system_id"]
        )

        timestamp = data["timestamp"]

        document_id = make_document_id(
            system_id,
            timestamp
        )

        doc_ref = (
            collection_ref
            .document(document_id)
        )

        batch.set(
            doc_ref,
            data,
            merge=True
        )

        batch_count += 1


    # ========================================================
    # COMMIT
    # ========================================================

    success = commit_with_retry(batch)

    if not success:

        print("\n==============================================")
        print("UPLOAD PAUSED SAFELY")
        print("==============================================")

        print(
            f"Successfully uploaded in this run: "
            f"{uploaded}"
        )

        print(
            f"Progress position remains: "
            f"{position}"
        )

        print(
            f"Remaining according to progress: "
            f"{total_new - position}"
        )

        print(
            "\nFirestore quota/error prevented the "
            "next batch."
        )

        print(
            "\nDO NOT DELETE "
            f"{PROGRESS_FILE}"
        )

        print(
            "\nWait until the quota resets and run:"
        )

        print(
            "python upload_dataset.py"
        )

        print(
            "\nThe script will verify Firestore again "
            "and continue safely."
        )

        raise SystemExit(0)


    # ========================================================
    # UPDATE PROGRESS
    # ========================================================

    position = batch_end

    uploaded += batch_count

    with open(
        PROGRESS_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            str(position)
        )


    # ========================================================
    # DISPLAY PROGRESS
    # ========================================================

    percentage = (
        position / total_new
    ) * 100

    print(
        f"Uploaded new records: "
        f"{position}/{total_new} "
        f"({percentage:.2f}%)"
    )


    # ========================================================
    # THROTTLE
    # ========================================================

    if position < total_new:

        time.sleep(
            BATCH_DELAY_SECONDS
        )


# ============================================================
# FINAL STATUS
# ============================================================

print("\n==============================================")

if position >= total_new:

    print("UPLOAD COMPLETE")

    print("==============================================")

    print(
        f"Previously existing: "
        f"{already_exists}"
    )

    print(
        f"New records uploaded this run: "
        f"{uploaded}"
    )

    print(
        f"Total CSV records: "
        f"{len(df)}"
    )

    print(
        f"Firestore collection: "
        f"{COLLECTION}"
    )

    print(
        "\nAll records have been processed."
    )

else:

    print("UPLOAD PAUSED")

    print("==============================================")

    print(
        f"Uploaded this run: "
        f"{uploaded}"
    )

    print(
        f"Remaining: "
        f"{total_new - position}"
    )

    print(
        "\nRun the same command again later "
        "to resume."
    )