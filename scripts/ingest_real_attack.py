# ── Ingest Real Attack Data into OpenSearch ─────────────────────────────
import json
from opensearchpy import OpenSearch, helpers
from pathlib import Path
import gzip

# ── 1. Connect to your OpenSearch ───────────────────────────────────────
client = OpenSearch(
    hosts         = ["http://localhost:9201"],          
    use_ssl       = False,                              
    verify_certs  = False,
)

INDEX_NAME = "riskpulse-logs"

# Drop existing index if it exists (to re-create with correct mapping)
if client.indices.exists(index=INDEX_NAME):
    print(f"Deleting existing index: {INDEX_NAME}")
    client.indices.delete(index=INDEX_NAME)

# Create index with proper mapping
client.indices.create(
    index=INDEX_NAME,
    body={
        "settings": {
            "number_of_shards": 1, 
            "number_of_replicas": 1
        },
        "mappings": {
            "properties": {
                "Keywords": {"type": "keyword"},  # Treat as keyword, not long
                "EventID": {"type": "integer"},
                "Computer": {"type": "keyword"},
                "RecordNumber": {"type": "long"},
                "TimeCreated": {"type": "date"},
                "timestamp": {"type": "date"}
            }
        }
    }
)
print(f"Created index: {INDEX_NAME} with proper mappings")

# ── 2. Choose & read your dataset ───────────────────────────────────────

file_path = "data/raw/master_all_datasets.jsonl"  # example from splunk/attack_data

def clean_event(event):
    """Remove empty string values and keep only valid data"""
    if not isinstance(event, dict):
        return event
    
    cleaned = {}
    for key, value in event.items():
        # Skip empty strings and None values
        if value == "" or value is None:
            continue
        cleaned[key] = value
    return cleaned

def read_events(file_path: str):
    path = Path(file_path)
    
    if path.suffix == ".gz":
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    event = json.loads(line)
                    yield clean_event(event)
    else:
        with open(path, 'r', encoding='utf-8') as f:
            # Try to read as JSONL (one JSON object per line) first
            first_line = f.readline()
            if first_line:
                try:
                    # Try parsing first line as JSON
                    event = json.loads(first_line.strip())
                    yield clean_event(event)
                    # If successful, read remaining lines as JSONL
                    for line in f:
                        line = line.strip()
                        if line:
                            event = json.loads(line)
                            yield clean_event(event)
                except json.JSONDecodeError:
                    # If first line isn't valid JSON, reset and try as single JSON object
                    f.seek(0)
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            yield clean_event(item)
                    else:
                        yield clean_event(data)

# ── 3. Bulk ingest ──────────────────────────────────────────────────────

actions = (
    {
        "_op_type": "index",           # or "create" if you want to fail on duplicates
        "_index":   INDEX_NAME,
        # "_id":      event.get("RecordNumber"),   # optional — good for dedup
        "_source":  event
    }
    for event in read_events(file_path)
)

# Bulk helper — very efficient & has retry logic
success, failed = 0, 0
error_log = []
first_5_errors = []

for ok, item in helpers.parallel_bulk(
    client,
    actions,
    thread_count=4,
    chunk_size=500,
    raise_on_error=False,
):
    if ok:
        success += 1
    else:
        failed += 1
        # Log error details
        if len(first_5_errors) < 5:
            first_5_errors.append(item)
        
        # Extract error reason for summary
        if "index" in item and "error" in item["index"]:
            error_info = item["index"].get("error", {})
            if isinstance(error_info, dict):
                error_reason = error_info.get("reason", str(error_info))
            else:
                error_reason = str(error_info)
            error_log.append(error_reason)

print(f"\nSuccessfully indexed {success:,} documents")
print(f"Failed documents: {failed:,}")

# Show first few errors in detail
if first_5_errors:
    print(f"\nFirst few errors:")
    for i, err in enumerate(first_5_errors[:3], 1):
        print(f"\n  Error {i}:")
        print(f"    {json.dumps(err, indent=6)}")

# Show error summary
if error_log:
    from collections import Counter
    error_counts = Counter(error_log)
    print("\n📊 Top error reasons:")
    for error, count in error_counts.most_common(5):
        print(f"  [{count:,}x] {error[:150]}")

# Quick check
count = client.count(index=INDEX_NAME)["count"]
print(f"Total documents in {INDEX_NAME}: {count:,}")