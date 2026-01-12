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

if not client.indices.exists(index=INDEX_NAME):
    client.indices.create(
        index=INDEX_NAME,
        body={
            "settings": {"number_of_shards": 1, "number_of_replicas": 1}
            }
    )
    print(f"Created index: {INDEX_NAME}")

# ── 2. Choose & read your dataset ───────────────────────────────────────

file_path = "data\\raw\\msf_record_mic_2020-06-09225055.json"  # example from splunk/attack_data

def read_events(file_path: str):
    path = Path(file_path)
    
    if path.suffix == ".gz":
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)
    else:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                yield from data
            else:
                # Assume NDJSON / json lines
                for line in f:
                    line = line.strip()
                    if line:
                        yield json.loads(line)

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

print(f"Successfully indexed {success:,} documents")
print(f"Failed documents: {failed:,}")

# Quick check
count = client.count(index=INDEX_NAME)["count"]
print(f"Total documents in {INDEX_NAME}: {count:,}")