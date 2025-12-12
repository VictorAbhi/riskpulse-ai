import time
import requests

print("Waiting for OpenSearch...", end="")
while True:
    try:
        r = requests.get("http://localhost:9201", timeout=3)
        if r.status_code == 200:
            print("\nOpenSearch is ready!")
            break
    except:
        print(".", end="", flush=True)
        time.sleep(2)