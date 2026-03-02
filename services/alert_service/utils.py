import os

FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5005))

BASE = "/data" if os.path.exists("/data") else "../data"
OUTPUT_FILE = os.getenv("OUTPUT_FILE", f"{BASE}/outputs/alert_service.json")
DEDUP_FILE  = os.getenv("DEDUP_FILE",  f"{BASE}/outputs/alert_dedup.json")

DEDUP_WINDOW_MINUTES = int(os.getenv("DEDUP_WINDOW_MINUTES", 30))
