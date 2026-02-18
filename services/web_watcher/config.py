import os

SCHEDULE_INTERVAL_MINUTES = int(os.getenv("SCHEDULE_INTERVAL_MINUTES", 1))

BASE = "/data" if os.path.exists("/data") else "../data"
TARGETS_FILE = f"{BASE}/inputs/targets.txt"
OUTPUT_FILE  = f"{BASE}/outputs/web_status.json"


RESPONSE_TIME_THRESHOLD = 10    
SSL_EXPIRY_WARNING_DAYS  = 30 

REQUEST_TIMEOUT = 15               # secondes