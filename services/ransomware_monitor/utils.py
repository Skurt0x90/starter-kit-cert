import os

FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
SCHEDULE_INTERVAL_HOURS = int(os.getenv("SCHEDULE_INTERVAL_HOURS", 24))

BASE = "/data" if os.path.exists("/data") else "../data"
TARGETS_FILE = f"{BASE}/inputs/members.txt"
OUTPUT_FILE  = f"{BASE}/outputs/ransomware_monitor.json"

IN_DOCKER = os.path.exists("/.dockerenv")
ALERT_SERVICE_URL = os.getenv("ALERT_SERVICE_URL", "http://alert_service:5005" if IN_DOCKER else "http://localhost:5005")


REQUEST_TIMEOUT = 15               # secondes

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

def load_members(filepath):
    members = []
    with open(filepath) as f:
        for line in f:
            if not line or line.startswith("#"):
                continue
            member = line
            members.append({"member": member})
    return members
