import os

SCHEDULE_INTERVAL_MINUTES = int(os.getenv("SCHEDULE_INTERVAL_MINUTES", 1))

BASE = "/data" if os.path.exists("/data") else "../data"
TARGETS_FILE = f"{BASE}/inputs/targets.txt"
OUTPUT_FILE  = f"{BASE}/outputs/web_status.json"


RESPONSE_TIME_THRESHOLD = 10    
SSL_EXPIRY_WARNING_DAYS  = 30 

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

def load_domains(filepath):
    domains_to_check = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domain, lon, lat, label = line.split(",")
            domains_to_check.append({"domain": domain.strip(), "longitude": float(lon), "latitude": float(lat), "label": label.strip()})
    return domains_to_check

