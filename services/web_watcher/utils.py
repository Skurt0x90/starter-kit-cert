import os
import csv
import logging 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


SCHEDULE_INTERVAL_MINUTES = int(os.getenv("SCHEDULE_INTERVAL_MINUTES", 1))

BASE = "/data" if os.path.exists("/data") else "../data"
TARGETS_FILE = f"{BASE}/inputs/targets.txt"
OUTPUT_FILE  = f"{BASE}/outputs/web_status.json"

IN_DOCKER = os.path.exists("/.dockerenv")
ALERT_SERVICE_URL = os.getenv("ALERT_SERVICE_URL", "http://alert_service:5005" if IN_DOCKER else "http://localhost:5005")

RESPONSE_TIME_THRESHOLD = 10    
SSL_EXPIRY_WARNING_DAYS  = 30 
RESPONSE_WARN_SECONDS = float(os.getenv("RESPONSE_WARN_SECONDS", 3))   # au-delà : "DEF" (lent)
RESPONSE_KO_SECONDS = float(os.getenv("RESPONSE_KO_SECONDS", 8))       # au-delà : "KO" (très lent)
SSL_CACHE_HOURS = int(os.getenv("SSL_CACHE_HOURS", 6))                 # fréquence de revérification du certificat
FAILURES_BEFORE_ALERT = int(os.getenv("FAILURES_BEFORE_ALERT", 1))     # cycles consécutifs avant alerte (1 = immédiat)
HTTP_RETRIES = int(os.getenv("HTTP_RETRIES", 2))
MAX_WORKERS = int(os.getenv("WATCHER_MAX_WORKERS", 10))

REQUEST_TIMEOUT = 15               # secondes

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

def parse_target_line(line):
    # domaine,longitude,latitude,titre[,scan_mode] : le titre peut contenir des virgules
    parts = line.split(",", 3)
    if len(parts) < 4:
        raise ValueError(f"ligne de cible invalide : {line!r}")
    domain, lon, lat, rest = (p.strip() for p in parts)

    scan_mode = "passive"
    head, sep, tail = rest.rpartition(",")
    if sep and tail.strip().lower() in ("active", "passive"):
        scan_mode = tail.strip().lower()
        rest = head.strip()

    return {
        "domain": domain,
        "longitude": float(lon),
        "latitude": float(lat),
        "label": rest,     # titre attendu de la page
        "title": rest,
        "scan_mode": scan_mode,
    }


def load_domains(filepath):
    domains_to_check = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains_to_check.append(parse_target_line(line))
    return domains_to_check


HIGH_CONFIDENCE = [
    "hacked by",
    "h4cked by",
    "h@cked by",
    "pwned by",
    "defaced by",
    "d3faced by",
    "owned by",
    "compromised by",
    "breached by",
    "attacked by",
    "rooted by",
    "hijacked by",
    "taken over by",
    "this site has been hacked",
    "this site has been defaced",
    "website hacked",
    "website defaced",
    "you got hacked",
    "you have been hacked",
    "your security is low",
    "security breached",
    "index hacked",
    "index owned",
    "index replaced",
    "hacked homepage",
    "mirror by",
]

MEDIUM_CONFIDENCE = [
    "hacked",
    "h4cked",
    "hacked!!!",
    "defaced",
    "d3faced",
    "d3f4ced",
    "defaced!!!",
    "pwned",
    "pwnd",
    "p0wned",
    "pwned!!!",
    "0wned",
    "0wn3d",
    "owned!!!",
    "h4x0r",
    "hax0r",
    "h4xor",
    "was here",
    "we are here",
]

TECHNICAL_INDICATORS = [
    "c99 shell",
    "r57 shell",
    "webshell",
    "shell uploaded",
    "uid=0",
    "gid=0",
    "root@",
]


