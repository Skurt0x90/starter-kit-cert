import json
import requests
import logging
from web_watcher import config
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

logger = logging.getLogger(__name__)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
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


## Check is site ddos-ed
def is_site_up(domain):
    url = f"https://{domain}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
        code = response.status_code
        if str(code)[0] not in ('2', '3'):
            logger.warning(f"[{domain}] Code HTTP anormal : {code}")
            return False
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"[{domain}] Erreur requête : {e}")
        return True
  

def run_watcher_cycle():
    domains_to_check = load_domains(config.TARGETS_FILE)
    results = []
    for d in domains_to_check:
        http_code = is_site_up(d["domain"])
        results.append({
            "domain": d["domain"],
            "site_up": http_code,
            "checked_at": datetime.now(ZoneInfo("Europe/Paris")).isoformat()
        })
        logger.info(f"{d['domain']} → {http_code}")

    Path(config.OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(config.OUTPUT_FILE, "w") as f:
        json.dump({"last_run": datetime.now(ZoneInfo("Europe/Paris")).isoformat(), "sites": results}, f, indent=2)
    