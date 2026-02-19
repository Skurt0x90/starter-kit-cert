import json
import requests
import logging
import contextlib
import socket
import ssl
from web_watcher import config
from datetime import datetime, timezone, date
from zoneinfo import ZoneInfo
from pathlib import Path

logger = logging.getLogger(__name__)
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


## Check is site up
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

## Check if SSL expire < 30j
def check_ssl_expiry(domain):
    try:
        ctx = ssl.create_default_context()
        with contextlib.closing(socket.socket(socket.AF_INET)) as sock:
            sock.settimeout(5.0)  
            conn = ctx.wrap_socket(sock, server_hostname=domain)
            conn.connect((domain, 443))
            ssl_info = conn.getpeercert()
            expiry_date = datetime.strptime(ssl_info["notAfter"], '%b %d %H:%M:%S %Y %Z').date()
            if (expiry_date - date.today()).days >= 30:
                return True
            return False
    except socket.timeout:
        logger.error(f"[{domain}] SSL check timeout")
        return True
    except Exception as e:
        logger.error(f"[{domain}] SSL check erreur : {e}")
        return True

## Check if reponse_time is OK, NOK, DEF
def check_response_time(domain):
    url = f"https://{domain}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=config.REQUEST_TIMEOUT)
        if response.elapsed.total_seconds() < 1:
            return "OK"
        if 1 < response.elapsed.total_seconds() < 2:
            return "DEF"
        return "KO"
    except requests.exceptions.RequestException as e:
        logger.error(f"[{domain}] Response time check erreur : {e}")
        return "KO"


#def generate_site_status(site_up, ssl_ok, response_time):
#    if not site_up:
#        return "KO"
#    if response_time == "KO" or not ssl_ok:
#        return "DEF"
#    if response_time == "DEF":
#        return "DEF"
#    return "OK"

def run_watcher_cycle():
    logger.info(f"---------------------------NEW CYCLE----------------------------")
    domains_to_check = load_domains(config.TARGETS_FILE)
    results = []
    for d in domains_to_check:
        logger.info(f"Site: {d["domain"]}")
        http_code = is_site_up(d["domain"])
        certif_ssl_ok = check_ssl_expiry(d['domain'])
        response_time = check_response_time(d["domain"])
        results.append({
            "domain": d["domain"],
            "site_up": http_code,
            "ssl_ok" : certif_ssl_ok,
            "response_time": response_time,
            "checked_at": datetime.now(ZoneInfo("Europe/Paris")).isoformat()
        })

                
    Path(config.OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(config.OUTPUT_FILE, "w") as f:
        json.dump({"last_run": datetime.now(ZoneInfo("Europe/Paris")).isoformat(), "sites": results}, f, indent=2)
    logger.info(f"---------------------------END CYCLE----------------------------")

    