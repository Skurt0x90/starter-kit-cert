import json
import requests
import logging
import contextlib
import socket
import ssl
from web_watcher import utils
from datetime import datetime, timezone, date
from zoneinfo import ZoneInfo
from pathlib import Path
from web_watcher.defacement import is_title_ok

logger = logging.getLogger(__name__)


## Check is site up
def is_site_up(domain):
    url = f"https://{domain}"
    try:
        response = requests.get(url, headers=utils.HEADERS, timeout=utils.REQUEST_TIMEOUT, allow_redirects=True)
        code = response.status_code
        if str(code)[0] not in ('2', '3'):
            logger.warning(f"[{domain}] Code HTTP anormal : {code}")
            return False
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"[{domain}] Erreur requête : {e}")
        return False

## Check if SSL expire < 30j
def is_ssl_expire_soon(domain):
    try:
        ctx = ssl.create_default_context()
        with contextlib.closing(socket.socket(socket.AF_INET)) as sock:
            sock.settimeout(5.0)  
            conn = ctx.wrap_socket(sock, server_hostname=domain)
            conn.connect((domain, 443))
            ssl_info = conn.getpeercert()
            expiry_date = datetime.strptime(ssl_info["notAfter"], '%b %d %H:%M:%S %Y %Z').date()
            if (expiry_date - date.today()).days >= 30:
                return False
            return True
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
        response = requests.get(url, headers=utils.HEADERS, timeout=utils.REQUEST_TIMEOUT)
        if response.elapsed.total_seconds() < 1:
            return "OK"
        if 1 < response.elapsed.total_seconds() < 2:
            return "DEF"
        return "KO"
    except requests.exceptions.RequestException as e:
        logger.error(f"[{domain}] Response time check erreur : {e}")
        return "KO"



def run_watcher_cycle():
    logger.info(f"---------------------------NEW CYCLE----------------------------")
    domains_to_check = utils.load_domains(utils.TARGETS_FILE)
    results = []
    for d in domains_to_check:
        logger.info(f"Site: {d["domain"]} - Label: {d["label"]}")
        http_code = is_site_up(d["domain"])
        certif_ssl_ok = is_ssl_expire_soon(d['domain'])
        response_time = check_response_time(d["domain"])
        title = is_title_ok(d["domain"], d["label"])
        results.append({
            "domain": d["domain"],
            "site_up": http_code,
            "ssl_ok" : not certif_ssl_ok,
            "response_time": response_time,
            "title_ok": title,
            "checked_at": datetime.now(ZoneInfo("Europe/Paris")).isoformat()
        })

                
    Path(utils.OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(utils.OUTPUT_FILE, "w") as f:
        json.dump({"last_run": datetime.now(ZoneInfo("Europe/Paris")).isoformat(), "sites": results}, f, indent=2)
    logger.info(f"---------------------------END CYCLE----------------------------")

    


""" def get_site_status(site_up, ssl_ok, response_time, defacement_detected):
    if not site_up:
        return "KO"                      # inaccessible, on sait rien de plus

    if defacement_detected and not ssl_ok:
        return "KO_DEFACED_SSL"          # compromis + SSL expirant = critique

    if defacement_detected and response_time == "KO":
        return "KO_DEFACED_SLOW"         # compromis + très lent

    if defacement_detected:
        return "KO_DEFACED"              # compromis seul

    if not ssl_ok and response_time == "KO":
        return "DEF_SSL_SLOW"            # SSL + très lent

    if not ssl_ok and response_time == "DEF":
        return "DEF_SSL_SLOW"            # SSL + lent

    if not ssl_ok:
        return "DEF_SSL"                 # SSL expirant seul

    if response_time == "KO":
        return "DEF_SLOW"                # très lent seul

    if response_time == "DEF":
        return "DEF_SLOW"                # lent seul

    return "OK"

Ce qui donne comme tableau de priorité :
KO                → inaccessible
KO_DEFACED        → compromis
KO_DEFACED_SSL    → compromis + SSL
KO_DEFACED_SLOW   → compromis + lent
DEF_SSL_SLOW      → SSL + lent
DEF_SSL           → SSL seul
DEF_SLOW          → lent seul
OK                → tout bon """