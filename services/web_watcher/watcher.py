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
from web_watcher.defacement import probability_site_defaced

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


def create_alerts(states):
    alerts = {}
    for site in states:
        domain = site["domain"]
        if site["site_up"] == False:
            alerts.setdefault(domain, []).append({"level": "CRITICAL", "message": f"{domain} est DOWN"})
        if site["ssl_ok"] == False:
            alerts.setdefault(domain, []).append({"level": "WARNING", "message": f"{domain} SSL expire < 30 jours"})
        if site["response_time"] == "DEF":
            alerts.setdefault(domain, []).append({"level": "WARNING", "message": f"{domain} temps de réponse long"})
        if site["defacement"] in ["DEFACEMENT FORTEMENT PROBABLE", "DEFACEMENT PROBABLE"]:
            alerts.setdefault(domain, []).append({"level": "CRITICAL", "message": f"{domain} défacement probable"})
    return alerts

def run_watcher_cycle():
    logger.info(f"---------------------------NEW CYCLE----------------------------")
    domains_to_check = utils.load_domains(utils.TARGETS_FILE)
    results = []
    alerts = []
    for d in domains_to_check:
        logger.info(f"Site: {d["domain"]} - Label: {d["label"]}")
        http_code = is_site_up(d["domain"])
        certif_ssl_ok = is_ssl_expire_soon(d['domain'])
        response_time = check_response_time(d["domain"])
        probability_defaced = probability_site_defaced(d["domain"], d["label"])
        results.append({
            "domain": d["domain"],
            "site_up": http_code,
            "ssl_ok" : not certif_ssl_ok,
            "response_time": response_time,
            "defacement": probability_defaced,
            "checked_at": datetime.now(ZoneInfo("Europe/Paris")).isoformat(),
            "localisation": f"{d["latitude"], d["longitude"]}"
        })
    alerts = create_alerts(results)
    logger.info(alerts)

    if alerts:
        try:
            requests.post(
                f"{utils.ALERT_SERVICE_URL}/api/alert",
                json={"service": "web_watcher", "alerts": alerts},
                timeout=5
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"Alert service injoignable : {e}")
            
    Path(utils.OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(utils.OUTPUT_FILE, "w") as f:
        json.dump({"last_run": datetime.now(ZoneInfo("Europe/Paris")).isoformat(), "sites": results}, f, indent=2)

    logger.info(f"---------------------------END CYCLE----------------------------")
