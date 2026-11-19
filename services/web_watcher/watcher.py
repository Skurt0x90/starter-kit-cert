import json
import requests
import logging
import contextlib
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from web_watcher import utils
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from pathlib import Path
from web_watcher.defacement import probability_site_defaced, decode_html

logger = logging.getLogger(__name__)

PARIS = ZoneInfo("Europe/Paris")
MAX_HTML_CHARS = 500_000
DEFACEMENT_ALERTS = ("DEFACEMENT FORTEMENT PROBABLE", "DEFACEMENT PROBABLE")


## Une seule requête par site : dispo + temps de réponse + HTML (réutilisé pour le défacement)
def fetch_site(domain):
    url = f"https://{domain}"
    for attempt in range(1, utils.HTTP_RETRIES + 1):
        try:
            response = requests.get(url, headers=utils.HEADERS, timeout=utils.REQUEST_TIMEOUT, allow_redirects=True)
            # temps total, redirections comprises (response.elapsed ne compte que le dernier saut)
            elapsed = response.elapsed + sum((r.elapsed for r in response.history), timedelta())
            content_type = response.headers.get("Content-Type", "").lower()
            html = decode_html(response)[:MAX_HTML_CHARS] if ("html" in content_type or not content_type) else None
            return {"status": response.status_code, "elapsed": elapsed.total_seconds(), "html": html}
        except requests.exceptions.RequestException as e:
            logger.warning(f"[{domain}] Erreur requête (try {attempt}/{utils.HTTP_RETRIES}) : {e}")
            if attempt < utils.HTTP_RETRIES:
                time.sleep(2)
    return {"status": None, "elapsed": None, "html": None}


def is_up(status):
    # 401/403/429 = serveur joignable mais bot filtré (WAF) : pas un DOWN
    return status is not None and (status < 400 or status in (401, 403, 429))


## OK / DEF (lent) / KO (très lent) / N/A (site injoignable)
def classify_response_time(elapsed):
    if elapsed is None:
        return "N/A"
    if elapsed < utils.RESPONSE_WARN_SECONDS:
        return "OK"
    if elapsed < utils.RESPONSE_KO_SECONDS:
        return "DEF"
    return "KO"


## Jours restants avant expiration, 0 si certificat invalide/expiré, None si vérification impossible (réseau)
def ssl_days_left(domain):
    try:
        ctx = ssl.create_default_context()
        with contextlib.closing(socket.create_connection((domain, 443), timeout=5.0)) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as conn:
                not_after = ssl.cert_time_to_seconds(conn.getpeercert()["notAfter"])
        return int((not_after - time.time()) // 86400)
    except ssl.SSLCertVerificationError as e:
        logger.error(f"[{domain}] Certificat invalide ou expiré : {e}")
        return 0
    except Exception as e:
        logger.error(f"[{domain}] SSL check erreur : {e}")
        return None


def get_ssl_status(domain, previous):
    # le certificat change rarement : revérifié seulement toutes les SSL_CACHE_HOURS
    old_days = previous.get("ssl_days_left")
    old_checked = previous.get("ssl_checked_at")
    if old_days is not None and old_checked:
        age = datetime.now(PARIS) - datetime.fromisoformat(old_checked)
        if age < timedelta(hours=utils.SSL_CACHE_HOURS):
            return old_days, old_checked
    days = ssl_days_left(domain)
    if days is None:
        # vérification impossible : on garde la dernière valeur connue plutôt que d'alerter à tort
        return old_days, old_checked
    return days, datetime.now(PARIS).isoformat()


def check_site(d, previous):
    domain = d["domain"]
    fetch = fetch_site(domain)
    site_up = is_up(fetch["status"])
    response_time = classify_response_time(fetch["elapsed"]) if site_up else "N/A"

    # défacement : seulement sur une vraie page (pas sur une page d'erreur ou un challenge WAF)
    defacement = "SITE OK (non défacé)"
    if fetch["html"] and fetch["status"] < 400:
        defacement = probability_site_defaced(domain, d.get("title", ""), content=fetch["html"]) or defacement

    days_left, ssl_checked_at = get_ssl_status(domain, previous)
    ssl_ok = days_left is None or days_left >= utils.SSL_EXPIRY_WARNING_DAYS

    # compteurs de cycles consécutifs en anomalie (remis à 0 dès que ça va mieux)
    old = previous.get("failures", {})
    failures = {
        "down": old.get("down", 0) + 1 if not site_up else 0,
        "slow": old.get("slow", 0) + 1 if response_time in ("DEF", "KO") else 0,
        "defacement": old.get("defacement", 0) + 1 if defacement in DEFACEMENT_ALERTS else 0,
    }

    return {
        "domain": domain,
        "site_up": site_up,
        "ssl_ok": ssl_ok,
        "ssl_days_left": days_left,
        "ssl_checked_at": ssl_checked_at,
        "response_time": response_time,
        "response_seconds": round(fetch["elapsed"], 2) if fetch["elapsed"] is not None else None,
        "defacement": defacement,
        "failures": failures,
        "checked_at": datetime.now(PARIS).isoformat(),
        "localisation": str((d["latitude"], d["longitude"])),
    }


def safe_check(d, previous):
    # une erreur sur un site ne doit pas faire tomber tout le cycle
    try:
        return check_site(d, previous.get(d["domain"], {}))
    except Exception as e:
        logger.error(f"[{d['domain']}] check échoué : {e}")
        return None


def load_previous():
    try:
        with open(utils.OUTPUT_FILE, "r") as f:
            return {s["domain"]: s for s in json.load(f).get("sites", [])}
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return {}


def confirmed(site, key):
    # alerte seulement après FAILURES_BEFORE_ALERT cycles consécutifs (évite les faux positifs ponctuels)
    failures = site.get("failures")
    return failures is None or failures.get(key, 0) >= utils.FAILURES_BEFORE_ALERT


def create_alerts(states):
    alerts = {}
    for site in states:
        domain = site["domain"]
        if site["site_up"] == False and confirmed(site, "down"):
            alerts.setdefault(domain, []).append({"level": "CRITICAL", "message": f"{domain} est DOWN"})
        if site["ssl_ok"] == False:
            alerts.setdefault(domain, []).append({"level": "WARNING", "message": f"{domain} SSL expire < 30 jours"})
        if site["response_time"] == "DEF" and confirmed(site, "slow"):
            alerts.setdefault(domain, []).append({"level": "WARNING", "message": f"{domain} temps de réponse long"})
        if site["response_time"] == "KO" and confirmed(site, "slow"):
            alerts.setdefault(domain, []).append({"level": "WARNING", "message": f"{domain} temps de réponse très long (> {utils.RESPONSE_KO_SECONDS:g}s)"})
        if site["defacement"] in DEFACEMENT_ALERTS and confirmed(site, "defacement"):
            level = "CRITICAL" if site["defacement"] == "DEFACEMENT FORTEMENT PROBABLE" else "WARNING"
            alerts.setdefault(domain, []).append({"level": level, "message": f"{domain} défacement probable"})
    return alerts


def run_watcher_cycle():
    logger.info("---------------------------NEW CYCLE WEB WATCHER----------------------------")
    domains_to_check = utils.load_domains(utils.TARGETS_FILE)
    previous = load_previous()

    # sites vérifiés en parallèle
    with ThreadPoolExecutor(max_workers=utils.MAX_WORKERS) as pool:
        results = [r for r in pool.map(lambda d: safe_check(d, previous), domains_to_check) if r]

    alerts = create_alerts(results)

    if alerts:
        headers = {"Host": "localhost", "Content-Type": "application/json"}  # Header corrigé
        try:
            requests.post(
                f"{utils.ALERT_SERVICE_URL}/api/alert",
                json={"service": "web_watcher", "alerts": alerts},
                headers=headers,
                timeout=5
            )
        except requests.exceptions.RequestException as e:
            logger.warning(f"Alert service injoignable : {e}")

    Path(utils.OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(utils.OUTPUT_FILE, "w") as f:
        json.dump({"last_run": datetime.now(PARIS).isoformat(), "sites": results}, f, indent=2)

    logger.info("---------------------------END CYCLE WEB WATCHER----------------------------")