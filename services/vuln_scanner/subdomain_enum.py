import logging
import time
import requests
import dns.resolver
from vuln_scanner import utils

logger = logging.getLogger(__name__)

CRTSH_TIMEOUT = 60   # crt.sh est souvent lent, 15s ne suffit pas
CRTSH_RETRIES = 3

# resolver avec timeout court pour ne pas bloquer le scan sur un DNS muet
resolver = dns.resolver.Resolver()
resolver.timeout = 2
resolver.lifetime = 5


def fetch_crtsh(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    for attempt in range(1, CRTSH_RETRIES + 1):
        try:
            response = requests.get(url, timeout=CRTSH_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            raw = []
            for entry in data:
                raw.extend(entry.get("name_value", "").splitlines())
            return raw
        except Exception as e:
            logger.warning(f"crt.sh injoignable pour {domain} (try {attempt}/{CRTSH_RETRIES}) : {e}")
            if attempt < CRTSH_RETRIES:
                time.sleep(attempt * 5)  # 5s puis 10s
    return None


def fetch_certspotter(domain):
    # fallback : API publique Certspotter (quota limité sans clé)
    url = "https://api.certspotter.com/v1/issuances"
    params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
    try:
        response = requests.get(url, params=params, timeout=utils.REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        raw = []
        for entry in data:
            raw.extend(entry.get("dns_names", []))
        return raw
    except Exception as e:
        logger.warning(f"certspotter injoignable pour {domain} : {e}")
        return None


def clean_names(raw, domain):
    names = set()
    for name in raw:
        name = name.strip().lower()
        if "*" not in name and name.endswith(f".{domain}"):
            names.add(name)
    return list(names)


def fetch_subdomains(domain):
    raw = fetch_crtsh(domain)
    if raw is None:
        logger.info(f"fallback certspotter pour {domain}")
        raw = fetch_certspotter(domain)
    if raw is None:
        return None  # échec total, différent de "aucun sous-domaine"

    return clean_names(raw, domain)


def resolve(subdomain):
    try:
        resolver.resolve(subdomain, "A")
        return True
    except Exception:
        try:
            resolver.resolve(subdomain, "AAAA")
            return True
        except Exception:
            return False


def check(domain):
    subdomains = fetch_subdomains(domain)

    alerts = []
    if subdomains is None:
        alerts.append({
            "level": "INFO",
            "message": f"Énumération des sous-domaines impossible pour {domain} (crt.sh et certspotter injoignables)"
        })
        return {"subdomains": [], "alerts": alerts}

    active = [s for s in subdomains if resolve(s)]

    if active:
        joined = ", ".join(sorted(active))
        alerts.append({
            "level": "WARNING",
            "message": f"Sous-domaines actifs détectés pour {domain} : {joined}"
        })

    return {"subdomains": active, "alerts": alerts}