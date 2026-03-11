import logging
import requests
import dns.resolver
from vuln_scanner import utils

logger = logging.getLogger(__name__)


def fetch_subdomains(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url, timeout=utils.REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        logger.warning(f"crt.sh injoignable pour {domain} : {e}")
        return []

    names = set()
    for entry in data:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if "*" not in name and name.endswith(f".{domain}"):
                names.add(name)

    return list(names)


def resolve(subdomain):
    try:
        dns.resolver.resolve(subdomain, "A")
        return True
    except Exception:
        try:
            dns.resolver.resolve(subdomain, "AAAA")
            return True
        except Exception:
            return False


def check(domain):
    subdomains = fetch_subdomains(domain)
    active = [s for s in subdomains if resolve(s)]

    alerts = []
    if active:
        joined = ", ".join(sorted(active))
        alerts.append({
            "level": "WARNING",
            "message": f"Sous-domaines actifs détectés pour {domain} : {joined}"
        })

    return {"subdomains": active, "alerts": alerts}