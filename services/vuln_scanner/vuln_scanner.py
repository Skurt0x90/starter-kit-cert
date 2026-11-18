import json
import logging
import requests
from datetime import datetime
from zoneinfo import ZoneInfo
from vuln_scanner import utils
from vuln_scanner.cve_lookup import check as cve_check
from vuln_scanner.subdomain_enum import check as subdomain_check
from vuln_scanner.dns_check import check as dns_check
from vuln_scanner.dnstwist import check as dnstwist_check

logger = logging.getLogger(__name__)

SENSITIVE_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
}

def match_note(cve):
    # précise si la CVE vient d'une version précise ou d'une version incomplète
    match = cve.get("match")
    if match == "range":
        return " [version partielle : CVE possible sur certaines versions de la branche, à confirmer]"
    if match == "keyword":
        return " [recherche par mot-clé : à vérifier]"
    return ""


def cve_location(domain, cve_result, cve):
    # où se trouve le composant : produit, port probable, site ou service de la même IP
    component = cve.get("component")
    if not component:
        if cve.get("source") == "internetdb":
            return f"composant non identifié sur l'IP de {domain}"
        component = cve_result["server"] or "composant inconnu"
    ports = cve.get("ports") or []
    where = component
    if ports:
        where += f" (port {', '.join(str(p) for p in ports)})"
    if cve.get("scope") == "infra":
        where += f", service sur la même IP que {domain}"
    else:
        where += f" sur {domain}"
    return where


def alert_level(cve):
    # CRITICAL seulement si CVSS > 7 ET version précise, sinon WARNING quel que soit le score
    return "CRITICAL" if cve["cvss"] > 7 and cve.get("match") == "exact" else "WARNING"


def build_alerts(domain, cve_result, subdomain_result, dns_result, dnstwist_result):
    alerts = []

    for cve in cve_result["cves"]:
        # note sans id (ex: version masquée) : on garde le message tel quel
        if cve["id"] is None:
            alerts.append({
                "level": "WARNING",
                "message": cve["description"]
            })
            continue

        # CVE signalée par InternetDB mais sans score (non retrouvée via NVD)
        if cve["cvss"] is None:
            alerts.append({
                "level": "WARNING",
                "message": f"{cve['id']} signalée par Shodan InternetDB (non confirmée via NVD) sur l'IP de {domain}"
            })
            continue

        where = cve_location(domain, cve_result, cve)

        level = alert_level(cve)
        alerts.append({
            "level": level,
            "message": f"{cve['id']} (CVSS {cve['cvss']}) : {where}{match_note(cve)}"
        })
    
    for port in cve_result.get("ports", []):
        # alerte ports sensibles
        if port["port"] in SENSITIVE_PORTS:
            alerts.append({
                "level": "CRITICAL",
                "message": f"Port {SENSITIVE_PORTS[port['port']]} ({port['port']}) exposé publiquement sur {domain}"
            })
        # alerte CVE sur le port
        for cve in port.get("cves", []):
            if cve["cvss"] is None:
                continue
            level = alert_level(cve)
            alerts.append({
                "level": level,
                "message": f"{cve['id']} (CVSS {cve['cvss']}) sur {port['product']} port {port['port']} ({domain}){match_note(cve)}"
            })
    for subdomain in subdomain_result.get("alerts", []):
        alerts.append(subdomain)

    for dnsalert in dns_result.get("alerts", []):
        alerts.append(dnsalert)

    for twist in dnstwist_result.get("alerts", []):
        alerts.append(twist)

    return alerts


def send_alerts(alerts_by_domain):
    headers = {"Host": "localhost", "Content-Type": "application/json"}  # Header corrigé
    if not alerts_by_domain:
        return
    try:
        requests.post(
            f"{utils.ALERT_SERVICE_URL}/api/alert",
            json={"service": "vuln_scanner", "alerts": alerts_by_domain},
            headers=headers,
            timeout=5
        )
    except requests.exceptions.RequestException as e:
        logger.warning(f"Alert service injoignable : {e}")


def run_cycle():
    logger.info("----------------------------NEW CYCLE VULN SCANNER----------------------------")
    targets = utils.load_domains(utils.TARGETS_FILE)
    now = datetime.now(ZoneInfo("Europe/Paris")).isoformat()

    sites = []
    alerts_by_domain = {}

    for target in targets:
        domain = target["domain"]
        logger.info(f"----> Scan {domain}")
        cve_result = cve_check(domain, scan_mode=target["scan_mode"],)
        subdomain_result = subdomain_check(domain)
        dns_result = dns_check(domain)
        dnstwist_result = dnstwist_check(domain)
        alerts = build_alerts(domain, cve_result, subdomain_result, dns_result, dnstwist_result)
        if alerts:
            alerts_by_domain[domain] = alerts

        # champs prêts à afficher pour le dashboard (même texte que dans les mails)
        for cve in cve_result["cves"]:
            if cve["id"] is not None:
                cve["where"] = cve_location(domain, cve_result, cve)
                cve["match_note"] = match_note(cve).strip()

        sites.append({
            "domain": domain,
            "scan_mode": target["scan_mode"],
            "headers": {
                "server": cve_result["server"],
                "x_powered_by": cve_result["x_powered_by"],
                "cves": cve_result["cves"],
            },
            "internetdb": cve_result.get("internetdb"),
            "ports": cve_result["ports"],        # ← extrait ici
            "subdomains": subdomain_result.get("subdomains", []),
            "dns": dns_result,
            "typosquatting": dnstwist_result.get("typosquatting", []),
            "checked_at": now
        })

    send_alerts(alerts_by_domain)

    output = {"last_run": now, "sites": sites}
    with open(utils.OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    logger.info("----------------------------END CYCLE VULN SCANNER----------------------------")