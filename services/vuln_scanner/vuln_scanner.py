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


def build_alerts(domain, cve_result, subdomain_result, dns_result, dnstwist_result):
    alerts = []

    for cve in cve_result["cves"]:
        if cve["cvss"] is None:
            alerts.append({
                "level": "WARNING",
                "message": cve["description"]
            })
        elif cve["cvss"] > 7:
            alerts.append({
                "level": "CRITICAL",
                "message": f"{cve['id']} (CVSS {cve['cvss']}) sur {cve_result['server']} ({domain})"
            })
        else:
            alerts.append({
                "level": "WARNING",
                "message": f"{cve['id']} (CVSS {cve['cvss']}) sur {cve_result['server']} ({domain})"
            })
    
    for subdomain in subdomain_result.get("alerts", []):
        alerts.append(subdomain)

    for dnsalert in dns_result.get("alerts", []):
        alerts.append(dnsalert)

    for twist in dnstwist_result.get("alerts", []):
        alerts.append(twist)

    return alerts


def send_alerts(alerts_by_domain):
    if not alerts_by_domain:
        return
    try:
        requests.post(
            f"{utils.ALERT_SERVICE_URL}/api/alert",
            json={"service": "vuln_scanner", "alerts": alerts_by_domain},
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
        logger.info(f"Scan de {domain}")

        cve_result = cve_check(domain, scan_mode=target["scan_mode"],)
        subdomain_result = subdomain_check(domain)
        dns_result = dns_check(domain)
        dnstwist_result = dnstwist_check(domain)
        alerts = build_alerts(domain, cve_result, subdomain_result, dns_result, dnstwist_result)
        if alerts:
            alerts_by_domain[domain] = alerts

        sites.append({
            "domain": domain,
            "scan_mode": target["scan_mode"],
            "headers": {
                "server": cve_result["server"],
                "x_powered_by": cve_result["x_powered_by"],
                "cves": cve_result["cves"],
            },
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