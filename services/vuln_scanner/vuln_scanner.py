import json
import logging
import requests
from datetime import datetime
from zoneinfo import ZoneInfo
from vuln_scanner import utils
from vuln_scanner.cve_lookup import check as cve_check

logger = logging.getLogger(__name__)


def build_alerts(domain, cve_result):
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

        cve_result = cve_check(domain)

        alerts = build_alerts(domain, cve_result)
        if alerts:
            alerts_by_domain[domain] = alerts

        sites.append({
            "domain": domain,
            "scan_mode": target["scan_mode"],
            "headers": cve_result,
            "subdomains": [],       # subdomain_enum — TODO
            "dns": {},              # dns_check — TODO
            "typosquatting": [],    # dnstwist — TODO
            "checked_at": now
        })

    send_alerts(alerts_by_domain)

    output = {"last_run": now, "sites": sites}
    with open(utils.OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    logger.info("----------------------------END CYCLE VULN SCANNER----------------------------")