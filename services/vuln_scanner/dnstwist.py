import logging
import dnstwist
from vuln_scanner import utils

logger = logging.getLogger(__name__)


import sys
import io
import dnstwist
from vuln_scanner import utils
import logging

logger = logging.getLogger(__name__)


def check(domain):
    try:
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        results = dnstwist.run(
            domain=domain,
            registered=True,
            format="list",
            threads=16,
            fuzzers="addition,omission,replacement,hyphenation,transposition,subdomain"
        )
        sys.stdout = old_stdout

        typosquats = [
            entry["domain"]
            for entry in results
            if entry.get("domain") != domain
            and (entry.get("dns_a") or entry.get("dns_mx"))
        ]

        alerts = []
        if typosquats:
            joined = ", ".join(sorted(typosquats))
            alerts.append({
                "level": "CRITICAL",
                "message": f"Typosquatting détecté pour {domain} — domaines enregistrés suspects : {joined} — risque de phishing ou d'usurpation d'identité"
            })

        return {"typosquatting": typosquats, "alerts": alerts}

    except Exception as e:
        sys.stdout = old_stdout if 'old_stdout' in locals() else sys.stdout
        logger.warning(f"dnstwist échoué pour {domain} : {e}")
        return {"typosquatting": [], "alerts": []}