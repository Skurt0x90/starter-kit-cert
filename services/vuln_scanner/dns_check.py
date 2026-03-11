import logging
import dns.resolver
from vuln_scanner import utils

logger = logging.getLogger(__name__)


def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for record in answers:
            if record.to_text().strip('"').startswith("v=spf1"):
                return True
        return False
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return False
    except Exception as e:
        logger.warning(f"Erreur SPF pour {domain} : {e}")
        return False


def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in answers:
            value = record.to_text().strip('"')
            if value.startswith("v=DMARC1"):
                policy = None
                for part in value.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        policy = part.split("=")[1].strip()
                        break
                return {"present": True, "policy": policy}
        return {"present": False, "policy": None}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"present": False, "policy": None}
    except Exception as e:
        logger.warning(f"Erreur DMARC pour {domain} : {e}")
        return {"present": False, "policy": None}


def check(domain):
    try:
        spf = check_spf(domain)
        dmarc = check_dmarc(domain)
        alerts = []
        if not spf:
            alerts.append({
                "level": "WARNING",
                "message": f"SPF absent sur {domain} — le domaine peut être usurpé pour envoyer des mails de phishing en se faisant passer pour {domain}"
            })
        if not dmarc["present"]:
            alerts.append({
                "level": "WARNING",
                "message": f"DMARC absent sur {domain} — aucune politique de traitement des mails non authentifiés, les tentatives d'usurpation ne sont pas bloquées"
            })
        elif dmarc["policy"] == "none":
            alerts.append({
                "level": "WARNING",
                "message": f"DMARC présent mais p=none sur {domain} — la politique est déclarée mais sans effet, les mails frauduleux ne sont ni rejetés ni mis en quarantaine"
            })
        return {"spf": spf, "dmarc": dmarc["present"], "dmarc_policy": dmarc["policy"], "alerts": alerts}
    except Exception as e:
        logger.warning(f"dns_check échoué pour {domain} : {e}")
        return {"spf": False, "dmarc": False, "dmarc_policy": None, "alerts": []}