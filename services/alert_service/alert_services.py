import json
import logging
import os
import smtplib
import ssl
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from html import escape
from pathlib import Path
from alert_service import utils
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import requests

logger = logging.getLogger(__name__)

ALLOWED_SERVICES = {"web_watcher", "vuln_scanner", "ransomware_monitor", "social_monitor"}
ALLOWED_LEVELS = {"CRITICAL", "WARNING", "INFO"}
MAX_MESSAGE_LENGTH = 1000
MAX_DOMAINS = 200
MAX_ALERTS_PER_DOMAIN = 100

# Flask est multi-thread : sans verrou, deux requêtes peuvent écraser les fichiers JSON de l'autre
_lock = threading.Lock()


def validate_payload(payload):
    if not isinstance(payload, dict):
        return "Payload invalide"
    if payload.get("service") not in ALLOWED_SERVICES:
        return "Service inconnu"
    alerts = payload.get("alerts")
    if not isinstance(alerts, dict) or len(alerts) > MAX_DOMAINS:
        return "Champ alerts invalide"
    for domain, domain_alerts in alerts.items():
        if not isinstance(domain_alerts, list) or len(domain_alerts) > MAX_ALERTS_PER_DOMAIN:
            return f"Alertes invalides pour {domain}"
        if not all(isinstance(a, dict) for a in domain_alerts):
            return f"Alerte mal formée pour {domain}"
    return None


def read_json(path, default):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp, path)   # écriture atomique : jamais de JSON à moitié écrit


def purge_dedup(dedup):
    # supprime les clés expirées, sinon le fichier grossit indéfiniment
    limit = datetime.now(ZoneInfo("Europe/Paris")) - timedelta(minutes=utils.DEDUP_WINDOW_MINUTES)
    kept = {}
    for key, value in dedup.items():
        try:
            if datetime.fromisoformat(value) >= limit:
                kept[key] = value
        except ValueError:
            continue
    return kept


def is_duplicate(alert):
    key = f"{alert['service']}|{alert['domain']}|{alert['level']}|{alert['message']}"
    dedup = read_json(utils.DEDUP_FILE, {})
    if key in dedup:
        last = datetime.fromisoformat(dedup[key])
        diff = datetime.now(ZoneInfo("Europe/Paris")) - last
        if diff.total_seconds() < utils.DEDUP_WINDOW_MINUTES * 60:
            return True
    return False


def send_email(alerts_to_send):
    if not utils.SMTP_USER:
        logger.warning("SMTP non configuré, email ignoré")
        return

    subject, body = format_email(alerts_to_send)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = utils.ALERT_EMAIL_FROM
    msg["To"]      = utils.ALERT_EMAIL_TO
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(utils.SMTP_HOST, utils.SMTP_PORT, timeout=10) as s:
            s.starttls(context=ssl.create_default_context())   # vérifie le certificat du serveur SMTP
            s.login(utils.SMTP_USER, utils.SMTP_PASSWORD)
            s.sendmail(utils.ALERT_EMAIL_FROM, utils.ALERT_EMAIL_TO, msg.as_string())
        logger.info(f"alert service send email {msg['Subject']}")

    except Exception as e:
        logger.error(f"Erreur email : {e}")


def send_signal(alerts_to_send):
    if not utils.SIGNAL_CLI_NUMBER or not utils.SIGNAL_CLI_GROUP_ID:
        logger.warning("Signal non configuré, message ignoré")
        return

    lignes = []
    for a in alerts_to_send:
        lignes.append(f"[{a['level']}] {a['domain']} — {a['message']}")

    texte = f"🚨 THREAT-RADAR — {len(alerts_to_send)} alerte(s)\n\n"
    texte += "\n".join(lignes)
    texte += f"\n\n🕐 {datetime.now(ZoneInfo('Europe/Paris')).strftime('%d/%m/%Y %H:%M')}"

    try:
        r = requests.post(
            f"{utils.SIGNAL_API_URL}/v2/send",
            json={
                "message": texte,
                "number": utils.SIGNAL_CLI_NUMBER,
                "recipients": [utils.SIGNAL_CLI_GROUP_ID]
            },
            timeout=10
        )
        r.raise_for_status()
        logger.info(f"Signal envoyé : {len(alerts_to_send)} alerte(s)")
    except Exception as e:
        logger.error(f"Erreur Signal : {e}")


def mark_sent(alert):
    key = f"{alert['service']}|{alert['domain']}|{alert['level']}|{alert['message']}"
    dedup = purge_dedup(read_json(utils.DEDUP_FILE, {}))
    dedup[key] = datetime.now(ZoneInfo("Europe/Paris")).isoformat()
    write_json(utils.DEDUP_FILE, dedup)


def _process_alert(payload):
    service = payload.get("service", "?")
    alerts  = payload.get("alerts", {})

    sent = 0
    deduplicated = 0
    history = read_json(utils.OUTPUT_FILE, {"alerts": []})
    alerts_to_send = []

    for domain, domain_alerts in alerts.items():
        for alert in domain_alerts:
            level = alert.get("level")
            alert_flat = {
                "service": service,
                "domain": str(domain)[:253],
                "level": level if level in ALLOWED_LEVELS else "INFO",
                "message": str(alert.get("message", ""))[:MAX_MESSAGE_LENGTH]
            }
            if is_duplicate(alert_flat):
                deduplicated += 1
                continue

            alerts_to_send.append(alert_flat)
            mark_sent(alert_flat)
            history["alerts"].insert(0, {
                "service": alert_flat["service"],
                "domain": alert_flat["domain"],
                "level": alert_flat["level"],
                "message": alert_flat["message"],
                "sent_at": datetime.now(ZoneInfo("Europe/Paris")).isoformat()
            })
            sent += 1
    if alerts_to_send:
        send_email(alerts_to_send)
        send_signal(alerts_to_send)

    history["alerts"] = history["alerts"][:200]
    history["last_run"] = datetime.now(ZoneInfo("Europe/Paris")).isoformat()
    write_json(utils.OUTPUT_FILE, history)

    return {"sent": sent, "deduplicated": deduplicated}


def process_alert(payload):
    with _lock:
        return _process_alert(payload)


def format_email(alerts_to_send):
    if not alerts_to_send:
        subject = "[THREAT-RADAR] 0 alerte détectée"
        body = f"""
        <h2>[THREAT-RADAR] Rapport d'alertes</h2>
        <p><b>Heure :</b> {datetime.now(ZoneInfo("Europe/Paris")).isoformat()}</p>
        <p>Aucune alerte détectée.</p>
        """
        return subject, body

    service_label = alerts_to_send[0]["service"].replace("_", " ").upper()
    subject = f"[THREAT-RADAR - {service_label}] {len(alerts_to_send)} alerte(s) détectée(s)"

    rows = ""
    for a in alerts_to_send:
        color = "red" if a["level"] == "CRITICAL" else "orange"
        # tout ce qui vient de l'extérieur (RSS, Telegram, DNS...) est échappé
        rows += f"""
        <tr>
            <td style="color:{color}"><b>{escape(a["level"])}</b></td>
            <td>{escape(a["domain"])}</td>
            <td>{escape(a["message"])}</td>
        </tr>
        """

    body = f"""
    <h2>[THREAT-RADAR] Rapport d'alertes</h2>
    <p><b>Heure :</b> {datetime.now(ZoneInfo("Europe/Paris")).isoformat()}</p>
    <table border="1" cellpadding="5">
        <tr><th>Niveau</th><th>Domaine</th><th>Message</th></tr>
        {rows}
    </table>
    """

    return subject, body