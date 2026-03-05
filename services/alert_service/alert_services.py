import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from alert_service import utils
from datetime import datetime
from zoneinfo import ZoneInfo
from flask import requests

logger = logging.getLogger(__name__)


def read_json(path, default):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default

def write_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)

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
    logger.info(f"send_email appelé avec {len(alerts_to_send)} alerte(s)")
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
        with smtplib.SMTP(utils.SMTP_HOST, utils.SMTP_PORT) as s:
            s.starttls()
            s.login(utils.SMTP_USER, utils.SMTP_PASSWORD)
            s.sendmail(utils.ALERT_EMAIL_FROM, utils.ALERT_EMAIL_TO, msg.as_string())
    except Exception as e:
        logger.error(f"Erreur email : {e}")

def send_signal(alerts_to_send):
    if not utils.SIGNAL_CLI_NUMBER or not utils.SIGNAL_CLI_GROUP_ID:
        logger.warning("Signal non configuré, message ignoré")
        return

    lignes = []
    for a in alerts_to_send:
        lignes.append(f"[{a['level']}] {a['domain']} — {a['message']}")

    texte = f"🚨 Skurt0x90 CERT — {len(alerts_to_send)} alerte(s)\n\n"
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
    dedup = read_json(utils.DEDUP_FILE, {})
    dedup[key] = datetime.now(ZoneInfo("Europe/Paris")).isoformat()
    write_json(utils.DEDUP_FILE, dedup)


def process_alert(payload):
    service = payload.get("service", "?")
    alerts  = payload.get("alerts", {})

    sent = 0
    deduplicated = 0
    history = read_json(utils.OUTPUT_FILE, {"alerts": []})
    alerts_to_send = []

    for domain, domain_alerts in alerts.items():
        for alert in domain_alerts:
            alert_flat = {
                "service": service,
                "domain": domain,
                "level": alert.get("level", "?"),
                "message": alert.get("message", "")
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
    logger.info(f"Fin de boucle, alerts_to_send = {alerts_to_send}")
    if alerts_to_send:
        logger.info(f"alerts_to_send non vide : {len(alerts_to_send)} alertes")
        send_email(alerts_to_send)
        send_signal(alerts_to_send)

    history["alerts"] = history["alerts"][:200]
    history["last_run"] = datetime.now(ZoneInfo("Europe/Paris")).isoformat()
    write_json(utils.OUTPUT_FILE, history)

    return {"sent": sent, "deduplicated": deduplicated}



def format_email(alerts_to_send):
    subject = f"[CERT] {len(alerts_to_send)} alerte(s) détectée(s)"
    rows = ""
    for a in alerts_to_send:
        color = "red" if a["level"] == "CRITICAL" else "orange"
        rows += f"""
        <tr>
            <td style="color:{color}"><b>{a["level"]}</b></td>
            <td>{a["domain"]}</td>
            <td>{a["message"]}</td>
        </tr>
        """
    body = f"""
    <h2>[CERT Aviation] Rapport d'alertes</h2>
    <p><b>Heure :</b> {datetime.now(ZoneInfo("Europe/Paris")).isoformat()}</p>
    <table border="1" cellpadding="5">
        <tr><th>Niveau</th><th>Domaine</th><th>Message</th></tr>
        {rows}
    </table>
    """
    return subject, body
