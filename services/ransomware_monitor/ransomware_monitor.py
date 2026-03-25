import json
import logging
import requests
from datetime import datetime
from zoneinfo import ZoneInfo
from ransomware_monitor import utils
from ransomware_monitor.correlator import get_victim_ransomfeed, get_victim_ransomlive, get_victim_ransomlook, correlate


logger = logging.getLogger(__name__)

def build_alerts(victime_ransomware):
    alerts = {}
    for victime in victime_ransomware:
        alerts.setdefault(victime["victime"], []).append({"level": "CRITICAL", "message": f"{victime["acteur"]} revendique ransomware sur {victime["victime"]}. Source: {victime["source"]}"})



    return alerts


def send_alerts(alerts):
    headers = {"Host": "localhost", "Content-Type": "application/json"}  # Header corrigé
    if not alerts:
        return
    try:
        requests.post(
            f"{utils.ALERT_SERVICE_URL}/api/alert",
            json={"service": "ransomware_monitor", "alerts": alerts},
            headers=headers,
            timeout=5
        )
    except requests.exceptions.RequestException as e:
        logger.warning(f"Alert service injoignable : {e}")


def run_cycle():
    logger.info("----------------------------NEW CYCLE RANSOMWARE MONITOR----------------------------")
    now = datetime.now(ZoneInfo("Europe/Paris")).isoformat()

    matches = correlate()

    alerts = build_alerts(matches)

    if alerts:
        send_alerts(alerts)

            
    output = {"last_run": now, "ransomware": matches}
    with open(utils.OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)


    logger.info("----------------------------END CYCLE RANSOMWARE MONITOR----------------------------")