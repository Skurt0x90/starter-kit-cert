import json
import logging
import requests
from datetime import datetime
from zoneinfo import ZoneInfo
from social_monitor import utils
from social_monitor.collectors.rss_monitor import collect as collect_rss
from social_monitor.collectors.telegram_scraper import collect as collect_telegram
from social_monitor.correlate import correlate

logger = logging.getLogger(__name__)


def build_alerts(items: list[dict]) -> dict:
    alerts = {}
    for item in items:
        key = item.get("channel", "unknown")
        alerts.setdefault(key, []).append({
            "level": item["level"],
            "message": f"[{item['source'].upper()}] {item.get('title') or item['content'][:120]} — mots-clés: {', '.join(item['matched_keywords'] + item['matched_members'])} — URL: {item.get('url')}"
        })
    return alerts


def send_alerts(alerts: dict):
    headers = {"Host": "localhost", "Content-Type": "application/json"}  # Header corrigé
    if not alerts:
        return
    try:
        requests.post(
            f"{utils.ALERT_SERVICE_URL}/api/alert",
            json={"service": "social_monitor", "alerts": alerts},
            headers=headers,
            timeout=5
        )

    except requests.exceptions.RequestException as e:
        logger.warning(f"Alert service injoignable : {e}")


def run_cycle():
    logger.info("----------------------------NEW CYCLE SOCIAL MONITOR----------------------------")
    now = datetime.now(ZoneInfo("Europe/Paris")).isoformat()

    raw_items = []
    raw_items.extend(collect_rss())
    raw_items.extend(collect_telegram())

    matched_items = correlate(raw_items)

    alerts = build_alerts(matched_items)
    if alerts:
        send_alerts(alerts)

    output = {"last_run": now, "items": matched_items}
    with open(utils.OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    logger.info(f"[social_monitor] Cycle terminé — {len(matched_items)} alerte(s) générée(s)")
    logger.info("----------------------------END CYCLE SOCIAL MONITOR----------------------------")