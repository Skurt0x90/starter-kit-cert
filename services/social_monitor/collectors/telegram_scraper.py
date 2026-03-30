import logging
import requests
from datetime import datetime, timezone, timedelta
from bs4 import BeautifulSoup
from zoneinfo import ZoneInfo
from social_monitor import utils

logger = logging.getLogger(__name__)

CONTENT_MAX_LENGTH = 500
BASE_URL = "https://t.me/s/{channel}"


def is_recent(dt: datetime) -> bool:
    limit = datetime.now(timezone.utc) - timedelta(days=utils.LOOKBACK_DAYS)
    return dt >= limit


def parse_channel(channel: str) -> list[dict]:
    url = BASE_URL.format(channel=channel)
    items = []

    try:
        response = requests.get(url, timeout=utils.REQUEST_TIMEOUT, headers={"Accept-Language": "fr-FR,fr;q=0.9"})
        if response.status_code == 404:
            logger.warning(f"[Telegram] Canal introuvable : {channel}")
            return []
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        messages = soup.find_all("div", class_="tgme_widget_message_wrap")

        for msg in messages:
            date_tag = msg.find("time")
            if not date_tag or not date_tag.get("datetime"):
                continue

            msg_dt = datetime.fromisoformat(date_tag["datetime"].replace("Z", "+00:00"))
            if not is_recent(msg_dt):
                continue

            text_tag = msg.find("div", class_="tgme_widget_message_text")
            content = text_tag.get_text(separator=" ", strip=True)[:CONTENT_MAX_LENGTH] if text_tag else ""

            link_tag = msg.find("a", class_="tgme_widget_message_date")
            msg_url = link_tag["href"] if link_tag else url

            items.append({
                "source": "telegram",
                "channel": channel,
                "title": None,
                "url": msg_url,
                "content": content,
                "detected_at": datetime.now(ZoneInfo("Europe/Paris")).isoformat(),
            })

    except requests.exceptions.RequestException as e:
        logger.warning(f"[Telegram] Erreur sur {channel} : {e}")

    return items


def collect() -> list[dict]:
    results = []
    for channel in utils.TELEGRAM_CHANNELS:
        items = parse_channel(channel)
        logger.info(f"[Telegram] {channel} : {len(items)} message(s) récupéré(s)")
        results.extend(items)
    return results