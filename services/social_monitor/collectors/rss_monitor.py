import logging
import feedparser
from datetime import datetime, timezone, timedelta
from bs4 import BeautifulSoup
from zoneinfo import ZoneInfo
from social_monitor import utils

logger = logging.getLogger(__name__)

CONTENT_MAX_LENGTH = 500


def clean_html(raw: str) -> str:
    return BeautifulSoup(raw, "html.parser").get_text(separator=" ", strip=True)


def is_recent(entry) -> bool:
    if not hasattr(entry, "published_parsed") or entry.published_parsed is None:
        return False
    pub_date = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
    limit = datetime.now(timezone.utc) - timedelta(days=utils.LOOKBACK_DAYS)
    return pub_date >= limit


def parse_feed(feed_cfg: dict) -> list[dict]:
    name = feed_cfg["name"]
    url = feed_cfg["url"]
    items = []

    try:
        feed = feedparser.parse(url)
        if feed.bozo:
            logger.warning(f"[RSS] Feed mal formé : {name}")

        for entry in feed.entries:
            if not is_recent(entry):
                continue

            title = entry.get("title", "").strip()
            link = entry.get("link", "").strip()
            summary_raw = entry.get("summary", entry.get("description", ""))
            content = clean_html(summary_raw)[:CONTENT_MAX_LENGTH]

            items.append({
                "source": "rss",
                "channel": name,
                "title": title,
                "url": link,
                "content": content,
                "detected_at": datetime.now(ZoneInfo("Europe/Paris")).isoformat(),
            })

    except Exception as e:
        logger.warning(f"[RSS] Erreur sur {name} ({url}) : {e}")

    return items


def collect() -> list[dict]:
    rss_feeds = utils.load_rss_feeds()
    results = []
    for feed_cfg in rss_feeds:
        items = parse_feed(feed_cfg)
        logger.info(f"[RSS] {feed_cfg['name']} : {len(items)} item(s) récupéré(s)")
        results.extend(items)
    return results