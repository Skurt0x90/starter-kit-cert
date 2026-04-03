import logging
import unicodedata
import re
from social_monitor import utils

logger = logging.getLogger(__name__)


def clean_text(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    return text.lower()


def find_keyword_matches(text: str, keywords: list[str]) -> list[str]:
    cleaned = clean_text(text)
    return [kw for kw in keywords if kw.lower() in cleaned]


def find_member_matches(text: str, members: list[str]) -> list[str]:
    cleaned = clean_text(text)
    return [m for m in members if m in cleaned]


def correlate(items: list[dict]) -> list[dict]:
    keywords = utils.load_keywords()
    members = utils.load_members()
    results = []

    for item in items:
        searchable = f"{item.get('title', '')} {item.get('content', '')}".strip()

        matched_keywords = find_keyword_matches(searchable, keywords)
        matched_members = find_member_matches(searchable, members)

        if not matched_keywords and not matched_members:
            continue

        level = "CRITICAL" if matched_members else "WARNING"

        results.append({
            **item,
            "matched_keywords": matched_keywords,
            "matched_members": matched_members,
            "level": level,
        })

    logger.info(f"[Correlate] {len(results)} item(s) pertinent(s) sur {len(items)} collecté(s)")
    return results