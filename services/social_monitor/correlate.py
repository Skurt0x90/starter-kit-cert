import logging
import unicodedata
import re
from social_monitor import utils

logger = logging.getLogger(__name__)


def clean_text(text: str) -> str:
    # sans accents, ponctuation remplacée par des espaces, espaces écrasés, minuscules
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    return re.sub(r"\s+", " ", text).lower().strip()


def compile_terms(terms: list[str]) -> list[tuple[str, re.Pattern]]:
    # mots entiers uniquement : "iga" ne matche plus "investigation", "aster" ne matche plus "disaster"
    # un "s" final est toléré ("drone" matche "drones"), les termes multi-mots sont normalisés comme le texte
    compiled = []
    for term in terms:
        cleaned = clean_text(term)
        if not cleaned:
            continue
        pattern = re.compile(rf"(?<![a-z0-9]){re.escape(cleaned)}s?(?![a-z0-9])")
        compiled.append((term, pattern))
    return compiled


def find_matches(cleaned_text: str, compiled: list[tuple[str, re.Pattern]]) -> list[str]:
    return [term for term, pattern in compiled if pattern.search(cleaned_text)]


def correlate(items: list[dict]) -> list[dict]:
    keywords = compile_terms(utils.load_keywords())
    members = compile_terms(utils.load_members())
    results = []

    for item in items:
        # title vaut None pour Telegram : "or ''" évite d'analyser le mot "None"
        searchable = clean_text(f"{item.get('title') or ''} {item.get('content') or ''}")

        matched_keywords = find_matches(searchable, keywords)
        matched_members = find_matches(searchable, members)

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