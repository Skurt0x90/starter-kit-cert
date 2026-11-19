import requests
import logging
import re
import unicodedata
from web_watcher import utils
from bs4 import BeautifulSoup
from html import unescape

logger = logging.getLogger(__name__)

MAX_OCCURRENCES = 3      # une même expression ne compte pas plus de 3 fois
TITLE_CHANGE_SCORE = 3   # seul, un titre modifié ne suffit pas à passer en "probable"


def decode_html(response):
    # sans charset déclaré, requests suppose ISO-8859-1 : on ne détecte l'encodage que dans ce cas (coûteux)
    if "charset" not in response.headers.get("Content-Type", "").lower():
        response.encoding = response.apparent_encoding
    return response.text


def get_html_content(domain):
    url = f"https://{domain}"
    try:
        response = requests.get(url, headers=utils.HEADERS, timeout=utils.REQUEST_TIMEOUT, allow_redirects=True)
        return decode_html(response)
    except requests.exceptions.RequestException as e:
        logger.error(f"[{domain}] Erreur requête : {e}")
        return None


def normalize_title(t):
    t = unescape(t or "")
    t = unicodedata.normalize("NFKC", t)
    t = t.replace("\u2019", "'").replace("\u2018", "'")  # apostrophes typographiques
    return t.strip()


def is_title_changed(content, title):
    # pas de titre attendu configuré : on ne compare pas
    if not normalize_title(title):
        return False
    soup = BeautifulSoup(content, 'html.parser')
    soup_title = soup.head.title.get_text() if soup.head and soup.head.title else ""
    if not normalize_title(soup_title):
        return False
    return normalize_title(title) != normalize_title(soup_title)


def extract_visible_text(content):
    # texte visible uniquement : on ignore scripts, CSS et templates (bundles JS = faux positifs)
    soup = BeautifulSoup(content, "html.parser")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    return soup.get_text(separator=" ", strip=True).lower()


def keyword_pattern(kw):
    # limites de mots : "owned" ne matche plus "co-owned" collé à un autre mot
    return rf"(?<!\w){re.escape(kw)}(?!\w)"


## score 0-4 normal, 5-9 suspect, 10+ très suspect
def count_keyword_hits(text, keywords, weight):
    hits = 0
    score = 0
    for kw in keywords:
        matches = len(re.findall(keyword_pattern(kw), text))
        if matches > 0:
            hits += 1
            score += min(matches, MAX_OCCURRENCES) * weight
    return hits, score


def matched_keywords(text, keywords):
    # uniquement pour les logs : permet de voir quel mot-clé cause un faux positif
    return [kw for kw in keywords if re.search(keyword_pattern(kw), text)]


def compute_density_bonus(total_hits, total_length):
    # au moins 2 hits : un seul mot sur une petite page ne suffit pas
    density = total_hits / max(total_length, 1)
    if total_hits >= 2 and density > 0.005:
        return 4
    return 0


def compute_category_bonus(categories_triggered):
    if categories_triggered >= 3:
        return 8  # 3 catégories = 8 points
    if categories_triggered >= 2:
        return 3  # 2 catégories = 3 points
    return 0


def process_defacement_scoring(content, domain="?"):
    text = extract_visible_text(content)
    score = 0
    categories_triggered = 0

    high_hits, high_score = count_keyword_hits(text, utils.HIGH_CONFIDENCE, weight=5)
    medium_hits, medium_score = count_keyword_hits(text, utils.MEDIUM_CONFIDENCE, weight=2)
    tech_hits, tech_score = count_keyword_hits(text, utils.TECHNICAL_INDICATORS, weight=4)

    if high_hits > 0:
        categories_triggered += 1
    if medium_hits > 0:
        categories_triggered += 1
    if tech_hits > 0:
        categories_triggered += 1

    score += high_score + medium_score + tech_score
    score += compute_category_bonus(categories_triggered)
    score += compute_density_bonus(high_hits + medium_hits + tech_hits, len(text))

    if score > 0:
        found = (matched_keywords(text, utils.HIGH_CONFIDENCE)
                 + matched_keywords(text, utils.MEDIUM_CONFIDENCE)
                 + matched_keywords(text, utils.TECHNICAL_INDICATORS))
        logger.info(f"[{domain}] score défacement (mots-clés) = {score} — {found}")

    return score


def interprete_scoring(score):
    if score == 0:
        return "SITE OK (non défacé)"
    elif score <= 4:
        return "DEFACEMENT PEU PROBABLE"
    elif score <= 9:
        return "DEFACEMENT PROBABLE"
    else:
        return "DEFACEMENT FORTEMENT PROBABLE"


def probability_site_defaced(domain, title, content=None):
    # content : HTML déjà récupéré par le watcher (évite une requête de plus)
    if content is None:
        content = get_html_content(domain)
    if not content:
        return None

    score = process_defacement_scoring(content, domain=domain)
    if is_title_changed(content, title):
        logger.info(f"[{domain}] titre différent du titre attendu")
        score += TITLE_CHANGE_SCORE
    return interprete_scoring(score)