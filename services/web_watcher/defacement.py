import json
import requests
import logging
import contextlib
import socket
import ssl
import re
import unicodedata
from web_watcher import utils
from datetime import datetime, timezone, date
from zoneinfo import ZoneInfo
from pathlib import Path
from bs4 import BeautifulSoup
from html import unescape

logger = logging.getLogger(__name__)

def get_html_content(domain):
    url = f"https://{domain}"
    try:
        response = requests.get(url, headers=utils.HEADERS, timeout=utils.REQUEST_TIMEOUT, allow_redirects=True)
        return response.text
    except requests.exceptions.RequestException as e:
        logger.error(f"[{domain}] Erreur requête : {e}")
        return None

def normalize_title(t):
    t = unescape(t or "")
    t = unicodedata.normalize("NFKC", t)  # normalise les variantes Unicode
    return t.strip()

def is_title_changed(content, title):
    soup = BeautifulSoup(content, 'html.parser')
    soup_title = soup.head.title.get_text() if soup.head and soup.head.title else ""
    logging.info(f"[TITLE] stored={repr(normalize_title(title))} fetched={repr(normalize_title(soup_title))}")
    return normalize_title(title) != normalize_title(soup_title)


## score 0-4 normal, 5-9 suspect, 10+ très suspect
def count_keyword_hits(text, keywords, weight):
    hits = 0
    score = 0
    for kw in keywords:
        matches = len(re.findall(re.escape(kw), text))
        if matches > 0:
            hits += 1
            score += matches * weight
    return hits, score


def compute_density_bonus(total_hits, total_length):
    density = total_hits / max(total_length, 1)
    if density > 0.005:
        return 4
    return 0


def compute_category_bonus(categories_triggered):
    if categories_triggered == 3:
        return 8   # 3 + 5
    if categories_triggered >= 2:
        return 3
    return 0


def process_defacement_scoring(content): 
    text = content.lower()
    score = 0
    categories_triggered = 0

    high_hits, high_score = count_keyword_hits(text, utils.HIGH_CONFIDENCE, weight=5)
    medium_hits, medium_score = count_keyword_hits(text, utils.MEDIUM_CONFIDENCE, weight=2)
    tech_hits, tech_score = count_keyword_hits(text, utils.TECHNICAL_INDICATORS, weight=4)

    score += high_score + medium_score + tech_score

    if high_hits:
        categories_triggered += 1
    if medium_hits:
        categories_triggered += 1
    if tech_hits:
        categories_triggered += 1

    score += compute_category_bonus(categories_triggered)
    score += compute_density_bonus(high_hits + medium_hits + tech_hits, len(text))

    return score

def interprete_scoring(score):
    if score == 0:
        return "SITE OK (non défacé)"
    if 0 < score <= 4:
        return "DEFACEMENT PEU PROBABLE"
    elif 4 < score < 10:
        return "DEFACEMENT PROBABLE"
    else:
        return "DEFACEMENT FORTEMENT PROBABLE"
    

def probability_site_defaced(domain, title):
    content = get_html_content(domain)
    score = 0
    if content:
        score = process_defacement_scoring(content)
        if is_title_changed(content, title):
            score += 5
        return interprete_scoring(score)
    else:
        return None
        
