""" Au lieu de vérifier tout le HTML, vérifie :
<title>


Absence de mots suspects dans le H1 ou autre:

hacked
hacked by
owned by
anonymous
pwned """



import json
import requests
import logging
import contextlib
import socket
import ssl
from web_watcher import utils
from datetime import datetime, timezone, date
from zoneinfo import ZoneInfo
from pathlib import Path
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def is_title_ok(domain, title):
    url = f"https://{domain}"
    try:
        response = requests.get(url, headers=utils.HEADERS, timeout=utils.REQUEST_TIMEOUT, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        soup_head = soup.head
        soup_title = soup_head.title.string if soup_head and soup_head.title else None
        soup_title = soup_title or ""
        if title == soup_title:
            return True
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"[{domain}] Erreur requête : {e}")
        return False
    return False
