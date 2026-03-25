import requests
import logging
import unicodedata
import re
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from ransomware_monitor import utils

logger = logging.getLogger(__name__)

def parse_and_filter_date(date_str: str) -> Optional[str]:
    if not date_str:
        return None

    try:
        date_part = date_str.split()[0]
        attack_date = datetime.strptime(date_part, "%Y-%m-%d")
    except (ValueError, IndexError):
        return None

    now = datetime.now()
    limit_date = now - timedelta(days=2)

    if attack_date >= limit_date:  # Comparaison de deux objets datetime
        return attack_date.strftime("%d-%m-%Y")
    return None

def get_victim_ransomfeed() -> List[Dict]:
    url = "https://api.ransomfeed.it/"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        formatted_data = []

        for entry in data:
            attack_date_str = entry.get("date", "")
            formatted_date = parse_and_filter_date(attack_date_str)

            if formatted_date:
                victim = entry.get("victim", "Unknown")
                actor = entry.get("gang", "Unknown")

                formatted_data.append({
                    "victime": victim,
                    "acteur": actor,
                    "date": formatted_date,
                    "source": "ransomfeed"
                })

        return formatted_data

    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur lors de la récupération des données : {e}")
        return []

def get_victim_ransomlive() -> List[Dict]:
    url = "https://api.ransomware.live/v2/recentvictims"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        formatted_data = []

        for entry in data:
            attack_date_str = entry.get("attackdate", "")
            formatted_date = parse_and_filter_date(attack_date_str)

            if formatted_date:
                victim = entry.get("victim", "Unknown")
                actor = entry.get("group", "Unknown")

                formatted_data.append({
                    "victime": victim,
                    "acteur": actor,
                    "date": formatted_date,
                    "source": "ransomlive"
                })

        return formatted_data

    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur lors de la récupération des données : {e}")
        return []
    
def get_victim_ransomlook() -> List[Dict]:
    url = "https://ransomlook.io/api/last/2"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        formatted_data = []

        for entry in data:
            attack_date_str = entry.get("discovered", "")
            formatted_date = parse_and_filter_date(attack_date_str)
            if formatted_date:
                victim = entry.get("post_title", "Unknown")
                actor = entry.get("group_name", "Unknown")


                formatted_data.append({
                    "victime": victim,
                    "acteur": actor,
                    "date": formatted_date,
                    "source": "ransomlook"
                })

        return formatted_data

    except requests.exceptions.RequestException as e:
        logger.error(f"Erreur lors de la récupération des données : {e}")
        return []


def clean_name(name: str) -> str:
    name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')
    name = re.sub(r'[^a-zA-Z0-9]', '', name)
    name = name.lower()

    return name



def correlate():
    ransomlist = get_victim_ransomfeed() 
    ransomlist += get_victim_ransomlive()
    ransomlist += get_victim_ransomlook()
    memberlist = utils.load_members(utils.TARGETS_FILE)
    
    matches = []
    for member in memberlist:
        member_clean = clean_name(member['member'])
        for victime in ransomlist:
            if member_clean == clean_name(victime['victime']):
                matches.append({
                    'victime': victime['victime'],
                    'acteur': victime['acteur'],
                    'date': victime['date'],
                    'source': victime['source']
                })
                break
    
    return matches
