import os

FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5004))
SCHEDULE_INTERVAL_MINUTES = int(os.getenv("SCHEDULE_INTERVAL_MINUTES", 60))
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", 7))

BASE = "/data" if os.path.exists("/data") else "../data"
TARGETS_FILE = f"{BASE}/inputs/members.txt"
OUTPUT_FILE  = f"{BASE}/outputs/social_monitor.json"

IN_DOCKER = os.path.exists("/.dockerenv")
ALERT_SERVICE_URL = os.getenv("ALERT_SERVICE_URL", "http://alert_service:5005" if IN_DOCKER else "http://localhost:5005")


REQUEST_TIMEOUT = 15               # secondes

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

RSS_FEEDS = [
    # Institutionnel FR
    {"name": "CERT-FR", "url": "https://www.cert.ssi.gouv.fr/feed/"},
    {"name": "ANSSI", "url": "https://www.ssi.gouv.fr/feed/"},
    # Threat Intel
    {"name": "Sekoia", "url": "https://blog.sekoia.io/feed/"},
    {"name": "Recorded Future", "url": "https://www.recordedfuture.com/feed"},
    {"name": "Mandiant", "url": "https://www.mandiant.com/resources/blog/rss.xml"},
    {"name": "Microsoft MSRC", "url": "https://msrc.microsoft.com/blog/feed"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "Schneier on Security", "url": "https://www.schneier.com/feed/atom"},
    # Défense / géopolitique
    {"name": "IHEDN", "url": "https://www.ihedn.fr/feed/"},
    {"name": "Portail de l'IE", "url": "https://portail-ie.fr/feed"},
]

TELEGRAM_CHANNELS = [
    # Hacktivistes pro-russes — DDoS, défacement, revendications
    "noname05716",           # NoName057(16) — très actif sur infra critique
    "cyberarmyofrussia_reborn",  # Cyber Army of Russia
    "killnet_channel",       # KillNet
    "from_russia_with_love2022",  # agrégateur revendications
    # Leaks / data brokers
    "leakbase",              # vente et partage de leaks
    "breachforums_official", # BreachForums channel officiel
    # CTI généraliste
    "thecyberexpress",       # news cyber
    "vxunderground",         # samples, APT reports
]

KEYWORDS = [
    # Acteurs FR majeurs
    "thales", "airbus", "dassault", "mbda", "naval group",
    "safran", "nexter", "arquus", "knds", "eurenco",
    "soitec", "lacroix", "sopra steria", "atos defense",
    # Programmes / systèmes
    "rafale", "leclerc", "tigre", "caesar", "mica",
    "fremm", "suffren", "barracuda", "scaf", "mgcs",
    "scorpion", "contact", "serval", "griffon",
    # Institutions
    "dga", "dgse", "drsd", "etat-major", "armée de l'air",
    "armée de terre", "marine nationale", "gendarmerie",
    "otan", "nato", "eda", "occar",
    # Générique défense
    "defense", "défense", "militaire", "armement", "munitions",
    "missile", "drone", "cyber warfare", "apt",
    # Géopolitique pertinent
    "ukraine", "russie", "chine", "iran", "corée du nord",
    "espionnage", "sabotage", "supply chain attack",
]

def load_members(filepath: str) -> list[str]:
    members = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                members.append(line.lower())
    except FileNotFoundError:
        pass
    return members
 