import os

FLASK_HOST = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5004))
SCHEDULE_INTERVAL_MINUTES = int(os.getenv("SCHEDULE_INTERVAL_MINUTES", 60))
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", 7))

BASE = "/data" if os.path.exists("/data") else "../data"
TARGETS_FILE = f"{BASE}/inputs/members.txt"
OUTPUT_FILE  = f"{BASE}/outputs/social_monitor.json"
RSS_FEEDS_FILE = f"{BASE}/inputs/rss_feeds.txt"
TELEGRAM_FILE = f"{BASE}/inputs/telegram_channels.txt"
KEYWORDS_FILE = f"{BASE}/inputs/keywords.txt"

IN_DOCKER = os.path.exists("/.dockerenv")
ALERT_SERVICE_URL = os.getenv("ALERT_SERVICE_URL", "http://alert_service:5005" if IN_DOCKER else "http://localhost:5005")


REQUEST_TIMEOUT = 15               # secondes


def read_lines(filepath: str) -> list[str]:
    lines = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                lines.append(line)
    except FileNotFoundError:
        pass
    return lines
 
 
def load_rss_feeds(filepath: str = RSS_FEEDS_FILE) -> list[dict]:
    feeds = []
    for line in read_lines(filepath):
        parts = line.split(",", 1)
        if len(parts) == 2:
            feeds.append({"name": parts[0].strip(), "url": parts[1].strip()})
    return feeds
 
 
def load_telegram_channels(filepath: str = TELEGRAM_FILE) -> list[str]:
    return read_lines(filepath)
 
 
def load_keywords(filepath: str = KEYWORDS_FILE) -> list[str]:
    return [line.lower() for line in read_lines(filepath)]
 
 
def load_members(filepath: str = TARGETS_FILE) -> list[str]:
    return [line.lower() for line in read_lines(filepath)]
 