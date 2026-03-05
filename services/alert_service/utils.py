import os

FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", 5005))

BASE = "/data" if os.path.exists("/data") else "../data"
OUTPUT_FILE = os.getenv("OUTPUT_FILE", f"{BASE}/outputs/alert_service.json")
DEDUP_FILE  = os.getenv("DEDUP_FILE",  f"{BASE}/outputs/alert_dedup.json")

DEDUP_WINDOW_MINUTES = int(os.getenv("DEDUP_WINDOW_MINUTES", 60))

SMTP_HOST        = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT        = int(os.getenv("SMTP_PORT", 587))
SMTP_USER        = os.getenv("SMTP_USER", "")
SMTP_PASSWORD    = os.getenv("SMTP_PASSWORD", "")
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM", "")
ALERT_EMAIL_TO   = os.getenv("ALERT_EMAIL_TO", "")

SIGNAL_CLI_NUMBER   = os.getenv("SIGNAL_CLI_NUMBER", "")
SIGNAL_CLI_GROUP_ID = os.getenv("SIGNAL_CLI_GROUP_ID", "")
