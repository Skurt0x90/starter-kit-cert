import os
from dotenv import load_dotenv

load_dotenv()  # cherche le .env dans le dossier courant puis les dossiers parents

CARTO_API_KEY = os.getenv("CARTO_API_KEY", "")

CARTO_TILE_URL = (
    "https://{s}.basemaps.cartocdn.com/rastertiles/dark_all/{z}/{x}/{y}{r}.png"
    f"?key={CARTO_API_KEY}"
)
CARTO_ATTRIBUTION = '&copy; <a href="https://carto.com/">CARTO</a> &copy; OpenStreetMap contributors'