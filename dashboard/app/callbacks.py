import ast
import os
import requests
from dash import Input, Output, callback, html
import dash_leaflet as dl

# URL watcher en local ou via docker
WATCHER_URL = os.getenv("WATCHER_URL", "http://localhost:5001/api/data")

def get_marker_color(site):
    if not site.get("site_up"):
        return "#ff4444"  # rouge
    defacement = site.get("defacement") or ""
    if "PEU PROBABLE" in defacement:
        return "#44ff88"  # vert
    if "PROBABLE" in defacement:
        return "#ff9944"  # orange
    return "#888888"  # gris


def parse_localisation(loc_str):
    try:
        lat, lon = ast.literal_eval(loc_str)
        return lat, lon
    except Exception:
        return None, None


def build_marker(site):
    lat, lon = parse_localisation(site.get("localisation", ""))
    if lat is None:
        return None

    color = get_marker_color(site)
    domain = site.get("domain", "?")
    site_up = "✅ En ligne" if site.get("site_up") else "❌ Hors ligne"
    ssl = "✅ OK" if site.get("ssl_ok") else "❌ KO"
    response = site.get("response_time", "?")
    defacement = site.get("defacement") or "N/A"
    checked_at = site.get("checked_at", "?")[:19].replace("T", " ")

    tooltip = dl.Tooltip(f"{domain} — {site_up}")
    popup = dl.Popup(
        html.Div([
            html.B(domain),
            html.Br(),
            html.Span(f"Statut : {site_up}"),
            html.Br(),
            html.Span(f"SSL : {ssl}"),
            html.Br(),
            html.Span(f"Temps réponse : {response}"),
            html.Br(),
            html.Span(f"Défacement : {defacement}"),
            html.Br(),
            html.Span(f"Vérifié à : {checked_at}", style={"color": "#888", "fontSize": "0.8em"}),
        ])
    )

    return dl.CircleMarker(
        center=[lat, lon],
        radius=10,
        color=color,
        fillColor=color,
        fillOpacity=0.8,
        children=[tooltip, popup],
    )

@callback(
    Output("markers", "children"),
    Output("last-update", "children"),
    Input("interval", "n_intervals"),
)
def update_map(n):
    try:
        resp = requests.get(WATCHER_URL, timeout=5)
        data = resp.json()
    except Exception:
        return [], "Erreur de connexion"

    markers = []
    for site in data.get("sites", []):
        m = build_marker(site)
        if m:
            markers.append(m)

    last_run = data.get("last_run", "")[:19].replace("T", " ")
    return markers, f"Mis à jour : {last_run}"