import ast
import os
import requests
from dash import Input, Output, callback, html
import dash_leaflet as dl

WATCHER_URL = os.getenv("WATCHER_URL", "http://localhost:5001/api/data")
VULN_URL = os.getenv("VULN_URL", "http://localhost:5002/api/data")


# ─── Helpers carte ────────────────────────────────────────────────────────────

def get_marker_color(site):
    if not site.get("site_up"):
        return "#ff4444"
    defacement = site.get("defacement") or ""
    if "SITE OK (non défacé)" in defacement or "PEU PROBABLE" in defacement:
        return "#44ff88"
    if "PROBABLE" in defacement:
        return "#ff9944"
    return "#888888"


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


# ─── Helpers CVE ──────────────────────────────────────────────────────────────

def build_cve_panel(sites):
    """Panel droite — une ligne par domaine avec CVE critiques."""
    items = []
    for site in sites:
        domain = site.get("domain", "?")
        cves = site.get("headers", {}).get("cves", [])
        critical = [c for c in cves if c.get("cvss") and c["cvss"] > 7]
        if not critical:
            continue
        items.append(
            html.Div(
                style={
                    "borderLeft": "3px solid #c0392b",
                    "paddingLeft": "8px",
                    "marginBottom": "8px",
                },
                children=[
                    html.Span(domain, style={"color": "#fff", "fontFamily": "monospace", "fontSize": "0.85em", "fontWeight": "bold"}),
                    html.Span(f" — {len(critical)} CVE critique(s)", style={"color": "#c0392b", "fontSize": "0.8em"}),
                ]
            )
        )
    if not items:
        return html.Span("Aucune CVE critique détectée", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})
    return items


def build_cve_detail_panel(sites):
    """Panel bas — détail complet des CVE critiques."""
    rows = []
    for site in sites:
        domain = site.get("domain", "?")
        cves = site.get("headers", {}).get("cves", [])
        critical = [c for c in cves if c.get("cvss") and c["cvss"] > 7]
        for cve in critical:
            rows.append(
                html.Div(
                    style={
                        "display": "flex",
                        "gap": "12px",
                        "padding": "6px 0",
                        "borderBottom": "1px solid #2a2d35",
                        "alignItems": "flex-start",
                    },
                    children=[
                        html.Span(domain, style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "160px"}),
                        html.Span(cve.get("id", "?"), style={"color": "#c0392b", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "140px"}),
                        html.Span(f"CVSS {cve.get('cvss', '?')}", style={"color": "#ff9944", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "70px"}),
                        html.Span(cve.get("description", ""), style={"color": "#aaa", "fontSize": "0.78em", "flex": "1"}),
                    ]
                )
            )
    if not rows:
        return html.Span("Aucune CVE critique", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})
    return rows


def build_placeholder_panel(message):
    return html.Span(message, style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})


# ─── Callback principal ───────────────────────────────────────────────────────

@callback(
    Output("markers", "children"),
    Output("last-update", "children"),
    Output("map", "bounds"),
    Output("cve-panel", "children"),
    Output("cve-detail-panel", "children"),
    Output("ransomware-panel", "children"),
    Output("social-panel", "children"),
    Input("interval", "n_intervals"),
)
def update_dashboard(n):
    markers = []
    lats, lons = [], []

    # ── Web watcher ──
    try:
        resp = requests.get(WATCHER_URL, timeout=5)
        watcher_data = resp.json()
    except Exception:
        watcher_data = {"sites": []}

    for site in watcher_data.get("sites", []):
        m = build_marker(site)
        if m:
            markers.append(m)
        lat, lon = parse_localisation(site.get("localisation", ""))
        if lat:
            lats.append(lat)
            lons.append(lon)

    last_run = watcher_data.get("last_run", "")[:19].replace("T", " ")
    bounds = [[min(lats) - 1, min(lons) - 1], [max(lats) + 1, max(lons) + 1]] if lats else None

    # ── Vuln scanner ──
    try:
        resp = requests.get(VULN_URL, timeout=5)
        vuln_data = resp.json()
        vuln_sites = vuln_data.get("sites", [])
    except Exception:
        vuln_sites = []

    cve_panel = build_cve_panel(vuln_sites)
    cve_detail = build_cve_detail_panel(vuln_sites)

    # ── Placeholders services à venir ──
    ransomware_panel = build_placeholder_panel("Service non disponible")
    social_panel = build_placeholder_panel("Service non disponible")

    return markers, f"Mis à jour : {last_run}", bounds, cve_panel, cve_detail, ransomware_panel, social_panel