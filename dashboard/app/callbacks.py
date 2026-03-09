import ast
import os
import requests
from datetime import datetime
from zoneinfo import ZoneInfo
from dash import Input, Output, callback, html, State
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
            html.B(domain), html.Br(),
            html.Span(f"Statut : {site_up}"), html.Br(),
            html.Span(f"SSL : {ssl}"), html.Br(),
            html.Span(f"Temps réponse : {response}"), html.Br(),
            html.Span(f"Défacement : {defacement}"), html.Br(),
            html.Span(f"Vérifié à : {checked_at}", style={"color": "#888", "fontSize": "0.8em"}),
        ])
    )
    return dl.CircleMarker(
        center=[lat, lon], radius=10,
        color=color, fillColor=color, fillOpacity=0.8,
        children=[tooltip, popup],
    )


# ─── Helpers CVE ──────────────────────────────────────────────────────────────

def cvss_color(cvss):
    if cvss is None:
        return "#555"
    if cvss >= 9:
        return "#c0392b"
    if cvss > 7:
        return "#e67e22"
    return "#f1c40f"


def build_cve_panel(sites):
    """Panel droite — nombre d'alertes par domaine."""
    items = []
    total = 0
    for site in sites:
        domain = site.get("domain", "?")
        cves = [c for c in site.get("headers", {}).get("cves", []) if c.get("id")]
        count = len(cves)
        if count == 0:
            continue
        total += count
        critical = sum(1 for c in cves if c.get("cvss") and c["cvss"] > 7)
        warning = count - critical
        items.append(
            html.Div(
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                    "padding": "4px 6px",
                    "marginBottom": "4px",
                    "borderLeft": "3px solid #c0392b" if critical else "3px solid #e67e22",
                    "paddingLeft": "8px",
                },
                children=[
                    html.Span(domain, style={"color": "#ddd", "fontFamily": "monospace", "fontSize": "0.82em"}),
                    html.Div([
                        html.Span(f"{critical}C", style={"color": "#c0392b", "fontFamily": "monospace", "fontSize": "0.78em", "marginRight": "4px"}) if critical else None,
                        html.Span(f"{warning}W", style={"color": "#e67e22", "fontFamily": "monospace", "fontSize": "0.78em"}) if warning else None,
                    ]),
                ]
            )
        )
    if not items:
        return html.Span("Aucune alerte détectée", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"}), 0
    return items, total


def build_cve_detail_panel(sites):
    """Panel bas — détail complet avec couleur par CVSS."""
    rows = []
    for site in sites:
        domain = site.get("domain", "?")
        cves = [c for c in site.get("headers", {}).get("cves", []) if c.get("id")]
        checked_at = site.get("checked_at", "")[:19].replace("T", " ")
        for cve in cves:
            cvss = cve.get("cvss")
            color = cvss_color(cvss)
            cvss_label = f"CVSS {cvss}" if cvss else "version masquée"
            rows.append(
                html.Div(
                    style={
                        "display": "flex",
                        "gap": "12px",
                        "padding": "5px 0",
                        "borderBottom": "1px solid #2a2d35",
                        "alignItems": "flex-start",
                        "backgroundColor": f"{color}11",
                    },
                    children=[
                        html.Span(domain, style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "150px"}),
                        html.Span(cve.get("id") or "—", style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "140px"}),
                        html.Span(cvss_label, style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "90px"}),
                        html.Span(cve.get("description", ""), style={"color": "#aaa", "fontSize": "0.78em", "flex": "1"}),
                        html.Span(checked_at, style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em", "minWidth": "120px"}),
                    ]
                )
            )
    if not rows:
        return html.Span("Aucune alerte CVE", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})
    return rows


def build_service_indicator(name, url):
    """Point vert/rouge selon si le service répond."""
    try:
        r = requests.get(url.replace("/api/data", "/health"), timeout=2)
        ok = r.status_code == 200
    except Exception:
        ok = False
    color = "#44ff88" if ok else "#ff4444"
    return html.Div([
        html.Span("⬤ ", style={"color": color, "fontSize": "0.7em"}),
        html.Span(name, style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.75em"}),
    ], style={"display": "flex", "alignItems": "center", "gap": "4px"})


def build_global_counters(watcher_sites, vuln_sites):
    sites_ok = sum(1 for s in watcher_sites if s.get("site_up"))
    sites_down = len(watcher_sites) - sites_ok
    cve_critical = sum(
        1 for s in vuln_sites
        for c in s.get("headers", {}).get("cves", [])
        if c.get("cvss") and c["cvss"] > 7
    )

    def counter(label, value, color):
        return html.Div([
            html.Span(str(value), style={"color": color, "fontFamily": "monospace", "fontWeight": "bold", "fontSize": "0.9em"}),
            html.Span(f" {label}", style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em"}),
        ], style={
            "border": "1px solid #2a2d35",
            "padding": "2px 10px",
            "borderRadius": "4px",
            "backgroundColor": "#141517",
        })

    return [
        counter("OK", sites_ok, "#44ff88"),
        counter("DOWN", sites_down, "#ff4444"),
        counter("CVE critiques", cve_critical, "#c0392b"),
    ]


# ─── Callbacks ────────────────────────────────────────────────────────────────

@callback(
    Output("legend-box", "style"),
    Input("legend-btn", "n_clicks"),
    State("legend-box", "style"),
    prevent_initial_call=True,
)
def toggle_legend(n_clicks, current_style):
    if current_style.get("display") == "none":
        return {**current_style, "display": "block"}
    return {**current_style, "display": "none"}


@callback(
    Output("markers", "children"),
    Output("last-update", "children"),
    Output("map", "bounds"),
    Output("cve-panel", "children"),
    Output("cve-badge", "children"),
    Output("cve-detail-panel", "children"),
    Output("ransomware-panel", "children"),
    Output("ransomware-badge", "children"),
    Output("social-panel", "children"),
    Output("social-badge", "children"),
    Output("global-counters", "children"),
    Output("service-indicators", "children"),
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
        vuln_last_run = vuln_data.get("last_run", "")[:19].replace("T", " ")
    except Exception:
        vuln_sites = []
        vuln_last_run = "indisponible"

    cve_panel_content, cve_total = build_cve_panel(vuln_sites)
    cve_detail = build_cve_detail_panel(vuln_sites)
    cve_badge = f"{cve_total} alerte(s)"

    # ── Placeholders ──
    placeholder = html.Span("Service non disponible", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})
    ransomware_panel = placeholder
    ransomware_badge = "—"
    social_panel = placeholder
    social_badge = "—"

    # ── Compteurs globaux ──
    counters = build_global_counters(watcher_data.get("sites", []), vuln_sites)

    # ── Indicateurs services + timestamps ──
    indicators = [
        build_service_indicator("web_watcher", WATCHER_URL),
        build_service_indicator("vuln_scanner", VULN_URL),
        html.Span(f"vuln: {vuln_last_run}", style={"color": "#444", "fontFamily": "monospace", "fontSize": "0.72em"}),
    ]

    return (
        markers, f"Mis à jour : {last_run}", bounds,
        cve_panel_content, cve_badge,
        cve_detail,
        ransomware_panel, ransomware_badge,
        social_panel, social_badge,
        counters, indicators,
    )