import ast
import os
import requests
from dash import Input, Output, callback, html, State, ctx
import dash_leaflet as dl
import logging

WATCHER_URL = os.getenv("WATCHER_URL", "http://localhost:5001/api/data")
VULN_URL = os.getenv("VULN_URL", "http://localhost:5002/api/data")

# Délais lus depuis les variables d'environnement
WATCHER_INTERVAL_MIN = int(os.getenv("SCHEDULE_INTERVAL_MINUTES", os.getenv("WEB_WATCHER_INTERVAL", 15)))
VULN_INTERVAL_H = int(os.getenv("SCHEDULE_INTERVAL_HOURS", os.getenv("VULN_SCANNER_INTERVAL", 24)))
DASHBOARD_REFRESH_SEC = 60
DEDUP_WINDOW_MIN = int(os.getenv("DEDUP_WINDOW_MINUTES", 30))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(),             # console
        logging.FileHandler("alert.log")  # fichier
    ]
)


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


# Positions spiral pour séparer les domaines aux coordonnées identiques
_SPIRAL_OFFSETS = [
    (0, 0),
    (0.012, 0), (-0.012, 0),
    (0, 0.018), (0, -0.018),
    (0.009, 0.013), (-0.009, 0.013),
    (0.009, -0.013), (-0.009, -0.013),
]


def build_marker(site, coord_offset=(0, 0)):
    lat, lon = parse_localisation(site.get("localisation", ""))
    if lat is None:
        return None
    lat += coord_offset[0]
    lon += coord_offset[1]
    color = get_marker_color(site)
    domain = site.get("domain", "?")
    site_up = "✅ En ligne" if site.get("site_up") else "❌ Hors ligne"
    ssl = "✅ OK" if site.get("ssl_ok") else "❌ KO"
    response = site.get("response_time", "?")
    defacement = site.get("defacement") or "N/A"
    checked_at = site.get("checked_at", "?")[:19].replace("T", " ")
    tooltip = dl.Tooltip(f"{domain} — {site_up}")
    popup = dl.Popup(html.Div([
        html.B(domain), html.Br(),
        html.Span(f"Statut : {site_up}"), html.Br(),
        html.Span(f"SSL : {ssl}"), html.Br(),
        html.Span(f"Temps réponse : {response}"), html.Br(),
        html.Span(f"Défacement : {defacement}"), html.Br(),
        html.Span(f"Vérifié à : {checked_at}", style={"color": "#888", "fontSize": "0.8em"}),
    ]))
    return dl.CircleMarker(center=[lat, lon], radius=10, color=color, fillColor=color, fillOpacity=0.8, children=[tooltip, popup])


# ─── Styles communs ───────────────────────────────────────────────────────────

def cvss_color(cvss):
    if cvss is None:
        return "#555"
    if cvss >= 9:
        return "#c0392b"
    if cvss > 7:
        return "#e67e22"
    return "#f1c40f"


def tag_style(color, bg):
    return {"color": color, "fontFamily": "monospace", "fontSize": "0.75em", "backgroundColor": bg, "padding": "1px 5px", "borderRadius": "3px", "marginRight": "4px", "marginBottom": "3px", "display": "inline-block"}


def filter_btn_styles(active_id, btn_ids):
    active = {"fontFamily": "monospace", "fontSize": "0.72em", "cursor": "pointer", "padding": "2px 8px", "border": "1px solid #00d4ff", "borderRadius": "10px", "backgroundColor": "#1a2a3a", "color": "#00d4ff", "marginRight": "4px"}
    inactive = {"fontFamily": "monospace", "fontSize": "0.72em", "cursor": "pointer", "padding": "2px 8px", "border": "1px solid #2a2d35", "borderRadius": "10px", "backgroundColor": "transparent", "color": "#555", "marginRight": "4px"}
    return [active if b == active_id else inactive for b in btn_ids]


# ─── Panels droite ────────────────────────────────────────────────────────────

def build_cve_panel(sites):
    items, total = [], 0
    for site in sites:
        domain = site.get("domain", "?")
        cves = [c for c in site.get("headers", {}).get("cves", []) if c.get("id")]
        if not cves:
            continue
        total += len(cves)
        critical = sum(1 for c in cves if c.get("cvss") and c["cvss"] > 7)
        warning = len(cves) - critical
        items.append(html.Div(
            style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "padding": "4px 8px", "marginBottom": "4px", "borderLeft": f"3px solid {'#c0392b' if critical else '#e67e22'}"},
            children=[
                html.Span(domain, style={"color": "#ddd", "fontFamily": "monospace", "fontSize": "0.82em"}),
                html.Div([
                    html.Span(f"{critical}C", style={"color": "#c0392b", "fontFamily": "monospace", "fontSize": "0.78em", "marginRight": "4px"}) if critical else None,
                    html.Span(f"{warning}W", style={"color": "#e67e22", "fontFamily": "monospace", "fontSize": "0.78em"}) if warning else None,
                ]),
            ]
        ))
    if not items:
        return html.Span("Aucune CVE détectée", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"}), 0
    return items, total


def build_subdomain_panel(sites):
    items, total = [], 0
    for site in sites:
        domain = site.get("domain", "?")
        subdomains = site.get("subdomains", [])
        if not subdomains:
            continue
        total += len(subdomains)
        items.append(html.Div(
            style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "padding": "4px 8px", "marginBottom": "4px", "borderLeft": "3px solid #2980b9"},
            children=[
                html.Span(domain, style={"color": "#ddd", "fontFamily": "monospace", "fontSize": "0.82em"}),
                html.Span(f"{len(subdomains)}", style={"color": "#5dade2", "fontFamily": "monospace", "fontSize": "0.78em"}),
            ]
        ))
    if not items:
        return html.Span("Aucun sous-domaine détecté", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"}), 0
    return items, total


def build_typosquat_panel(sites):
    items, total = [], 0
    for site in sites:
        domain = site.get("domain", "?")
        typos = site.get("typosquatting", [])
        if not typos:
            continue
        total += len(typos)
        items.append(html.Div(
            style={"display": "flex", "justifyContent": "space-between", "alignItems": "center", "padding": "4px 8px", "marginBottom": "4px", "borderLeft": "3px solid #c0392b"},
            children=[
                html.Span(domain, style={"color": "#ddd", "fontFamily": "monospace", "fontSize": "0.82em"}),
                html.Span(f"{len(typos)}", style={"color": "#e74c3c", "fontFamily": "monospace", "fontSize": "0.78em"}),
            ]
        ))
    if not items:
        return html.Span("Aucun typosquat détecté", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"}), 0
    return items, total


# ─── Panel bas ────────────────────────────────────────────────────────────────

def build_cve_detail_panel(sites, filtre="all"):
    logging.info(f"Construction du CVE detail panel avec {len(sites)} sites")
    rows = []
    for site in sites:
        domain = site.get("domain", "?")
        checked_at = site.get("checked_at", "")[:19].replace("T", " ")
        
        # CVE headers (existant)
        cves = [c for c in site.get("headers", {}).get("cves", []) if c.get("id")]
        for cve in cves:
            cvss = cve.get("cvss")
            level = "critical" if cvss and cvss > 7 else "warning"
            if filtre == "critical" and level != "critical": continue
            if filtre == "warning" and level != "warning": continue
            color = cvss_color(cvss)
            rows.append(html.Div(
                style={"display": "flex", "gap": "12px", "padding": "5px 0", "borderBottom": "1px solid #2a2d35", "alignItems": "flex-start", "backgroundColor": f"{color}11"},
                children=[
                    html.Span(domain, style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "150px"}),
                    html.Span(cve.get("id") or "—", style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "140px"}),
                    html.Span(f"CVSS {cvss}" if cvss else "version masquée", style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "90px"}),
                    html.Span("header", style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em", "minWidth": "60px"}),
                    html.Span(cve.get("description", ""), style={"color": "#aaa", "fontSize": "0.78em", "flex": "1"}),
                    html.Span(checked_at, style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em", "minWidth": "120px"}),
                ]
            ))

        # CVE ports nmap (nouveau)
        for port in site.get("ports", []):
            for cve in port.get("cves", []):
                cvss = cve.get("cvss")
                if not cvss: continue
                level = "critical" if cvss > 7 else "warning"
                if filtre == "critical" and level != "critical": continue
                if filtre == "warning" and level != "warning": continue
                color = cvss_color(cvss)
                rows.append(html.Div(
                    style={"display": "flex", "gap": "12px", "padding": "5px 0", "borderBottom": "1px solid #2a2d35", "alignItems": "flex-start", "backgroundColor": f"{color}11"},
                    children=[
                        html.Span(domain, style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "150px"}),
                        html.Span(cve.get("id") or "—", style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "140px"}),
                        html.Span(f"CVSS {cvss}", style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "90px"}),
                        html.Span(f"port {port['port']}", style={"color": "#5dade2", "fontFamily": "monospace", "fontSize": "0.75em", "minWidth": "60px"}),
                        html.Span(cve.get("description", ""), style={"color": "#aaa", "fontSize": "0.78em", "flex": "1"}),
                        html.Span(checked_at, style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em", "minWidth": "120px"}),
                    ]
                ))
    if not rows:
        return html.Span("Aucune alerte CVE", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})
    return rows

def build_dns_detail_panel(sites, filtre="all"):
    rows = []
    for site in sites:
        domain = site.get("domain", "?")
        dns = site.get("dns", {})
        if not dns:
            continue
        spf = dns.get("spf")
        dmarc = dns.get("dmarc")
        dmarc_policy = dns.get("dmarc_policy") or "—"
        checked_at = site.get("checked_at", "")[:19].replace("T", " ")

        if filtre == "spf" and spf:
            continue
        if filtre == "dmarc" and dmarc:
            continue
        if filtre == "none" and dmarc_policy != "none":
            continue

        spf_color = "#44ff88" if spf else "#ff4444"
        dmarc_color = "#44ff88" if dmarc and dmarc_policy != "none" else "#ff4444" if not dmarc else "#e67e22"

        rows.append(html.Div(
            style={"display": "flex", "gap": "12px", "padding": "5px 0", "borderBottom": "1px solid #2a2d35", "alignItems": "center"},
            children=[
                html.Span(domain, style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "160px"}),
                html.Span("SPF ✓" if spf else "SPF ✗", style={"color": spf_color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "70px"}),
                html.Span("DMARC ✓" if dmarc else "DMARC ✗", style={"color": dmarc_color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "90px"}),
                html.Span(f"p={dmarc_policy}" if dmarc else "—", style={"color": dmarc_color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "90px"}),
                html.Span(checked_at, style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em"}),
            ]
        ))
    if not rows:
        return html.Span("Aucune donnée DNS", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})
    return rows


def build_subdomain_detail_panel(sites, filtre="all"):
    rows = []
    for site in sites:
        domain = site.get("domain", "?")
        subdomains = site.get("subdomains", [])
        typos = site.get("typosquatting", [])
        checked_at = site.get("checked_at", "")[:19].replace("T", " ")

        show_sub = bool(subdomains) and filtre in ("all", "subdomains")
        show_typo = bool(typos) and filtre in ("all", "typo")

        if not show_sub and not show_typo:
            continue

        children = [
            html.Div(
                style={"display": "flex", "justifyContent": "space-between", "marginBottom": "6px"},
                children=[
                    html.Span(domain, style={"color": "#ddd", "fontFamily": "monospace", "fontSize": "0.85em", "fontWeight": "bold"}),
                    html.Span(checked_at, style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em"}),
                ]
            )
        ]

        if show_sub:
            children.append(html.Div(style={"marginBottom": "4px"}, children=[
                html.Span("Sous-domaines actifs : ", style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.78em"}),
                html.Span(f"{len(subdomains)}", style={"color": "#5dade2", "fontFamily": "monospace", "fontSize": "0.78em"}),
            ]))
            children.append(html.Div([html.Span(sub, style=tag_style("#5dade2", "#1a2a3a")) for sub in sorted(subdomains)], style={"marginBottom": "6px"}))

        if show_typo:
            children.append(html.Div(style={"marginBottom": "4px"}, children=[
                html.Span("Typosquats détectés : ", style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.78em"}),
                html.Span(f"{len(typos)}", style={"color": "#e74c3c", "fontFamily": "monospace", "fontSize": "0.78em"}),
            ]))
            children.append(html.Div([html.Span(typo, style=tag_style("#e74c3c", "#2a1a1a")) for typo in sorted(typos)]))

        rows.append(html.Div(style={"padding": "8px 0", "borderBottom": "1px solid #2a2d35"}, children=children))

    if not rows:
        return html.Span("Aucune donnée", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})
    return rows


# ─── Modal domaine ────────────────────────────────────────────────────────────

def build_modal_body(domain, vuln_sites):
    site = next((s for s in vuln_sites if s.get("domain") == domain), None)
    if not site:
        return []

    cves = [c for c in site.get("headers", {}).get("cves", []) if c.get("id")]
    subdomains = site.get("subdomains", [])
    typos = site.get("typosquatting", [])
    dns = site.get("dns", {})
    checked_at = site.get("checked_at", "")[:19].replace("T", " ")
    server = site.get("headers", {}).get("server") or "—"

    sections = []

    sections.append(html.Div(
        style={"marginBottom": "16px", "padding": "10px", "backgroundColor": "#141517", "borderRadius": "6px"},
        children=[
            html.Div([html.Span("Serveur : ", style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.82em"}), html.Span(server, style={"color": "#ddd", "fontFamily": "monospace", "fontSize": "0.82em"})], style={"marginBottom": "4px"}),
            html.Div([html.Span("Dernier scan : ", style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.82em"}), html.Span(checked_at, style={"color": "#ddd", "fontFamily": "monospace", "fontSize": "0.82em"})]),
        ]
    ))

    if cves:
        sections.append(html.Div("CVE", style={"color": "#c0392b", "fontFamily": "monospace", "fontSize": "0.78em", "textTransform": "uppercase", "letterSpacing": "0.05em", "marginBottom": "6px"}))
        for cve in cves:
            cvss = cve.get("cvss")
            color = cvss_color(cvss)
            sections.append(html.Div(
                style={"display": "flex", "gap": "10px", "padding": "4px 0", "borderBottom": "1px solid #2a2d35", "backgroundColor": f"{color}11"},
                children=[
                    html.Span(cve.get("id"), style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "140px"}),
                    html.Span(f"CVSS {cvss}" if cvss else "—", style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "80px"}),
                    html.Span(cve.get("description", ""), style={"color": "#aaa", "fontSize": "0.78em"}),
                ]
            ))
        sections.append(html.Div(style={"marginBottom": "14px"}))

    if dns:
        spf = dns.get("spf")
        dmarc = dns.get("dmarc")
        dmarc_policy = dns.get("dmarc_policy") or "—"
        spf_color = "#44ff88" if spf else "#ff4444"
        dmarc_color = "#44ff88" if dmarc and dmarc_policy != "none" else "#ff4444" if not dmarc else "#e67e22"
        sections.append(html.Div("DNS / SPF / DMARC", style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.78em", "textTransform": "uppercase", "letterSpacing": "0.05em", "marginBottom": "6px"}))
        sections.append(html.Div(
            style={"display": "flex", "gap": "16px", "marginBottom": "14px"},
            children=[
                html.Span("SPF ✓" if spf else "SPF ✗", style={"color": spf_color, "fontFamily": "monospace", "fontSize": "0.85em"}),
                html.Span("DMARC ✓" if dmarc else "DMARC ✗", style={"color": dmarc_color, "fontFamily": "monospace", "fontSize": "0.85em"}),
                html.Span(f"p={dmarc_policy}" if dmarc else "", style={"color": dmarc_color, "fontFamily": "monospace", "fontSize": "0.85em"}),
            ]
        ))

    if subdomains:
        sections.append(html.Div(f"Sous-domaines actifs ({len(subdomains)})", style={"color": "#2980b9", "fontFamily": "monospace", "fontSize": "0.78em", "textTransform": "uppercase", "letterSpacing": "0.05em", "marginBottom": "6px"}))
        sections.append(html.Div([html.Span(sub, style=tag_style("#5dade2", "#1a2a3a")) for sub in sorted(subdomains)], style={"marginBottom": "14px"}))

    if typos:
        sections.append(html.Div(f"Typosquats détectés ({len(typos)})", style={"color": "#e74c3c", "fontFamily": "monospace", "fontSize": "0.78em", "textTransform": "uppercase", "letterSpacing": "0.05em", "marginBottom": "6px"}))
        sections.append(html.Div([html.Span(typo, style=tag_style("#e74c3c", "#2a1a1a")) for typo in sorted(typos)], style={"marginBottom": "14px"}))

    return sections


# ─── Helpers header ───────────────────────────────────────────────────────────

def build_service_indicator(name, url):
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
    cve_critical = (
        sum(1 for s in vuln_sites for c in s.get("headers", {}).get("cves", []) if c.get("cvss") and c["cvss"] > 7)
        + sum(1 for s in vuln_sites for p in s.get("ports", []) for c in p.get("cves", []) if c.get("cvss") and c["cvss"] > 7)
    )
    typosquat_total = sum(len(s.get("typosquatting", [])) for s in vuln_sites)
    dns_issues = sum(1 for s in vuln_sites if not s.get("dns", {}).get("spf") or not s.get("dns", {}).get("dmarc"))

    def counter(label, value, color):
        return html.Div([
            html.Span(str(value), style={"color": color, "fontFamily": "monospace", "fontWeight": "bold", "fontSize": "0.9em"}),
            html.Span(f" {label}", style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em"}),
        ], style={"border": "1px solid #2a2d35", "padding": "2px 10px", "borderRadius": "4px", "backgroundColor": "#141517"})

    return [
        counter("OK", sites_ok, "#44ff88"),
        counter("DOWN", sites_down, "#ff4444"),
        counter("CVE critiques", cve_critical, "#c0392b"),
        counter("typosquats", typosquat_total, "#e74c3c"),
        counter("DNS ⚠", dns_issues, "#e67e22"),
    ]


# ─── Helper délais pour le modal aide ────────────────────────────────────────

def build_delays_content():
    def delay_row(label, value, color="#44ff88", note=None):
        children = [
            html.Span(label, style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "220px"}),
            html.Span(value, style={"color": color, "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "80px"}),
        ]
        if note:
            children.append(html.Span(note, style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.75em"}))
        return html.Div(children, style={"display": "flex", "gap": "12px", "paddingLeft": "8px", "marginBottom": "5px", "alignItems": "center"})

    return [
        delay_row("Dashboard — rafraîchissement", f"{DASHBOARD_REFRESH_SEC}s"),
        delay_row("Web Watcher — cycle de scan", f"{WATCHER_INTERVAL_MIN} min", note="disponibilité, SSL, défacement"),
        delay_row("Vuln Scanner — cycle de scan", f"{VULN_INTERVAL_H}h", note="CVE, DNS, sous-domaines, typosquats"),
        delay_row("Alert service — déduplication", f"{DEDUP_WINDOW_MIN} min", "#e67e22", note="fenêtre glissante anti-doublon"),
        html.Div(
            "Les délais sont configurables via les variables d'environnement du .env",
            style={"color": "#444", "fontFamily": "monospace", "fontSize": "0.75em", "paddingLeft": "8px", "marginTop": "6px"}
        ),
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
    Output("help-modal", "style"),
    Output("help-delays-content", "children"),
    Input("help-btn", "n_clicks"),
    Input("help-modal-close", "n_clicks"),
    Input("help-modal-overlay", "n_clicks"),
    prevent_initial_call=True,
)
def toggle_help_modal(n_open, n_close, n_overlay):
    visible = {"display": "block"}
    hidden = {"display": "none"}
    if ctx.triggered_id == "help-btn":
        return visible, build_delays_content()
    return hidden, []


@callback(
    Output("panel-bottom-body", "style"),
    Output("panel-expand-btn", "children"),
    Input("panel-expand-btn", "n_clicks"),
    State("panel-bottom-body", "style"),
    prevent_initial_call=True,
)
def toggle_panel_expand(n_clicks, current_style):
    expanded = current_style.get("maxHeight") == "500px"
    return {**current_style, "maxHeight": "200px" if expanded else "500px"}, "⛶ Agrandir" if expanded else "⛶ Réduire"


@callback(
    Output("tab-cve", "style"),
    Output("tab-dns", "style"),
    Output("tab-subdomains", "style"),
    Output("tab-btn-cve", "style"),
    Output("tab-btn-dns", "style"),
    Output("tab-btn-subdomains", "style"),
    Output("filters-cve", "style"),
    Output("filters-dns", "style"),
    Output("filters-sub", "style"),
    Input("tab-btn-cve", "n_clicks"),
    Input("tab-btn-dns", "n_clicks"),
    Input("tab-btn-subdomains", "n_clicks"),
    prevent_initial_call=False,
)
def switch_tab(n_cve, n_dns, n_sub):
    triggered = ctx.triggered_id or "tab-btn-cve"
    visible = {"display": "block"}
    hidden = {"display": "none"}
    btn_on = {"fontFamily": "monospace", "fontSize": "0.78em", "cursor": "pointer", "padding": "4px 12px", "border": "none", "borderRadius": "4px", "backgroundColor": "#2a2d35", "color": "#00d4ff"}
    btn_off = {"fontFamily": "monospace", "fontSize": "0.78em", "cursor": "pointer", "padding": "4px 12px", "border": "none", "borderRadius": "4px", "backgroundColor": "transparent", "color": "#555"}
    flex = {"display": "flex", "alignItems": "center", "gap": "2px"}
    no_flex = {"display": "none", "alignItems": "center", "gap": "2px"}

    if triggered == "tab-btn-dns":
        return hidden, visible, hidden, btn_off, btn_on, btn_off, no_flex, flex, no_flex
    if triggered == "tab-btn-subdomains":
        return hidden, hidden, visible, btn_off, btn_off, btn_on, no_flex, no_flex, flex
    return visible, hidden, hidden, btn_on, btn_off, btn_off, flex, no_flex, no_flex


@callback(
    Output("active-filter-cve", "data"),
    Output("filter-cve-all", "style"),
    Output("filter-cve-critical", "style"),
    Output("filter-cve-warning", "style"),
    Input("filter-cve-all", "n_clicks"),
    Input("filter-cve-critical", "n_clicks"),
    Input("filter-cve-warning", "n_clicks"),
    prevent_initial_call=True,
)
def update_filter_cve(n_all, n_crit, n_warn):
    mapping = {"filter-cve-all": "all", "filter-cve-critical": "critical", "filter-cve-warning": "warning"}
    active = mapping.get(ctx.triggered_id, "all")
    return active, *filter_btn_styles(ctx.triggered_id, ["filter-cve-all", "filter-cve-critical", "filter-cve-warning"])


@callback(
    Output("active-filter-dns", "data"),
    Output("filter-dns-all", "style"),
    Output("filter-dns-spf", "style"),
    Output("filter-dns-dmarc", "style"),
    Output("filter-dns-none", "style"),
    Input("filter-dns-all", "n_clicks"),
    Input("filter-dns-spf", "n_clicks"),
    Input("filter-dns-dmarc", "n_clicks"),
    Input("filter-dns-none", "n_clicks"),
    prevent_initial_call=True,
)
def update_filter_dns(n_all, n_spf, n_dmarc, n_none):
    mapping = {"filter-dns-all": "all", "filter-dns-spf": "spf", "filter-dns-dmarc": "dmarc", "filter-dns-none": "none"}
    active = mapping.get(ctx.triggered_id, "all")
    return active, *filter_btn_styles(ctx.triggered_id, ["filter-dns-all", "filter-dns-spf", "filter-dns-dmarc", "filter-dns-none"])


@callback(
    Output("active-filter-sub", "data"),
    Output("filter-sub-all", "style"),
    Output("filter-sub-subdomains", "style"),
    Output("filter-sub-typo", "style"),
    Input("filter-sub-all", "n_clicks"),
    Input("filter-sub-subdomains", "n_clicks"),
    Input("filter-sub-typo", "n_clicks"),
    prevent_initial_call=True,
)
def update_filter_sub(n_all, n_sub, n_typo):
    mapping = {"filter-sub-all": "all", "filter-sub-subdomains": "subdomains", "filter-sub-typo": "typo"}
    active = mapping.get(ctx.triggered_id, "all")
    return active, *filter_btn_styles(ctx.triggered_id, ["filter-sub-all", "filter-sub-subdomains", "filter-sub-typo"])


@callback(
    Output("tab-cve-content", "children", allow_duplicate=True),
    Output("tab-dns-content", "children", allow_duplicate=True),
    Output("tab-subdomains-content", "children", allow_duplicate=True),
    Input("active-filter-cve", "data"),
    Input("active-filter-dns", "data"),
    Input("active-filter-sub", "data"),
    State("vuln-data-store", "data"),
    prevent_initial_call=True,
)
def apply_filters(filter_cve, filter_dns, filter_sub, vuln_data):
    vuln_sites = (vuln_data or {}).get("sites", [])
    return (
        build_cve_detail_panel(vuln_sites, filter_cve or "all"),
        build_dns_detail_panel(vuln_sites, filter_dns or "all"),
        build_subdomain_detail_panel(vuln_sites, filter_sub or "all"),
    )


@callback(
    Output("domain-modal", "style"),
    Output("modal-title", "children"),
    Output("modal-body", "children"),
    Input("modal-close", "n_clicks"),
    Input("modal-overlay", "n_clicks"),
    prevent_initial_call=True,
)
def close_modal(n_close, n_overlay):
    return {"display": "none"}, "", []


@callback(
    Output("markers", "children"),
    Output("last-update", "children"),
    Output("map", "bounds"),
    Output("cve-panel", "children"),
    Output("cve-badge", "children"),
    Output("subdomain-panel", "children"),
    Output("subdomain-badge", "children"),
    Output("typosquat-panel", "children"),
    Output("typosquat-badge", "children"),
    Output("tab-cve-content", "children"),
    Output("tab-dns-content", "children"),
    Output("tab-subdomains-content", "children"),
    Output("ransomware-panel", "children"),
    Output("ransomware-badge", "children"),
    Output("social-panel", "children"),
    Output("social-badge", "children"),
    Output("global-counters", "children"),
    Output("service-indicators", "children"),
    Output("vuln-data-store", "data"),
    Input("interval", "n_intervals"),
    State("active-filter-cve", "data"),
    State("active-filter-dns", "data"),
    State("active-filter-sub", "data"),
)
def update_dashboard(n, filter_cve, filter_dns, filter_sub):
    markers, lats, lons = [], [], []
    logging.info(f"Update dashboard ")
    
    logging.info(f" WATCHER_URL: {WATCHER_URL}")
    logging.info(f" Request: {requests.get(WATCHER_URL, timeout=5)}")

    try:
        watcher_data = requests.get(WATCHER_URL, timeout=5).json()
        logging.info(f"Try watcher_data, len: {len(watcher_data)} ")
    except Exception as e :
        logging.error(f"Erreur lors de la récupération des données depuis WATCHER_URL: {e}")
        watcher_data = {"sites": []}

    # Décalage spiral : sépare les domaines aux coordonnées identiques
    coord_counts = {}
    for site in watcher_data.get("sites", []):
        lat, lon = parse_localisation(site.get("localisation", ""))
        if lat is None:
            continue
        key = (round(lat, 4), round(lon, 4))
        idx = coord_counts.get(key, 0)
        coord_counts[key] = idx + 1
        offset = _SPIRAL_OFFSETS[idx] if idx < len(_SPIRAL_OFFSETS) else (idx * 0.008, 0)
        m = build_marker(site, coord_offset=offset)
        if m:
            markers.append(m)
        lats.append(lat)
        lons.append(lon)

    last_run = watcher_data.get("last_run", "")[:19].replace("T", " ")
    bounds = [[min(lats) - 1, min(lons) - 1], [max(lats) + 1, max(lons) + 1]] if lats else None

    try:
        vuln_data = requests.get(VULN_URL, timeout=5).json()
        vuln_sites = vuln_data.get("sites", [])
        vuln_last_run = vuln_data.get("last_run", "")[:19].replace("T", " ")
    except Exception:
        vuln_sites, vuln_last_run, vuln_data = [], "indisponible", {}

    cve_panel, cve_total = build_cve_panel(vuln_sites)
    sub_panel, sub_total = build_subdomain_panel(vuln_sites)
    typo_panel, typo_total = build_typosquat_panel(vuln_sites)

    placeholder = html.Span("Service non disponible", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"})

    indicators = [
        build_service_indicator("web_watcher", WATCHER_URL),
        build_service_indicator("vuln_scanner", VULN_URL),
        html.Span(f"vuln: {vuln_last_run}", style={"color": "#444", "fontFamily": "monospace", "fontSize": "0.72em"}),
    ]

    return (
        markers, f"Mis à jour : {last_run}", bounds,
        cve_panel, f"{cve_total} CVE",
        sub_panel, f"{sub_total} sous-domaines",
        typo_panel, f"{typo_total} typosquats",
        build_cve_detail_panel(vuln_sites, filter_cve or "all"),
        build_dns_detail_panel(vuln_sites, filter_dns or "all"),
        build_subdomain_detail_panel(vuln_sites, filter_sub or "all"),
        placeholder, "—",
        placeholder, "—",
        build_global_counters(watcher_data.get("sites", []), vuln_sites),
        indicators,
        vuln_data,
    )
