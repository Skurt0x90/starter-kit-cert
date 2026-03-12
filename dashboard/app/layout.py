from dash import html, dcc
import dash_mantine_components as dmc
import dash_leaflet as dl


def service_panel(title, list_id, badge_id, color_header="#c0392b"):
    return dmc.Box(
        style={
            "backgroundColor": "#1a1b1e",
            "border": "1px solid #2a2d35",
            "borderRadius": "8px",
            "marginBottom": "10px",
            "overflow": "hidden",
        },
        children=[
            dmc.Box(
                style={
                    "backgroundColor": color_header,
                    "padding": "6px 14px",
                    "display": "flex",
                    "justifyContent": "space-between",
                    "alignItems": "center",
                },
                children=[
                    dmc.Text(title, size="sm", fw=700, c="white", style={"fontFamily": "monospace"}),
                    html.Span(id=badge_id, style={
                        "backgroundColor": "rgba(0,0,0,0.3)",
                        "color": "white",
                        "fontFamily": "monospace",
                        "fontSize": "0.75em",
                        "padding": "2px 8px",
                        "borderRadius": "10px",
                    }),
                ]
            ),
            dmc.Box(
                style={"padding": "8px", "maxHeight": "150px", "overflowY": "auto"},
                children=[html.Div(id=list_id)],
            ),
        ]
    )


def tab_button(label, btn_id, active=False):
    return html.Button(
        label, id=btn_id, n_clicks=0,
        style={
            "fontFamily": "monospace", "fontSize": "0.78em", "cursor": "pointer",
            "padding": "4px 12px", "border": "none", "borderRadius": "4px",
            "backgroundColor": "#2a2d35" if active else "transparent",
            "color": "#00d4ff" if active else "#555",
        }
    )


def filter_btn(label, btn_id, active=False):
    return html.Button(
        label, id=btn_id, n_clicks=0,
        style={
            "fontFamily": "monospace", "fontSize": "0.72em", "cursor": "pointer",
            "padding": "2px 8px",
            "border": f"1px solid {'#00d4ff' if active else '#2a2d35'}",
            "borderRadius": "10px",
            "backgroundColor": "#1a2a3a" if active else "transparent",
            "color": "#00d4ff" if active else "#555",
            "marginRight": "4px",
        }
    )


def help_section(title, color, children):
    """Bloc de section dans le modal d'aide."""
    return html.Div(
        style={"marginBottom": "20px"},
        children=[
            html.Div(
                title,
                style={
                    "color": color, "fontFamily": "monospace", "fontSize": "0.78em",
                    "textTransform": "uppercase", "letterSpacing": "0.08em",
                    "borderBottom": f"1px solid {color}44", "paddingBottom": "4px",
                    "marginBottom": "8px",
                }
            ),
            *children,
        ]
    )


def help_line(text, color="#aaa"):
    return html.Div(text, style={"color": color, "fontSize": "0.82em", "fontFamily": "monospace", "marginBottom": "4px", "paddingLeft": "8px"})


def create_layout():
    return dmc.MantineProvider(
        theme={"colorScheme": "dark"},
        children=[
            dmc.Box(
                style={"backgroundColor": "#1a1b1e", "minHeight": "100vh", "display": "flex", "flexDirection": "column"},
                children=[

                    # ── Modal domaine ─────────────────────────────────────────
                    html.Div(
                        id="domain-modal",
                        style={"display": "none"},
                        children=[
                            html.Div(
                                id="modal-overlay",
                                style={
                                    "position": "fixed", "top": "0", "left": "0",
                                    "width": "100%", "height": "100%",
                                    "backgroundColor": "rgba(0,0,0,0.75)", "zIndex": "999",
                                }
                            ),
                            html.Div(
                                style={
                                    "position": "fixed", "top": "50%", "left": "50%",
                                    "transform": "translate(-50%, -50%)",
                                    "width": "75%", "maxHeight": "80vh",
                                    "backgroundColor": "#1a1b1e", "border": "1px solid #2a2d35",
                                    "borderRadius": "10px", "zIndex": "1000",
                                    "overflow": "hidden", "display": "flex", "flexDirection": "column",
                                },
                                children=[
                                    html.Div(
                                        style={
                                            "backgroundColor": "#141517", "padding": "12px 20px",
                                            "display": "flex", "justifyContent": "space-between",
                                            "alignItems": "center", "borderBottom": "1px solid #2a2d35",
                                        },
                                        children=[
                                            html.Span(id="modal-title", style={"color": "#00d4ff", "fontFamily": "monospace", "fontWeight": "bold", "fontSize": "1em"}),
                                            html.Button("✕", id="modal-close", n_clicks=0, style={"background": "none", "border": "none", "color": "#888", "fontSize": "1.2em", "cursor": "pointer"}),
                                        ]
                                    ),
                                    html.Div(id="modal-body", style={"overflowY": "auto", "padding": "16px 20px", "flex": "1"}),
                                ]
                            ),
                        ]
                    ),

                    # ── Modal aide (?) ────────────────────────────────────────
                    html.Div(
                        id="help-modal",
                        style={"display": "none"},
                        children=[
                            html.Div(
                                id="help-modal-overlay",
                                style={
                                    "position": "fixed", "top": "0", "left": "0",
                                    "width": "100%", "height": "100%",
                                    "backgroundColor": "rgba(0,0,0,0.75)", "zIndex": "999",
                                }
                            ),
                            html.Div(
                                style={
                                    "position": "fixed", "top": "50%", "left": "50%",
                                    "transform": "translate(-50%, -50%)",
                                    "width": "680px", "maxWidth": "90vw", "maxHeight": "85vh",
                                    "backgroundColor": "#1a1b1e", "border": "1px solid #2a2d35",
                                    "borderRadius": "10px", "zIndex": "1000",
                                    "overflow": "hidden", "display": "flex", "flexDirection": "column",
                                },
                                children=[
                                    # Header modal
                                    html.Div(
                                        style={
                                            "backgroundColor": "#141517", "padding": "12px 20px",
                                            "display": "flex", "justifyContent": "space-between",
                                            "alignItems": "center", "borderBottom": "1px solid #2a2d35",
                                        },
                                        children=[
                                            html.Span("Documentation & Délais", style={"color": "#00d4ff", "fontFamily": "monospace", "fontWeight": "bold", "fontSize": "1em"}),
                                            html.Button("✕", id="help-modal-close", n_clicks=0, style={"background": "none", "border": "none", "color": "#888", "fontSize": "1.2em", "cursor": "pointer"}),
                                        ]
                                    ),
                                    # Corps modal
                                    html.Div(
                                        style={"overflowY": "auto", "padding": "20px 24px", "flex": "1"},
                                        children=[

                                            # Section 1 — Sous-domaines
                                            help_section("⚠ Risques — Sous-domaines actifs", "#2980b9", [
                                                help_line("Un sous-domaine actif et oublié est une surface d'attaque non surveillée."),
                                                help_line("Exemples de risques :"),
                                                help_line("→  Sous-domaine pointant vers un service tiers désactivé (subdomain takeover)", "#e67e22"),
                                                help_line("→  Environnement de dev/staging exposé publiquement sans authentification", "#e67e22"),
                                                help_line("→  Ancien service non patché toujours résolvable via DNS", "#e67e22"),
                                                help_line("→  Absence de certificat SSL sur un sous-domaine actif", "#e67e22"),
                                                help_line("Action recommandée : vérifier la légitimité de chaque sous-domaine détecté et supprimer les entrées DNS orphelines."),
                                            ]),

                                            # Section 2 — DNS / SPF / DMARC
                                            help_section("⚠ Risques — DNS / SPF / DMARC", "#e67e22", [
                                                help_line("Une mauvaise configuration DNS expose les membres aux attaques par usurpation d'identité."),
                                                html.Div(style={"marginBottom": "6px", "marginTop": "6px"}, children=[
                                                    html.Div(style={"display": "flex", "gap": "8px", "marginBottom": "4px", "paddingLeft": "8px"}, children=[
                                                        html.Span("SPF absent", style={"color": "#ff4444", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "120px"}),
                                                        html.Span("→ n'importe qui peut envoyer des emails au nom du domaine", style={"color": "#aaa", "fontSize": "0.8em", "fontFamily": "monospace"}),
                                                    ]),
                                                    html.Div(style={"display": "flex", "gap": "8px", "marginBottom": "4px", "paddingLeft": "8px"}, children=[
                                                        html.Span("DMARC absent", style={"color": "#ff4444", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "120px"}),
                                                        html.Span("→ aucune politique de rejet, phishing facilité", style={"color": "#aaa", "fontSize": "0.8em", "fontFamily": "monospace"}),
                                                    ]),
                                                    html.Div(style={"display": "flex", "gap": "8px", "marginBottom": "4px", "paddingLeft": "8px"}, children=[
                                                        html.Span("DMARC p=none", style={"color": "#e67e22", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "120px"}),
                                                        html.Span("→ monitoring uniquement, aucun email illégitime bloqué", style={"color": "#aaa", "fontSize": "0.8em", "fontFamily": "monospace"}),
                                                    ]),
                                                    html.Div(style={"display": "flex", "gap": "8px", "paddingLeft": "8px"}, children=[
                                                        html.Span("DKIM absent", style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "120px"}),
                                                        html.Span("→ non vérifié (sélecteur inconnu en mode passif)", style={"color": "#555", "fontSize": "0.8em", "fontFamily": "monospace"}),
                                                    ]),
                                                ]),
                                                help_line("Action recommandée : viser SPF strict + DMARC p=quarantine ou p=reject."),
                                            ]),

                                            # Section 3 — Délais
                                            help_section("🕐 Délais de rafraîchissement", "#44ff88", [
                                                html.Div(id="help-delays-content"),
                                            ]),

                                            # Section 4 — Licence / auteur
                                            help_section("ℹ️ À propos", "#888", [
                                                html.Div(
                                                    style={"paddingLeft": "8px", "fontFamily": "monospace", "fontSize": "0.8em", "color": "#888"},
                                                    children=[
                                                        html.Span("Starter Kit CERT Aviation — "),
                                                        html.Span("MIT License — "),
                                                        html.Span("Développé par "),
                                                        html.Span("Skurt0x90", style={"color": "#00d4ff"}),
                                                        html.Span(" — Inspiré de MISC N°142 (David LE GOFF & Marion BUCHET) — "),
                                                        html.A(
                                                            "github.com/Skurt0x90/starter-kit-cert",
                                                            href="https://github.com/Skurt0x90/starter-kit-cert",
                                                            target="_blank",
                                                            style={"color": "#00d4ff", "textDecoration": "none"},
                                                        ),
                                                    ]
                                                ),
                                            ]),

                                        ]
                                    ),
                                ]
                            ),
                        ]
                    ),

                    # ── Header ───────────────────────────────────────────────
                    dmc.Box(
                        style={
                            "borderBottom": "1px solid #2a2d35", "padding": "10px 24px",
                            "display": "flex", "justifyContent": "space-between",
                            "alignItems": "center", "backgroundColor": "#141517",
                        },
                        children=[
                            dmc.Text("CERT - Skurt0x90", size="xl", fw=700, c="cyan", style={"letterSpacing": "0.1em", "fontFamily": "monospace"}),
                            html.Div(id="global-counters", style={"display": "flex", "gap": "10px", "alignItems": "center"}),
                            html.Div(id="service-indicators", style={"display": "flex", "gap": "16px", "alignItems": "center"}),
                            html.Div(
                                style={"display": "flex", "gap": "8px", "alignItems": "center"},
                                children=[
                                    html.Span(id="last-update", style={"fontSize": "0.75rem", "color": "#888", "fontFamily": "monospace", "border": "1px solid #2a2d35", "padding": "2px 8px", "borderRadius": "4px"}),
                                    html.Button(
                                        "?",
                                        id="help-btn",
                                        n_clicks=0,
                                        title="Documentation & délais",
                                        style={
                                            "fontFamily": "monospace", "fontSize": "0.82em", "fontWeight": "bold",
                                            "cursor": "pointer", "padding": "2px 9px",
                                            "border": "1px solid #2a2d35", "borderRadius": "50%",
                                            "backgroundColor": "transparent", "color": "#00d4ff",
                                            "lineHeight": "1.4",
                                        }
                                    ),
                                ]
                            ),
                        ],
                    ),

                    # ── Carte + panels droite ─────────────────────────────────
                    dmc.Box(
                        style={"display": "flex", "flexDirection": "row", "padding": "16px 20px 8px 20px", "gap": "16px", "flex": "1"},
                        children=[

                            # Carte
                            dmc.Box(
                                style={"width": "75%", "position": "relative"},
                                children=[
                                    dl.Map(
                                        id="map", center=[48.0, 10.0], zoom=4,
                                        style={"height": "calc(100vh - 280px)", "width": "100%", "borderRadius": "8px", "border": "1px solid #2a2d35"},
                                        children=[
                                            dl.TileLayer(url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", attribution='&copy; <a href="https://carto.com/">CARTO</a>'),
                                            dl.LayerGroup(id="markers"),
                                        ],
                                    ),
                                    html.Div(id="legend-btn", n_clicks=0, style={"position": "absolute", "bottom": "20px", "left": "20px", "zIndex": "1000", "backgroundColor": "#141517", "border": "1px solid #2a2d35", "borderRadius": "6px", "padding": "6px 12px", "cursor": "pointer", "color": "#aaa", "fontFamily": "monospace", "fontSize": "0.75em"}, children="⬤ Légende"),
                                    html.Div(
                                        id="legend-box",
                                        style={"display": "none", "position": "absolute", "bottom": "55px", "left": "20px", "zIndex": "1000", "backgroundColor": "#141517", "border": "1px solid #2a2d35", "borderRadius": "8px", "padding": "12px 16px", "fontFamily": "monospace", "fontSize": "0.8em", "minWidth": "240px"},
                                        children=[
                                            html.Div("Couleurs des marqueurs", style={"color": "#888", "marginBottom": "8px"}),
                                            html.Div([html.Span("⬤ ", style={"color": "#44ff88"}), html.Span("En ligne, défacement peu probable", style={"color": "#aaa"})], style={"marginBottom": "4px"}),
                                            html.Div([html.Span("⬤ ", style={"color": "#ff9944"}), html.Span("En ligne, défacement probable", style={"color": "#aaa"})], style={"marginBottom": "4px"}),
                                            html.Div([html.Span("⬤ ", style={"color": "#ff4444"}), html.Span("Site hors ligne (DOWN)", style={"color": "#aaa"})], style={"marginBottom": "4px"}),
                                            html.Div([html.Span("⬤ ", style={"color": "#888"}), html.Span("Statut inconnu", style={"color": "#aaa"})], style={"marginBottom": "12px"}),
                                            html.Div("Conditions d'alerte", style={"color": "#888", "marginBottom": "8px"}),
                                            html.Div("DOWN : timeout ou HTTP KO", style={"color": "#aaa", "marginBottom": "4px"}),
                                            html.Div("DÉFACEMENT : balise <title> modifiée", style={"color": "#aaa", "marginBottom": "4px"}),
                                            html.Div("SSL : certificat expirant < 30 jours", style={"color": "#aaa"}),
                                        ]
                                    ),
                                ]
                            ),

                            # Panels droite
                            dmc.Box(
                                style={"width": "25%", "display": "flex", "flexDirection": "column", "overflowY": "auto", "maxHeight": "calc(100vh - 280px)"},
                                children=[
                                    dmc.Box(
                                        style={"backgroundColor": "#1a1b1e", "border": "1px solid #2a2d35", "borderRadius": "8px", "marginBottom": "10px", "overflow": "hidden"},
                                        children=[
                                            dmc.Box(style={"backgroundColor": "#922b21", "padding": "6px 14px"}, children=[dmc.Text("🔍 Vuln Scanner", size="sm", fw=700, c="white", style={"fontFamily": "monospace"})]),
                                            dmc.Box(style={"padding": "6px 10px", "borderBottom": "1px solid #2a2d35"}, children=[
                                                html.Div(style={"display": "flex", "justifyContent": "space-between", "marginBottom": "5px"}, children=[
                                                    html.Span("CVE", style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.75em", "textTransform": "uppercase"}),
                                                    html.Span(id="cve-badge", style={"color": "#c0392b", "fontFamily": "monospace", "fontSize": "0.72em"}),
                                                ]),
                                                html.Div(id="cve-panel", style={"maxHeight": "120px", "overflowY": "auto"}),
                                            ]),
                                            dmc.Box(style={"padding": "6px 10px", "borderBottom": "1px solid #2a2d35"}, children=[
                                                html.Div(style={"display": "flex", "justifyContent": "space-between", "marginBottom": "5px"}, children=[
                                                    html.Span("Sous-domaines actifs", style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.75em", "textTransform": "uppercase"}),
                                                    html.Span(id="subdomain-badge", style={"color": "#2980b9", "fontFamily": "monospace", "fontSize": "0.72em"}),
                                                ]),
                                                html.Div(id="subdomain-panel", style={"maxHeight": "120px", "overflowY": "auto"}),
                                            ]),
                                            dmc.Box(style={"padding": "6px 10px"}, children=[
                                                html.Div(style={"display": "flex", "justifyContent": "space-between", "marginBottom": "5px"}, children=[
                                                    html.Span("Typosquatting", style={"color": "#888", "fontFamily": "monospace", "fontSize": "0.75em", "textTransform": "uppercase"}),
                                                    html.Span(id="typosquat-badge", style={"color": "#e74c3c", "fontFamily": "monospace", "fontSize": "0.72em"}),
                                                ]),
                                                html.Div(id="typosquat-panel", style={"maxHeight": "120px", "overflowY": "auto"}),
                                            ]),
                                        ]
                                    ),
                                    service_panel("🦠 Ransomware Monitor", "ransomware-panel", "ransomware-badge", "#6c3483"),
                                    service_panel("📡 Social Monitor", "social-panel", "social-badge", "#1a5276"),
                                ],
                            ),
                        ]
                    ),

                    # ── Panel bas ─────────────────────────────────────────────
                    dmc.Box(
                        style={"margin": "0 20px 20px 20px", "border": "1px solid #2a2d35", "borderRadius": "8px", "overflow": "hidden"},
                        children=[
                            dmc.Box(
                                style={"backgroundColor": "#141517", "padding": "6px 14px", "display": "flex", "alignItems": "center", "gap": "4px", "borderBottom": "1px solid #2a2d35", "flexWrap": "wrap"},
                                children=[
                                    dmc.Text("Détail", size="sm", fw=700, c="cyan", style={"fontFamily": "monospace", "marginRight": "12px"}),
                                    tab_button("CVE", "tab-btn-cve", active=True),
                                    tab_button("DNS / SPF / DMARC", "tab-btn-dns"),
                                    tab_button("Sous-domaines & Typosquatting", "tab-btn-subdomains"),
                                    html.Span("│", style={"color": "#2a2d35", "margin": "0 8px"}),
                                    html.Div(id="filters-cve", style={"display": "flex", "alignItems": "center", "gap": "2px"}, children=[
                                        html.Span("Filtre :", style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.72em", "marginRight": "4px"}),
                                        filter_btn("Tous", "filter-cve-all", active=True),
                                        filter_btn("Critical", "filter-cve-critical"),
                                        filter_btn("Warning", "filter-cve-warning"),
                                    ]),
                                    html.Div(id="filters-dns", style={"display": "none", "alignItems": "center", "gap": "2px"}, children=[
                                        html.Span("Filtre :", style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.72em", "marginRight": "4px"}),
                                        filter_btn("Tous", "filter-dns-all", active=True),
                                        filter_btn("SPF ✗", "filter-dns-spf"),
                                        filter_btn("DMARC ✗", "filter-dns-dmarc"),
                                        filter_btn("p=none", "filter-dns-none"),
                                    ]),
                                    html.Div(id="filters-sub", style={"display": "none", "alignItems": "center", "gap": "2px"}, children=[
                                        html.Span("Filtre :", style={"color": "#555", "fontFamily": "monospace", "fontSize": "0.72em", "marginRight": "4px"}),
                                        filter_btn("Tous", "filter-sub-all", active=True),
                                        filter_btn("Sous-domaines", "filter-sub-subdomains"),
                                        filter_btn("Typosquats", "filter-sub-typo"),
                                    ]),
                                    html.Button("⛶ Agrandir", id="panel-expand-btn", n_clicks=0, style={"marginLeft": "auto", "fontFamily": "monospace", "fontSize": "0.72em", "cursor": "pointer", "padding": "2px 10px", "border": "1px solid #2a2d35", "borderRadius": "4px", "backgroundColor": "transparent", "color": "#555"}),
                                ]
                            ),
                            html.Div(
                                id="panel-bottom-body",
                                style={"maxHeight": "200px", "overflowY": "auto", "backgroundColor": "#1a1b1e", "padding": "10px 12px"},
                                children=[
                                    html.Div(id="tab-cve", style={"display": "block"}, children=[html.Div(id="tab-cve-content")]),
                                    html.Div(id="tab-dns", style={"display": "none"}, children=[html.Div(id="tab-dns-content")]),
                                    html.Div(id="tab-subdomains", style={"display": "none"}, children=[html.Div(id="tab-subdomains-content")]),
                                ]
                            ),
                        ]
                    ),

                    dcc.Store(id="active-filter-cve", data="all"),
                    dcc.Store(id="active-filter-dns", data="all"),
                    dcc.Store(id="active-filter-sub", data="all"),
                    dcc.Store(id="vuln-data-store", data={}),
                    dcc.Interval(id="interval", interval=60 * 1000, n_intervals=0),
                ]
            )
        ],
    )