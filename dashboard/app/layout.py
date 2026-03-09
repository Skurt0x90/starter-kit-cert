from dash import html, dcc
import dash_mantine_components as dmc
import dash_leaflet as dl


def service_panel(title, list_id, badge_id, color_header="#c0392b"):
    return dmc.Box(
        style={
            "backgroundColor": "#1a1b1e",
            "border": "1px solid #2a2d35",
            "borderRadius": "8px",
            "marginBottom": "12px",
            "overflow": "hidden",
        },
        children=[
            dmc.Box(
                style={
                    "backgroundColor": color_header,
                    "padding": "8px 14px",
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
                style={
                    "padding": "8px",
                    "maxHeight": "180px",
                    "overflowY": "auto",
                },
                children=[html.Div(id=list_id)],
            ),
        ]
    )


def create_layout():
    return dmc.MantineProvider(
        theme={"colorScheme": "dark"},
        children=[
            dmc.Box(
                style={
                    "backgroundColor": "#1a1b1e",
                    "minHeight": "100vh",
                    "display": "flex",
                    "flexDirection": "column",
                },
                children=[

                    # ── Header ──────────────────────────────────────────────
                    dmc.Box(
                        style={
                            "borderBottom": "1px solid #2a2d35",
                            "padding": "12px 24px",
                            "display": "flex",
                            "justifyContent": "space-between",
                            "alignItems": "center",
                            "backgroundColor": "#141517",
                        },
                        children=[
                            dmc.Text(
                                "CERT - Skurt0x90",
                                size="xl", fw=700, c="cyan",
                                style={"letterSpacing": "0.1em", "fontFamily": "monospace"},
                            ),
                            html.Div(id="global-counters", style={"display": "flex", "gap": "12px", "alignItems": "center"}),
                            html.Div(id="service-indicators", style={"display": "flex", "gap": "16px", "alignItems": "center"}),
                            html.Span(
                                id="last-update",
                                style={
                                    "fontSize": "0.75rem",
                                    "color": "#888",
                                    "fontFamily": "monospace",
                                    "border": "1px solid #2a2d35",
                                    "padding": "2px 8px",
                                    "borderRadius": "4px",
                                }
                            ),
                        ],
                    ),

                    # ── Carte + panels droite ────────────────────────────────
                    dmc.Box(
                        style={
                            "display": "flex",
                            "flexDirection": "row",
                            "padding": "20px",
                            "gap": "16px",
                            "flex": "1",
                        },
                        children=[

                            # Carte
                            dmc.Box(
                                style={"width": "75%", "position": "relative"},
                                children=[
                                    dl.Map(
                                        id="map",
                                        center=[48.0, 10.0],
                                        zoom=4,
                                        style={
                                            "height": "calc(100vh - 250px)",
                                            "width": "100%",
                                            "borderRadius": "8px",
                                            "border": "1px solid #2a2d35",
                                        },
                                        children=[
                                            dl.TileLayer(
                                                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
                                                attribution='&copy; <a href="https://carto.com/">CARTO</a>',
                                            ),
                                            dl.LayerGroup(id="markers"),
                                        ],
                                    ),

                                    # Bouton légende flottant
                                    html.Div(
                                        id="legend-btn",
                                        n_clicks=0,
                                        style={
                                            "position": "absolute",
                                            "bottom": "20px",
                                            "left": "20px",
                                            "zIndex": "1000",
                                            "backgroundColor": "#141517",
                                            "border": "1px solid #2a2d35",
                                            "borderRadius": "6px",
                                            "padding": "6px 12px",
                                            "cursor": "pointer",
                                            "color": "#aaa",
                                            "fontFamily": "monospace",
                                            "fontSize": "0.75em",
                                        },
                                        children="⬤ Légende",
                                    ),

                                    # Légende (toggle)
                                    html.Div(
                                        id="legend-box",
                                        style={
                                            "display": "none",
                                            "position": "absolute",
                                            "bottom": "55px",
                                            "left": "20px",
                                            "zIndex": "1000",
                                            "backgroundColor": "#141517",
                                            "border": "1px solid #2a2d35",
                                            "borderRadius": "8px",
                                            "padding": "12px 16px",
                                            "fontFamily": "monospace",
                                            "fontSize": "0.8em",
                                            "minWidth": "240px",
                                        },
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
                                style={"width": "25%", "display": "flex", "flexDirection": "column"},
                                children=[
                                    service_panel("🔍 Vuln Scanner", "cve-panel", "cve-badge", "#c0392b"),
                                    service_panel("🦠 Ransomware Monitor", "ransomware-panel", "ransomware-badge", "#6c3483"),
                                    service_panel("📡 Social Monitor", "social-panel", "social-badge", "#1a5276"),
                                ],
                            ),
                        ]
                    ),

                    # ── Panel bas — détail CVE ───────────────────────────────
                    dmc.Box(
                        style={
                            "margin": "0 20px 20px 20px",
                            "border": "1px solid #2a2d35",
                            "borderRadius": "8px",
                            "overflow": "hidden",
                        },
                        children=[
                            dmc.Box(
                                style={"backgroundColor": "#141517", "padding": "8px 14px"},
                                children=[
                                    dmc.Text("Détail des alertes CVE", size="sm", fw=700, c="cyan", style={"fontFamily": "monospace"}),
                                ]
                            ),
                            dmc.Box(
                                style={
                                    "padding": "12px",
                                    "maxHeight": "200px",
                                    "overflowY": "auto",
                                    "backgroundColor": "#1a1b1e",
                                },
                                children=[html.Div(id="cve-detail-panel")],
                            ),
                        ]
                    ),

                    dcc.Interval(id="interval", interval=60 * 1000, n_intervals=0),
                ]
            )
        ],
    )