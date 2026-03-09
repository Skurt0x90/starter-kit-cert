from dash import html, dcc
import dash_mantine_components as dmc
import dash_leaflet as dl


def service_panel(title, list_id, color_header="#c0392b"):
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
                },
                children=[
                    dmc.Text(title, size="sm", fw=700, c="white", style={"fontFamily": "monospace"}),
                ]
            ),
            dmc.Box(
                style={
                    "padding": "8px",
                    "maxHeight": "220px",
                    "overflowY": "auto",
                },
                children=[
                    html.Div(id=list_id),
                ]
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
                    # Header
                    dmc.Box(
                        style={
                            "borderBottom": "1px solid #2a2d35",
                            "padding": "16px 24px",
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

                    # Carte + panels droite
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
                                style={"width": "75%"},
                                children=[
                                    dl.Map(
                                        id="map",
                                        center=[48.0, 10.0],
                                        zoom=4,
                                        style={
                                            "height": "calc(100vh - 420px)",
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
                                ]
                            ),

                            # Panels droite
                            dmc.Box(
                                style={"width": "25%", "display": "flex", "flexDirection": "column"},
                                children=[
                                    service_panel("🔍 Vuln Scanner — CVE critiques", "cve-panel", "#c0392b"),
                                    service_panel("🦠 Ransomware Monitor", "ransomware-panel", "#6c3483"),
                                    service_panel("📡 Social Monitor", "social-panel", "#1a5276"),
                                ],
                            ),
                        ]
                    ),

                    # Panel bas — détail CVE
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
                                    dmc.Text(
                                        "Détail des CVE critiques",
                                        size="sm", fw=700, c="cyan",
                                        style={"fontFamily": "monospace"},
                                    ),
                                ]
                            ),
                            dmc.Box(
                                style={
                                    "padding": "12px",
                                    "maxHeight": "220px",
                                    "overflowY": "auto",
                                    "backgroundColor": "#1a1b1e",
                                },
                                children=[html.Div(id="cve-detail-panel")],
                            ),
                        ]
                    ),

                    # Interval
                    dcc.Interval(id="interval", interval=60 * 1000, n_intervals=0),
                ]
            )
        ],
    )