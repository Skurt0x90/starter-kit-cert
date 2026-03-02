from dash import html, dcc
import dash_mantine_components as dmc
import dash_leaflet as dl

def create_layout():
    return dmc.MantineProvider(
        theme={"colorScheme": "dark"},
        children=[
            dmc.Box(
                style={
                    "backgroundColor": "#1a1b1e",
                    "minHeight": "100vh",
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
                    # Carte
                    dmc.Box(
                        style={"padding": "20px", "width": "75%"},
                        children=[
                            dl.Map(
                                id="map",
                                center=[48.0, 10.0],
                                zoom=4,
                                style={
                                    "height": "calc(100vh - 120px)",
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
                    # Interval
                    dcc.Interval(
                        id="interval",
                        interval=60 * 1000,
                        n_intervals=0,
                    ),
                ]
            )
        ],
    )