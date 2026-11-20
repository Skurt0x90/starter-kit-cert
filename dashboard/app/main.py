from dash import Dash, _dash_renderer
from app.layout import create_layout
import app.callbacks 


_dash_renderer._set_react_version("18.2.0") 

app = Dash(__name__, title="THREAT-RADAR", suppress_callback_exceptions=True)
app.layout = create_layout()

server = app.server

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8050, debug=False)