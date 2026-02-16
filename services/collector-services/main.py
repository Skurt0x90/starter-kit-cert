#Point d'entrée Flask
from flask import Flask
from app.routes import monitor  # Importez le nouveau routeur

app = Flask(__name__)
app.register_blueprint(monitor.bp)  

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)