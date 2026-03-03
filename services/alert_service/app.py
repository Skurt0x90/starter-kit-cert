import logging
import os
import json
from flask import Flask, jsonify, request
from alert_service import utils, alert_services

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(),             # console
        logging.FileHandler("alert.log")  # fichier
    ]
)

logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/api/data", methods=["GET"])
def get_datas():
    try:
        with open(utils.OUTPUT_FILE, "r") as f:
            return jsonify(json.load(f)), 200
    except FileNotFoundError:
        return jsonify({"error": "Pas encore de données, premier cycle en cours"}), 503
    
@app.route("/api/alert", methods=["POST"])
def post_alert():
    payload = request.get_json(force=True)
    champs_requis = {"service", "alerts"}
    champs_manquants = champs_requis - payload.keys()
    if champs_manquants:
        return jsonify({"error": f"Champs manquants : {champs_manquants}"}), 400
    result = process_alert(payload)

    return jsonify(result), 200


if __name__ == "__main__":
    app.run(host=os.getenv("FLASK_HOST", "127.0.0.1"), port=int(os.getenv("FLASK_PORT", 5005)))