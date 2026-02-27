import logging
import os
import json
from flask import Flask, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
from web_watcher.watcher import run_watcher_cycle
from web_watcher import utils

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(),             # console
        logging.FileHandler("watcher.log")  # fichier
    ]
)

logger = logging.getLogger(__name__)

app = Flask(__name__)
scheduler = BackgroundScheduler()

@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/api/data", methods=["GET"])
def get_datas():
    logger.info(f"Output pat: {utils.OUTPUT_FILE}")
    try:
        with open(utils.OUTPUT_FILE, "r") as f:
            return jsonify(json.load(f)), 200
    except FileNotFoundError:
        return jsonify({"error": "Pas encore de données, premier cycle en cours"}), 503
    
if __name__ == "__main__":
    scheduler.add_job(run_watcher_cycle, "interval", minutes=utils.SCHEDULE_INTERVAL_MINUTES)
    scheduler.start()
    run_watcher_cycle()  # premier cycle immédiat
    app.run(host=os.getenv("FLASK_HOST", "127.0.0.1"), port=int(os.getenv("FLASK_PORT", 5001)))