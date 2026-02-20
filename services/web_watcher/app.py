import logging
import os
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

app = Flask(__name__)
scheduler = BackgroundScheduler()

@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/api/data", methods=["GET"])
def get_data():
    return jsonify({"message": "Données de surveillance à venir"}), 200

if __name__ == "__main__":
    scheduler.add_job(run_watcher_cycle, "interval", minutes=utils.SCHEDULE_INTERVAL_MINUTES)
    scheduler.start()
    run_watcher_cycle()  # premier cycle immédiat
    app.run(host=os.getenv("FLASK_HOST", "127.0.0.1"), port=int(os.getenv("FLASK_PORT", 5001)))