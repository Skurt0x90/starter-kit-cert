from flask import Flask, jsonify
from apscheduler.schedulers.background import BackgroundScheduler
from watcher import run_watcher_cycle
import config

app = Flask(__name__)
scheduler = BackgroundScheduler()

@app.route("/health")
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    scheduler.add_job(run_watcher_cycle, "interval", minutes=config.SCHEDULE_INTERVAL_MINUTES)
    scheduler.start()
    run_watcher_cycle()  # premier cycle immédiat
    app.run(host="0.0.0.0", port=5001)