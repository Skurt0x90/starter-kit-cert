from flask import Blueprint, jsonify
from app.tasks.monitor import check_site_health, check_site_response_time, check_site_ssl_expiration
import requests

bp = Blueprint("monitor", __name__)

@bp.route("/monitor/<string:url>", methods=["GET"])
def monitor_site(url):
    isAlive = check_site_health(url)
    data = {url:{'isAlive':isAlive}}
    if(isAlive):
        responseTime = check_site_response_time(url)
        sslExpiration = check_site_ssl_expiration(url)
    data = {url:{'isAlive':isAlive}}
    return jsonify(data)
