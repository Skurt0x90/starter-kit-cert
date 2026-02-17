from flask import Blueprint, jsonify, request
from app.tasks.monitor import check_site_health, check_site_response_time, check_site_ssl_expiration, check_site_title_changed

bp = Blueprint("monitor", __name__)

@bp.route("/monitor/<string:url>", methods=["GET"])
def monitor_site(url):
    expected_title = request.args.get('expected_title', None)
    is_alive = check_site_health(url)
    data = {url:{'is_alive':is_alive}}
    if(is_alive):
        response_time = check_site_response_time(url)
        ssl_expiration = check_site_ssl_expiration(url)
        title_changed = check_site_title_changed(url, expected_title)
        data[url]['response_time'] = response_time
        data[url]['ssl_expiration'] = ssl_expiration
        data[url]['title_changed'] = title_changed
    return jsonify(data)
