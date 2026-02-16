import requests
import socket
import ssl
from datetime import datetime

def check_site_health(url):
    try:
        response = requests.get(f"https://{url}", timeout=10)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def check_site_response_time(url):
    response = requests.get(f"https://{url}")
    return response.elapsed.total_seconds()

def check_site_ssl_expiration(url):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((url, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=url) as ssock:
                cert = ssock.getpeercert()

                expiry_date_str = cert['notAfter']
                expiry_date = datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")
                return expiry_date
    except Exception as e:
        print(f"Erreur lors de la récupération du certificat SSL : {e}")
        return None

def check_site_title_changed(url, title):
    return False


