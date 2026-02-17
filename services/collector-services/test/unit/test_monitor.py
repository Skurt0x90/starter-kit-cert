import pytest
import requests
from unittest.mock import patch
from app.tasks.monitor import check_site_health

def test_check_site_health_up():
    # Mock de requests.get pour simuler une réponse HTTP 200
    with patch("app.tasks.monitor.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        assert check_site_health("google.com") is True


import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from app.tasks.monitor import (
    check_site_health,
    check_site_response_time,
    check_site_ssl_expiration,
    check_site_title_changed
)

# --- Tests pour check_site_health ---
def test_check_site_health_up():
    with patch("app.tasks.monitor.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        assert check_site_health("google.com") is True

def test_check_site_health_down():
    with patch("app.tasks.monitor.requests.get") as mock_get:
        # Utilisez une exception de type `requests.exceptions.RequestException`
        mock_get.side_effect = requests.exceptions.RequestException("Connection refused")
        assert check_site_health("google.com") is False

def test_check_site_health_non_200():
    with patch("app.tasks.monitor.requests.get") as mock_get:
        mock_get.return_value.status_code = 500
        assert check_site_health("google.com") is False

# --- Tests pour check_site_response_time ---
def test_check_site_response_time():
    with patch("app.tasks.monitor.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.elapsed.total_seconds.return_value = 2.5
        mock_get.return_value = mock_response
        assert check_site_response_time("google.com") == 2.5

# --- Tests pour check_site_ssl_expiration ---
def test_check_site_ssl_expiration_success():
    mock_cert = {
        'notAfter': 'Dec 31 23:59:59 2025 GMT'
    }
    with patch("app.tasks.monitor.socket.create_connection") as mock_socket, \
         patch("app.tasks.monitor.ssl.create_default_context") as mock_ssl:
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = mock_cert
        mock_ssl.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssock
        result = check_site_ssl_expiration("google.com")
        assert result == datetime.strptime('Dec 31 23:59:59 2025 GMT', "%b %d %H:%M:%S %Y %Z")

def test_check_site_ssl_expiration_failure():
    with patch("app.tasks.monitor.socket.create_connection") as mock_socket:
        mock_socket.side_effect = Exception("Connection error")
        assert check_site_ssl_expiration("google.com") is None

# --- Tests pour check_site_title_changed ---
def test_check_site_title_changed_true():
    with patch("app.tasks.monitor.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><head><title>Nouveau Titre</title></head></html>"
        mock_get.return_value = mock_response
        assert check_site_title_changed("google.com", "Ancien Titre") is True

def test_check_site_title_changed_false():
    with patch("app.tasks.monitor.requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><head><title>Ancien Titre</title></head></html>"
        mock_get.return_value = mock_response
        assert check_site_title_changed("google.com", "Ancien Titre") is False

def test_check_site_title_changed_exception():
    with patch("app.tasks.monitor.requests.get") as mock_get:
        # Utilisez une exception de type `requests.exceptions.RequestException`
        mock_get.side_effect = requests.exceptions.RequestException("Connection refused")
        assert check_site_title_changed("google.com", "Ancien Titre") is False
