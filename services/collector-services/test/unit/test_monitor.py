import pytest
from unittest.mock import patch
from app.tasks.monitor import check_site_health

def test_check_site_health_up():
    # Mock de requests.get pour simuler une réponse HTTP 200
    with patch("app.tasks.monitor.requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        assert check_site_health("google.com") is True
