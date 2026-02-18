import unittest
from unittest.mock import patch, MagicMock
import requests
from web_watcher.watcher import is_site_up 
from web_watcher.config import REQUEST_TIMEOUT

class TestIsSiteUp(unittest.TestCase):

    @patch('requests.get')
    def test_site_up_with_2xx_code(self, mock_get):
        # Simule une réponse avec un code 200 (OK)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = is_site_up("example.com")
        self.assertTrue(result)

    @patch('requests.get')
    def test_site_up_with_3xx_code(self, mock_get):
        # Simule une réponse avec un code 301 (redirection)
        mock_response = MagicMock()
        mock_response.status_code = 301
        mock_get.return_value = mock_response

        result = is_site_up("example.com")
        self.assertTrue(result)

    @patch('requests.get')
    def test_site_down_with_4xx_code(self, mock_get):
        # Simule une réponse avec un code 404 (Not Found)
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = is_site_up("example.com")
        self.assertFalse(result)

    @patch('requests.get')
    def test_site_down_with_5xx_code(self, mock_get):
        # Simule une réponse avec un code 500 (Internal Server Error)
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = is_site_up("example.com")
        self.assertFalse(result)

    @patch('requests.get')
    def test_request_exception(self, mock_get):
        # Simule une exception (timeout, connexion refusée, etc.)
        mock_get.side_effect = requests.exceptions.RequestException("Timeout")

        result = is_site_up("example.com")
        self.assertTrue(result)  # Selon ta logique, une exception retourne True

if __name__ == '__main__':
    unittest.main()
