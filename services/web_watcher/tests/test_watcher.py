import unittest
from unittest.mock import patch, MagicMock, mock_open
from datetime import date, timedelta
import requests
from web_watcher.watcher import load_domains, is_site_up, check_ssl_expiry, check_response_time, run_watcher_cycle


class TestLoadDomains(unittest.TestCase):

    def test_nominal(self):
        fake_file = "example.com, 2.3522, 48.8566, Paris\n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["domain"], "example.com")
        self.assertEqual(result[0]["longitude"], 2.3522)
        self.assertEqual(result[0]["latitude"], 48.8566)
        self.assertEqual(result[0]["label"], "Paris")

    def test_ignore_empty_lines(self):
        fake_file = "\n\nexample.com, 2.3522, 48.8566, Paris\n\n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(len(result), 1)

    def test_ignore_comment_lines(self):
        fake_file = "# commentaire\nexample.com, 2.3522, 48.8566, Paris\n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(len(result), 1)

    def test_multiple_domains(self):
        fake_file = (
            "example.com, 2.3522, 48.8566, Paris\n"
            "google.com, -0.1276, 51.5074, London\n"
        )
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[1]["domain"], "google.com")

    def test_strips_whitespace(self):
        fake_file = "  example.com  , 2.3522, 48.8566,   Paris   \n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(result[0]["domain"], "example.com")
        self.assertEqual(result[0]["label"], "Paris")

    def test_empty_file(self):
        with patch("builtins.open", mock_open(read_data="")):
            result = load_domains("fake_path.txt")
        self.assertEqual(result, [])

    def test_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_domains("fichier_inexistant.txt")

    def test_malformed_line(self):
        fake_file = "example.com, 2.3522\n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            with self.assertRaises(ValueError):
                load_domains("fake_path.txt")


class TestIsSiteUp(unittest.TestCase):

    @patch("requests.get")
    def test_site_up_200(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        self.assertTrue(is_site_up("example.com"))

    @patch("requests.get")
    def test_site_up_301(self, mock_get):
        mock_get.return_value = MagicMock(status_code=301)
        self.assertTrue(is_site_up("example.com"))

    @patch("requests.get")
    def test_site_down_404(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        self.assertFalse(is_site_up("example.com"))

    @patch("requests.get")
    def test_site_down_500(self, mock_get):
        mock_get.return_value = MagicMock(status_code=500)
        self.assertFalse(is_site_up("example.com"))

    @patch("requests.get")
    def test_request_exception(self, mock_get):
        mock_get.side_effect = requests.exceptions.RequestException("Timeout")
        self.assertTrue(is_site_up("example.com"))


class TestCheckSslExpiry(unittest.TestCase):

    def _mock_ssl(self, mock_ctx, expiry_date):
        mock_conn = MagicMock()
        mock_conn.getpeercert.return_value = {
            "notAfter": expiry_date.strftime('%b %d %H:%M:%S %Y GMT')
        }
        mock_ctx.return_value.wrap_socket.return_value = mock_conn

    @patch("web_watcher.watcher.socket.socket")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_ssl_valid(self, mock_ctx, mock_sock):
        self._mock_ssl(mock_ctx, date.today() + timedelta(days=60))
        self.assertTrue(check_ssl_expiry("example.com"))

    @patch("web_watcher.watcher.socket.socket")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_ssl_expiring_soon(self, mock_ctx, mock_sock):
        self._mock_ssl(mock_ctx, date.today() + timedelta(days=10))
        self.assertFalse(check_ssl_expiry("example.com"))

    @patch("web_watcher.watcher.socket.socket")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_ssl_exactly_30_days(self, mock_ctx, mock_sock):
        self._mock_ssl(mock_ctx, date.today() + timedelta(days=30))
        self.assertTrue(check_ssl_expiry("example.com"))

    @patch("web_watcher.watcher.socket.socket")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_ssl_expired(self, mock_ctx, mock_sock):
        self._mock_ssl(mock_ctx, date.today() - timedelta(days=5))
        self.assertFalse(check_ssl_expiry("example.com"))

    @patch("web_watcher.watcher.socket.socket")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_timeout(self, mock_ctx, mock_sock):
        mock_ctx.return_value.wrap_socket.side_effect = TimeoutError()
        self.assertTrue(check_ssl_expiry("example.com"))

    @patch("web_watcher.watcher.socket.socket")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_connection_error(self, mock_ctx, mock_sock):
        mock_ctx.return_value.wrap_socket.side_effect = Exception("Connection refused")
        self.assertTrue(check_ssl_expiry("example.com"))


class TestCheckResponseTime(unittest.TestCase):

    @patch("web_watcher.watcher.requests.get")
    def test_response_ok(self, mock_get):
        mock_response = MagicMock()
        mock_response.elapsed.total_seconds.return_value = 0.5
        mock_get.return_value = mock_response
        self.assertEqual(check_response_time("example.com"), "OK")

    @patch("web_watcher.watcher.requests.get")
    def test_response_def(self, mock_get):
        mock_response = MagicMock()
        mock_response.elapsed.total_seconds.return_value = 1.5
        mock_get.return_value = mock_response
        self.assertEqual(check_response_time("example.com"), "DEF")

    @patch("web_watcher.watcher.requests.get")
    def test_response_ko(self, mock_get):
        mock_response = MagicMock()
        mock_response.elapsed.total_seconds.return_value = 3.0
        mock_get.return_value = mock_response
        self.assertEqual(check_response_time("example.com"), "KO")

    @patch("web_watcher.watcher.requests.get")
    def test_response_connection_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("Connection aborted")
        result = check_response_time("example.com")
        self.assertEqual(result, "KO")

class TestRunWatcherCycle(unittest.TestCase):

    def setUp(self):
        self.fake_domains = [
            {"domain": "example.com", "longitude": 2.35, "latitude": 48.85, "label": "Paris"},
            {"domain": "google.com",  "longitude": -0.12, "latitude": 51.50, "label": "London"},
        ]

    @patch("web_watcher.watcher.check_response_time", return_value="OK")
    @patch("web_watcher.watcher.check_ssl_expiry", return_value=True)
    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", return_value=True)
    @patch("web_watcher.watcher.load_domains")
    def test_nominal(self, mock_load, mock_is_up, mock_file, mock_path, mock_json, mock_ssl, mock_rt):
        mock_load.return_value = self.fake_domains
        run_watcher_cycle()
        mock_load.assert_called_once()
        self.assertEqual(mock_is_up.call_count, 2)
        mock_json.assert_called_once()

    @patch("web_watcher.watcher.check_response_time", return_value="OK")
    @patch("web_watcher.watcher.check_ssl_expiry", return_value=True)
    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", return_value=True)
    @patch("web_watcher.watcher.load_domains", return_value=[])
    def test_empty_domains(self, mock_load, mock_is_up, mock_file, mock_path, mock_json, mock_ssl, mock_rt):
        run_watcher_cycle()
        mock_is_up.assert_not_called()
        written_data = mock_json.call_args[0][0]
        self.assertEqual(written_data["sites"], [])

    @patch("web_watcher.watcher.check_response_time", return_value="OK")
    @patch("web_watcher.watcher.check_ssl_expiry", return_value=True)
    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", return_value=False)
    @patch("web_watcher.watcher.load_domains")
    def test_site_down(self, mock_load, mock_is_up, mock_file, mock_path, mock_json, mock_ssl, mock_rt):
        mock_load.return_value = [self.fake_domains[0]]
        run_watcher_cycle()
        written_data = mock_json.call_args[0][0]
        self.assertFalse(written_data["sites"][0]["site_up"])

    @patch("web_watcher.watcher.check_response_time", return_value="OK")
    @patch("web_watcher.watcher.check_ssl_expiry", return_value=True)
    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", return_value=True)
    @patch("web_watcher.watcher.load_domains")
    def test_output_structure(self, mock_load, mock_is_up, mock_file, mock_path, mock_json, mock_ssl, mock_rt):
        mock_load.return_value = [self.fake_domains[0]]
        run_watcher_cycle()
        written_data = mock_json.call_args[0][0]
        self.assertIn("last_run",      written_data)
        self.assertIn("sites",         written_data)
        self.assertIn("domain",        written_data["sites"][0])
        self.assertIn("site_up",       written_data["sites"][0])
        self.assertIn("ssl_ok",        written_data["sites"][0])
        self.assertIn("response_time", written_data["sites"][0])
        self.assertIn("checked_at",    written_data["sites"][0])

    @patch("web_watcher.watcher.check_response_time", side_effect=["OK", "KO"])
    @patch("web_watcher.watcher.check_ssl_expiry", return_value=True)
    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", side_effect=[True, False])
    @patch("web_watcher.watcher.load_domains")
    def test_mixed_up_down(self, mock_load, mock_is_up, mock_file, mock_path, mock_json, mock_ssl, mock_rt):
        mock_load.return_value = self.fake_domains
        run_watcher_cycle()
        written_data = mock_json.call_args[0][0]
        self.assertTrue(written_data["sites"][0]["site_up"])
        self.assertFalse(written_data["sites"][1]["site_up"])
        self.assertEqual(written_data["sites"][0]["response_time"], "OK")
        self.assertEqual(written_data["sites"][1]["response_time"], "KO")


if __name__ == "__main__":
    unittest.main()