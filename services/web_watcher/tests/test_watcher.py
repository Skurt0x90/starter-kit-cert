import unittest
from unittest.mock import patch, MagicMock, mock_open, call
import requests
from web_watcher.watcher import is_site_up, load_domains, run_watcher_cycle
from web_watcher import config

class TestWatcher(unittest.TestCase):

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

    def test_nominal(self):
        """Ligne valide standard"""
        fake_file = "example.com, 2.3522, 48.8566, Paris\n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["domain"], "example.com")
        self.assertEqual(result[0]["longitude"], 2.3522)
        self.assertEqual(result[0]["latitude"], 48.8566)
        self.assertEqual(result[0]["label"], "Paris")

    def test_ignore_empty_lines(self):
        """Les lignes vides sont ignorées"""
        fake_file = "\n\nexample.com, 2.3522, 48.8566, Paris\n\n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(len(result), 1)

    def test_ignore_comment_lines(self):
        """Les lignes commençant par # sont ignorées"""
        fake_file = "# ceci est un commentaire\nexample.com, 2.3522, 48.8566, Paris\n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["domain"], "example.com")

    def test_multiple_domains(self):
        """Plusieurs domaines valides"""
        fake_file = (
            "example.com, 2.3522, 48.8566, Paris\n"
            "google.com, -0.1276, 51.5074, London\n"
        )
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[1]["domain"], "google.com")
        self.assertEqual(result[1]["label"], "London")

    def test_strips_whitespace(self):
        """Les espaces autour du domaine et du label sont supprimés"""
        fake_file = "  example.com  , 2.3522, 48.8566,   Paris   \n"
        with patch("builtins.open", mock_open(read_data=fake_file)):
            result = load_domains("fake_path.txt")
        self.assertEqual(result[0]["domain"], "example.com")
        self.assertEqual(result[0]["label"], "Paris")

    def test_file_not_found(self):
        """Lève une exception si le fichier n'existe pas"""
        with self.assertRaises(FileNotFoundError):
            load_domains("fichier_inexistant.txt")

    def test_malformed_line_raises_error(self):
        """Lève une exception si une ligne n'a pas 4 champs"""
        fake_file = "example.com, 2.3522\n"  # manque lat et label
        with patch("builtins.open", mock_open(read_data=fake_file)):
            with self.assertRaises(ValueError):
                load_domains("fake_path.txt")

    def test_empty_file(self):
        """Un fichier vide retourne une liste vide"""
        with patch("builtins.open", mock_open(read_data="")):
            result = load_domains("fake_path.txt")
        self.assertEqual(result, [])


    def setUp(self):
        self.fake_domains = [
            {"domain": "example.com", "longitude": 2.35, "latitude": 48.85, "label": "Paris"},
            {"domain": "google.com",  "longitude": -0.12, "latitude": 51.50, "label": "London"},
        ]

    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", return_value=True)
    @patch("web_watcher.watcher.load_domains")
    def test_nominal(self, mock_load, mock_is_up, mock_file, mock_path, mock_json):
        """Cycle nominal : 2 domaines up, fichier écrit"""
        mock_load.return_value = self.fake_domains

        run_watcher_cycle()

        # load_domains appelé avec le bon fichier
        mock_load.assert_called_once()

        # is_site_up appelé pour chaque domaine
        self.assertEqual(mock_is_up.call_count, 2)
        mock_is_up.assert_any_call("example.com")
        mock_is_up.assert_any_call("google.com")

        # Le fichier de sortie est bien ouvert en écriture
        mock_file.assert_called_once()

        # json.dump appelé une fois
        mock_json.assert_called_once()

    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", return_value=True)
    @patch("web_watcher.watcher.load_domains", return_value=[])
    def test_empty_domains(self, mock_load, mock_is_up, mock_file, mock_path, mock_json):
        """Aucun domaine : is_site_up jamais appelé, fichier quand même écrit"""
        run_watcher_cycle()

        mock_is_up.assert_not_called()
        mock_json.assert_called_once()

        # La liste sites doit être vide
        written_data = mock_json.call_args[0][0]
        self.assertEqual(written_data["sites"], [])

    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", return_value=False)
    @patch("web_watcher.watcher.load_domains")
    def test_site_down(self, mock_load, mock_is_up, mock_file, mock_path, mock_json):
        """Un domaine down : site_up=False dans le résultat"""
        mock_load.return_value = [self.fake_domains[0]]

        run_watcher_cycle()

        written_data = mock_json.call_args[0][0]
        self.assertFalse(written_data["sites"][0]["site_up"])

    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up", return_value=True)
    @patch("web_watcher.watcher.load_domains")
    def test_output_structure(self, mock_load, mock_is_up, mock_file, mock_path, mock_json):
        """Vérifie la structure du JSON écrit : last_run + sites"""
        mock_load.return_value = [self.fake_domains[0]]

        run_watcher_cycle()

        written_data = mock_json.call_args[0][0]
        self.assertIn("last_run", written_data)
        self.assertIn("sites", written_data)
        self.assertIn("domain",     written_data["sites"][0])
        self.assertIn("site_up",    written_data["sites"][0])
        self.assertIn("checked_at", written_data["sites"][0])

    @patch("web_watcher.watcher.json.dump")
    @patch("web_watcher.watcher.Path")
    @patch("builtins.open", new_callable=mock_open)
    @patch("web_watcher.watcher.is_site_up")
    @patch("web_watcher.watcher.load_domains")
    def test_mixed_up_down(self, mock_load, mock_is_up, mock_file, mock_path, mock_json):
        """Un domaine up, un domaine down"""
        mock_load.return_value = self.fake_domains
        mock_is_up.side_effect = [True, False]

        run_watcher_cycle()

        written_data = mock_json.call_args[0][0]
        self.assertTrue(written_data["sites"][0]["site_up"])
        self.assertFalse(written_data["sites"][1]["site_up"])

if __name__ == '__main__':
    unittest.main()
