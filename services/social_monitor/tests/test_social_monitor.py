import json
import os
import tempfile
import unittest
from unittest.mock import patch
import requests
from social_monitor import utils
from social_monitor.social_monitor import build_alerts, send_alerts, run_cycle

ITEM = {"source": "rss", "channel": "Bleeping", "title": "Titre", "content": "contenu", "url": "https://x/1",
        "matched_keywords": ["ransomware"], "matched_members": ["acme"], "level": "CRITICAL"}


class TestBuildAlerts(unittest.TestCase):

    def test_format(self):
        alert = build_alerts([ITEM])["Bleeping"][0]
        self.assertEqual(alert["level"], "CRITICAL")
        self.assertIn("[RSS] Titre", alert["message"])
        self.assertIn("ransomware, acme", alert["message"])
        self.assertIn("URL: https://x/1", alert["message"])

    def test_sans_titre_utilise_le_contenu(self):
        item = {**ITEM, "title": None, "content": "c" * 300}
        self.assertIn("c" * 120, build_alerts([item])["Bleeping"][0]["message"])
        self.assertNotIn("c" * 121, build_alerts([item])["Bleeping"][0]["message"])

    def test_canal_inconnu(self):
        item = {k: v for k, v in ITEM.items() if k != "channel"}
        self.assertIn("unknown", build_alerts([item]))

    def test_groupe_par_canal(self):
        alerts = build_alerts([ITEM, ITEM, {**ITEM, "channel": "Autre"}])
        self.assertEqual(len(alerts["Bleeping"]), 2)
        self.assertEqual(len(alerts["Autre"]), 1)

    def test_aucun_item(self):
        self.assertEqual(build_alerts([]), {})


class TestSendAlerts(unittest.TestCase):

    @patch("social_monitor.social_monitor.requests.post")
    def test_rien_a_envoyer(self, mock_post):
        send_alerts({})
        mock_post.assert_not_called()

    @patch("social_monitor.social_monitor.requests.post")
    def test_envoi(self, mock_post):
        alerts = {"c": [{"level": "WARNING", "message": "m"}]}
        send_alerts(alerts)
        self.assertEqual(mock_post.call_args.kwargs["json"], {"service": "social_monitor", "alerts": alerts})

    @patch("social_monitor.social_monitor.requests.post", side_effect=requests.exceptions.ConnectionError())
    def test_alert_service_injoignable(self, _):
        send_alerts({"c": [{"level": "WARNING", "message": "m"}]})


class TestRunCycle(unittest.TestCase):

    def _cycle(self, matched):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            with patch.object(utils, "OUTPUT_FILE", out), \
                 patch("social_monitor.social_monitor.collect_rss", return_value=[{"a": 1}]), \
                 patch("social_monitor.social_monitor.collect_telegram", return_value=[{"b": 2}]), \
                 patch("social_monitor.social_monitor.correlate", return_value=matched) as mock_corr, \
                 patch("social_monitor.social_monitor.send_alerts") as mock_send:
                run_cycle()
            with open(out) as f:
                data = json.load(f)
        return data, mock_corr, mock_send

    def test_cycle_avec_correspondances(self):
        data, mock_corr, mock_send = self._cycle([ITEM])
        mock_corr.assert_called_once_with([{"a": 1}, {"b": 2}])
        self.assertEqual(data["items"], [ITEM])
        self.assertIn("last_run", data)
        self.assertIn("Bleeping", mock_send.call_args[0][0])

    def test_cycle_sans_correspondance(self):
        data, _, mock_send = self._cycle([])
        self.assertEqual(data["items"], [])
        mock_send.assert_not_called()


if __name__ == "__main__":
    unittest.main()