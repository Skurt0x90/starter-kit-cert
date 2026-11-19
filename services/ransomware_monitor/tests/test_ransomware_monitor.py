import json
import os
import tempfile
import unittest
from unittest.mock import patch
import requests
from ransomware_monitor import utils
from ransomware_monitor.ransomware_monitor import build_alerts, send_alerts, run_cycle

MATCH = {"victime": "Acme", "acteur": "lockbit", "date": "19-11-2026", "source": "ransomlive"}


class TestBuildAlerts(unittest.TestCase):

    def test_alerte_critical_par_victime(self):
        alerts = build_alerts([MATCH])
        self.assertEqual(alerts, {"Acme": [{"level": "CRITICAL", "message": "lockbit revendique ransomware sur Acme. Source: ransomlive"}]})

    def test_aucune_victime(self):
        self.assertEqual(build_alerts([]), {})


class TestSendAlerts(unittest.TestCase):

    @patch("ransomware_monitor.ransomware_monitor.requests.post")
    def test_rien_a_envoyer(self, mock_post):
        send_alerts({})
        mock_post.assert_not_called()

    @patch("ransomware_monitor.ransomware_monitor.requests.post")
    def test_envoi(self, mock_post):
        alerts = build_alerts([MATCH])
        send_alerts(alerts)
        self.assertEqual(mock_post.call_args.kwargs["json"], {"service": "ransomware_monitor", "alerts": alerts})

    @patch("ransomware_monitor.ransomware_monitor.requests.post", side_effect=requests.exceptions.ConnectionError())
    def test_alert_service_injoignable(self, _):
        send_alerts(build_alerts([MATCH]))


class TestRunCycle(unittest.TestCase):

    def _cycle(self, matches):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            with patch.object(utils, "OUTPUT_FILE", out), \
                 patch("ransomware_monitor.ransomware_monitor.correlate", return_value=matches), \
                 patch("ransomware_monitor.ransomware_monitor.send_alerts") as mock_send:
                run_cycle()
            with open(out) as f:
                data = json.load(f)
        return data, mock_send

    def test_avec_correspondance(self):
        data, mock_send = self._cycle([MATCH])
        self.assertEqual(data["ransomware"], [MATCH])
        self.assertIn("last_run", data)
        self.assertIn("Acme", mock_send.call_args[0][0])

    def test_sans_correspondance(self):
        data, mock_send = self._cycle([])
        self.assertEqual(data["ransomware"], [])
        mock_send.assert_not_called()


if __name__ == "__main__":
    unittest.main()