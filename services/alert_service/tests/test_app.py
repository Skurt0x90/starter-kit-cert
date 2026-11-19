import unittest
from unittest.mock import patch
from app_test_mixin import DataApiMixin
from alert_service import app as alert_app, utils


class TestAlertApi(DataApiMixin, unittest.TestCase):
    flask_app = alert_app.app
    utils_module = utils

    def test_post_corps_non_json(self):
        r = self.client.post("/api/alert", data="pas du json", content_type="application/json")
        self.assertEqual(r.status_code, 400)

    def test_post_payload_vide(self):
        self.assertEqual(self.client.post("/api/alert", json={}).status_code, 400)

    def test_post_champ_manquant(self):
        r = self.client.post("/api/alert", json={"service": "web_watcher"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("alerts", r.get_json()["error"])

    def test_post_valide(self):
        payload = {"service": "web_watcher", "alerts": {"a.fr": [{"level": "CRITICAL", "message": "DOWN"}]}}
        with patch("alert_service.app.process_alert", return_value={"sent": 1, "deduplicated": 0}) as mock_process:
            r = self.client.post("/api/alert", json=payload)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"sent": 1, "deduplicated": 0})
        mock_process.assert_called_once_with(payload)


if __name__ == "__main__":
    unittest.main()