import json
import os
import tempfile
from unittest.mock import patch


class DataApiMixin:
    """Tests communs de /health et /api/data.

    Les sous-classes (avec unittest.TestCase) définissent flask_app (l'application Flask)
    et utils_module (le module utils du service, qui porte OUTPUT_FILE).
    """
    flask_app = None
    utils_module = None

    def setUp(self):
        self.client = self.flask_app.test_client()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.output_path = os.path.join(tmp.name, "out.json")
        patcher = patch.object(self.utils_module, "OUTPUT_FILE", self.output_path)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_health(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"status": "ok"})

    def test_data_sans_fichier_retourne_503(self):
        r = self.client.get("/api/data")
        self.assertEqual(r.status_code, 503)

    def test_data_retourne_le_json(self):
        with open(self.output_path, "w") as f:
            json.dump({"last_run": "x", "sites": []}, f)
        r = self.client.get("/api/data")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["last_run"], "x")