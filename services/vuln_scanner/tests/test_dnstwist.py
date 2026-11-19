import sys
import unittest
from unittest.mock import patch
from vuln_scanner import dnstwist as twist


class TestCheck(unittest.TestCase):

    def test_domaines_enregistres_detectes(self):
        results = [
            {"domain": "example.fr", "dns_a": ["1.1.1.1"]},         # le domaine lui-même
            {"domain": "exampel.fr", "dns_a": ["1.2.3.4"]},
            {"domain": "exarnple.fr", "dns_mx": ["mx.exarnple.fr"]},
            {"domain": "nodns.fr"},                                  # ni A ni MX : ignoré
        ]
        with patch.object(twist.dnstwist, "run", return_value=results):
            result = twist.check("example.fr")
        self.assertEqual(sorted(result["typosquatting"]), ["exampel.fr", "exarnple.fr"])
        self.assertEqual(result["alerts"][0]["level"], "CRITICAL")
        self.assertIn("exampel.fr", result["alerts"][0]["message"])

    def test_aucun_typosquat(self):
        with patch.object(twist.dnstwist, "run", return_value=[{"domain": "example.fr"}]):
            self.assertEqual(twist.check("example.fr"), {"typosquatting": [], "alerts": []})

    def test_erreur_retourne_vide_et_restaure_stdout(self):
        original = sys.stdout
        with patch.object(twist.dnstwist, "run", side_effect=RuntimeError("boom")):
            result = twist.check("example.fr")
        self.assertEqual(result, {"typosquatting": [], "alerts": []})
        self.assertIs(sys.stdout, original)

    def test_stdout_restaure_apres_succes(self):
        original = sys.stdout
        with patch.object(twist.dnstwist, "run", return_value=[]):
            twist.check("example.fr")
        self.assertIs(sys.stdout, original)


if __name__ == "__main__":
    unittest.main()