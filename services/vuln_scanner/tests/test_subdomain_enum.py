import unittest
from unittest.mock import patch, MagicMock
import requests
from vuln_scanner import subdomain_enum as se


def _json_response(data):
    r = MagicMock()
    r.json.return_value = data
    return r


class TestCleanNames(unittest.TestCase):

    def test_filtre_et_normalise(self):
        raw = ["a.example.com", "*.example.com", " B.EXAMPLE.COM ", "other.org", "example.com", "a.example.com"]
        self.assertEqual(sorted(se.clean_names(raw, "example.com")), ["a.example.com", "b.example.com"])


class TestFetchCrtsh(unittest.TestCase):

    @patch("vuln_scanner.subdomain_enum.requests.get")
    def test_extrait_les_noms(self, mock_get):
        mock_get.return_value = _json_response([{"name_value": "a.example.com\nb.example.com"}, {"name_value": "c.example.com"}])
        self.assertEqual(se.fetch_crtsh("example.com"), ["a.example.com", "b.example.com", "c.example.com"])

    @patch("vuln_scanner.subdomain_enum.time.sleep")
    @patch("vuln_scanner.subdomain_enum.requests.get", side_effect=requests.exceptions.Timeout())
    def test_retries_puis_none(self, mock_get, mock_sleep):
        self.assertIsNone(se.fetch_crtsh("example.com"))
        self.assertEqual(mock_get.call_count, se.CRTSH_RETRIES)
        self.assertEqual([c.args[0] for c in mock_sleep.call_args_list], [5, 10])


class TestFetchCertspotter(unittest.TestCase):

    @patch("vuln_scanner.subdomain_enum.requests.get")
    def test_extrait_les_noms(self, mock_get):
        mock_get.return_value = _json_response([{"dns_names": ["a.example.com", "b.example.com"]}])
        self.assertEqual(se.fetch_certspotter("example.com"), ["a.example.com", "b.example.com"])

    @patch("vuln_scanner.subdomain_enum.requests.get", side_effect=requests.exceptions.ConnectionError())
    def test_erreur_retourne_none(self, _):
        self.assertIsNone(se.fetch_certspotter("example.com"))


class TestFetchSubdomains(unittest.TestCase):

    def test_crtsh_suffit(self):
        with patch.object(se, "fetch_crtsh", return_value=["a.example.com"]), \
             patch.object(se, "fetch_certspotter") as mock_cs:
            self.assertEqual(se.fetch_subdomains("example.com"), ["a.example.com"])
        mock_cs.assert_not_called()

    def test_fallback_certspotter(self):
        with patch.object(se, "fetch_crtsh", return_value=None), \
             patch.object(se, "fetch_certspotter", return_value=["b.example.com"]):
            self.assertEqual(se.fetch_subdomains("example.com"), ["b.example.com"])

    def test_echec_total_retourne_none(self):
        with patch.object(se, "fetch_crtsh", return_value=None), \
             patch.object(se, "fetch_certspotter", return_value=None):
            self.assertIsNone(se.fetch_subdomains("example.com"))


class TestResolve(unittest.TestCase):

    @patch("vuln_scanner.subdomain_enum.resolver")
    def test_enregistrement_a(self, mock_resolver):
        self.assertTrue(se.resolve("a.example.com"))

    @patch("vuln_scanner.subdomain_enum.resolver")
    def test_repli_sur_aaaa(self, mock_resolver):
        mock_resolver.resolve.side_effect = [Exception("pas de A"), MagicMock()]
        self.assertTrue(se.resolve("a.example.com"))

    @patch("vuln_scanner.subdomain_enum.resolver")
    def test_ne_resout_pas(self, mock_resolver):
        mock_resolver.resolve.side_effect = Exception("nxdomain")
        self.assertFalse(se.resolve("a.example.com"))


class TestCheck(unittest.TestCase):

    def test_enumeration_impossible(self):
        with patch.object(se, "fetch_subdomains", return_value=None):
            result = se.check("example.com")
        self.assertEqual(result["subdomains"], [])
        self.assertEqual(result["alerts"][0]["level"], "INFO")

    def test_seuls_les_sous_domaines_actifs_sont_retenus(self):
        with patch.object(se, "fetch_subdomains", return_value=["a.example.com", "b.example.com"]), \
             patch.object(se, "resolve", side_effect=lambda s: s == "a.example.com"):
            result = se.check("example.com")
        self.assertEqual(result["subdomains"], ["a.example.com"])
        self.assertEqual(result["alerts"][0]["level"], "WARNING")
        self.assertIn("a.example.com", result["alerts"][0]["message"])

    def test_aucun_actif_pas_d_alerte(self):
        with patch.object(se, "fetch_subdomains", return_value=["a.example.com"]), \
             patch.object(se, "resolve", return_value=False):
            result = se.check("example.com")
        self.assertEqual(result, {"subdomains": [], "alerts": []})


if __name__ == "__main__":
    unittest.main()