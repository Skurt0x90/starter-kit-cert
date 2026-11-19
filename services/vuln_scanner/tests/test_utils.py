import unittest
from unittest.mock import patch, mock_open
from vuln_scanner.utils import load_domains


class TestLoadDomains(unittest.TestCase):

    def _load(self, data):
        with patch("builtins.open", mock_open(read_data=data)):
            return load_domains("fake.txt")

    def test_nominal_mode_passif_par_defaut(self):
        r = self._load("example.com,2.3522,48.8566,Example Domain\n")[0]
        self.assertEqual(r["domain"], "example.com")
        self.assertEqual(r["longitude"], 2.3522)
        self.assertEqual(r["latitude"], 48.8566)
        self.assertEqual(r["label"], "Example Domain")
        self.assertEqual(r["scan_mode"], "passive")

    def test_scan_mode_active(self):
        self.assertEqual(self._load("target_test,2.35,48.85,DVWA Test,active\n")[0]["scan_mode"], "active")

    def test_titre_avec_virgule(self):
        r = self._load("boutique.fr,0.71,47.43,Armée de l'Air, Boutique officielle\n")[0]
        self.assertEqual(r["label"], "Armée de l'Air, Boutique officielle")
        self.assertEqual(r["scan_mode"], "passive")

    def test_titre_avec_virgule_et_active(self):
        r = self._load("x.fr,1,2,Titre, avec virgule,active\n")[0]
        self.assertEqual(r["label"], "Titre, avec virgule")
        self.assertEqual(r["scan_mode"], "active")

    def test_ignore_commentaires_et_lignes_vides(self):
        self.assertEqual(len(self._load("# c\n\nexample.com,2.35,48.85,T\n")), 1)

    def test_ligne_malformee(self):
        with self.assertRaises(ValueError):
            self._load("example.com,2.3522\n")

    def test_fichier_introuvable(self):
        with self.assertRaises(FileNotFoundError):
            load_domains("inexistant.txt")


if __name__ == "__main__":
    unittest.main()