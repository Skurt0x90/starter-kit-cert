import unittest
from unittest.mock import patch, mock_open
from web_watcher.utils import load_domains, parse_target_line


class TestParseTargetLine(unittest.TestCase):

    def test_nominal(self):
        r = parse_target_line("example.com,2.3522,48.8566,Example Domain")
        self.assertEqual(r["domain"], "example.com")
        self.assertEqual(r["longitude"], 2.3522)
        self.assertEqual(r["latitude"], 48.8566)
        self.assertEqual(r["label"], "Example Domain")
        self.assertEqual(r["title"], "Example Domain")
        self.assertEqual(r["scan_mode"], "passive")

    def test_titre_avec_virgule(self):
        r = parse_target_line("boutique.fr,0.71,47.43,Armée de l'Air, Boutique officielle")
        self.assertEqual(r["title"], "Armée de l'Air, Boutique officielle")
        self.assertEqual(r["scan_mode"], "passive")

    def test_scan_mode_active(self):
        r = parse_target_line("target_test,2.35,48.85,DVWA Test,active")
        self.assertEqual(r["title"], "DVWA Test")
        self.assertEqual(r["scan_mode"], "active")

    def test_titre_avec_virgule_et_scan_mode(self):
        r = parse_target_line("x.fr,1,2,Titre, avec virgule,active")
        self.assertEqual(r["title"], "Titre, avec virgule")
        self.assertEqual(r["scan_mode"], "active")

    def test_espaces_supprimes(self):
        r = parse_target_line("  example.com  , 2.3522, 48.8566,   Paris   ")
        self.assertEqual(r["domain"], "example.com")
        self.assertEqual(r["title"], "Paris")

    def test_ligne_incomplete(self):
        with self.assertRaises(ValueError):
            parse_target_line("example.com,2.3522")

    def test_coordonnee_invalide(self):
        with self.assertRaises(ValueError):
            parse_target_line("example.com,abc,48.85,Titre")


class TestLoadDomains(unittest.TestCase):

    def test_ignore_commentaires_et_lignes_vides(self):
        data = "# commentaire\n\nexample.com,2.35,48.85,Titre\n\n"
        with patch("builtins.open", mock_open(read_data=data)):
            result = load_domains("fake.txt")
        self.assertEqual(len(result), 1)

    def test_plusieurs_domaines(self):
        data = "a.com,2.35,48.85,A\nb.com,-0.12,51.50,B\n"
        with patch("builtins.open", mock_open(read_data=data)):
            result = load_domains("fake.txt")
        self.assertEqual([r["domain"] for r in result], ["a.com", "b.com"])

    def test_fichier_vide(self):
        with patch("builtins.open", mock_open(read_data="")):
            self.assertEqual(load_domains("fake.txt"), [])

    def test_fichier_introuvable(self):
        with self.assertRaises(FileNotFoundError):
            load_domains("fichier_inexistant.txt")

    def test_ligne_malformee(self):
        with patch("builtins.open", mock_open(read_data="example.com,2.3522\n")):
            with self.assertRaises(ValueError):
                load_domains("fake.txt")


if __name__ == "__main__":
    unittest.main()