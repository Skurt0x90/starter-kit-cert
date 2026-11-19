import unittest
from unittest.mock import patch, mock_open
from ransomware_monitor.utils import load_members


class TestLoadMembers(unittest.TestCase):

    def _load(self, data):
        with patch("builtins.open", mock_open(read_data=data)):
            return load_members("fake.txt")

    def test_ignore_commentaires_lignes_vides_et_espaces(self):
        self.assertEqual(self._load("# commentaire\n\n  Acme Corp  \nAutre\n"),
                         [{"member": "Acme Corp"}, {"member": "Autre"}])

    def test_fichier_vide(self):
        self.assertEqual(self._load(""), [])

    def test_fichier_introuvable(self):
        with self.assertRaises(FileNotFoundError):
            load_members("inexistant.txt")


if __name__ == "__main__":
    unittest.main()