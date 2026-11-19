import unittest
from unittest.mock import patch
from social_monitor import correlate as co


def _correlate(items, keywords=(), members=()):
    with patch.object(co.utils, "load_keywords", return_value=list(keywords)), \
         patch.object(co.utils, "load_members", return_value=list(members)):
        return co.correlate(items)


class TestCleanText(unittest.TestCase):

    def test_accents_ponctuation_casse(self):
        self.assertEqual(co.clean_text("Épée, ÉTÉ!!"), "epee ete")

    def test_espaces_ecrases(self):
        self.assertEqual(co.clean_text("a   b\n c"), "a b c")

    def test_none(self):
        self.assertEqual(co.clean_text(None), "")


class TestCompileTerms(unittest.TestCase):

    def test_termes_vides_ignores(self):
        self.assertEqual(co.compile_terms(["", "!!!"]), [])


class TestMatching(unittest.TestCase):

    def _item(self, content, title=""):
        return {"source": "rss", "channel": "c", "title": title, "content": content, "url": "u"}

    def test_mot_entier_uniquement(self):
        text = "Investigation of machine drones adapted by a disaster team"
        result = _correlate([self._item(text)], keywords=["iga", "chine", "apt", "aster", "drone"])
        self.assertEqual(result[0]["matched_keywords"], ["drone"])  # drones = pluriel toléré

    def test_expression_multi_mots_normalisee(self):
        result = _correlate([self._item("Le Ministère des Armées annonce")], keywords=["ministere des armees"])
        self.assertEqual(result[0]["matched_keywords"], ["ministere des armees"])

    def test_membre_donne_critical(self):
        result = _correlate([self._item("NVIDIA hit by ransomware")], keywords=["ransomware"], members=["nvidia"])
        self.assertEqual(result[0]["level"], "CRITICAL")
        self.assertEqual(result[0]["matched_members"], ["nvidia"])
        self.assertEqual(result[0]["matched_keywords"], ["ransomware"])

    def test_mot_cle_seul_donne_warning(self):
        result = _correlate([self._item("New ransomware wave")], keywords=["ransomware"])
        self.assertEqual(result[0]["level"], "WARNING")

    def test_aucune_correspondance_exclue(self):
        self.assertEqual(_correlate([self._item("Recette de cuisine")], keywords=["ransomware"], members=["nvidia"]), [])

    def test_membre_avec_accents(self):
        result = _correlate([self._item("Ecole de l'air recrute")], members=["école de l'air"])
        self.assertEqual(len(result), 1)

    def test_titre_none_n_est_pas_analyse(self):
        item = {"source": "telegram", "channel": "c", "title": None, "content": "hello", "url": "u"}
        self.assertEqual(_correlate([item], keywords=["none"]), [])

    def test_le_titre_est_analyse(self):
        result = _correlate([self._item("rien", title="Alerte ransomware")], keywords=["ransomware"])
        self.assertEqual(len(result), 1)

    def test_conserve_les_champs_de_l_item(self):
        result = _correlate([self._item("ransomware")], keywords=["ransomware"])
        self.assertEqual((result[0]["channel"], result[0]["url"]), ("c", "u"))


if __name__ == "__main__":
    unittest.main()