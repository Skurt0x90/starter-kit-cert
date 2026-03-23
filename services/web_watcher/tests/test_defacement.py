import unittest
from unittest.mock import patch, MagicMock
import requests
from web_watcher.defacement import (
    get_html_content,
    is_title_changed,
    count_keyword_hits,
    compute_density_bonus,
    compute_category_bonus,
    process_defacement_scoring,
    interprete_scoring,
    probability_site_defaced,
)
from web_watcher import utils

# ─── Fixtures HTML ────────────────────────────────────────────────────────────

NORMAL_HTML = """
<html>
<head><title>Aéroport de Paris</title></head>
<body><h1>Bienvenue sur le site de l'aéroport</h1></body>
</html>
"""

DEFACED_HTML = f"""
<html>
<head><title>Hacked by XYZ</title></head>
<body>
    <h1>Hacked by XYZ Team</h1>
    <p>{utils.HIGH_CONFIDENCE[0]} {utils.HIGH_CONFIDENCE[1]}</p>
    <p>{utils.MEDIUM_CONFIDENCE[0]} {utils.MEDIUM_CONFIDENCE[1]}</p>
    <p>{utils.TECHNICAL_INDICATORS[0]} {utils.TECHNICAL_INDICATORS[1]}</p>
</body>
</html>
"""

EMPTY_TITLE_HTML = """
<html><head><title></title></head><body></body>
</html>
"""

NO_HEAD_HTML = """
<html><body><p>Pas de head</p></body></html>
"""


# ─── get_html_content ─────────────────────────────────────────────────────────

class TestGetHtmlContent(unittest.TestCase):

    @patch("web_watcher.defacement.requests.get")
    def test_retourne_le_texte_html(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = NORMAL_HTML
        mock_get.return_value = mock_response

        result = get_html_content("aeroport-paris.fr")
        self.assertEqual(result, NORMAL_HTML)

    @patch("web_watcher.defacement.requests.get")
    def test_url_construite_en_https(self, mock_get):
        mock_response = MagicMock()
        mock_response.text = NORMAL_HTML
        mock_get.return_value = mock_response

        get_html_content("aeroport-paris.fr")
        call_args = mock_get.call_args
        self.assertEqual(call_args[0][0], "https://aeroport-paris.fr")

    @patch("web_watcher.defacement.requests.get", side_effect=requests.exceptions.ConnectionError())
    def test_connection_error_retourne_none(self, mock_get):
        result = get_html_content("site-inexistant.fr")
        self.assertIsNone(result)

    @patch("web_watcher.defacement.requests.get", side_effect=requests.exceptions.Timeout())
    def test_timeout_retourne_none(self, mock_get):
        result = get_html_content("aeroport-lent.fr")
        self.assertIsNone(result)

    @patch("web_watcher.defacement.requests.get", side_effect=requests.exceptions.SSLError())
    def test_ssl_error_retourne_none(self, mock_get):
        result = get_html_content("aeroport-ssl-broken.fr")
        self.assertIsNone(result)


# ─── is_title_changed ─────────────────────────────────────────────────────────

class TestIsTitleChanged(unittest.TestCase):

    def test_titre_identique_retourne_false(self):
        result = is_title_changed(NORMAL_HTML, "Aéroport de Paris")
        self.assertFalse(result)

    def test_titre_different_retourne_true(self):
        result = is_title_changed(NORMAL_HTML, "Hacked by XYZ")
        self.assertTrue(result)

    def test_titre_html_vide_attendu_vide_retourne_false(self):
        result = is_title_changed(EMPTY_TITLE_HTML, "")
        self.assertFalse(result)

    def test_titre_html_vide_attendu_non_vide_retourne_false(self):
        result = is_title_changed(EMPTY_TITLE_HTML, "Aéroport de Paris")
        self.assertFalse(result)

    def test_pas_de_head_retourne_false(self):
        result = is_title_changed(NO_HEAD_HTML, "Aéroport de Paris")
        self.assertFalse(result)

    def test_sensible_a_la_casse(self):
        result = is_title_changed(NORMAL_HTML, "aéroport de paris")
        self.assertTrue(result)


# ─── count_keyword_hits ───────────────────────────────────────────────────────

class TestCountKeywordHits(unittest.TestCase):

    def test_aucun_mot_cle_present(self):
        hits, score = count_keyword_hits("contenu normal", ["hacked", "defaced"], weight=5)
        self.assertEqual(hits, 0)
        self.assertEqual(score, 0)

    def test_un_mot_cle_present_une_fois(self):
        hits, score = count_keyword_hits("site hacked by xyz", ["hacked"], weight=5)
        self.assertEqual(hits, 1)
        self.assertEqual(score, 5)

    def test_un_mot_cle_present_plusieurs_fois(self):
        hits, score = count_keyword_hits("hacked hacked hacked", ["hacked"], weight=5)
        self.assertEqual(hits, 1)
        self.assertEqual(score, 15)

    def test_plusieurs_mots_cles_presents(self):
        hits, score = count_keyword_hits("hacked defaced", ["hacked", "defaced"], weight=5)
        self.assertEqual(hits, 2)
        self.assertEqual(score, 10)

    def test_poids_applique_correctement(self):
        hits, score = count_keyword_hits("hacked", ["hacked"], weight=2)
        self.assertEqual(score, 2)


# ─── compute_density_bonus ────────────────────────────────────────────────────

class TestComputeDensityBonus(unittest.TestCase):

    def test_densite_sous_seuil_retourne_zero(self):
        result = compute_density_bonus(1, 10000)
        self.assertEqual(result, 0)

    def test_densite_au_dessus_seuil_retourne_quatre(self):
        # 10 hits / 100 chars = 0.1 > 0.005
        result = compute_density_bonus(10, 100)
        self.assertEqual(result, 4)

    def test_total_length_zero_ne_leve_pas_exception(self):
        result = compute_density_bonus(0, 0)
        self.assertEqual(result, 0)


# ─── compute_category_bonus ───────────────────────────────────────────────────

class TestComputeCategoryBonus(unittest.TestCase):

    def test_zero_categorie_retourne_zero(self):
        self.assertEqual(compute_category_bonus(0), 0)

    def test_une_categorie_retourne_zero(self):
        self.assertEqual(compute_category_bonus(1), 0)

    def test_deux_categories_retourne_trois(self):
        self.assertEqual(compute_category_bonus(2), 3)

    def test_trois_categories_retourne_huit(self):
        self.assertEqual(compute_category_bonus(3), 8)


# ─── interprete_scoring ───────────────────────────────────────────────────────

class TestInterpreteScoring(unittest.TestCase):

    def test_score_zero_retourne_peu_probable(self):
        # score == 0 → ni 0<=s<=4, ni 4<s<10 → else
        self.assertEqual(interprete_scoring(0), "SITE OK (non défacé)")

    def test_score_1_peu_probable(self):
        self.assertEqual(interprete_scoring(1), "DEFACEMENT PEU PROBABLE")

    def test_score_4_peu_probable(self):
        self.assertEqual(interprete_scoring(4), "DEFACEMENT PEU PROBABLE")

    def test_score_5_probable(self):
        self.assertEqual(interprete_scoring(5), "DEFACEMENT PROBABLE")

    def test_score_9_probable(self):
        self.assertEqual(interprete_scoring(9), "DEFACEMENT PROBABLE")

    def test_score_10_fortement_probable(self):
        self.assertEqual(interprete_scoring(10), "DEFACEMENT FORTEMENT PROBABLE")

    def test_score_eleve_fortement_probable(self):
        self.assertEqual(interprete_scoring(50), "DEFACEMENT FORTEMENT PROBABLE")


# ─── probability_site_defaced ─────────────────────────────────────────────────

class TestProbabilitySiteDefaced(unittest.TestCase):

    @patch("web_watcher.defacement.get_html_content", return_value=None)
    def test_contenu_none_retourne_none(self, mock_content):
        result = probability_site_defaced("site-down.fr", "Titre")
        self.assertIsNone(result)

    @patch("web_watcher.defacement.get_html_content", return_value=NORMAL_HTML)
    def test_site_normal_peu_probable(self, mock_content):
        result = probability_site_defaced("aeroport-paris.fr", "Aéroport de Paris")
        self.assertEqual(result, "SITE OK (non défacé)")  

    @patch("web_watcher.defacement.get_html_content", return_value=DEFACED_HTML)
    def test_site_defaced__probable(self, mock_content):
        result = probability_site_defaced("aeroport-paris.fr", "Aéroport de Paris")
        self.assertEqual(result, "DEFACEMENT PROBABLE")

    @patch("web_watcher.defacement.get_html_content", return_value=NORMAL_HTML)
    def test_titre_change_augmente_score(self, mock_content):
        """Un titre modifié ajoute 5 pts au score"""
        result = probability_site_defaced("aeroport-paris.fr", "Titre différent")
        self.assertIn(result, ["DEFACEMENT PEU PROBABLE", "DEFACEMENT PROBABLE", "DEFACEMENT FORTEMENT PROBABLE"])


if __name__ == "__main__":
    unittest.main()