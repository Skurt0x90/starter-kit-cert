import unittest
from unittest.mock import patch, MagicMock
import requests
from web_watcher.defacement import (
    get_html_content,
    decode_html,
    normalize_title,
    is_title_changed,
    extract_visible_text,
    count_keyword_hits,
    matched_keywords,
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

EMPTY_TITLE_HTML = "<html><head><title></title></head><body></body></html>"
NO_HEAD_HTML = "<html><body><p>Pas de head</p></body></html>"


def _response(text, content_type="text/html; charset=utf-8"):
    r = MagicMock()
    r.text = text
    r.headers = {"Content-Type": content_type}
    return r


# ─── get_html_content / decode_html ───────────────────────────────────────────

class TestGetHtmlContent(unittest.TestCase):

    @patch("web_watcher.defacement.requests.get")
    def test_retourne_le_texte_html(self, mock_get):
        mock_get.return_value = _response(NORMAL_HTML)
        self.assertEqual(get_html_content("aeroport-paris.fr"), NORMAL_HTML)

    @patch("web_watcher.defacement.requests.get")
    def test_url_construite_en_https(self, mock_get):
        mock_get.return_value = _response(NORMAL_HTML)
        get_html_content("aeroport-paris.fr")
        self.assertEqual(mock_get.call_args[0][0], "https://aeroport-paris.fr")

    @patch("web_watcher.defacement.requests.get", side_effect=requests.exceptions.ConnectionError())
    def test_connection_error_retourne_none(self, _):
        self.assertIsNone(get_html_content("site-inexistant.fr"))

    @patch("web_watcher.defacement.requests.get", side_effect=requests.exceptions.Timeout())
    def test_timeout_retourne_none(self, _):
        self.assertIsNone(get_html_content("aeroport-lent.fr"))

    @patch("web_watcher.defacement.requests.get", side_effect=requests.exceptions.SSLError())
    def test_ssl_error_retourne_none(self, _):
        self.assertIsNone(get_html_content("aeroport-ssl-broken.fr"))


class TestDecodeHtml(unittest.TestCase):

    def test_detecte_l_encodage_sans_charset(self):
        r = _response("x", content_type="text/html")
        r.apparent_encoding = "utf-8"
        decode_html(r)
        self.assertEqual(r.encoding, "utf-8")

    def test_respecte_le_charset_declare(self):
        r = _response("x", content_type="text/html; charset=iso-8859-1")
        r.encoding = "iso-8859-1"
        r.apparent_encoding = "utf-8"
        decode_html(r)
        self.assertEqual(r.encoding, "iso-8859-1")


# ─── normalize_title / is_title_changed ───────────────────────────────────────

class TestNormalizeTitle(unittest.TestCase):

    def test_none_retourne_vide(self):
        self.assertEqual(normalize_title(None), "")

    def test_entites_html(self):
        self.assertEqual(normalize_title("L&#039;École"), "L'École")

    def test_apostrophe_typographique(self):
        self.assertEqual(normalize_title("L\u2019École"), "L'École")

    def test_tirets_typographiques(self):
        self.assertEqual(normalize_title("Accueil \u2013 Fondation"), "Accueil - Fondation")

    def test_espaces_multiples_et_insecables(self):
        self.assertEqual(normalize_title("  Hello \u00a0  world "), "Hello world")


class TestIsTitleChanged(unittest.TestCase):

    def test_titre_identique(self):
        self.assertFalse(is_title_changed(NORMAL_HTML, "Aéroport de Paris"))

    def test_titre_different(self):
        self.assertTrue(is_title_changed(NORMAL_HTML, "Hacked by XYZ"))

    def test_titre_page_vide(self):
        self.assertFalse(is_title_changed(EMPTY_TITLE_HTML, "Aéroport de Paris"))

    def test_titre_attendu_vide_desactive_la_comparaison(self):
        self.assertFalse(is_title_changed(NORMAL_HTML, ""))

    def test_pas_de_head(self):
        self.assertFalse(is_title_changed(NO_HEAD_HTML, "Aéroport de Paris"))

    def test_sensible_a_la_casse(self):
        self.assertTrue(is_title_changed(NORMAL_HTML, "aéroport de paris"))

    def test_entite_html_dans_le_titre_de_la_page(self):
        html = "<html><head><title>L&#039;École de l'air</title></head></html>"
        self.assertFalse(is_title_changed(html, "L'École de l'air"))

    def test_tiret_typographique_ignore(self):
        html = "<html><head><title>Accueil \u2013 Fondation</title></head></html>"
        self.assertFalse(is_title_changed(html, "Accueil - Fondation"))


# ─── extract_visible_text ─────────────────────────────────────────────────────

class TestExtractVisibleText(unittest.TestCase):

    def test_ignore_scripts_et_styles(self):
        html = ("<html><head><style>.a{color:red}</style><title>Titre</title></head>"
                "<body><script>var hacked = 1</script><p>Bonjour Monde</p></body></html>")
        text = extract_visible_text(html)
        self.assertIn("bonjour monde", text)
        self.assertNotIn("var hacked", text)
        self.assertNotIn("color:red", text)

    def test_en_minuscules(self):
        self.assertEqual(extract_visible_text("<p>ABC</p>"), "abc")


# ─── count_keyword_hits / matched_keywords ────────────────────────────────────

class TestCountKeywordHits(unittest.TestCase):

    def test_aucun_mot_cle(self):
        self.assertEqual(count_keyword_hits("contenu normal", ["hacked", "defaced"], weight=5), (0, 0))

    def test_une_occurrence(self):
        self.assertEqual(count_keyword_hits("site hacked by xyz", ["hacked"], weight=5), (1, 5))

    def test_occurrences_plafonnees(self):
        # 5 occurrences, plafond à 3
        self.assertEqual(count_keyword_hits("hacked " * 5, ["hacked"], weight=5), (1, 15))

    def test_plusieurs_mots_cles(self):
        self.assertEqual(count_keyword_hits("hacked defaced", ["hacked", "defaced"], weight=5), (2, 10))

    def test_mots_entiers_uniquement(self):
        self.assertEqual(count_keyword_hits("unhacked rehacked", ["hacked"], weight=5), (0, 0))

    def test_expression_multi_mots(self):
        self.assertEqual(count_keyword_hits("this site has been hacked", ["this site has been hacked"], weight=5), (1, 5))

    def test_matched_keywords(self):
        self.assertEqual(matched_keywords("site hacked", ["hacked", "defaced"]), ["hacked"])


# ─── bonus ────────────────────────────────────────────────────────────────────

class TestBonus(unittest.TestCase):

    def test_densite_sous_seuil(self):
        self.assertEqual(compute_density_bonus(2, 10000), 0)

    def test_densite_au_dessus_du_seuil(self):
        self.assertEqual(compute_density_bonus(10, 100), 4)

    def test_un_seul_hit_ne_donne_pas_de_bonus(self):
        self.assertEqual(compute_density_bonus(1, 10), 0)

    def test_longueur_zero(self):
        self.assertEqual(compute_density_bonus(0, 0), 0)

    def test_bonus_categories(self):
        self.assertEqual(compute_category_bonus(0), 0)
        self.assertEqual(compute_category_bonus(1), 0)
        self.assertEqual(compute_category_bonus(2), 3)
        self.assertEqual(compute_category_bonus(3), 8)


# ─── process_defacement_scoring ───────────────────────────────────────────────

class TestProcessScoring(unittest.TestCase):

    def test_page_normale(self):
        self.assertEqual(process_defacement_scoring(NORMAL_HTML), 0)

    def test_page_defacee(self):
        self.assertGreaterEqual(process_defacement_scoring(DEFACED_HTML), 10)

    def test_mot_cle_dans_un_script_ignore(self):
        html = '<html><body><script>var s = "hacked by";</script><p>bienvenue</p></body></html>'
        self.assertEqual(process_defacement_scoring(html), 0)

    def test_un_seul_mot_moyen(self):
        self.assertEqual(process_defacement_scoring("<p>this site was hacked yesterday</p>"), 2)

    def test_occurrences_plafonnees(self):
        html = "<p>" + "hacked " * 10 + "</p>"
        self.assertEqual(process_defacement_scoring(html), 6)

    def test_mots_colles_ignores(self):
        self.assertEqual(process_defacement_scoring("<p>unhacked rehacked</p>"), 0)


# ─── interprete_scoring ───────────────────────────────────────────────────────

class TestInterpreteScoring(unittest.TestCase):

    def test_seuils(self):
        self.assertEqual(interprete_scoring(0), "SITE OK (non défacé)")
        self.assertEqual(interprete_scoring(1), "DEFACEMENT PEU PROBABLE")
        self.assertEqual(interprete_scoring(4), "DEFACEMENT PEU PROBABLE")
        self.assertEqual(interprete_scoring(5), "DEFACEMENT PROBABLE")
        self.assertEqual(interprete_scoring(9), "DEFACEMENT PROBABLE")
        self.assertEqual(interprete_scoring(10), "DEFACEMENT FORTEMENT PROBABLE")
        self.assertEqual(interprete_scoring(50), "DEFACEMENT FORTEMENT PROBABLE")


# ─── probability_site_defaced ─────────────────────────────────────────────────

class TestProbabilitySiteDefaced(unittest.TestCase):

    @patch("web_watcher.defacement.get_html_content", return_value=None)
    def test_contenu_none(self, _):
        self.assertIsNone(probability_site_defaced("site-down.fr", "Titre"))

    @patch("web_watcher.defacement.get_html_content", return_value=NORMAL_HTML)
    def test_site_normal(self, _):
        self.assertEqual(probability_site_defaced("aeroport-paris.fr", "Aéroport de Paris"), "SITE OK (non défacé)")

    @patch("web_watcher.defacement.get_html_content", return_value=DEFACED_HTML)
    def test_site_defacee(self, _):
        self.assertEqual(probability_site_defaced("aeroport-paris.fr", "Aéroport de Paris"), "DEFACEMENT FORTEMENT PROBABLE")

    @patch("web_watcher.defacement.get_html_content", return_value=NORMAL_HTML)
    def test_titre_modifie_seul_reste_peu_probable(self, _):
        self.assertEqual(probability_site_defaced("aeroport-paris.fr", "Titre différent"), "DEFACEMENT PEU PROBABLE")

    @patch("web_watcher.defacement.get_html_content", return_value=NORMAL_HTML)
    def test_titre_attendu_vide_pas_de_penalite(self, _):
        self.assertEqual(probability_site_defaced("aeroport-paris.fr", ""), "SITE OK (non défacé)")

    @patch("web_watcher.defacement.get_html_content", return_value=None)
    def test_contenu_fourni_pas_de_nouvelle_requete(self, mock_get):
        result = probability_site_defaced("aeroport-paris.fr", "Aéroport de Paris", content=NORMAL_HTML)
        mock_get.assert_not_called()
        self.assertEqual(result, "SITE OK (non défacé)")

    def test_mot_cle_et_titre_modifie_donnent_probable(self):
        html = "<html><head><title>X</title></head><body>hacked</body></html>"
        self.assertEqual(probability_site_defaced("a.fr", "Y", content=html), "DEFACEMENT PROBABLE")


if __name__ == "__main__":
    unittest.main()