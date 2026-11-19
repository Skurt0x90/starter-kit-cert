import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import requests
from ransomware_monitor import correlator as co


def _date(days_ago, with_time=False):
    d = datetime.now() - timedelta(days=days_ago)
    return d.strftime("%Y-%m-%d %H:%M:%S" if with_time else "%Y-%m-%d")


def _json(data):
    r = MagicMock()
    r.json.return_value = data
    return r


class TestParseAndFilterDate(unittest.TestCase):

    def test_vide_ou_none(self):
        self.assertIsNone(co.parse_and_filter_date(""))
        self.assertIsNone(co.parse_and_filter_date(None))

    def test_format_invalide(self):
        self.assertIsNone(co.parse_and_filter_date("pas une date"))

    def test_date_recente_reformatee(self):
        expected = (datetime.now() - timedelta(days=1)).strftime("%d-%m-%Y")
        self.assertEqual(co.parse_and_filter_date(_date(1)), expected)

    def test_ignore_l_heure(self):
        self.assertIsNotNone(co.parse_and_filter_date(_date(0, with_time=True)))

    def test_date_ancienne(self):
        self.assertIsNone(co.parse_and_filter_date(_date(10)))


class TestSources(unittest.TestCase):

    @patch("ransomware_monitor.correlator.requests.get")
    def test_ransomfeed(self, mock_get):
        mock_get.return_value = _json([
            {"date": _date(0), "victim": "Acme", "gang": "lockbit"},
            {"date": _date(30), "victim": "Vieux", "gang": "x"},
        ])
        result = co.get_victim_ransomfeed()
        self.assertEqual(len(result), 1)
        self.assertEqual((result[0]["victime"], result[0]["acteur"], result[0]["source"]), ("Acme", "lockbit", "ransomfeed"))

    @patch("ransomware_monitor.correlator.requests.get")
    def test_ransomlive(self, mock_get):
        mock_get.return_value = _json([{"attackdate": _date(0), "victim": "Acme", "group": "akira"}])
        result = co.get_victim_ransomlive()
        self.assertEqual((result[0]["acteur"], result[0]["source"]), ("akira", "ransomlive"))

    @patch("ransomware_monitor.correlator.requests.get")
    def test_ransomlook(self, mock_get):
        mock_get.return_value = _json([{"discovered": _date(0, with_time=True), "post_title": "Acme", "group_name": "krybit"}])
        result = co.get_victim_ransomlook()
        self.assertEqual((result[0]["victime"], result[0]["acteur"], result[0]["source"]), ("Acme", "krybit", "ransomlook"))

    @patch("ransomware_monitor.correlator.requests.get", side_effect=requests.exceptions.ConnectionError())
    def test_erreur_reseau_retourne_liste_vide(self, _):
        self.assertEqual(co.get_victim_ransomfeed(), [])
        self.assertEqual(co.get_victim_ransomlive(), [])
        self.assertEqual(co.get_victim_ransomlook(), [])


class TestCleanName(unittest.TestCase):

    def test_normalisation(self):
        self.assertEqual(co.clean_name("Café-Müller S.A."), "cafemullersa")
        self.assertEqual(co.clean_name("École de l'Air"), "ecoledelair")


def _victim(name, source="ransomlive"):
    return {"victime": name, "acteur": "lockbit", "date": "19-11-2026", "source": source}


class TestCorrelate(unittest.TestCase):

    def _correlate(self, members, victims):
        with patch.object(co, "get_victim_ransomfeed", return_value=list(victims)), \
             patch.object(co, "get_victim_ransomlive", return_value=[]), \
             patch.object(co, "get_victim_ransomlook", return_value=[]), \
             patch.object(co.utils, "load_members", return_value=[{"member": m} for m in members]):
            return co.correlate()

    def test_correspondance_insensible_a_la_forme(self):
        matches = self._correlate(["Acme Corp"], [_victim("ACME-corp")])
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["victime"], "ACME-corp")
        self.assertEqual(matches[0]["acteur"], "lockbit")

    def test_correspondance_exacte_pas_partielle(self):
        self.assertEqual(self._correlate(["Acme"], [_victim("Acme Corp")]), [])

    def test_aucun_membre_concerne(self):
        self.assertEqual(self._correlate(["Autre"], [_victim("Acme")]), [])

    def test_une_seule_correspondance_par_membre(self):
        victims = [_victim("Acme", "ransomlive"), _victim("Acme", "ransomlook")]
        self.assertEqual(len(self._correlate(["Acme"], victims)), 1)

    def test_nom_vide_ne_correspond_a_rien(self):
        self.assertEqual(self._correlate(["!!!"], [_victim("???")]), [])

    def test_aucun_membre(self):
        self.assertEqual(self._correlate([], [_victim("Acme")]), [])


if __name__ == "__main__":
    unittest.main()