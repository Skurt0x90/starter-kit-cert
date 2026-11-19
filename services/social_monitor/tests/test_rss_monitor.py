import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from social_monitor import utils
from social_monitor.collectors import rss_monitor as rss


def _parsed(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).timetuple()


class FakeEntry(dict):
    """Entrée feedparser : accès par clé (get) et par attribut (published_parsed)."""
    def __init__(self, days_ago=0, **fields):
        super().__init__(**fields)
        self.published_parsed = _parsed(days_ago) if days_ago is not None else None


@patch.object(utils, "LOOKBACK_DAYS", 7)
class TestIsRecent(unittest.TestCase):

    def test_recent(self):
        self.assertTrue(rss.is_recent(FakeEntry(1)))

    def test_ancien(self):
        self.assertFalse(rss.is_recent(FakeEntry(30)))

    def test_sans_date(self):
        self.assertFalse(rss.is_recent(FakeEntry(None)))
        self.assertFalse(rss.is_recent(SimpleNamespace()))


class TestCleanHtml(unittest.TestCase):

    def test_retire_les_balises(self):
        self.assertEqual(rss.clean_html("<p>Hello <b>monde</b></p>"), "Hello monde")


@patch.object(utils, "LOOKBACK_DAYS", 7)
class TestParseFeed(unittest.TestCase):

    CFG = {"name": "Flux", "url": "https://x/feed"}

    def _parse(self, entries, bozo=False):
        with patch("social_monitor.collectors.rss_monitor.feedparser.parse",
                   return_value=SimpleNamespace(bozo=bozo, entries=entries)):
            return rss.parse_feed(self.CFG)

    def test_item_complet(self):
        entry = FakeEntry(0, title="  Titre  ", link=" https://x/1 ", summary="<p>Hello <b>monde</b></p>")
        item = self._parse([entry])[0]
        self.assertEqual(item["source"], "rss")
        self.assertEqual(item["channel"], "Flux")
        self.assertEqual(item["title"], "Titre")
        self.assertEqual(item["url"], "https://x/1")
        self.assertEqual(item["content"], "Hello monde")
        self.assertIn("detected_at", item)

    def test_repli_sur_description(self):
        entry = FakeEntry(0, title="T", link="l", description="<i>desc</i>")
        self.assertEqual(self._parse([entry])[0]["content"], "desc")

    def test_contenu_tronque(self):
        entry = FakeEntry(0, title="T", link="l", summary="x" * 1000)
        self.assertEqual(len(self._parse([entry])[0]["content"]), rss.CONTENT_MAX_LENGTH)

    def test_articles_anciens_ignores(self):
        self.assertEqual(self._parse([FakeEntry(30, title="T", link="l", summary="s")]), [])

    def test_flux_mal_forme_traite_quand_meme(self):
        self.assertEqual(len(self._parse([FakeEntry(0, title="T", link="l", summary="s")], bozo=True)), 1)

    def test_erreur_retourne_liste_vide(self):
        with patch("social_monitor.collectors.rss_monitor.feedparser.parse", side_effect=Exception("boom")):
            self.assertEqual(rss.parse_feed(self.CFG), [])


class TestCollect(unittest.TestCase):

    def test_concatene_les_flux(self):
        feeds = [{"name": "A", "url": "ua"}, {"name": "B", "url": "ub"}]
        with patch.object(utils, "load_rss_feeds", return_value=feeds), \
             patch.object(rss, "parse_feed", side_effect=lambda cfg: [{"channel": cfg["name"]}]):
            self.assertEqual(rss.collect(), [{"channel": "A"}, {"channel": "B"}])

    def test_aucun_flux(self):
        with patch.object(utils, "load_rss_feeds", return_value=[]):
            self.assertEqual(rss.collect(), [])


if __name__ == "__main__":
    unittest.main()