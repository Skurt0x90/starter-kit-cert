import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock, mock_open
import json
import socket
import ssl
import requests
from web_watcher import utils
from web_watcher.watcher import (
    PARIS,
    fetch_site,
    is_up,
    classify_response_time,
    ssl_days_left,
    get_ssl_status,
    check_site,
    safe_check,
    load_previous,
    confirmed,
    create_alerts,
    run_watcher_cycle,
)


def _http_response(status=200, elapsed=0.5, history=None, content_type="text/html; charset=utf-8", text="<html></html>"):
    r = MagicMock()
    r.status_code = status
    r.elapsed = timedelta(seconds=elapsed)
    r.history = history or []
    r.headers = {"Content-Type": content_type}
    r.text = text
    return r


# ─── fetch_site ───────────────────────────────────────────────────────────────

class TestFetchSite(unittest.TestCase):

    @patch("web_watcher.watcher.requests.get")
    def test_nominal(self, mock_get):
        mock_get.return_value = _http_response(200, 0.5, text="<html>ok</html>")
        r = fetch_site("example.com")
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["elapsed"], 0.5)
        self.assertEqual(r["html"], "<html>ok</html>")
        self.assertEqual(mock_get.call_args[0][0], "https://example.com")

    @patch("web_watcher.watcher.requests.get")
    def test_temps_cumule_les_redirections(self, mock_get):
        redirect = MagicMock(elapsed=timedelta(seconds=1))
        mock_get.return_value = _http_response(200, 0.5, history=[redirect])
        self.assertEqual(fetch_site("example.com")["elapsed"], 1.5)

    @patch("web_watcher.watcher.requests.get")
    def test_contenu_non_html_pas_de_html(self, mock_get):
        mock_get.return_value = _http_response(200, content_type="application/json", text="{}")
        self.assertIsNone(fetch_site("example.com")["html"])

    @patch("web_watcher.watcher.MAX_HTML_CHARS", 10)
    @patch("web_watcher.watcher.requests.get")
    def test_html_tronque(self, mock_get):
        mock_get.return_value = _http_response(200, text="x" * 100)
        self.assertEqual(len(fetch_site("example.com")["html"]), 10)

    @patch("web_watcher.watcher.time.sleep")
    @patch("web_watcher.watcher.requests.get", side_effect=requests.exceptions.ConnectionError())
    def test_echec_apres_tous_les_essais(self, mock_get, mock_sleep):
        with patch.object(utils, "HTTP_RETRIES", 2):
            r = fetch_site("down.fr")
        self.assertEqual(r, {"status": None, "elapsed": None, "html": None})
        self.assertEqual(mock_get.call_count, 2)

    @patch("web_watcher.watcher.time.sleep")
    @patch("web_watcher.watcher.requests.get")
    def test_succes_au_second_essai(self, mock_get, mock_sleep):
        mock_get.side_effect = [requests.exceptions.Timeout(), _http_response(200)]
        with patch.object(utils, "HTTP_RETRIES", 2):
            r = fetch_site("lent.fr")
        self.assertEqual(r["status"], 200)
        self.assertEqual(mock_get.call_count, 2)


# ─── is_up / classify_response_time ──────────────────────────────────────────

class TestIsUp(unittest.TestCase):

    def test_codes_up(self):
        for code in (200, 204, 301, 302):
            self.assertTrue(is_up(code), code)

    def test_waf_pas_down(self):
        for code in (401, 403, 429):
            self.assertTrue(is_up(code), code)

    def test_codes_down(self):
        for code in (404, 500, 502, 503):
            self.assertFalse(is_up(code), code)

    def test_injoignable(self):
        self.assertFalse(is_up(None))


@patch.object(utils, "RESPONSE_WARN_SECONDS", 3)
@patch.object(utils, "RESPONSE_KO_SECONDS", 8)
class TestClassifyResponseTime(unittest.TestCase):

    def test_injoignable(self):
        self.assertEqual(classify_response_time(None), "N/A")

    def test_ok(self):
        self.assertEqual(classify_response_time(0.5), "OK")

    def test_def(self):
        self.assertEqual(classify_response_time(3), "DEF")
        self.assertEqual(classify_response_time(5), "DEF")

    def test_ko(self):
        self.assertEqual(classify_response_time(8), "KO")
        self.assertEqual(classify_response_time(12), "KO")


# ─── ssl_days_left ────────────────────────────────────────────────────────────

class TestSslDaysLeft(unittest.TestCase):

    def _mock_cert(self, mock_ctx, days):
        not_after = (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%b %d %H:%M:%S %Y GMT")
        conn = mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value
        conn.getpeercert.return_value = {"notAfter": not_after}

    @patch("web_watcher.watcher.socket.create_connection")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_certificat_valide(self, mock_ctx, mock_conn):
        self._mock_cert(mock_ctx, 60)
        self.assertIn(ssl_days_left("example.com"), (59, 60))

    @patch("web_watcher.watcher.socket.create_connection")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_certificat_expirant(self, mock_ctx, mock_conn):
        self._mock_cert(mock_ctx, 10)
        self.assertIn(ssl_days_left("example.com"), (9, 10))

    @patch("web_watcher.watcher.socket.create_connection")
    @patch("web_watcher.watcher.ssl.create_default_context")
    def test_certificat_invalide_retourne_zero(self, mock_ctx, mock_conn):
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError("expired")
        self.assertEqual(ssl_days_left("expired.badssl.com"), 0)

    @patch("web_watcher.watcher.socket.create_connection", side_effect=socket.timeout())
    def test_timeout_retourne_none(self, _):
        self.assertIsNone(ssl_days_left("example.com"))

    @patch("web_watcher.watcher.socket.create_connection", side_effect=ConnectionRefusedError())
    def test_connexion_refusee_retourne_none(self, _):
        self.assertIsNone(ssl_days_left("example.com"))


# ─── get_ssl_status ───────────────────────────────────────────────────────────

@patch.object(utils, "SSL_CACHE_HOURS", 6)
class TestGetSslStatus(unittest.TestCase):

    @patch("web_watcher.watcher.ssl_days_left")
    def test_cache_valide(self, mock_days):
        previous = {"ssl_days_left": 40, "ssl_checked_at": datetime.now(PARIS).isoformat()}
        days, checked = get_ssl_status("a.fr", previous)
        mock_days.assert_not_called()
        self.assertEqual((days, checked), (40, previous["ssl_checked_at"]))

    @patch("web_watcher.watcher.ssl_days_left")
    def test_certificat_invalide_aussi_en_cache(self, mock_days):
        previous = {"ssl_days_left": 0, "ssl_checked_at": datetime.now(PARIS).isoformat()}
        self.assertEqual(get_ssl_status("a.fr", previous)[0], 0)
        mock_days.assert_not_called()

    @patch("web_watcher.watcher.ssl_days_left", return_value=25)
    def test_cache_expire(self, mock_days):
        old = (datetime.now(PARIS) - timedelta(hours=10)).isoformat()
        days, checked = get_ssl_status("a.fr", {"ssl_days_left": 40, "ssl_checked_at": old})
        mock_days.assert_called_once_with("a.fr")
        self.assertEqual(days, 25)
        self.assertNotEqual(checked, old)

    @patch("web_watcher.watcher.ssl_days_left", return_value=60)
    def test_pas_d_historique(self, mock_days):
        days, checked = get_ssl_status("a.fr", {})
        self.assertEqual(days, 60)
        self.assertIsNotNone(checked)

    @patch("web_watcher.watcher.ssl_days_left", return_value=None)
    def test_verification_impossible_garde_la_derniere_valeur(self, _):
        old = (datetime.now(PARIS) - timedelta(hours=10)).isoformat()
        self.assertEqual(get_ssl_status("a.fr", {"ssl_days_left": 40, "ssl_checked_at": old}), (40, old))

    @patch("web_watcher.watcher.ssl_days_left", return_value=None)
    def test_verification_impossible_sans_historique(self, _):
        self.assertEqual(get_ssl_status("a.fr", {}), (None, None))


# ─── check_site ───────────────────────────────────────────────────────────────

TARGET = {"domain": "example.com", "longitude": 2.35, "latitude": 48.85,
          "label": "Example", "title": "Example", "scan_mode": "passive"}


def _fetch(status=200, elapsed=0.5, html="<html><head><title>Example</title></head></html>"):
    return {"status": status, "elapsed": elapsed, "html": html}


class TestCheckSite(unittest.TestCase):

    def _run(self, fetch, previous=None, ssl_status=(60, "ts"), defacement="SITE OK (non défacé)"):
        with patch("web_watcher.watcher.fetch_site", return_value=fetch), \
             patch("web_watcher.watcher.get_ssl_status", return_value=ssl_status), \
             patch("web_watcher.watcher.probability_site_defaced", return_value=defacement) as mock_def, \
             patch.object(utils, "RESPONSE_WARN_SECONDS", 3), \
             patch.object(utils, "RESPONSE_KO_SECONDS", 8), \
             patch.object(utils, "SSL_EXPIRY_WARNING_DAYS", 30):
            return check_site(TARGET, previous or {}), mock_def

    def test_nominal(self):
        result, mock_def = self._run(_fetch())
        self.assertTrue(result["site_up"])
        self.assertTrue(result["ssl_ok"])
        self.assertEqual(result["response_time"], "OK")
        self.assertEqual(result["defacement"], "SITE OK (non défacé)")
        self.assertEqual(result["failures"], {"down": 0, "slow": 0, "defacement": 0})
        self.assertEqual(result["localisation"], "(48.85, 2.35)")
        mock_def.assert_called_once_with("example.com", "Example", content=_fetch()["html"])

    def test_site_injoignable(self):
        result, mock_def = self._run({"status": None, "elapsed": None, "html": None})
        self.assertFalse(result["site_up"])
        self.assertEqual(result["response_time"], "N/A")
        self.assertEqual(result["failures"]["down"], 1)
        mock_def.assert_not_called()

    def test_page_d_erreur_pas_analysee_pour_defacement(self):
        result, mock_def = self._run(_fetch(status=404))
        self.assertFalse(result["site_up"])
        mock_def.assert_not_called()

    def test_waf_403_pas_down_et_pas_de_defacement(self):
        result, mock_def = self._run(_fetch(status=403))
        self.assertTrue(result["site_up"])
        mock_def.assert_not_called()

    def test_site_lent(self):
        result, _ = self._run(_fetch(elapsed=5))
        self.assertEqual(result["response_time"], "DEF")
        self.assertEqual(result["failures"]["slow"], 1)

    def test_compteurs_incrementes(self):
        previous = {"failures": {"down": 1, "slow": 0, "defacement": 1}}
        result, _ = self._run(_fetch(), previous=previous, defacement="DEFACEMENT PROBABLE")
        self.assertEqual(result["failures"]["defacement"], 2)
        self.assertEqual(result["failures"]["down"], 0)

    def test_compteurs_remis_a_zero(self):
        previous = {"failures": {"down": 3, "slow": 2, "defacement": 2}}
        result, _ = self._run(_fetch(), previous=previous)
        self.assertEqual(result["failures"], {"down": 0, "slow": 0, "defacement": 0})

    def test_ssl_expire_bientot(self):
        result, _ = self._run(_fetch(), ssl_status=(10, "ts"))
        self.assertFalse(result["ssl_ok"])

    def test_ssl_verification_impossible_pas_d_alerte(self):
        result, _ = self._run(_fetch(), ssl_status=(None, None))
        self.assertTrue(result["ssl_ok"])


class TestSafeCheck(unittest.TestCase):

    @patch("web_watcher.watcher.check_site", return_value={"domain": "a.fr"})
    def test_transmet_l_historique_du_domaine(self, mock_check):
        previous = {"a.fr": {"failures": {"down": 1}}}
        self.assertEqual(safe_check({"domain": "a.fr"}, previous), {"domain": "a.fr"})
        mock_check.assert_called_once_with({"domain": "a.fr"}, {"failures": {"down": 1}})

    @patch("web_watcher.watcher.check_site", side_effect=RuntimeError("boom"))
    def test_erreur_retourne_none(self, _):
        self.assertIsNone(safe_check({"domain": "a.fr"}, {}))


class TestLoadPrevious(unittest.TestCase):

    def test_indexe_par_domaine(self):
        data = json.dumps({"sites": [{"domain": "a.fr", "site_up": True}]})
        with patch("builtins.open", mock_open(read_data=data)):
            self.assertEqual(load_previous(), {"a.fr": {"domain": "a.fr", "site_up": True}})

    def test_fichier_absent(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            self.assertEqual(load_previous(), {})

    def test_json_corrompu(self):
        with patch("builtins.open", mock_open(read_data="{{{")):
            self.assertEqual(load_previous(), {})


# ─── confirmed / create_alerts ────────────────────────────────────────────────

class TestConfirmed(unittest.TestCase):

    @patch.object(utils, "FAILURES_BEFORE_ALERT", 2)
    def test_seuil(self):
        self.assertTrue(confirmed({}, "down"))                              # pas de compteur
        self.assertFalse(confirmed({"failures": {"down": 1}}, "down"))
        self.assertTrue(confirmed({"failures": {"down": 2}}, "down"))
        self.assertFalse(confirmed({"failures": {}}, "down"))


def _site(**over):
    site = {"domain": "example.com", "site_up": True, "ssl_ok": True,
            "response_time": "OK", "defacement": "SITE OK (non défacé)"}
    site.update(over)
    return site


@patch.object(utils, "FAILURES_BEFORE_ALERT", 2)
@patch.object(utils, "RESPONSE_KO_SECONDS", 8)
class TestCreateAlerts(unittest.TestCase):

    def test_aucune_alerte(self):
        self.assertEqual(create_alerts([_site()]), {})

    def test_site_down(self):
        result = create_alerts([_site(site_up=False)])
        self.assertEqual(result["example.com"][0]["level"], "CRITICAL")
        self.assertIn("DOWN", result["example.com"][0]["message"])

    def test_down_non_confirme(self):
        self.assertEqual(create_alerts([_site(site_up=False, failures={"down": 1})]), {})

    def test_down_confirme(self):
        self.assertIn("example.com", create_alerts([_site(site_up=False, failures={"down": 2})]))

    def test_ssl_alerte_immediate(self):
        result = create_alerts([_site(ssl_ok=False, failures={"down": 0})])
        self.assertEqual(result["example.com"][0]["level"], "WARNING")

    def test_temps_long(self):
        result = create_alerts([_site(response_time="DEF")])
        self.assertIn("temps de réponse long", result["example.com"][0]["message"])

    def test_temps_tres_long(self):
        result = create_alerts([_site(response_time="KO")])
        self.assertIn("très long", result["example.com"][0]["message"])

    def test_defacement_fortement_probable_critical(self):
        result = create_alerts([_site(defacement="DEFACEMENT FORTEMENT PROBABLE")])
        self.assertEqual(result["example.com"][0]["level"], "CRITICAL")

    def test_defacement_probable_warning(self):
        result = create_alerts([_site(defacement="DEFACEMENT PROBABLE")])
        self.assertEqual(result["example.com"][0]["level"], "WARNING")

    def test_defacement_peu_probable_pas_d_alerte(self):
        self.assertEqual(create_alerts([_site(defacement="DEFACEMENT PEU PROBABLE")]), {})

    def test_plusieurs_alertes_meme_domaine(self):
        result = create_alerts([_site(site_up=False, ssl_ok=False, response_time="DEF", defacement="DEFACEMENT PROBABLE")])
        self.assertEqual(len(result["example.com"]), 4)

    def test_groupees_par_domaine(self):
        result = create_alerts([_site(domain="a.com", site_up=False), _site(domain="b.com", ssl_ok=False)])
        self.assertEqual(set(result), {"a.com", "b.com"})


# ─── run_watcher_cycle ────────────────────────────────────────────────────────

def _result(domain, **over):
    r = {"domain": domain, "site_up": True, "ssl_ok": True, "ssl_days_left": 60, "ssl_checked_at": "x",
         "response_time": "OK", "response_seconds": 0.5, "defacement": "SITE OK (non défacé)",
         "failures": {"down": 0, "slow": 0, "defacement": 0}, "checked_at": "x", "localisation": "(48.0, 2.0)"}
    r.update(over)
    return r


class TestRunWatcherCycle(unittest.TestCase):

    DOMAINS = [{"domain": "a.fr"}, {"domain": "b.fr"}]

    def _cycle(self, domains, check_fn, post_side_effect=None):
        with patch("web_watcher.utils.load_domains", return_value=domains), \
             patch("web_watcher.watcher.load_previous", return_value={}), \
             patch("web_watcher.watcher.check_site", side_effect=check_fn), \
             patch("web_watcher.watcher.requests.post", side_effect=post_side_effect) as mock_post, \
             patch("web_watcher.watcher.Path"), \
             patch("web_watcher.watcher.json.dump") as mock_dump, \
             patch("builtins.open", new_callable=mock_open), \
             patch.object(utils, "FAILURES_BEFORE_ALERT", 1):
            run_watcher_cycle()
        return mock_post, mock_dump

    def test_nominal_sans_alerte(self):
        mock_post, mock_dump = self._cycle(self.DOMAINS, lambda d, prev: _result(d["domain"]))
        written = mock_dump.call_args[0][0]
        self.assertEqual([s["domain"] for s in written["sites"]], ["a.fr", "b.fr"])
        self.assertIn("last_run", written)
        mock_post.assert_not_called()

    def test_domaines_vides(self):
        mock_post, mock_dump = self._cycle([], lambda d, prev: _result(d["domain"]))
        self.assertEqual(mock_dump.call_args[0][0]["sites"], [])
        mock_post.assert_not_called()

    def test_alerte_envoyee_au_alert_service(self):
        fn = lambda d, prev: _result(d["domain"], site_up=(d["domain"] != "a.fr"))
        mock_post, _ = self._cycle(self.DOMAINS, fn)
        mock_post.assert_called_once()
        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(payload["service"], "web_watcher")
        self.assertIn("a.fr", payload["alerts"])
        self.assertNotIn("b.fr", payload["alerts"])

    def test_alert_service_injoignable_ne_leve_pas(self):
        fn = lambda d, prev: _result(d["domain"], site_up=False)
        _, mock_dump = self._cycle(self.DOMAINS, fn, post_side_effect=requests.exceptions.ConnectionError())
        mock_dump.assert_called_once()

    def test_un_site_en_erreur_n_arrete_pas_le_cycle(self):
        def fn(d, prev):
            if d["domain"] == "a.fr":
                raise RuntimeError("boom")
            return _result(d["domain"])
        _, mock_dump = self._cycle(self.DOMAINS, fn)
        self.assertEqual([s["domain"] for s in mock_dump.call_args[0][0]["sites"]], ["b.fr"])


if __name__ == "__main__":
    unittest.main()