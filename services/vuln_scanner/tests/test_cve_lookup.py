import unittest
from unittest.mock import patch, MagicMock
import nmap
import requests
from vuln_scanner import utils
from vuln_scanner import cve_lookup as cl


# ─── Parsing et versions ──────────────────────────────────────────────────────

class TestParsing(unittest.TestCase):

    def test_parse_idb_cpe_format_22(self):
        self.assertEqual(cl.parse_idb_cpe("cpe:/a:apache:http_server:2.4.41"), ("a", "apache", "http_server", "2.4.41"))

    def test_parse_idb_cpe_sans_version(self):
        self.assertEqual(cl.parse_idb_cpe("cpe:/a:apache:http_server"), ("a", "apache", "http_server", None))

    def test_parse_idb_cpe_format_23(self):
        self.assertEqual(cl.parse_idb_cpe("cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*"), ("a", "openbsd", "openssh", "9.2"))

    def test_parse_idb_cpe_format_23_version_joker(self):
        self.assertEqual(cl.parse_idb_cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"), ("a", "openbsd", "openssh", None))

    def test_parse_idb_cpe_invalide(self):
        self.assertIsNone(cl.parse_idb_cpe("n'importe quoi"))

    def test_parse_stack_garde_le_premier_token(self):
        self.assertEqual(cl.parse_stack("Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1"), ("Apache", "2.4.41"))

    def test_parse_stack_sans_version(self):
        self.assertEqual(cl.parse_stack("nginx"), ("nginx", None))

    def test_parse_stack_vide(self):
        self.assertEqual(cl.parse_stack(None), (None, None))
        self.assertEqual(cl.parse_stack(""), (None, None))

    def test_parse_stack_version_partielle(self):
        self.assertEqual(cl.parse_stack("PHP/8.2"), ("PHP", "8.2"))


class TestVersions(unittest.TestCase):

    def test_is_partial_version(self):
        self.assertTrue(cl.is_partial_version("8.2"))
        self.assertTrue(cl.is_partial_version("8"))
        self.assertFalse(cl.is_partial_version("8.2.12"))

    def test_version_precision(self):
        self.assertEqual(cl.version_precision(["apache"], "http_server", "2.4.41"), "exact")
        self.assertEqual(cl.version_precision(["php"], "php", "8.2"), "range")
        # OpenSSH n'a que deux nombres : "9.2" est complète
        self.assertEqual(cl.version_precision(["openbsd"], "openssh", "9.2"), "exact")

    def test_normalize_version(self):
        self.assertEqual(cl.normalize_version("7.4p1"), "7.4")
        self.assertEqual(cl.normalize_version("1.18.0-ubuntu"), "1.18.0")
        self.assertIsNone(cl.normalize_version(None))
        self.assertIsNone(cl.normalize_version("abc"))
        self.assertIsNone(cl.normalize_version(""))

    def test_version_tuple(self):
        self.assertEqual(cl.version_tuple("2.4.41"), (2, 4, 41))
        self.assertEqual(cl.version_tuple(None), ())
        self.assertEqual(cl.version_tuple("abc"), ())
        self.assertGreater(cl.version_tuple("2.4.58"), cl.version_tuple("2.4.41"))
        self.assertGreater(cl.version_tuple("2.10.0"), cl.version_tuple("2.9.0"))

    def test_next_version(self):
        self.assertEqual(cl.next_version("8.2"), "8.3")
        self.assertEqual(cl.next_version("8"), "9")
        self.assertEqual(cl.next_version("2.4.9"), "2.4.10")

    def test_build_cpe_params_version_exacte(self):
        self.assertEqual(cl.build_cpe_params("php", "php", "8.2.12"),
                         {"virtualMatchString": "cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*"})

    def test_build_cpe_params_version_partielle_cherche_une_plage(self):
        p = cl.build_cpe_params("php", "php", "8.2")
        self.assertEqual(p["virtualMatchString"], "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")
        self.assertEqual((p["versionStart"], p["versionEnd"]), ("8.2", "8.3"))
        self.assertEqual((p["versionStartType"], p["versionEndType"]), ("including", "excluding"))

    def test_build_cpe_params_exact_force(self):
        p = cl.build_cpe_params("openbsd", "openssh", "9.2", exact=True)
        self.assertEqual(p, {"virtualMatchString": "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*"})

    def test_extract_cvss(self):
        v31 = {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}
        v2 = {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]}
        self.assertEqual(cl.extract_cvss(v31), 9.8)
        self.assertEqual(cl.extract_cvss(v2), 7.5)
        self.assertEqual(cl.extract_cvss({**v2, **v31}), 9.8)
        self.assertIsNone(cl.extract_cvss({}))

    def test_expected_ports(self):
        self.assertEqual(cl.expected_ports(["apache"], "http_server", [80, 22]), [80])


# ─── Fusion de la stack ───────────────────────────────────────────────────────

class TestMergeStack(unittest.TestCase):

    def test_la_version_la_plus_recente_gagne(self):
        inv = {}
        cl.add_candidate(inv, "Apache", "2.4.58", "headers")
        cl.add_candidate(inv, "http_server", "2.4.41", "internetdb", vendor="apache")
        items, notes, idb_outdated = cl.merge_stack(inv, [80, 443], "d.fr")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["version"], "2.4.58")
        self.assertEqual(items[0]["source"], "headers")
        self.assertEqual(items[0]["ports"], [80, 443])
        self.assertEqual(items[0]["scope"], "web")
        self.assertTrue(idb_outdated)
        self.assertEqual(notes, [])

    def test_internetdb_plus_recent_que_le_header_n_est_pas_perime(self):
        inv = {}
        cl.add_candidate(inv, "Apache", "2.4.30", "headers")
        cl.add_candidate(inv, "http_server", "2.4.41", "internetdb", vendor="apache")
        items, _, idb_outdated = cl.merge_stack(inv, [80], "d.fr")
        self.assertEqual(items[0]["version"], "2.4.41")
        self.assertFalse(idb_outdated)

    def test_version_moins_precise_de_la_meme_branche_ne_contredit_pas(self):
        inv = {}
        cl.add_candidate(inv, "PHP", "8.2", "headers")
        cl.add_candidate(inv, "php", "8.2.12", "internetdb", vendor="php")
        items, notes, idb_outdated = cl.merge_stack(inv, [80], "d.fr")
        self.assertEqual(items[0]["version"], "8.2.12")
        self.assertFalse(idb_outdated)
        self.assertEqual(notes, [])

    def test_egalite_la_source_la_plus_fiable_gagne(self):
        inv = {}
        cl.add_candidate(inv, "Apache", "2.4.58", "headers")
        cl.add_candidate(inv, "Apache httpd", "2.4.58", "nmap", ports=[80])
        items, _, _ = cl.merge_stack(inv, [], "d.fr")
        self.assertEqual(items[0]["source"], "nmap")
        self.assertEqual(items[0]["sources"], ["headers", "nmap"])
        self.assertEqual(items[0]["ports"], [80])

    def test_version_masquee_genere_une_note(self):
        inv = {}
        cl.add_candidate(inv, "nginx", None, "headers")
        items, notes, _ = cl.merge_stack(inv, [], "d.fr")
        self.assertEqual(items, [])
        self.assertEqual(notes[0]["description"], "Version masquée pour nginx")
        self.assertIsNone(notes[0]["id"])

    def test_version_partielle_genere_une_note(self):
        inv = {}
        cl.add_candidate(inv, "PHP", "8.5", "headers")
        items, notes, _ = cl.merge_stack(inv, [], "d.fr")
        self.assertEqual(items[0]["version"], "8.5")
        self.assertIn("Version partielle pour PHP (8.5)", notes[0]["description"])

    def test_openssh_deux_nombres_pas_de_note(self):
        inv = {}
        cl.add_candidate(inv, "OpenSSH", "9.2", "nmap", ports=[22])
        _, notes, _ = cl.merge_stack(inv, [], "d.fr")
        self.assertEqual(notes, [])

    def test_produit_inconnu_recherche_par_mot_cle(self):
        inv = {}
        cl.add_candidate(inv, "FooServer", "1.0.0", "headers")
        items, _, _ = cl.merge_stack(inv, [], "d.fr")
        self.assertEqual(items[0]["key"], "kw:fooserver")

    def test_internetdb_seul_sans_version_ignore(self):
        inv = {}
        cl.add_candidate(inv, "http_server", None, "internetdb", vendor="apache")
        items, notes, _ = cl.merge_stack(inv, [], "d.fr")
        self.assertEqual((items, notes), ([], []))


# ─── NVD ──────────────────────────────────────────────────────────────────────

def _nvd_item(cve_id, score, desc="desc"):
    metrics = {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]} if score is not None else {}
    return {"cve": {"id": cve_id, "descriptions": [{"lang": "en", "value": desc}], "metrics": metrics}}


def _nvd_response(items):
    r = MagicMock()
    r.json.return_value = {"vulnerabilities": items}
    return r


class TestQueryNvd(unittest.TestCase):

    @patch("vuln_scanner.cve_lookup.time.sleep")
    @patch("vuln_scanner.cve_lookup.requests.get")
    def test_filtre_sur_cvss_min(self, mock_get, mock_sleep):
        mock_get.return_value = _nvd_response([_nvd_item("CVE-1", 9.8), _nvd_item("CVE-2", 5.0), _nvd_item("CVE-3", None)])
        with patch.object(utils, "NVD_API_KEY", "key"), patch.object(utils, "CVSS_MIN", 7.0):
            cves = cl.query_nvd({"virtualMatchString": "x"}, "d.fr", "x")
        self.assertEqual([c["id"] for c in cves], ["CVE-1"])
        self.assertEqual(cves[0]["cvss"], 9.8)
        self.assertEqual(cves[0]["description"], "desc")

    @patch("vuln_scanner.cve_lookup.time.sleep")
    @patch("vuln_scanner.cve_lookup.requests.get")
    def test_seuil_inclusif(self, mock_get, mock_sleep):
        mock_get.return_value = _nvd_response([_nvd_item("CVE-1", 7.0)])
        with patch.object(utils, "NVD_API_KEY", "key"), patch.object(utils, "CVSS_MIN", 7.0):
            self.assertEqual(len(cl.query_nvd({}, "d.fr", "x")), 1)

    @patch("vuln_scanner.cve_lookup.time.sleep")
    @patch("vuln_scanner.cve_lookup.requests.get")
    def test_cle_api_envoyee_sans_attente(self, mock_get, mock_sleep):
        mock_get.return_value = _nvd_response([])
        with patch.object(utils, "NVD_API_KEY", "secret"):
            cl.query_nvd({}, "d.fr", "x")
        self.assertEqual(mock_get.call_args.kwargs["headers"], {"apiKey": "secret"})
        mock_sleep.assert_not_called()

    @patch("vuln_scanner.cve_lookup.time.sleep")
    @patch("vuln_scanner.cve_lookup.requests.get")
    def test_sans_cle_attend_6_secondes(self, mock_get, mock_sleep):
        mock_get.return_value = _nvd_response([])
        with patch.object(utils, "NVD_API_KEY", ""):
            cl.query_nvd({}, "d.fr", "x")
        mock_sleep.assert_called_once_with(6)

    @patch("vuln_scanner.cve_lookup.time.sleep")
    @patch("vuln_scanner.cve_lookup.requests.get", side_effect=requests.exceptions.Timeout())
    def test_retries_puis_liste_vide(self, mock_get, mock_sleep):
        with patch.object(utils, "NVD_API_KEY", "key"):
            self.assertEqual(cl.query_nvd({}, "d.fr", "x"), [])
        self.assertEqual(mock_get.call_count, cl.NVD_RETRIES)
        self.assertEqual([c.args[0] for c in mock_sleep.call_args_list], [10, 20])


class TestLookupItem(unittest.TestCase):

    ITEM = {"key": "http_server", "name": "Apache", "vendors": ["apache"], "part": "a", "version": "2.4.58",
            "source": "headers", "sources": ["headers"], "ports": [80], "scope": "web"}

    @staticmethod
    def _nvd(*args, **kwargs):
        return [{"id": "CVE-1", "cvss": 9.8, "description": "d"}]

    def test_version_exacte(self):
        with patch("vuln_scanner.cve_lookup.query_nvd", side_effect=self._nvd) as mock_q:
            cves = cl.lookup_item(self.ITEM, "d.fr")
        c = cves[0]
        self.assertEqual(c["match"], "exact")
        self.assertEqual(c["component"], "apache:http_server 2.4.58")
        self.assertEqual((c["ports"], c["scope"], c["source"]), ([80], "web", "headers"))
        self.assertEqual(mock_q.call_args[0][0]["virtualMatchString"], "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*")

    def test_version_partielle_donne_range(self):
        item = {**self.ITEM, "key": "php", "vendors": ["php"], "version": "8.2"}
        with patch("vuln_scanner.cve_lookup.query_nvd", side_effect=self._nvd) as mock_q:
            cves = cl.lookup_item(item, "d.fr")
        self.assertEqual(cves[0]["match"], "range")
        self.assertEqual(mock_q.call_args[0][0]["versionStart"], "8.2")

    def test_plusieurs_vendors_plusieurs_requetes(self):
        item = {**self.ITEM, "key": "nginx", "vendors": ["f5", "nginx"], "version": "1.25.3"}
        with patch("vuln_scanner.cve_lookup.query_nvd", side_effect=self._nvd) as mock_q:
            cl.lookup_item(item, "d.fr")
        self.assertEqual(mock_q.call_count, 2)

    def test_produit_inconnu_recherche_par_mot_cle(self):
        item = {**self.ITEM, "key": "kw:fooserver", "name": "FooServer", "vendors": [], "version": "1.0.0"}
        with patch("vuln_scanner.cve_lookup.query_nvd", side_effect=self._nvd) as mock_q:
            cves = cl.lookup_item(item, "d.fr")
        self.assertEqual(mock_q.call_args[0][0], {"keywordSearch": "FooServer 1.0.0"})
        self.assertEqual(cves[0]["match"], "keyword")
        self.assertEqual(cves[0]["component"], "FooServer 1.0.0")


class TestDedupe(unittest.TestCase):

    def test_garde_la_correspondance_la_plus_precise(self):
        cves = [{"id": "CVE-1", "match": "range"}, {"id": "CVE-1", "match": "exact"}, {"id": "CVE-2", "match": "keyword"}]
        result = {c["id"]: c["match"] for c in cl.dedupe(cves)}
        self.assertEqual(result, {"CVE-1": "exact", "CVE-2": "keyword"})

    def test_conserve_les_notes_sans_id(self):
        cves = [{"id": None, "description": "note"}, {"id": "CVE-1", "match": "exact"}]
        self.assertEqual(len(cl.dedupe(cves)), 2)


# ─── Collecte brute ───────────────────────────────────────────────────────────

class TestGetStack(unittest.TestCase):

    @patch("vuln_scanner.cve_lookup.requests.get")
    def test_lit_les_headers(self, mock_get):
        mock_get.return_value = MagicMock(headers={"Server": "nginx", "X-Powered-By": "PHP/8.2"})
        self.assertEqual(cl.get_stack("d.fr"), {"server": "nginx", "x_powered_by": "PHP/8.2"})

    @patch("vuln_scanner.cve_lookup.requests.get", side_effect=requests.exceptions.ConnectionError())
    def test_erreur_reseau(self, _):
        self.assertEqual(cl.get_stack("d.fr"), {"server": None, "x_powered_by": None})


def _ip(address):
    return MagicMock(**{"to_text.return_value": address})


def _idb_response(status=200, **data):
    r = MagicMock(status_code=status)
    r.json.return_value = data
    return r


class TestGetInternetdb(unittest.TestCase):

    @patch("vuln_scanner.cve_lookup.time.sleep")
    @patch("vuln_scanner.cve_lookup.requests.get")
    @patch("vuln_scanner.cve_lookup.dns.resolver.resolve")
    def test_fusionne_les_ip(self, mock_resolve, mock_get, mock_sleep):
        mock_resolve.return_value = [_ip("1.1.1.1"), _ip("2.2.2.2")]
        mock_get.side_effect = [
            _idb_response(ports=[80, 443], cpes=["cpe:/a:nginx:nginx:1.18.0"], vulns=["CVE-1"]),
            _idb_response(ports=[22, 80], cpes=[], vulns=["CVE-2"], hostnames=["h.fr"]),
        ]
        result = cl.get_internetdb("d.fr")
        self.assertEqual(result["ips"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(result["ports"], [22, 80, 443])
        self.assertEqual(result["vulns"], ["CVE-1", "CVE-2"])
        self.assertEqual(result["hostnames"], ["h.fr"])

    @patch("vuln_scanner.cve_lookup.time.sleep")
    @patch("vuln_scanner.cve_lookup.requests.get")
    @patch("vuln_scanner.cve_lookup.dns.resolver.resolve")
    def test_aucune_donnee(self, mock_resolve, mock_get, mock_sleep):
        mock_resolve.return_value = [_ip("1.1.1.1")]
        mock_get.return_value = MagicMock(status_code=404)
        self.assertIsNone(cl.get_internetdb("d.fr"))

    @patch("vuln_scanner.cve_lookup.dns.resolver.resolve", side_effect=Exception("NXDOMAIN"))
    def test_dns_impossible(self, _):
        self.assertIsNone(cl.get_internetdb("d.fr"))


class TestGetStackNmap(unittest.TestCase):

    @patch("vuln_scanner.cve_lookup.nmap.PortScanner")
    def test_ports_ouverts_uniquement(self, mock_scanner):
        nm = mock_scanner.return_value
        nm.all_hosts.return_value = ["1.2.3.4"]
        nm.__getitem__.return_value = {"tcp": {
            22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.2"},
            23: {"state": "closed", "name": "telnet", "product": "", "version": ""},
        }}
        self.assertEqual(cl.get_stack_nmap("d.fr"),
                         [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2"}])

    @patch("vuln_scanner.cve_lookup.nmap.PortScanner", side_effect=nmap.PortScannerError("introuvable"))
    def test_nmap_absent(self, _):
        self.assertEqual(cl.get_stack_nmap("d.fr"), [])

    @patch("vuln_scanner.cve_lookup.nmap.PortScanner")
    def test_aucun_hote(self, mock_scanner):
        mock_scanner.return_value.all_hosts.return_value = []
        self.assertEqual(cl.get_stack_nmap("d.fr"), [])


# ─── check ────────────────────────────────────────────────────────────────────

IDB = {"ips": ["1.2.3.4"], "ports": [80, 443], "cpes": ["cpe:/a:apache:http_server:2.4.41"],
       "hostnames": [], "tags": [], "vulns": ["CVE-2020-0001"]}
NO_STACK = {"server": None, "x_powered_by": None}


class TestCheck(unittest.TestCase):

    def _run(self, stack, idb=None, nmap_ports=None, cves=None, scan_mode="passive"):
        with patch("vuln_scanner.cve_lookup.get_stack", return_value=stack), \
             patch("vuln_scanner.cve_lookup.get_internetdb", return_value=idb), \
             patch("vuln_scanner.cve_lookup.get_stack_nmap", return_value=nmap_ports or []) as mock_nmap, \
             patch("vuln_scanner.cve_lookup.lookup_item",
                   side_effect=lambda item, domain: [dict(c) for c in (cves or [])]) as mock_lookup:
            result = cl.check("d.fr", scan_mode=scan_mode)
        return result, mock_nmap, mock_lookup

    def test_passif_n_appelle_pas_nmap(self):
        cve = {"id": "CVE-1", "cvss": 9.8, "description": "d", "match": "exact"}
        result, mock_nmap, mock_lookup = self._run({"server": "Apache/2.4.58", "x_powered_by": None}, cves=[cve])
        mock_nmap.assert_not_called()
        self.assertEqual(result["server"], "Apache/2.4.58")
        self.assertEqual([c["id"] for c in result["cves"]], ["CVE-1"])
        self.assertEqual(mock_lookup.call_args[0][0]["version"], "2.4.58")
        self.assertEqual(result["ports"], [])

    def test_actif_appelle_nmap_et_fusionne(self):
        nmap_ports = [{"port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.2"}]
        result, mock_nmap, mock_lookup = self._run(NO_STACK, nmap_ports=nmap_ports, scan_mode="active")
        mock_nmap.assert_called_once()
        item = mock_lookup.call_args[0][0]
        self.assertEqual((item["key"], item["version"], item["source"], item["ports"]), ("openssh", "9.2", "nmap", [22]))
        self.assertEqual(result["ports"], [{**nmap_ports[0], "cves": []}])

    def test_echec_nmap_ne_leve_pas(self):
        with patch("vuln_scanner.cve_lookup.get_stack", return_value=NO_STACK), \
             patch("vuln_scanner.cve_lookup.get_internetdb", return_value=None), \
             patch("vuln_scanner.cve_lookup.get_stack_nmap", side_effect=Exception("boom")):
            result = cl.check("d.fr", scan_mode="active")
        self.assertEqual(result["ports"], [])

    def test_version_masquee_donne_une_note(self):
        result, _, _ = self._run({"server": "nginx", "x_powered_by": None})
        self.assertEqual(result["cves"][0]["description"], "Version masquée pour nginx")

    def test_internetdb_seul_ajoute_ses_cve_brutes(self):
        result, _, mock_lookup = self._run(NO_STACK, idb=IDB)
        self.assertEqual(mock_lookup.call_args[0][0]["version"], "2.4.41")
        raw = [c for c in result["cves"] if c["id"] == "CVE-2020-0001"]
        self.assertEqual(len(raw), 1)
        self.assertIsNone(raw[0]["cvss"])
        self.assertEqual(raw[0]["source"], "internetdb")

    def test_internetdb_perime_ses_cve_brutes_sont_ignorees(self):
        result, _, _ = self._run({"server": "Apache/2.4.58", "x_powered_by": None}, idb=IDB)
        self.assertNotIn("CVE-2020-0001", [c["id"] for c in result["cves"]])

    def test_header_plus_ancien_que_internetdb_garde_les_cve_brutes(self):
        result, _, _ = self._run({"server": "Apache/2.4.30", "x_powered_by": None}, idb=IDB)
        self.assertIn("CVE-2020-0001", [c["id"] for c in result["cves"]])

    def test_internetdb_expose_dans_le_resultat(self):
        result, _, _ = self._run(NO_STACK, idb=IDB)
        self.assertEqual(result["internetdb"], IDB)


if __name__ == "__main__":
    unittest.main()