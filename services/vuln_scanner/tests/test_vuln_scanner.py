import json
import os
import tempfile
import unittest
from unittest.mock import patch
import requests
from vuln_scanner import utils
from vuln_scanner.vuln_scanner import (
    match_note,
    cve_location,
    alert_level,
    build_alerts,
    send_alerts,
    run_cycle,
)

EMPTY_SUB = {"subdomains": [], "alerts": []}
EMPTY_DNS = {"spf": True, "dmarc": True, "dmarc_policy": "reject", "alerts": []}
EMPTY_TWIST = {"typosquatting": [], "alerts": []}

CVE = {"id": "CVE-1", "cvss": 9.8, "match": "exact", "component": "nginx 1.0", "ports": [80],
       "scope": "web", "description": "d"}


def _cve_result(cves=None, ports=None, server="nginx"):
    return {"server": server, "x_powered_by": None, "cves": cves or [], "ports": ports or [], "internetdb": None}


class TestMatchNote(unittest.TestCase):

    def test_notes(self):
        self.assertEqual(match_note({"match": "exact"}), "")
        self.assertIn("version partielle", match_note({"match": "range"}))
        self.assertIn("mot-clé", match_note({"match": "keyword"}))
        self.assertEqual(match_note({}), "")


class TestCveLocation(unittest.TestCase):

    def test_composant_web_avec_ports(self):
        cve = {"component": "apache:http_server 2.4.58", "ports": [80, 443], "scope": "web"}
        self.assertEqual(cve_location("d.fr", _cve_result(), cve), "apache:http_server 2.4.58 (port 80, 443) sur d.fr")

    def test_composant_infra(self):
        cve = {"component": "isc:bind 9.16", "ports": [53], "scope": "infra"}
        self.assertEqual(cve_location("d.fr", _cve_result(), cve), "isc:bind 9.16 (port 53), service sur la même IP que d.fr")

    def test_internetdb_sans_composant(self):
        self.assertEqual(cve_location("d.fr", _cve_result(), {"source": "internetdb"}), "composant non identifié sur l'IP de d.fr")

    def test_repli_sur_le_header_server(self):
        self.assertEqual(cve_location("d.fr", _cve_result(server="nginx"), {}), "nginx sur d.fr")

    def test_composant_inconnu(self):
        self.assertEqual(cve_location("d.fr", _cve_result(server=None), {}), "composant inconnu sur d.fr")


@patch.object(utils, "CVSS_CRITICAL", 9.0)
class TestAlertLevel(unittest.TestCase):

    def test_critical_version_precise(self):
        self.assertEqual(alert_level({"cvss": 9.8, "match": "exact"}), "CRITICAL")

    def test_seuil_inclusif(self):
        self.assertEqual(alert_level({"cvss": 9.0, "match": "exact"}), "CRITICAL")

    def test_version_partielle_reste_warning(self):
        self.assertEqual(alert_level({"cvss": 9.8, "match": "range"}), "WARNING")
        self.assertEqual(alert_level({"cvss": 9.8, "match": "keyword"}), "WARNING")

    def test_score_sous_le_seuil(self):
        self.assertEqual(alert_level({"cvss": 8.9, "match": "exact"}), "WARNING")


@patch.object(utils, "CVSS_CRITICAL", 9.0)
class TestBuildAlerts(unittest.TestCase):

    def _build(self, cve_result, sub=EMPTY_SUB, dns=EMPTY_DNS, twist=EMPTY_TWIST):
        return build_alerts("d.fr", cve_result, sub, dns, twist)

    def test_aucune_alerte(self):
        self.assertEqual(self._build(_cve_result()), [])

    def test_cve_critique(self):
        alerts = self._build(_cve_result([CVE]))
        self.assertEqual(alerts, [{"level": "CRITICAL", "message": "CVE-1 (CVSS 9.8) : nginx 1.0 (port 80) sur d.fr"}])

    def test_cve_version_partielle_warning_avec_note(self):
        alerts = self._build(_cve_result([{**CVE, "match": "range"}]))
        self.assertEqual(alerts[0]["level"], "WARNING")
        self.assertIn("version partielle", alerts[0]["message"])

    def test_note_sans_id(self):
        note = {"id": None, "cvss": None, "description": "Version masquée pour nginx"}
        self.assertEqual(self._build(_cve_result([note])), [{"level": "WARNING", "message": "Version masquée pour nginx"}])

    def test_cve_internetdb_sans_score(self):
        raw = {"id": "CVE-2", "cvss": None, "description": "x", "source": "internetdb"}
        alert = self._build(_cve_result([raw]))[0]
        self.assertEqual(alert["level"], "WARNING")
        self.assertIn("InternetDB", alert["message"])

    def test_port_sensible(self):
        ports = [{"port": 3389, "product": "x", "cves": []}]
        alert = self._build(_cve_result(ports=ports))[0]
        self.assertEqual(alert["level"], "CRITICAL")
        self.assertIn("RDP (3389)", alert["message"])

    def test_port_non_sensible(self):
        self.assertEqual(self._build(_cve_result(ports=[{"port": 22, "product": "OpenSSH", "cves": []}])), [])

    def test_cve_sur_un_port(self):
        ports = [{"port": 80, "product": "Apache", "cves": [{"id": "CVE-3", "cvss": 9.8, "match": "exact"},
                                                            {"id": "CVE-4", "cvss": None}]}]
        alerts = self._build(_cve_result(ports=ports))
        self.assertEqual(len(alerts), 1)
        self.assertIn("CVE-3", alerts[0]["message"])

    def test_alertes_des_autres_modules_reprises(self):
        sub = {"subdomains": [], "alerts": [{"level": "WARNING", "message": "sub"}]}
        dns = {**EMPTY_DNS, "alerts": [{"level": "WARNING", "message": "dns"}]}
        twist = {"typosquatting": [], "alerts": [{"level": "CRITICAL", "message": "twist"}]}
        self.assertEqual([a["message"] for a in self._build(_cve_result(), sub, dns, twist)], ["sub", "dns", "twist"])


class TestSendAlerts(unittest.TestCase):

    @patch("vuln_scanner.vuln_scanner.requests.post")
    def test_rien_a_envoyer(self, mock_post):
        send_alerts({})
        mock_post.assert_not_called()

    @patch("vuln_scanner.vuln_scanner.requests.post")
    def test_envoi(self, mock_post):
        alerts = {"d.fr": [{"level": "WARNING", "message": "m"}]}
        send_alerts(alerts)
        self.assertEqual(mock_post.call_args.kwargs["json"], {"service": "vuln_scanner", "alerts": alerts})

    @patch("vuln_scanner.vuln_scanner.requests.post", side_effect=requests.exceptions.ConnectionError())
    def test_alert_service_injoignable(self, _):
        send_alerts({"d.fr": [{"level": "WARNING", "message": "m"}]})  # ne doit pas lever


class TestRunCycle(unittest.TestCase):

    def test_ecrit_le_json_et_envoie_les_alertes(self):
        target = {"domain": "a.fr", "longitude": 2.0, "latitude": 48.0, "label": "A", "scan_mode": "passive"}
        note = {"id": None, "cvss": None, "description": "Version masquée pour x"}
        cve_result = _cve_result([dict(CVE), note])
        sub = {"subdomains": ["x.a.fr"], "alerts": []}

        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            with patch.object(utils, "load_domains", return_value=[target]), \
                 patch.object(utils, "OUTPUT_FILE", out), \
                 patch.object(utils, "CVSS_CRITICAL", 9.0), \
                 patch("vuln_scanner.vuln_scanner.cve_check", return_value=cve_result) as mock_cve, \
                 patch("vuln_scanner.vuln_scanner.subdomain_check", return_value=sub), \
                 patch("vuln_scanner.vuln_scanner.dns_check", return_value=EMPTY_DNS), \
                 patch("vuln_scanner.vuln_scanner.dnstwist_check", return_value=EMPTY_TWIST), \
                 patch("vuln_scanner.vuln_scanner.send_alerts") as mock_send:
                run_cycle()
            with open(out) as f:
                data = json.load(f)

        mock_cve.assert_called_once_with("a.fr", scan_mode="passive")
        site = data["sites"][0]
        self.assertEqual(site["domain"], "a.fr")
        self.assertEqual(site["subdomains"], ["x.a.fr"])
        cves = site["headers"]["cves"]
        self.assertEqual(cves[0]["where"], "nginx 1.0 (port 80) sur a.fr")
        self.assertEqual(cves[0]["match_note"], "")
        self.assertNotIn("where", cves[1])  # les notes sans id n'ont pas de champs d'affichage
        sent = mock_send.call_args[0][0]
        self.assertEqual([a["level"] for a in sent["a.fr"]], ["WARNING", "CRITICAL"])
        self.assertIn("last_run", data)

    def test_aucune_alerte_envoyee_si_rien_a_signaler(self):
        target = {"domain": "a.fr", "longitude": 2.0, "latitude": 48.0, "label": "A", "scan_mode": "passive"}
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out.json")
            with patch.object(utils, "load_domains", return_value=[target]), \
                 patch.object(utils, "OUTPUT_FILE", out), \
                 patch("vuln_scanner.vuln_scanner.cve_check", return_value=_cve_result()), \
                 patch("vuln_scanner.vuln_scanner.subdomain_check", return_value=EMPTY_SUB), \
                 patch("vuln_scanner.vuln_scanner.dns_check", return_value=EMPTY_DNS), \
                 patch("vuln_scanner.vuln_scanner.dnstwist_check", return_value=EMPTY_TWIST), \
                 patch("vuln_scanner.vuln_scanner.send_alerts") as mock_send:
                run_cycle()
        self.assertEqual(mock_send.call_args[0][0], {})


if __name__ == "__main__":
    unittest.main()