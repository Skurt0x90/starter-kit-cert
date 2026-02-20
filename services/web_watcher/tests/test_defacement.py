import pytest
from unittest.mock import patch, MagicMock, mock_open
from bs4 import BeautifulSoup
import requests
from web_watcher.defacement import is_title_ok

class TestIsTitleOk:

    @patch("web_watcher.watcher.requests.get")
    def test_titre_correspondant(self, mock_get):
        """Le titre HTML correspond au titre attendu → True"""
        mock_response = MagicMock()
        mock_response.text = '<html><head><title>Aéroport de Paris</title></head></html>'
        mock_get.return_value = mock_response

        result = is_title_ok("aeroport-paris.fr", "Aéroport de Paris")
        assert result is True

    @patch("web_watcher.watcher.requests.get")
    def test_titre_different(self, mock_get):
        """Le titre HTML ne correspond pas → False (potentiel défacement)"""
        mock_response = MagicMock()
        mock_response.text = '<html><head><title>Hacked by XYZ</title></head></html>'
        mock_get.return_value = mock_response

        result = is_title_ok("aeroport-paris.fr", "Aéroport de Paris")
        assert result is False

    @patch("web_watcher.watcher.requests.get")
    def test_pas_de_balise_title(self, mock_get):
        """Aucune balise <title> dans le HTML → False"""
        mock_response = MagicMock()
        mock_response.text = '<html><head></head><body>Contenu</body></html>'
        mock_get.return_value = mock_response

        result = is_title_ok("aeroport-paris.fr", "Aéroport de Paris")
        assert result is False

    @patch("web_watcher.watcher.requests.get")
    def test_pas_de_balise_head(self, mock_get):
        """Aucune balise <head> dans le HTML → False"""
        mock_response = MagicMock()
        mock_response.text = '<html><body>Contenu sans head</body></html>'
        mock_get.return_value = mock_response

        result = is_title_ok("aeroport-paris.fr", "Aéroport de Paris")
        assert result is False

    @patch("web_watcher.watcher.requests.get")
    def test_titre_vide_attendu_non_vide(self, mock_get):
        """Balise <title> vide, titre attendu non vide → False"""
        mock_response = MagicMock()
        mock_response.text = '<html><head><title></title></head></html>'
        mock_get.return_value = mock_response

        result = is_title_ok("aeroport-paris.fr", "Aéroport de Paris")
        assert result is False

    @patch("web_watcher.watcher.requests.get")
    def test_titre_attendu_vide_et_titre_html_vide(self, mock_get):
        """Les deux titres sont vides → True (après normalisation None → '')"""
        mock_response = MagicMock()
        mock_response.text = '<html><head><title></title></head></html>'
        mock_get.return_value = mock_response

        result = is_title_ok("aeroport-paris.fr", "")
        assert result is True

    @patch("web_watcher.watcher.requests.get", side_effect=requests.exceptions.ConnectionError("Connexion refusée"))
    def test_exception_connection_error(self, mock_get):
        """Erreur de connexion → False sans lever d'exception"""
        result = is_title_ok("site-inexistant.fr", "Titre quelconque")
        assert result is False

    @patch("web_watcher.watcher.requests.get", side_effect=requests.exceptions.Timeout("Timeout"))
    def test_exception_timeout(self, mock_get):
        """Timeout de la requête → False"""
        result = is_title_ok("aeroport-lent.fr", "Titre quelconque")
        assert result is False

    @patch("web_watcher.watcher.requests.get", side_effect=requests.exceptions.SSLError("Certificat invalide"))
    def test_exception_ssl_error(self, mock_get):
        """Erreur SSL → False"""
        result = is_title_ok("aeroport-ssl-broken.fr", "Titre quelconque")
        assert result is False

    @patch("web_watcher.watcher.requests.get")
    def test_url_construite_avec_https(self, mock_get):
        """Vérifie que la requête est bien faite en HTTPS"""
        mock_response = MagicMock()
        mock_response.text = '<html><head><title>Mon Titre</title></head></html>'
        mock_get.return_value = mock_response

        is_title_ok("example.com", "Mon Titre")

        call_args = mock_get.call_args
        assert call_args[0][0] == "https://example.com"

    @patch("web_watcher.watcher.requests.get")
    def test_comparaison_sensible_a_la_casse(self, mock_get):
        """La comparaison de titres est sensible à la casse → False si casse différente"""
        mock_response = MagicMock()
        mock_response.text = '<html><head><title>aéroport de paris</title></head></html>'
        mock_get.return_value = mock_response

        result = is_title_ok("aeroport-paris.fr", "Aéroport de Paris")
        assert result is False

    @patch("web_watcher.watcher.requests.get")
    def test_titre_avec_espaces_superflus(self, mock_get):
        """Titre HTML avec espaces superflus ≠ titre attendu sans espaces → False"""
        mock_response = MagicMock()
        mock_response.text = '<html><head><title>  Aéroport de Paris  </title></head></html>'
        mock_get.return_value = mock_response

        result = is_title_ok("aeroport-paris.fr", "Aéroport de Paris")
        assert result is False