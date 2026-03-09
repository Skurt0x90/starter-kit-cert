import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
from zoneinfo import ZoneInfo

from alert_service.alert_services import (
    read_json,
    write_json,
    is_duplicate,
    mark_sent,
    format_email,
    send_email,
    send_signal,
    process_alert,
)
from alert_service import utils

PARIS = ZoneInfo("Europe/Paris")

ALERT_FLAT = {
    "service": "web_watcher",
    "domain":  "exemple.fr",
    "level":   "CRITICAL",
    "message": "exemple.fr est DOWN",
}

PAYLOAD = {
    "service": "web_watcher",
    "alerts": {
        "exemple.fr": [
            {"level": "CRITICAL", "message": "exemple.fr est DOWN"}
        ]
    },
}

DEDUP_KEY = "web_watcher|exemple.fr|CRITICAL|exemple.fr est DOWN"


def _now():
    return datetime.now(PARIS)


# ---------------------------------------------------------------------------
# read_json / write_json
# ---------------------------------------------------------------------------

class TestReadJson(unittest.TestCase):

    def test_returns_parsed_json(self):
        data = {"key": "value"}
        with patch("builtins.open", mock_open(read_data=json.dumps(data))):
            result = read_json("fake.json", {})
        self.assertEqual(result, data)

    def test_missing_file_returns_default(self):
        with patch("builtins.open", side_effect=FileNotFoundError):
            result = read_json("nope.json", {"default": True})
        self.assertEqual(result, {"default": True})

    def test_corrupt_json_returns_default(self):
        with patch("builtins.open", mock_open(read_data="NOT JSON{{{")):
            result = read_json("bad.json", [])
        self.assertEqual(result, [])


class TestWriteJson(unittest.TestCase):

    def test_creates_file_with_content(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "sub" / "out.json"
            write_json(str(out), {"hello": "world"})
            self.assertEqual(json.loads(out.read_text()), {"hello": "world"})

    def test_creates_parent_dirs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b" / "c" / "file.json"
            write_json(str(deep), {})
            self.assertTrue(deep.exists())


# ---------------------------------------------------------------------------
# is_duplicate
# ---------------------------------------------------------------------------

class TestIsDuplicate(unittest.TestCase):

    def test_fresh_alert_is_not_duplicate(self):
        with patch("alert_service.alert_services.read_json", return_value={}), \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 60):
            self.assertFalse(is_duplicate(ALERT_FLAT))

    def test_recent_alert_is_duplicate(self):
        recent = (_now() - timedelta(minutes=5)).isoformat()
        dedup  = {DEDUP_KEY: recent}
        with patch("alert_service.alert_services.read_json", return_value=dedup), \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 60):
            self.assertTrue(is_duplicate(ALERT_FLAT))

    def test_expired_alert_is_not_duplicate(self):
        old   = (_now() - timedelta(hours=2)).isoformat()
        dedup = {DEDUP_KEY: old}
        with patch("alert_service.alert_services.read_json", return_value=dedup), \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 60):
            self.assertFalse(is_duplicate(ALERT_FLAT))

    def test_different_key_is_not_duplicate(self):
        recent = (_now() - timedelta(minutes=5)).isoformat()
        dedup  = {"web_watcher|autre.fr|WARNING|autre message": recent}
        with patch("alert_service.alert_services.read_json", return_value=dedup), \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 60):
            self.assertFalse(is_duplicate(ALERT_FLAT))


# ---------------------------------------------------------------------------
# format_email
# ---------------------------------------------------------------------------

class TestFormatEmail(unittest.TestCase):

    def test_subject_contains_count(self):
        subject, _ = format_email([ALERT_FLAT, ALERT_FLAT])
        self.assertIn("2", subject)

    def test_body_contains_domain(self):
        _, body = format_email([ALERT_FLAT])
        self.assertIn("exemple.fr", body)

    def test_body_critical_is_red(self):
        _, body = format_email([ALERT_FLAT])
        self.assertIn("red", body)

    def test_body_warning_is_orange(self):
        alert = {**ALERT_FLAT, "level": "WARNING"}
        _, body = format_email([alert])
        self.assertIn("orange", body)

    def test_empty_list_returns_strings(self):
        subject, body = format_email([])
        self.assertIsInstance(subject, str)
        self.assertIsInstance(body, str)


# ---------------------------------------------------------------------------
# send_email
# ---------------------------------------------------------------------------

class TestSendEmail(unittest.TestCase):

    def test_skipped_when_smtp_not_configured(self):
        with patch.object(utils, "SMTP_USER", ""), \
             patch("alert_service.alert_services.smtplib.SMTP") as mock_smtp:
            send_email([ALERT_FLAT])
        mock_smtp.assert_not_called()

    def test_sends_when_smtp_configured(self):
        mock_instance = MagicMock()
        mock_instance.__enter__ = MagicMock(return_value=mock_instance)
        mock_instance.__exit__ = MagicMock(return_value=False)

        with patch.object(utils, "SMTP_USER",        "user@gmail.com"), \
             patch.object(utils, "SMTP_PASSWORD",    "secret"), \
             patch.object(utils, "SMTP_HOST",        "smtp.gmail.com"), \
             patch.object(utils, "SMTP_PORT",        587), \
             patch.object(utils, "ALERT_EMAIL_FROM", "from@cert.fr"), \
             patch.object(utils, "ALERT_EMAIL_TO",   "to@cert.fr"), \
             patch("alert_service.alert_services.smtplib.SMTP", return_value=mock_instance) as mock_smtp:
            send_email([ALERT_FLAT])

        mock_smtp.assert_called_once_with("smtp.gmail.com", 587)
        mock_instance.starttls.assert_called_once()
        mock_instance.login.assert_called_once_with("user@gmail.com", "secret")
        mock_instance.sendmail.assert_called_once()

    def test_smtp_exception_does_not_raise(self):
        with patch.object(utils, "SMTP_USER",        "user@gmail.com"), \
             patch.object(utils, "SMTP_PASSWORD",    "secret"), \
             patch.object(utils, "SMTP_HOST",        "smtp.gmail.com"), \
             patch.object(utils, "SMTP_PORT",        587), \
             patch.object(utils, "ALERT_EMAIL_FROM", "from@cert.fr"), \
             patch.object(utils, "ALERT_EMAIL_TO",   "to@cert.fr"), \
             patch("alert_service.alert_services.smtplib.SMTP", side_effect=Exception("refused")):
            send_email([ALERT_FLAT])  # ne doit pas lever


# ---------------------------------------------------------------------------
# send_signal
# ---------------------------------------------------------------------------

class TestSendSignal(unittest.TestCase):

    def test_skipped_when_not_configured(self):
        with patch.object(utils, "SIGNAL_CLI_NUMBER",   ""), \
             patch.object(utils, "SIGNAL_CLI_GROUP_ID", ""), \
             patch("alert_service.alert_services.requests.post") as mock_post:
            send_signal([ALERT_FLAT])
        mock_post.assert_not_called()

    def test_posts_when_configured(self):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()

        with patch.object(utils, "SIGNAL_CLI_NUMBER",   "+33600000000"), \
             patch.object(utils, "SIGNAL_CLI_GROUP_ID", "group.ABC=="), \
             patch.object(utils, "SIGNAL_API_URL",      "http://signal_cli:8080"), \
             patch("alert_service.alert_services.requests.post", return_value=mock_response) as mock_post:
            send_signal([ALERT_FLAT])

        mock_post.assert_called_once()
        payload = mock_post.call_args.kwargs.get("json") or mock_post.call_args[1]["json"]
        self.assertEqual(payload["number"], "+33600000000")
        self.assertIn("group.ABC==", payload["recipients"])

    def test_request_exception_does_not_raise(self):
        with patch.object(utils, "SIGNAL_CLI_NUMBER",   "+33600000000"), \
             patch.object(utils, "SIGNAL_CLI_GROUP_ID", "group.ABC=="), \
             patch.object(utils, "SIGNAL_API_URL",      "http://signal_cli:8080"), \
             patch("alert_service.alert_services.requests.post", side_effect=Exception("timeout")):
            send_signal([ALERT_FLAT])  # ne doit pas lever


# ---------------------------------------------------------------------------
# process_alert
# ---------------------------------------------------------------------------

class TestProcessAlert(unittest.TestCase):

    def _patch_io(self, dedup=None, history=None):
        """Simule read_json sans toucher au disque."""
        dedup   = dedup   or {}
        history = history or {"alerts": []}

        def fake_read(path, default):
            if "dedup" in path:
                return dedup
            return history

        return fake_read

    def test_sends_new_alert(self):
        with patch("alert_service.alert_services.read_json",  side_effect=self._patch_io()), \
             patch("alert_service.alert_services.write_json"), \
             patch("alert_service.alert_services.send_email")  as mock_email, \
             patch("alert_service.alert_services.send_signal") as mock_signal, \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 60):
            result = process_alert(PAYLOAD)

        self.assertEqual(result["sent"], 1)
        self.assertEqual(result["deduplicated"], 0)
        mock_email.assert_called_once()
        mock_signal.assert_called_once()

    def test_deduplicates_repeat_alert(self):
        recent = (_now() - timedelta(minutes=5)).isoformat()
        dedup  = {DEDUP_KEY: recent}

        with patch("alert_service.alert_services.read_json",  side_effect=self._patch_io(dedup=dedup)), \
             patch("alert_service.alert_services.write_json"), \
             patch("alert_service.alert_services.send_email") as mock_email, \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 60):
            result = process_alert(PAYLOAD)

        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["deduplicated"], 1)
        mock_email.assert_not_called()

    def test_writes_output_file(self):
        written = {}

        def capture_write(path, data):
            written.update(data)

        with patch("alert_service.alert_services.read_json",  side_effect=self._patch_io()), \
             patch("alert_service.alert_services.write_json", side_effect=capture_write), \
             patch("alert_service.alert_services.send_email"), \
             patch("alert_service.alert_services.send_signal"), \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 60):
            process_alert(PAYLOAD)

        self.assertIn("last_run", written)
        self.assertEqual(len(written["alerts"]), 1)
        self.assertEqual(written["alerts"][0]["domain"], "exemple.fr")

    def test_history_capped_at_200(self):
        existing = [
            {"service": "x", "domain": f"d{i}.fr", "level": "INFO",
             "message": "m", "sent_at": _now().isoformat()}
            for i in range(200)
        ]
        history = {"alerts": existing, "last_run": _now().isoformat()}
        written = {}

        def capture_write(path, data):
            written.update(data)

        with patch("alert_service.alert_services.read_json",  side_effect=self._patch_io(history=history)), \
             patch("alert_service.alert_services.write_json", side_effect=capture_write), \
             patch("alert_service.alert_services.send_email"), \
             patch("alert_service.alert_services.send_signal"), \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 0):
            process_alert(PAYLOAD)

        self.assertEqual(len(written["alerts"]), 200)

    def test_empty_alerts_payload(self):
        with patch("alert_service.alert_services.read_json",  side_effect=self._patch_io()), \
             patch("alert_service.alert_services.write_json"), \
             patch("alert_service.alert_services.send_email") as mock_email, \
             patch.object(utils, "DEDUP_WINDOW_MINUTES", 60):
            result = process_alert({"service": "web_watcher", "alerts": {}})

        self.assertEqual(result, {"sent": 0, "deduplicated": 0})
        mock_email.assert_not_called()


if __name__ == "__main__":
    unittest.main()