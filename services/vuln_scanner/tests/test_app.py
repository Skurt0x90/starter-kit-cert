import unittest
from app_test_mixin import DataApiMixin
from vuln_scanner import app as vuln_app, utils


class TestVulnApi(DataApiMixin, unittest.TestCase):
    flask_app = vuln_app.app
    utils_module = utils


if __name__ == "__main__":
    unittest.main()