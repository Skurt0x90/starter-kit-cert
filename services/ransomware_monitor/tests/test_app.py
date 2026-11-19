import unittest
from app_test_mixin import DataApiMixin
from ransomware_monitor import app as ransomware_app, utils


class TestRansomwareApi(DataApiMixin, unittest.TestCase):
    flask_app = ransomware_app.app
    utils_module = utils


if __name__ == "__main__":
    unittest.main()