import unittest
from app_test_mixin import DataApiMixin
from social_monitor import app as social_app, utils


class TestSocialApi(DataApiMixin, unittest.TestCase):
    flask_app = social_app.app
    utils_module = utils


if __name__ == "__main__":
    unittest.main()