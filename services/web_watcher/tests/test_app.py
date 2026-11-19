import unittest
from app_test_mixin import DataApiMixin
from web_watcher import app as watcher_app, utils


class TestWatcherApi(DataApiMixin, unittest.TestCase):
    flask_app = watcher_app.app
    utils_module = utils


if __name__ == "__main__":
    unittest.main()