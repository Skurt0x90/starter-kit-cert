import pytest
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

@pytest.fixture
def app():
    from app.main import app
    app.config['TESTING'] = True
    yield app