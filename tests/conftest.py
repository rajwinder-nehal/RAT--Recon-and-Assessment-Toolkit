import os
import sys

import pytest

# Make "from modules import ..." work no matter where pytest is started
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from modules import session                      # noqa: E402
from modules import target as target_state       # noqa: E402


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
    """Every test starts with no saved results and no target."""
    session.clear()
    monkeypatch.setattr(target_state, "current_target", None)
    yield
    session.clear()