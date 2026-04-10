import pytest
from unittest.mock import MagicMock

from talkdoc_secure_pm.managers.pip_manager import PipManager
from talkdoc_secure_pm.managers.npm_manager import NpmManager
from talkdoc_secure_pm.managers.cargo_manager import CargoManager

@pytest.fixture
def manager():
    m = PipManager()
    m.auditor = MagicMock()
    m.auditor.audit_package_source.return_value = True
    m.auditor.client = None
    m.auditor.model = None
    return m
