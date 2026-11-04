"""Shared pytest setup.

The automation scripts are plain scripts (not an installed package) that do
``from utils.x import y``, so their directory is put on sys.path here. No test
touches the network: HTTP clients are mocked and OpenSearch/Discord singletons
are replaced with fakes.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AUTOMATION_SCRIPTS = REPO_ROOT / "scripts" / "automation" / "scripts"

if str(AUTOMATION_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(AUTOMATION_SCRIPTS))


def load_module_from_path(name, path):
    """Import a script whose filename isn't a valid module name (e.g. has dashes)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def repo_root():
    return REPO_ROOT


@pytest.fixture(autouse=True)
def _no_real_credentials(monkeypatch):
    """Make sure tests never pick up real credentials from the environment."""
    for var in (
        "ABUSEIPDB_KEY", "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID",
        "DISCORD_WEBHOOK", "OPENSEARCH_PASS", "ELK_PASS", "BLOCK_THRESHOLD",
    ):
        monkeypatch.delenv(var, raising=False)
