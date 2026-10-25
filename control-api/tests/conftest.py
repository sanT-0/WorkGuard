from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

CONTROL_API = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CONTROL_API))

# Must be set before app.config is imported.
os.environ["APP_ENV"] = "local"
os.environ["AUTH_MODE"] = "dev"
os.environ["ALLOW_DEV_AUTH"] = "1"
os.environ["ALLOW_INSECURE_DEVICE_HEADER"] = "0"
os.environ["RATE_LIMIT_ENABLED"] = "0"
os.environ["WG_DB_PATH"] = str(Path(tempfile.mkdtemp(prefix="wg-env-")) / "unused.db")
os.environ["WG_DEVICE_TOKEN_FILE"] = str(
    Path(tempfile.mkdtemp(prefix="wg-env-")) / "tokens.json"
)
os.environ["POLICY_SIGNING_KEY_PATH"] = str(
    Path(tempfile.mkdtemp(prefix="wg-env-")) / "signing.pem"
)

from fastapi.testclient import TestClient  # noqa: E402

from app import config, signing  # noqa: E402
from app.main import app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "workguard.db")
    monkeypatch.setattr(config, "DEVICE_TOKEN_FILE", tmp_path / "tokens.json")
    monkeypatch.setattr(config, "SIGNING_KEY_PATH", tmp_path / "signing.pem")
    monkeypatch.setattr(config, "RATE_LIMIT_ENABLED", False)
    signing.reset_key_cache()
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def admin_headers():
    def _headers(user: str = "dev-admin", role: str = "security_admin"):
        return {"X-Dev-User": user, "X-Dev-Role": role}

    return _headers


@pytest.fixture()
def device_token(client):
    import json

    tokens = json.loads(config.DEVICE_TOKEN_FILE.read_text(encoding="utf-8"))
    return tokens["dev-sim-001"]


@pytest.fixture()
def agent_headers(device_token):
    return {"Authorization": f"Bearer {device_token}"}
