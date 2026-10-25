from __future__ import annotations

from app import config
from app import seed as seed_module
from app.database import get_connection


def test_seed_does_not_create_demo_identities_outside_local(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "production.db")
    monkeypatch.setattr(config, "DEVICE_TOKEN_FILE", tmp_path / "tokens.json")

    seed_module.seed()

    conn = get_connection()
    try:
        assert conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM admin_audit_events").fetchone()[0] == 0
    finally:
        conn.close()

    # A deployed control plane must never write a plaintext simulator token
    # file; device credentials are issued through enrollment instead.
    assert not (tmp_path / "tokens.json").exists()
