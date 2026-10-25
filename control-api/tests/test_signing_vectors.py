from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from app.policy_verify import PolicyVerificationError, verify_envelope

VECTOR_FILE = Path(__file__).resolve().parent / "signing" / "vectors.json"
DATA = json.loads(VECTOR_FILE.read_text(encoding="utf-8"))
NOW = datetime.fromisoformat(DATA["verification_now"].replace("Z", "+00:00"))


@pytest.mark.parametrize(
    "vector", DATA["vectors"], ids=[item["name"] for item in DATA["vectors"]]
)
def test_signing_spec_vectors(vector):
    kwargs = {"last_applied_version": vector["last_applied_version"]}

    if vector["expect"] == "accept":
        result = verify_envelope(
            vector["envelope"],
            DATA["jwks"],
            vector["expected_device"],
            now=NOW,
            **kwargs,
        )
        assert result.policy_version == vector["envelope"]["policy_version"]
        return

    with pytest.raises(PolicyVerificationError, match=vector["reason"]):
        verify_envelope(
            vector["envelope"],
            DATA["jwks"],
            vector["expected_device"],
            now=NOW,
            **kwargs,
        )
