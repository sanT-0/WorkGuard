from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "admin-web"


def _html() -> str:
    return (WEB / "index.html").read_text(encoding="utf-8")


def _js() -> str:
    return (WEB / "app.js").read_text(encoding="utf-8")


def test_console_has_no_inline_handlers_or_html_sinks():
    html = _html().lower()
    js = _js()

    for pattern in ("onclick=", "oninput=", "onchange=", "onerror=", "onload="):
        assert pattern not in html, f"inline handler {pattern} found in index.html"

    for sink in (".innerhtml =", ".outerhtml =", "insertadjacenthtml", "document.write"):
        assert sink not in js.lower(), f"unsafe DOM sink {sink} found in app.js"

    assert "javascript:" not in js.lower()


def test_console_is_served_with_a_strict_script_csp(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "app.js" in response.text

    csp = response.headers.get("content-security-policy", "")
    script_policy = csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "'self'" in script_policy
    assert "'unsafe-inline'" not in script_policy


def test_console_does_not_claim_unimplemented_features():
    html = _html()
    for claim in (
        "128-bit salted",
        "Two-Person Approve & Publish",
        "Ed25519 Verified Signatures",
        "All controls enforced & read-back",
    ):
        assert claim not in html


def test_console_covers_the_implemented_lifecycle_and_auth_modes():
    js = _js()
    for route in (
        "/admin/policies",
        "/new-draft",
        "/submit",
        "/approve",
        "/publish",
        "/rollback",
        "/admin/exceptions",
        "/admin/audit-events/verify",
        "/admin/enrollment-codes",
    ):
        assert route in js, f"console does not call {route}"

    assert "X-Dev-User" in js
    assert "Authorization" in js
    assert "X-Dev-Role" in js
