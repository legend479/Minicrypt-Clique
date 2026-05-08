"""Static smoke checks for the PA#0 frontend integration contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_frontend_reducer_column_uses_chain_and_foundation_payload():
    app = (ROOT / "frontend" / "src" / "App.jsx").read_text()
    assert "chain.path" in app
    assert "black_box_from_column_1" in app
    assert "defaultPayload(foundation)" in app
    assert "'OWP':" in app and "/api/pa1/owp" in app
