"""Static smoke checks for the PA#0 frontend integration contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_frontend_reducer_column_uses_chain_and_foundation_payload():
    app = (ROOT / "frontend" / "src" / "App.jsx").read_text()
    assert "chain.path" in app
    assert "black_box_from_column_1" in app
    assert "defaultPayload(foundation)" in app
    assert "'OWP':" in app and "/api/pa1/owp" in app


def test_frontend_consumes_catalog_and_has_guided_presets():
    app = (ROOT / "frontend" / "src" / "App.jsx").read_text()
    assert "getJson('/api/catalog')" in app
    assert "GUIDED_PRESETS" in app
    assert "OWF → PRG → PRF → PRP → MAC" in app
    assert "PRF → CPA-Enc → CCA-Enc" in app
    assert "CRHF → HMAC → MAC" in app
    assert "PKC → OT → SecureAND → MPC" in app


def test_frontend_exposes_hidden_pa_demo_endpoints():
    app = (ROOT / "frontend" / "src" / "App.jsx").read_text()
    required = [
        "pa7-md",
        "pa9-birthday",
        "pa11-dh",
        "pa13-miller-rabin",
        "pa14-hastad",
        "pa16-elgamal",
    ]
    catalog = (ROOT / "api" / "catalog.py").read_text()
    for item in required:
        assert item in app or item in catalog
    for path in [
        "/api/pa7/md",
        "/api/pa9/birthday",
        "/api/pa11/dh",
        "/api/pa13/miller_rabin",
        "/api/pa14/hastad",
        "/api/pa16/elgamal",
    ]:
        assert path in catalog


def test_frontend_has_minimal_demo_board_without_raw_json_ui():
    app = (ROOT / "frontend" / "src" / "App.jsx").read_text()
    assert "DemoBoard" in app
    assert "LineageRail" in app
    assert "EvidenceCard" in app
    assert "Hint" in app
    assert "AttackLab" in app
    assert "DemoRunnerTile" in app
    assert "isInteractiveDemo" in app
    assert "formatResult" in app
    assert "TraceTimeline" in app
    assert "Interactive attacks" in app
    assert "All demos" in app
    assert "Raw output" not in app
