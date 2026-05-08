"""Smoke tests for the PA#0 Flask API surface."""

import pytest

from api.server import create_app


@pytest.fixture(scope="module")
def client():
    return create_app().test_client()


def _post_ok(client, path, payload=None):
    resp = client.post(path, json=payload or {})
    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "error" not in data
    return data


def test_health_and_clique_metadata(client):
    assert client.get("/api/health").get_json() == {"status": "ok"}
    clique = client.get("/api/clique").get_json()
    assert "OWF" in clique["primitives"]
    assert any(e["src"] == "OWF" and e["dst"] == "PRG" for e in clique["edges"])


def test_reduce_validation(client):
    ok = _post_ok(client, "/api/reduce", {"from": "OWF", "to": "MPC", "direction": "forward"})
    assert ok["path"]
    assert client.post("/api/reduce", json={}).status_code == 400
    assert client.post(
        "/api/reduce",
        json={"from": "OWF", "to": "PRG", "direction": "sideways"},
    ).status_code == 400


@pytest.mark.parametrize(("path", "payload", "required_key"), [
    ("/api/pa1/owp", {"bits": 80, "x": 3}, "output"),
    ("/api/pa1/prg", {"foundation": "DLP", "seed": "00" * 16, "output_bytes": 8, "bits": 80}, "output_hex"),
    ("/api/pa2/ggm", {"key": "00" * 16, "x": 3, "input_bits": 4}, "output_hex"),
    ("/api/pa3/cpa", {"key": "00" * 16, "message": "hello"}, "recovered"),
    ("/api/pa4/modes", {"mode": "CTR", "key": "00" * 16, "message": "hello"}, "recovered"),
    ("/api/pa5/mac", {"kind": "CBCMAC", "key": "00" * 16, "message": "auth"}, "tag_hex"),
    ("/api/pa6/cca", {"k_E": "11" * 16, "k_M": "22" * 16, "message": "secret"}, "recovered"),
    ("/api/pa7/md", {"message": "hello", "block_size": 16, "output_size": 8}, "digest_hex"),
    ("/api/pa8/hash", {"message": "hello", "bits": 80}, "digest_hex"),
    ("/api/pa9/birthday", {"n_bits": 8, "dlp_bits": 80}, "found"),
    ("/api/pa10/hmac", {"key": "00" * 16, "message": "hi"}, "tag_hex"),
    ("/api/pa11/dh", {"bits": 128}, "K_alice"),
    ("/api/pa12/rsa", {"bits": 512, "message": "hi", "mode": "pkcs"}, "recovered"),
    ("/api/pa13/miller_rabin", {"n": 561, "rounds": 10}, "miller_rabin"),
    ("/api/pa14/hastad", {"m": 4660}, "match_original"),
    ("/api/pa15/sign", {"message": "I agree", "tamper": True}, "verify"),
    ("/api/pa16/elgamal", {"m": 42, "multiplier": 3}, "malleability"),
    ("/api/pa17/signcrypt", {"m": 12345, "tamper": True}, "rejected"),
    ("/api/pa18/ot", {"b": 1, "m0": 11, "m1": 22}, "received"),
    ("/api/pa19/and", {"a": 1, "b": 1}, "result"),
    ("/api/pa20/mpc", {"circuit": "millionaires", "n": 4, "x": 7, "y": 12}, "result"),
])
def test_pa_demo_endpoints(client, path, payload, required_key):
    data = _post_ok(client, path, payload)
    assert required_key in data
