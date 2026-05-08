"""Tests for MPC: PA#18-#20."""
import pytest
from crypto_core.foundation.dlp_foundation import DLPFoundation
from crypto_core.mpc.ot import run_ot, OTSender, OTReceiver
from crypto_core.mpc.secure_gates import secure_and, secure_xor, secure_not
from crypto_core.mpc.circuit import (
    equality_circuit, bit_add_circuit, millionaires_circuit, secure_eval,
)


# Single foundation reused across tests for speed.
_F = None
def _f():
    global _F
    if _F is None:
        _F = DLPFoundation(bits=128)
    return _F


# ---------- PA#18: OT ----------

def test_ot_correctness_all_inputs():
    f = _f()
    for b in (0, 1):
        for m0, m1 in [(11, 22), (100, 200), (3, 7)]:
            out = run_ot(f, b, m0, m1)
            assert out == (m0 if b == 0 else m1)


# ---------- PA#19: secure gates ----------

def test_secure_and_truth_table():
    f = _f()
    for a in (0, 1):
        for b in (0, 1):
            assert secure_and(a, b, f) == (a & b)


def test_secure_xor_free():
    for a in (0, 1):
        for b in (0, 1):
            assert secure_xor(a, b) == (a ^ b)


def test_secure_not_free():
    assert secure_not(0) == 1
    assert secure_not(1) == 0


# ---------- PA#20: circuits ----------

def _to_bits(x, n):
    return [(x >> i) & 1 for i in range(n)]


def test_equality_4bit_truth_table():
    f = _f()
    c = equality_circuit(4)
    for x in range(16):
        for y in range(0, 16, 4):  # subset for speed
            out, _ = secure_eval(c, _to_bits(x, 4), _to_bits(y, 4), f)
            assert out[0] == (1 if x == y else 0)


def test_bit_add_4bit_modular():
    f = _f()
    c = bit_add_circuit(4)
    for x in range(0, 16, 3):
        for y in range(0, 16, 5):
            out, _ = secure_eval(c, _to_bits(x, 4), _to_bits(y, 4), f)
            r = sum(b << i for i, b in enumerate(out))
            assert r == (x + y) % 16


def test_millionaires_4bit():
    f = _f()
    c = millionaires_circuit(4)
    for x in range(0, 16, 3):
        for y in range(0, 16, 4):
            out, _ = secure_eval(c, _to_bits(x, 4), _to_bits(y, 4), f)
            assert out[0] == (1 if x > y else 0)


def test_circuit_reports_and_count():
    """Number of OT calls = number of AND gates in the circuit."""
    f = _f()
    c = equality_circuit(4)
    out, stats = secure_eval(c, _to_bits(5, 4), _to_bits(5, 4), f)
    # equality(n) uses n-1 ORs (each = 1 AND) + 0 ANDs in the diff layer
    # diff layer: n XORs (free)
    # OR layer:   n-1 ORs, each = 1 XOR + 1 AND
    # NOT at end: free
    # So AND count = n-1 = 3.
    assert stats["and_gates"] == 3
