"""Tests for crypto_core/common."""
import os
import pytest
from crypto_core.common import bitops, randomness, trace, exceptions
from crypto_core.common.exceptions import PaddingError


def test_int_bytes_roundtrip():
    for v, n in [(0, 1), (255, 1), (256, 2), (0xCAFE, 4)]:
        assert bitops.bytes_to_int(bitops.int_to_bytes(v, n)) == v


def test_bits_bytes_roundtrip():
    for length in (8, 16, 64, 128):
        b = os.urandom(length // 8)
        assert bitops.bits_to_bytes(bitops.bytes_to_bits(b)) == b


def test_xor_bytes():
    assert bitops.xor_bytes(b"\xff\x00", b"\x0f\xf0") == b"\xf0\xf0"
    with pytest.raises(ValueError):
        bitops.xor_bytes(b"a", b"ab")


def test_pkcs7_round_trip():
    for data, bs in [(b"", 16), (b"a", 16), (b"a" * 16, 16), (b"hello world", 8)]:
        padded = bitops.pkcs7_pad(data, bs)
        assert len(padded) % bs == 0
        assert bitops.pkcs7_unpad(padded, bs) == data


def test_pkcs7_rejects_malformed():
    with pytest.raises(PaddingError):
        bitops.pkcs7_unpad(b"\x00" * 16, 16)


def test_md_strengthening_pad_length_field():
    """The last 8 bytes must encode the original message length in bits."""
    m = b"hello"
    padded = bitops.md_strengthening_pad(m, 16)
    assert len(padded) % 16 == 0
    length_field = int.from_bytes(padded[-8:], "big")
    assert length_field == 5 * 8


def test_secure_random_bytes():
    a = randomness.secure_random_bytes(32)
    b = randomness.secure_random_bytes(32)
    assert a != b
    assert len(a) == 32


def test_secure_randrange():
    for _ in range(100):
        x = randomness.secure_randrange(10, 20)
        assert 10 <= x < 20


def test_step_trace_records():
    t = trace.StepTrace()
    t.record("op", inputs={"x": b"\x01\x02"}, outputs={"y": 7}, theorem="test", pa_number=99)
    j = t.to_json()
    assert len(j) == 1
    assert j[0]["name"] == "op"
    assert j[0]["theorem"] == "test"
