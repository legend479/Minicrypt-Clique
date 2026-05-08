"""Foundation tests: AES (FIPS-197) and DLP."""
import os
import pytest
from crypto_core.foundation.aes_foundation import (
    aes128_encrypt_block, aes128_decrypt_block, AESFoundation,
)
from crypto_core.foundation.dlp_foundation import DLPFoundation
from crypto_core.common.exceptions import NotSupported
from crypto_core.number_theory.modular import mod_pow


def test_aes_fips197_appendix_b():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt  = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    ct  = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    assert aes128_encrypt_block(key, pt) == ct
    assert aes128_decrypt_block(key, ct) == pt


def test_aes_fips197_appendix_c1():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt  = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct  = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes128_encrypt_block(key, pt) == ct
    assert aes128_decrypt_block(key, ct) == pt


def test_aes_round_trip_random():
    for _ in range(20):
        k = os.urandom(16); m = os.urandom(16)
        assert aes128_decrypt_block(k, aes128_encrypt_block(k, m)) == m


def test_aes_foundation_views():
    aes = AESFoundation()
    prp = aes.as_prp()
    k, x = b"\x00" * 16, b"\x11" * 16
    assert prp.invert(k, prp.evaluate(k, x)) == x


def test_aes_foundation_no_owp():
    with pytest.raises(NotSupported):
        AESFoundation().as_owp()


def test_dlp_construction():
    f = DLPFoundation(bits=64)
    assert f.p == 2 * f.q + 1
    assert mod_pow(f.g, f.q, f.p) == 1


def test_dlp_owp_evaluation():
    f = DLPFoundation(bits=64)
    owp = f.as_owp()
    assert owp.evaluate(0) == 1
    assert owp.evaluate(1) == f.g


def test_dlp_owp_is_permutation_small_q():
    f = DLPFoundation(bits=16)
    owp = f.as_owp()
    seen = set()
    for x in range(min(f.q, 1024)):
        y = owp.evaluate(x)
        assert y not in seen
        seen.add(y)


def test_dlp_hard_core_balanced():
    f = DLPFoundation(bits=32)
    owp = f.as_owp()
    n = 1000
    ones = sum(owp.hard_core_predicate(int.from_bytes(os.urandom(4), "big") % f.q)
               for _ in range(n))
    assert 400 < ones < 600


def test_dlp_no_prf_view():
    with pytest.raises(NotSupported):
        DLPFoundation(bits=32).as_prf()
