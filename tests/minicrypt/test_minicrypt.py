"""Tests for Minicrypt: PA#1-#6."""
import os
import pytest
from crypto_core.foundation.aes_foundation import AESFoundation
from crypto_core.foundation.dlp_foundation import DLPFoundation
from crypto_core.minicrypt.prg import (
    HILLPRG, prg_as_owf, monobit_frequency_test, runs_test, serial_test_lite,
)
from crypto_core.minicrypt.prf_ggm import GGMTreePRF, prf_as_prg
from crypto_core.minicrypt.prp_feistel import LubyRackoffPRP
from crypto_core.minicrypt.cpa_enc import (
    CPAEncryption, DeterministicCPAEncryption, ind_cpa_game,
)
from crypto_core.minicrypt.modes import CBC, OFB, CTR
from crypto_core.minicrypt.mac import (
    PRFMAC, CBCMAC, constant_time_eq, euf_cma_game, mac_as_prf,
)
from crypto_core.minicrypt.cca_enc import EncryptThenMAC
from crypto_core.common.exceptions import MacVerificationFailure


# ---------- PA#1: PRG ----------

def test_prg_determinism():
    f = DLPFoundation(bits=64)
    prg1 = HILLPRG(f.as_owp())
    prg2 = HILLPRG(f.as_owp())
    seed = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    prg1.seed(seed); prg2.seed(seed)
    assert prg1.next_bits(32) == prg2.next_bits(32)


def test_prg_passes_basic_randomness():
    f = DLPFoundation(bits=80)
    prg = HILLPRG(f.as_owp())
    prg.seed(os.urandom(prg.seed_length))
    sample = prg.next_bits(128)  # 1024 bits
    p_freq, ok_freq = monobit_frequency_test(sample)
    p_runs, ok_runs = runs_test(sample)
    assert ok_freq, f"monobit frequency failed (p={p_freq})"
    assert ok_runs, f"runs test failed (p={p_runs})"


def test_prg_to_owf_backward():
    f = DLPFoundation(bits=64)
    prg = HILLPRG(f.as_owp())
    owf = prg_as_owf(prg, output_bytes=16)
    seed = os.urandom(prg.seed_length)
    y = owf.evaluate(seed)
    # Determinism
    assert owf.evaluate(seed) == y


# ---------- PA#2: PRF / PRP ----------

def test_ggm_determinism_and_avalanche():
    f = DLPFoundation(bits=80)
    prg = HILLPRG(f.as_owp())
    prf = GGMTreePRF(prg, input_bits=4, key_bytes=16)
    k = os.urandom(16)
    # Inputs differ in the LOW-order bits (which is what input_bits selects).
    out0 = prf.evaluate(k, b"\x00" * 16)            # low 4 bits = 0000
    out1 = prf.evaluate(k, b"\x00" * 15 + b"\x01")  # low 4 bits = 0001
    assert out0 != out1
    assert prf.evaluate(k, b"\x00" * 16) == out0


def test_prf_to_prg_backward():
    aes = AESFoundation().as_prf()
    prg = prf_as_prg(aes)
    prg.seed(b"\x00" * aes.key_size)
    a = prg.next_bits(64)
    prg.seed(b"\x00" * aes.key_size)
    b = prg.next_bits(64)
    assert a == b
    assert len(a) == 64


def test_luby_rackoff_round_trip():
    aes = AESFoundation().as_prf()
    prp = LubyRackoffPRP(aes, rounds=3)
    k = os.urandom(aes.key_size)
    x = os.urandom(prp.block_size)
    assert prp.invert(k, prp.evaluate(k, x)) == x


# ---------- PA#3: CPA ----------

def test_cpa_round_trip():
    cpa = CPAEncryption(AESFoundation().as_prf())
    k = os.urandom(16)
    for length in (1, 16, 31, 100):
        m = os.urandom(length)
        assert cpa.decrypt(k, cpa.encrypt(k, m)) == m


def test_cpa_secure_advantage_random_baseline():
    cpa = CPAEncryption(AESFoundation().as_prf())
    k = os.urandom(16)
    correct = 0
    n = 50
    for _ in range(n):
        result = ind_cpa_game(cpa, k, b"alpha" * 4, b"omega" * 4)
        if result["correct"]:
            correct += 1
    # Random adversary -> expected ~25/50; advantage |correct-25| <= 15 with high prob.
    assert abs(correct - n / 2) <= 15


def test_cpa_broken_with_nonce_reuse():
    """Deterministic variant produces identical ciphertexts for identical messages."""
    cpa_bad = DeterministicCPAEncryption(AESFoundation().as_prf())
    k = os.urandom(16)
    m = b"the same message"
    _, c1 = cpa_bad.encrypt(k, m)
    _, c2 = cpa_bad.encrypt(k, m)
    assert c1 == c2  # the leak


# ---------- PA#4: modes ----------

@pytest.mark.parametrize("ModeCls,uses_prp", [
    (CBC, True), (OFB, False), (CTR, False),
])
def test_modes_round_trip(ModeCls, uses_prp):
    aes = AESFoundation()
    prim = aes.as_prp() if uses_prp else aes.as_prf()
    mode = ModeCls(prim)
    k = os.urandom(16)
    for length in (5, 16, 31, 64, 100):
        m = os.urandom(length)
        ct = mode.encrypt(k, m)
        pt = mode.decrypt(k, ct)
        assert pt == m


def test_ofb_keystream_independent():
    """OFB keystream can be precomputed before plaintext is known."""
    aes = AESFoundation().as_prf()
    ofb = OFB(aes)
    k = os.urandom(16)
    iv = os.urandom(16)
    ks1 = ofb.precompute_keystream(k, iv, 4)
    ks2 = ofb.precompute_keystream(k, iv, 4)
    assert ks1 == ks2


# ---------- PA#5: MAC ----------

def test_prfmac_verify():
    mac = PRFMAC(AESFoundation().as_prf())
    k = os.urandom(16)
    m = os.urandom(16)
    t = mac.mac(k, m)
    assert mac.verify(k, m, t)
    # tampered
    bad = bytes([t[0] ^ 0xff]) + t[1:]
    assert not mac.verify(k, m, bad)


def test_cbcmac_variable_length():
    mac = CBCMAC(AESFoundation().as_prp())
    k = os.urandom(16)
    for m in (b"", b"a", b"abcd" * 5, b"x" * 100):
        t = mac.mac(k, m)
        assert mac.verify(k, m, t)


def test_constant_time_eq():
    assert constant_time_eq(b"abc", b"abc")
    assert not constant_time_eq(b"abc", b"abd")
    assert not constant_time_eq(b"abc", b"abcd")


def test_euf_cma_naive_adversary_fails():
    """A naive adversary returning a random tag almost never forges."""
    mac = CBCMAC(AESFoundation().as_prp())
    k = os.urandom(16)

    def adv(oracle):
        for i in range(20):
            oracle(f"msg{i}".encode())
        return b"never_seen", os.urandom(mac.tag_size)

    res = euf_cma_game(mac, k, n_queries=50, adversary_fn=adv)
    assert not res["forged"]


# ---------- PA#6: CCA ----------

def test_cca_round_trip():
    aes = AESFoundation()
    cca = EncryptThenMAC(CPAEncryption(aes.as_prf()), CBCMAC(aes.as_prp()))
    k_E, k_M = os.urandom(16), os.urandom(16)
    for length in (5, 16, 100):
        m = os.urandom(length)
        ct = cca.encrypt((k_E, k_M), m)
        assert cca.decrypt((k_E, k_M), ct) == m


def test_cca_rejects_tampered():
    aes = AESFoundation()
    cca = EncryptThenMAC(CPAEncryption(aes.as_prf()), CBCMAC(aes.as_prp()))
    k_E, k_M = os.urandom(16), os.urandom(16)
    m = b"protected message"
    (r, c), t = cca.encrypt((k_E, k_M), m)
    # Flip one bit of c
    tampered = (r, bytes([c[0] ^ 0x01]) + c[1:])
    with pytest.raises(MacVerificationFailure):
        cca.decrypt((k_E, k_M), (tampered, t))
