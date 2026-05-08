"""Tests for hashing layer: PA#7, #8, #9, #10."""
import os
import pytest
from crypto_core.hashing.merkle_damgard import MerkleDamgard, XorToyCompression
from crypto_core.hashing.dlp_hash import DLPCompression, DLPHash
from crypto_core.foundation.dlp_foundation import DLPFoundation
from crypto_core.hashing.birthday import birthday_attack_naive, birthday_attack_floyd
from crypto_core.hashing.hmac import HMAC, EncryptThenHMAC, mac_to_compression, make_mac_based_crhf
from crypto_core.foundation.aes_foundation import AESFoundation
from crypto_core.minicrypt.cpa_enc import CPAEncryption
from crypto_core.common.exceptions import MacVerificationFailure


# ---------- PA#7: Merkle-Damgard ----------

def test_md_with_toy_compression():
    toy = XorToyCompression(output_size=4, block_size=16)
    md = MerkleDamgard(toy, b"\x00" * 4, 16, 4)
    assert len(md.digest(b"")) == 4
    assert len(md.digest(b"a")) == 4
    assert len(md.digest(b"x" * 100)) == 4
    # different inputs => different digests
    assert md.digest(b"hello") != md.digest(b"world")


def test_md_padding_handles_boundaries():
    toy = XorToyCompression(output_size=4, block_size=16)
    md = MerkleDamgard(toy, b"\x00" * 4, 16, 4)
    for length in (0, 1, 7, 15, 16, 23, 64, 100):
        d = md.digest(b"a" * length)
        assert len(d) == 4


# ---------- PA#8: DLP hash ----------

def test_dlp_hash_determinism():
    h = DLPHash(bits=80)
    assert h.digest(b"hello") == h.digest(b"hello")
    assert h.digest(b"hello") != h.digest(b"world")


def test_dlp_hash_distinguishes_inputs():
    h = DLPHash(bits=80)
    digests = {h.digest(f"msg-{i}".encode()) for i in range(10)}
    assert len(digests) == 10  # all distinct


def test_dlp_hash_truncation():
    h = DLPHash(bits=80, truncate_to=4)
    d = h.digest(b"hello")
    assert len(d) == 4


def test_dlp_compression_rejects_noncanonical_state_collision():
    f = DLPFoundation(bits=80)
    comp = DLPCompression(f)
    block = (1).to_bytes(comp.block_size, "big")
    z1 = (1).to_bytes(comp.output_size, "big")
    z2 = (1 + f.q).to_bytes(comp.output_size, "big")
    assert z1 != z2
    out1 = comp(z1, block)
    try:
        out2 = comp(z2, block)
    except ValueError:
        return
    assert out1 != out2


# ---------- PA#9: Birthday attack ----------

def test_birthday_naive_finds_collision_on_small_hash():
    """With 12-bit output, 2^6 = 64 expected queries; allow 5x margin."""
    h = DLPHash(bits=80, truncate_to=2)  # 16-bit output
    result = birthday_attack_naive(h.digest, input_bytes=8, max_queries=10_000)
    assert result is not None
    assert h.digest(result["x1"]) == h.digest(result["x2"])
    assert result["x1"] != result["x2"]


def test_birthday_empirical_cost_reasonable():
    """For 16-bit truncation, expect ~256 queries; we generously allow up to 5000."""
    import statistics
    h = DLPHash(bits=80, truncate_to=2)
    counts = []
    for _ in range(5):
        result = birthday_attack_naive(h.digest, input_bytes=8, max_queries=10_000)
        if result:
            counts.append(result["queries"])
    assert len(counts) >= 4
    # 2^{16/2} = 256; mean should be in [50, 5000]
    assert 50 < statistics.mean(counts) < 5000


# ---------- PA#10: HMAC ----------

def test_hmac_round_trip():
    h = DLPHash(bits=80)
    hm = HMAC(h)
    k = os.urandom(16)
    for m in (b"", b"hi", b"x" * 200):
        t = hm.mac(k, m)
        assert hm.verify(k, m, t)


def test_hmac_rejects_tampered_message():
    h = DLPHash(bits=80)
    hm = HMAC(h)
    k = os.urandom(16)
    m = b"signed message"
    t = hm.mac(k, m)
    assert not hm.verify(k, m + b"!", t)
    assert not hm.verify(k, m, t[:-1] + bytes([t[-1] ^ 1]))


def test_hmac_key_padding():
    h = DLPHash(bits=80)
    hm = HMAC(h)
    short_k = b"abc"
    long_k = b"x" * 200
    # Should not crash and be deterministic
    t1 = hm.mac(short_k, b"m")
    t2 = hm.mac(short_k, b"m")
    assert t1 == t2
    t3 = hm.mac(long_k, b"m")
    assert hm.verify(long_k, b"m", t3)


def test_encrypt_then_hmac():
    h = DLPHash(bits=80)
    hm = HMAC(h)
    aes = AESFoundation()
    eth = EncryptThenHMAC(CPAEncryption(aes.as_prf()), hm)
    k_E, k_M = os.urandom(16), os.urandom(16)
    m = b"top secret payload"
    ct = eth.encrypt((k_E, k_M), m)
    assert eth.decrypt((k_E, k_M), ct) == m


def test_eth_rejects_tampered():
    h = DLPHash(bits=80)
    hm = HMAC(h)
    aes = AESFoundation()
    eth = EncryptThenHMAC(CPAEncryption(aes.as_prf()), hm)
    k_E, k_M = os.urandom(16), os.urandom(16)
    m = b"top secret payload"
    (r, c), t = eth.encrypt((k_E, k_M), m)
    tampered = ((r, bytes([c[0] ^ 1]) + c[1:]), t)
    with pytest.raises(MacVerificationFailure):
        eth.decrypt((k_E, k_M), tampered)


def test_mac_to_compression_backward():
    """Bidirectional: derive a CRHF from HMAC."""
    h = DLPHash(bits=80)
    hm = HMAC(h)
    fixed = b"fixed-key-public" + b"\x00" * (hm.key_size - 16)
    compression = mac_to_compression(hm, fixed)
    z = b"\x00" * hm.tag_size
    block = b"\x11" * 16
    out = compression(z, block)
    assert len(out) == hm.tag_size
