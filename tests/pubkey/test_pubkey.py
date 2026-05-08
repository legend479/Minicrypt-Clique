"""Tests for pubkey: PA#11-#17."""
import os
import pytest

from crypto_core.pubkey.diffie_hellman import DiffieHellman, MITMAdversary
from crypto_core.pubkey.rsa import RSA, PKCS1v15
from crypto_core.pubkey.rsa_attacks import (
    determinism_demo, hastad_broadcast_attack, rsa_sign_homomorphism_forgery,
)
from crypto_core.pubkey.signatures import RSASignature, RawRSASignature
from crypto_core.pubkey.elgamal import ElGamal, elgamal_malleability_attack
from crypto_core.pubkey.cca_pkc import Signcryption
from crypto_core.hashing.dlp_hash import DLPHash
from crypto_core.common.exceptions import MacVerificationFailure
from crypto_core.number_theory.modular import mod_pow


# ---------- PA#11: DH ----------

def test_dh_shared_secret_matches():
    dh = DiffieHellman(bits=128)
    a, A = dh.alice_step1()
    b, B = dh.bob_step1()
    assert dh.alice_step2(a, B) == dh.bob_step2(b, A)


def test_dh_mitm_holds_both_secrets():
    dh = DiffieHellman(bits=128)
    a, A = dh.alice_step1()
    b, B = dh.bob_step1()
    eve = MITMAdversary(dh)
    A_fake = eve.intercept_alice(A)
    B_fake = eve.intercept_bob(B)
    K_a = dh.alice_step2(a, B_fake)
    K_b = dh.bob_step2(b, A_fake)
    assert K_a == eve.shared_with_alice()
    assert K_b == eve.shared_with_bob()
    # Honest endpoints don't agree (they're talking to Eve, not each other).
    assert K_a != K_b


# ---------- PA#12: RSA ----------

def test_rsa_round_trip():
    rsa = RSA(bits=512)
    pk, sk = rsa.keygen()
    m = 0xCAFEBABE
    c = rsa.encrypt(pk, m)
    assert rsa.decrypt(sk, c) == m


def test_rsa_crt_matches_standard():
    rsa = RSA(bits=512)
    pk, sk = rsa.keygen()
    m = 0xDEADBEEF12345
    c = rsa.encrypt(pk, m)
    assert rsa.decrypt_crt(sk, c) == rsa.decrypt(sk, c) == m


def test_textbook_rsa_deterministic_leak():
    rsa = RSA(bits=512)
    pk, sk = rsa.keygen()
    res = determinism_demo(rsa, pk, b"vote: yes", n_trials=5)
    assert res["all_identical"]


def test_pkcs15_round_trip_and_random():
    rsa = RSA(bits=512)
    pk, sk = rsa.keygen()
    pkcs = PKCS1v15(rsa)
    m = b"hello pkcs"
    c1 = pkcs.encrypt(pk, m)
    c2 = pkcs.encrypt(pk, m)
    assert c1 != c2  # randomized
    assert pkcs.decrypt(sk, c1) == m
    assert pkcs.decrypt(sk, c2) == m


# ---------- PA#13 already tested in number_theory tests ----------

# ---------- PA#14: Hastad ----------

def test_hastad_e3_recovers_plaintext():
    e = 3
    keys = []
    for _ in range(e):
        while True:
            rsa = RSA(bits=256, e=e)
            try:
                pk, _ = rsa.keygen()
                keys.append(pk); break
            except Exception:
                continue
    m = 0xABCD1234
    cts = [mod_pow(m, e, pk.N) for pk in keys]
    moduli = [pk.N for pk in keys]
    res = hastad_broadcast_attack(cts, moduli, e)
    assert res["recovered_m"] == m
    assert res["is_perfect_root"]


# ---------- PA#15: signatures ----------

def test_rsa_signature_verify():
    sig = RSASignature(RSA(bits=512), DLPHash(bits=80))
    vk, sk = sig.keygen()
    m = b"signed terms"
    sigma = sig.sign(sk, m)
    assert sig.verify(vk, m, sigma)


def test_rsa_signature_rejects_tamper():
    sig = RSASignature(RSA(bits=512), DLPHash(bits=80))
    vk, sk = sig.keygen()
    m = b"signed terms"
    sigma = sig.sign(sk, m)
    assert not sig.verify(vk, m + b"!", sigma)


def test_raw_rsa_homomorphism_forgery():
    """Without hashing, raw RSA signatures are forgeable on m1*m2."""
    raw = RawRSASignature(RSA(bits=512))
    vk, sk = raw.keygen()
    m1, m2 = 7, 11
    s1 = raw.sign(sk, m1)
    s2 = raw.sign(sk, m2)
    forged = rsa_sign_homomorphism_forgery(vk, s1, s2, vk.N)
    expected_m = (m1 * m2) % vk.N
    assert raw.verify(vk, expected_m, forged)


# ---------- PA#16: ElGamal ----------

def test_elgamal_round_trip():
    eg = ElGamal(bits=128)
    pk, sk = eg.keygen()
    m = 42
    assert eg.decrypt(sk, eg.encrypt(pk, m)) == m


def test_elgamal_malleability():
    eg = ElGamal(bits=128)
    pk, sk = eg.keygen()
    m = 5
    ct = eg.encrypt(pk, m)
    attacked = elgamal_malleability_attack(ct, 3, pk.p)
    assert eg.decrypt(sk, attacked) == (3 * m) % pk.p


# ---------- PA#17: Signcryption ----------

def test_signcryption_round_trip():
    sig = RSASignature(RSA(bits=512), DLPHash(bits=80))
    sc = Signcryption(ElGamal(bits=128), sig)
    pk_combined, sk_combined = sc.keygen()
    vk_sig, sk_sig = sig.keygen()
    m = b"top secret"
    ct = sc.encrypt(pk_combined, m, sender_sk_sig=sk_sig)
    rec = sc.decrypt(sk_combined, ct, sender_vk_sig=vk_sig)
    assert rec == m


def test_signcryption_rejects_tampered():
    sig = RSASignature(RSA(bits=512), DLPHash(bits=80))
    sc = Signcryption(ElGamal(bits=128), sig)
    pk_combined, sk_combined = sc.keygen()
    vk_sig, sk_sig = sig.keygen()
    m = b"top secret"
    (c1, c2), sigma = sc.encrypt(pk_combined, m, sender_sk_sig=sk_sig)
    p = pk_combined[0].p
    tampered = ((c1, (c2 * 2) % p), sigma)
    with pytest.raises(MacVerificationFailure):
        sc.decrypt(sk_combined, tampered, sender_vk_sig=vk_sig)
