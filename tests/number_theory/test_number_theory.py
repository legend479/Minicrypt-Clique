"""Tests for number_theory layer (PA#13, PA#14)."""
import pytest
from crypto_core.number_theory.modular import mod_pow, mod_inverse, ext_gcd, gcd
from crypto_core.number_theory.miller_rabin import miller_rabin, fermat_test
from crypto_core.number_theory.prime_gen import gen_prime, gen_safe_prime
from crypto_core.number_theory.crt import crt, garner_recombine
from crypto_core.number_theory.integer_root import integer_nth_root, is_perfect_power


def test_mod_pow_matches_builtin():
    for a, b, n in [(2, 100, 17), (123, 456, 1009), (0, 0, 7), (5, 0, 13)]:
        assert mod_pow(a, b, n) == pow(a, b, n)


def test_mod_inverse():
    for a, n in [(7, 26), (3, 11), (17, 1009)]:
        inv = mod_inverse(a, n)
        assert (a * inv) % n == 1


def test_mod_inverse_gcd_check():
    with pytest.raises(ValueError):
        mod_inverse(6, 9)


def test_ext_gcd_invariant():
    for a, b in [(123, 456), (7, 13), (1009, 17)]:
        g, x, y = ext_gcd(a, b)
        assert a * x + b * y == g
        assert g == gcd(a, b)


KNOWN_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 97, 101, 1009, 7919, 104729]
KNOWN_COMPOSITES = [4, 9, 15, 21, 25, 100, 1001]
CARMICHAELS = [561, 1105, 1729, 2465, 2821]


def test_miller_rabin_primes():
    for p in KNOWN_PRIMES:
        assert miller_rabin(p, k=20)


def test_miller_rabin_composites():
    for c in KNOWN_COMPOSITES:
        assert not miller_rabin(c, k=20)


def test_miller_rabin_catches_carmichael():
    for c in CARMICHAELS:
        assert not miller_rabin(c, k=40), f"MR failed on Carmichael {c}"


def test_gen_prime_64_bit():
    p = gen_prime(64)
    assert miller_rabin(p, k=40)
    assert p.bit_length() == 64


def test_gen_safe_prime():
    p, q = gen_safe_prime(32)
    assert p == 2 * q + 1
    assert miller_rabin(p, k=40)
    assert miller_rabin(q, k=40)


def test_crt_basic():
    assert crt([2, 3, 2], [3, 5, 7]) == 23


def test_crt_random():
    import random
    random.seed(0)
    for moduli in [(11, 13, 17), (101, 103, 107), (3, 5, 7, 11, 13)]:
        N = 1
        for n in moduli:
            N *= n
        x = random.randrange(1, 10**6) % N
        residues = [x % n for n in moduli]
        assert crt(residues, list(moduli)) == x


def test_garner_matches_standard_rsa():
    from crypto_core.pubkey.rsa import RSA
    rsa = RSA(bits=512)
    pk, sk = rsa.keygen()
    m = 0xCAFEBABE12345678
    c = rsa.encrypt(pk, m)
    assert rsa.decrypt(sk, c) == rsa.decrypt_crt(sk, c) == m


def test_integer_nth_root():
    assert integer_nth_root(125, 3) == 5
    assert integer_nth_root(124, 3) == 4
    assert integer_nth_root(126, 3) == 5
    assert integer_nth_root(0, 5) == 0
    assert integer_nth_root(1, 7) == 1


def test_is_perfect_power():
    assert is_perfect_power(125, 3)
    assert is_perfect_power(1024, 10)
    assert not is_perfect_power(126, 3)
