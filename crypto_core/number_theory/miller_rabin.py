"""
PA#13: Miller-Rabin primality testing.

Probabilistic test: if it returns COMPOSITE, definitely composite.
If it returns PROBABLY_PRIME, error probability <= 4^{-k} for k rounds.
"""
from crypto_core.common.randomness import secure_randrange
from crypto_core.number_theory.modular import mod_pow


def _trial_division(n: int) -> bool:
    """Quick reject by small primes. Returns True if composite, False otherwise."""
    small_primes = (
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
        53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    )
    for p in small_primes:
        if n == p:
            return False
        if n % p == 0:
            return True
    return False


def miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin test with k rounds. Returns True iff n is probably prime.

    Algorithm:
      Write n-1 = 2^s * d with d odd.
      For each round, pick witness a in [2, n-2] uniformly.
      Compute x = a^d mod n.
      If x == 1 or x == n-1: continue (round passed).
      Else square x up to s-1 times; if any square hits n-1, round passes.
      Else: composite.
    """
    if n < 2:
        return False
    if n < 4:
        return True  # 2 and 3 are prime
    if n % 2 == 0:
        return False
    if _trial_division(n):
        return False

    # Write n-1 = 2^s * d, d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = secure_randrange(2, n - 1)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def is_prime(n: int, k: int = 40) -> bool:
    """Convenience alias for miller_rabin."""
    return miller_rabin(n, k)


# ---------- Naive Fermat test (used in PA#13's Carmichael demo) ----------

def fermat_test(n: int, k: int = 20) -> bool:
    """
    Fermat primality test. Fooled by Carmichael numbers (e.g., 561). Used only
    to demonstrate why we need Miller-Rabin.
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    for _ in range(k):
        a = secure_randrange(2, n - 1)
        if mod_pow(a, n - 1, n) != 1:
            return False
    return True
