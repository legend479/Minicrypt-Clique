"""
Prime and safe-prime generation, built on Miller-Rabin (PA#13).
"""
from crypto_core.common.randomness import secure_random_odd_nbit
from crypto_core.number_theory.miller_rabin import miller_rabin


def gen_prime(bits: int, mr_rounds: int = 40, max_attempts: int = 100_000) -> int:
    """
    Generate a probable prime with exactly `bits` bits (top bit set).

    Returns the prime; raises RuntimeError if max_attempts exceeded.
    """
    if bits < 2:
        raise ValueError("bits must be >= 2")
    for _ in range(max_attempts):
        candidate = secure_random_odd_nbit(bits)
        if miller_rabin(candidate, mr_rounds):
            return candidate
    raise RuntimeError(f"gen_prime: failed to find a {bits}-bit prime in {max_attempts} attempts")


def gen_safe_prime(bits: int, mr_rounds: int = 20, max_attempts: int = 200_000) -> tuple:
    """
    Generate a safe prime p = 2q + 1 with q also prime. Both p and q are tested
    with Miller-Rabin.

    Returns (p, q).
    """
    if bits < 4:
        raise ValueError("bits must be >= 4")
    for _ in range(max_attempts):
        q = secure_random_odd_nbit(bits - 1)
        if not miller_rabin(q, mr_rounds):
            continue
        p = 2 * q + 1
        if miller_rabin(p, mr_rounds):
            return p, q
    raise RuntimeError(f"gen_safe_prime: failed for {bits} bits in {max_attempts} attempts")
