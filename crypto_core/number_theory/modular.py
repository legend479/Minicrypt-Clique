"""
Modular arithmetic: square-and-multiply exponentiation, extended GCD,
modular inverse. All implemented from scratch (no library pow with three args
when used in security-critical paths).

Note: Python's built-in `pow(a, b, n)` is also a square-and-multiply, but the
spec requires "implement square-and-multiply yourself" so we provide our own
mod_pow and use it everywhere in crypto_core/.
"""


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Compute base^exponent mod modulus using square-and-multiply.

    O(log exponent) multiplications.
    """
    if modulus == 1:
        return 0
    if modulus < 1:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        # Use modular inverse for negative exponent.
        inv = mod_inverse(base, modulus)
        return mod_pow(inv, -exponent, modulus)

    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        exponent >>= 1
        base = (base * base) % modulus
    return result


def ext_gcd(a: int, b: int):
    """
    Extended Euclidean algorithm. Returns (g, x, y) with g = gcd(a, b) and
    a*x + b*y = g. Iterative implementation to avoid recursion depth limits.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(a: int, n: int) -> int:
    """Modular inverse a^{-1} mod n. Raises ValueError if gcd(a,n) != 1."""
    g, x, _ = ext_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"mod_inverse: {a} has no inverse mod {n} (gcd={g})")
    return x % n


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)
