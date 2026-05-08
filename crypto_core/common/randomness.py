"""
The single chokepoint for cryptographic randomness in the codebase.

Only os.urandom is used. This is the one library exception explicitly permitted
by the spec ("OS-level randomness").
"""
import os


def secure_random_bytes(n: int) -> bytes:
    """Return n cryptographically secure random bytes."""
    if n < 0:
        raise ValueError("n must be non-negative")
    return os.urandom(n)


def secure_randint(n_bits: int) -> int:
    """Uniform random non-negative integer in [0, 2^n_bits)."""
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    n_bytes = (n_bits + 7) // 8
    raw = os.urandom(n_bytes)
    val = int.from_bytes(raw, "big")
    # Clear top bits beyond n_bits.
    extra = n_bytes * 8 - n_bits
    if extra:
        val >>= extra
    return val


def secure_randrange(low: int, high: int) -> int:
    """
    Uniform random integer in [low, high). Rejection sampling for unbiased output.
    """
    if low >= high:
        raise ValueError("require low < high")
    span = high - low
    n_bits = span.bit_length()
    while True:
        x = secure_randint(n_bits)
        if x < span:
            return low + x


def secure_random_odd_nbit(n_bits: int) -> int:
    """Random odd integer with the top bit set (used for prime generation)."""
    x = secure_randint(n_bits)
    x |= (1 << (n_bits - 1))  # ensure top bit set => exactly n_bits
    x |= 1                    # ensure odd
    return x
