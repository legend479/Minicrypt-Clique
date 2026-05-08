"""
Integer e-th root via Newton's method.

Used by Hastad's broadcast attack (PA#14): after CRT recovers m^e as an
integer, take the e-th integer root to recover m.
"""


def integer_nth_root(n: int, e: int) -> int:
    """
    Return floor(n^(1/e)) for non-negative integer n and positive integer e.

    Uses Newton's iteration on the integers:
        x_{k+1} = ((e-1)*x_k + n // x_k^{e-1}) // e
    Converges quadratically. Final correction step ensures floor result.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if e < 1:
        raise ValueError("e must be positive")
    if n < 2:
        return n
    if e == 1:
        return n

    # Initial estimate: 2^ceil(bit_length(n)/e)
    x = 1 << ((n.bit_length() + e - 1) // e)
    while True:
        # x_{k+1} = ((e-1)*x + n // x^{e-1}) // e
        t = ((e - 1) * x + n // pow(x, e - 1)) // e
        if t >= x:
            break
        x = t
    # x might be one too large; correct downward.
    while pow(x, e) > n:
        x -= 1
    # And ensure we haven't overshot the floor.
    while pow(x + 1, e) <= n:
        x += 1
    return x


def is_perfect_power(n: int, e: int) -> bool:
    """True iff n is exactly a perfect e-th power."""
    r = integer_nth_root(n, e)
    return pow(r, e) == n
