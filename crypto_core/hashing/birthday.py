"""
PA#9: Birthday attack -- collision finding in O(2^{n/2}).

Two algorithms:
  birthday_attack_naive: hash table approach. O(2^{n/2}) time and space.
  birthday_attack_floyd: tortoise-and-hare. O(2^{n/2}) time, O(1) space.

Both return (x1, x2, h) with x1 != x2 and H(x1) == H(x2), plus the number of
hash evaluations performed.
"""
from typing import Callable, Optional, Tuple
from crypto_core.common.randomness import secure_random_bytes


def birthday_attack_naive(hash_fn: Callable[[bytes], bytes],
                          input_bytes: int = 8,
                          max_queries: int = 1_000_000) -> Optional[dict]:
    """
    Naive birthday attack: hash random inputs, store in a dict, return the
    first collision found.

    Returns {'x1', 'x2', 'h', 'queries'} or None if not found within budget.
    """
    seen = {}
    for q in range(1, max_queries + 1):
        x = secure_random_bytes(input_bytes)
        h = hash_fn(x)
        if h in seen and seen[h] != x:
            return {"x1": seen[h], "x2": x, "h": h, "queries": q,
                    "method": "naive"}
        seen[h] = x
    return None


def birthday_attack_floyd(hash_fn: Callable[[bytes], bytes],
                          input_bytes: int = 8,
                          max_iterations: int = 10_000_000) -> Optional[dict]:
    """
    Floyd's tortoise-and-hare cycle-finding birthday attack.

    Treat the hash as a function f : input_space -> input_space by setting
    f(x) = (some deterministic encoding of) hash_fn(x).

    1. Phase 1: tortoise advances 1 step, hare advances 2 steps until they meet.
    2. Phase 2: reset tortoise to start; both advance 1 step. Meeting point is
       the cycle entry point.
    3. The pair (tortoise_prev, hare_prev) just before the meeting point gives
       a collision under f.

    Returns {'x1', 'x2', 'h', 'iterations'} or None.
    """
    # Reduce hash output to an input-sized string so f maps input -> input.
    def f(x: bytes) -> bytes:
        h = hash_fn(x)
        # Take last input_bytes of the hash (or pad if shorter).
        if len(h) >= input_bytes:
            return h[-input_bytes:]
        return h.rjust(input_bytes, b"\x00")

    x0 = secure_random_bytes(input_bytes)
    tortoise = f(x0)
    hare = f(f(x0))
    iters = 3
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(f(hare))
        iters += 3
        if iters > max_iterations:
            return None

    # Phase 2: find cycle entry.
    tortoise = x0
    while True:
        if f(tortoise) == f(hare):
            # Collision detected.
            x1, x2 = tortoise, hare
            iters += 2
            if x1 == x2:
                # Same input; not a useful collision. Restart with fresh seed
                # would be needed; for our purposes, signal absence.
                return None
            if hash_fn(x1) == hash_fn(x2):
                return {
                    "x1": x1, "x2": x2,
                    "h": hash_fn(x1),
                    "iterations": iters,
                    "method": "floyd",
                }
            # Reduction collision, not a real one in the original hash output;
            # this can happen with our truncation. Move forward and try again.
            tortoise = f(tortoise)
            hare = f(hare)
            iters += 2
            if iters > max_iterations:
                return None
            continue
        tortoise = f(tortoise)
        hare = f(hare)
        iters += 2
        if iters > max_iterations:
            return None


def empirical_birthday_curve(hash_fn: Callable[[bytes], bytes],
                             input_bytes: int = 8,
                             trials: int = 50,
                             max_queries: int = 100_000) -> dict:
    """
    Run birthday_attack_naive `trials` times. Returns mean and std of the
    number of queries. Used to verify the empirical match with 2^{n/2}.
    """
    import statistics
    counts = []
    for _ in range(trials):
        result = birthday_attack_naive(hash_fn, input_bytes, max_queries)
        if result is not None:
            counts.append(result["queries"])
    if not counts:
        return {"trials_completed": 0}
    return {
        "trials_completed": len(counts),
        "mean": statistics.mean(counts),
        "stdev": statistics.stdev(counts) if len(counts) > 1 else 0.0,
        "min": min(counts),
        "max": max(counts),
    }
