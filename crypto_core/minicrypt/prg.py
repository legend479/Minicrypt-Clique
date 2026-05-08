"""
PA#1: Pseudorandom Generators.

Forward (PA#1a):  OWF + hard-core bit  ==>  PRG
  HILL/Blum-Micali iterative construction:
    seed s = x_0;  x_{i+1} = f(x_i);  output b(x_0) || b(x_1) || ... || b(x_l)

  When f is a one-way permutation (DLP), this is exactly Blum-Micali; security
  reduces to DLP hardness in a single tight reduction.

Backward (PA#1b):  PRG ==> OWF
  f(s) = G(s) is itself a OWF: any inverter for G(s) recovers s, breaking
  pseudorandomness.

Bidirectional reduction explicit and tested.
"""
from typing import Optional
from crypto_core.common.interfaces import PRG, OWF
from crypto_core.common.bitops import bits_to_bytes, bytes_to_bits, int_to_bytes


# ============== PA#1a forward: OWF + hard-core ==> PRG ==============

class HILLPRG(PRG):
    """
    Iterative hard-core-bit PRG from a one-way function.

    Given OWF f and hard-core predicate b:
      x_0 = seed
      x_{i+1} = f(x_i)
      output bit i: b(x_i)

    With OWP (e.g. DLP) this is provably secure under DLP hardness.
    With a generic OWF you may need stretching / Goldreich-Levin; here we
    accept whatever hard-core predicate the OWF provides.
    """

    def __init__(self, owf: OWF):
        self._owf = owf
        self._seed: Optional[int] = None
        # Domain bits = number of bits in seed = number of bits per state
        self._domain_bits = owf.domain_bits

    @property
    def seed_length(self) -> int:
        return (self._domain_bits + 7) // 8

    def seed(self, s: bytes) -> None:
        if len(s) < self.seed_length:
            raise ValueError(f"HILLPRG seed must be >= {self.seed_length} bytes")
        # Truncate / mask to fit domain
        seed_int = int.from_bytes(s[:self.seed_length], "big")
        # Mask to domain_bits to ensure within domain
        seed_int &= (1 << self._domain_bits) - 1
        # If domain is Z_q (DLP), ensure within bounds (modulo if necessary)
        if hasattr(self._owf, "q"):
            seed_int %= self._owf.q
        self._seed = seed_int

    def next_bits(self, n_bytes: int, *, trace=None) -> bytes:
        """Produce n_bytes pseudorandom bytes by iterating f and concatenating b(x_i)."""
        if self._seed is None:
            raise RuntimeError("HILLPRG: seed not set")
        if n_bytes <= 0:
            return b""

        n_bits = n_bytes * 8
        bits = []
        x = self._seed
        for i in range(n_bits):
            bits.append(self._owf.hard_core_predicate(x))
            x = self._owf.evaluate(x)
            # If foundation has domain bound, keep in bound
            if hasattr(self._owf, "q"):
                x %= self._owf.q
        out = bits_to_bytes(bits)

        if trace is not None:
            trace.record(
                name="HILL hard-core-bit PRG",
                inputs={"seed": self._seed, "n_bytes": n_bytes},
                outputs={"prg_output": out},
                theorem="HILL: OWF + hard-core bit ==> PRG (Blum-Micali if OWF is OWP)",
                pa_number=1,
            )
        return out


# ============== PA#1b backward: PRG ==> OWF ==============

class PRGAsOWF(OWF):
    """
    Backward reduction: a PRG G is itself a one-way function.

    f(s) = G(s).  Inverting f means recovering the seed from PRG output, which
    would directly distinguish PRG output from random (uniform random has no
    matching seed almost surely), breaking PRG security.
    """

    def __init__(self, prg: PRG, output_bytes: int = None):
        self._prg = prg
        self._output_bytes = output_bytes or (prg.seed_length * 2)
        self._domain_bits = prg.seed_length * 8

    @property
    def domain_bits(self) -> int:
        return self._domain_bits

    def evaluate(self, x, *, trace=None):
        if isinstance(x, int):
            seed_bytes = int_to_bytes(x, self._prg.seed_length)
        else:
            seed_bytes = x
        self._prg.seed(seed_bytes)
        out = self._prg.next_bits(self._output_bytes)
        if trace is not None:
            trace.record(
                name="PRG-as-OWF f(s) = G(s)",
                inputs={"seed": seed_bytes},
                outputs={"f(s)": out},
                theorem="PRG ==> OWF (any inverter breaks pseudorandomness)",
                pa_number=1,
            )
        return out

    def hard_core_predicate(self, x) -> int:
        if isinstance(x, int):
            return x & 1
        return x[-1] & 1


def prg_as_owf(prg: PRG, output_bytes: int = None) -> OWF:
    """Backward reduction: wrap a PRG as a OWF."""
    return PRGAsOWF(prg, output_bytes)


# ============== Statistical tests (NIST SP 800-22 subset) ==============

def monobit_frequency_test(data: bytes) -> tuple:
    """
    NIST SP 800-22 Section 2.1 - Frequency (Monobit) test.

    Counts the proportion of 1 bits and tests for ~50%.
    Returns (p_value, passed). Pass threshold: p_value >= 0.01.
    """
    import math
    bits = bytes_to_bits(data)
    n = len(bits)
    # S_n = sum of (2*bit - 1)
    s_n = sum(2 * b - 1 for b in bits)
    s_obs = abs(s_n) / math.sqrt(n)
    # erfc(s_obs / sqrt(2))
    p = math.erfc(s_obs / math.sqrt(2))
    return p, p >= 0.01


def runs_test(data: bytes) -> tuple:
    """
    NIST SP 800-22 Section 2.3 - Runs test.

    Tests that runs (maximal blocks of identical bits) are consistent with random.
    Returns (p_value, passed).
    """
    import math
    bits = bytes_to_bits(data)
    n = len(bits)
    pi = sum(bits) / n
    # Pre-test: |pi - 0.5| must be < 2/sqrt(n)
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0, False
    # Count runs
    v_n = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            v_n += 1
    numerator = abs(v_n - 2 * n * pi * (1 - pi))
    denominator = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    if denominator == 0:
        return 0.0, False
    p = math.erfc(numerator / denominator)
    return p, p >= 0.01


def serial_test_lite(data: bytes) -> tuple:
    """
    Lightweight serial-style test: chi-square on 2-bit pair frequencies.
    Returns (p_or_chi, passed). Used as an additional independence check.

    Not a full NIST serial test, but a useful sanity check that bit pairs
    appear with frequencies near 0.25 each.
    """
    bits = bytes_to_bits(data)
    n = len(bits)
    if n < 4:
        return 0.0, False
    # Count overlapping 2-bit patterns
    counts = [0, 0, 0, 0]
    for i in range(n - 1):
        pat = (bits[i] << 1) | bits[i + 1]
        counts[pat] += 1
    expected = (n - 1) / 4
    chi = sum((c - expected) ** 2 / expected for c in counts)
    # df=3 chi-square 0.99 critical ~= 11.345
    return chi, chi < 11.345
