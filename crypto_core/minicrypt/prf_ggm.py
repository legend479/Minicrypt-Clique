"""
PA#2: Pseudorandom Functions via the GGM tree.

Forward (PA#2a):  PRG G : {0,1}^n -> {0,1}^{2n}  ==>  PRF F_k(x)
  Write G(s) = G_0(s) || G_1(s).
  Define F_k(b_1 b_2 ... b_n) = G_{b_n}(G_{b_{n-1}}(... G_{b_1}(k) ...))
  Cost: n PRG evaluations per query (root-to-leaf path, one per query).

Backward (PA#2b):  PRF ==> PRG
  G(s) = F_s(0) || F_s(1)  is length-doubling pseudorandom.

Bidirectional reduction explicit and tested.
"""
from typing import List
from crypto_core.common.interfaces import PRG, PRF
from crypto_core.common.bitops import bytes_to_bits, int_to_bytes


# ============== PA#2a forward: PRG ==> PRF (GGM tree) ==============


class GGMTreePRF(PRF):
    """
    GGM construction: a PRF whose key is the seed of a length-doubling PRG.

    For an n-bit input x = b_1 b_2 ... b_n:
      s_0 = k
      s_i = G_{b_i}(s_{i-1})    where G(s) = G_0(s) || G_1(s)
      F_k(x) = s_n
    """

    def __init__(self, prg: PRG, input_bits: int = 16, key_bytes: int = 16):
        """
        prg: any length-doubling PRG (e.g. HILLPRG, AESPRF wrapped).
        input_bits: number of input bits = depth of the tree.
        key_bytes: size of seed/intermediate state in bytes.
        """
        self._prg = prg
        self._input_bits = input_bits
        self._key_bytes = key_bytes

    @property
    def block_size(self) -> int:
        return self._key_bytes

    @property
    def key_size(self) -> int:
        return self._key_bytes

    @property
    def input_bits(self) -> int:
        return self._input_bits

    def _split(self, expanded: bytes):
        half = self._key_bytes
        return expanded[:half], expanded[half:2 * half]

    def evaluate(self, k: bytes, x: bytes, *, trace=None) -> bytes:
        """
        x is interpreted as an integer (big-endian). Only the first input_bits
        bits are used (most-significant-first).
        """
        if len(k) != self._key_bytes:
            raise ValueError(f"GGMTreePRF: key must be {self._key_bytes} bytes")
        # Extract input_bits bits from x.
        x_int = int.from_bytes(x, "big")
        # Mask to input_bits bits (low-order); then iterate MSB first.
        x_int &= (1 << self._input_bits) - 1
        bits = [(x_int >> (self._input_bits - 1 - i)) & 1 for i in range(self._input_bits)]

        s = k
        path = [s]
        for bit in bits:
            self._prg.seed(s)
            expanded = self._prg.next_bits(2 * self._key_bytes)
            g0, g1 = self._split(expanded)
            s = g1 if bit else g0
            path.append(s)

        if trace is not None:
            trace.record(
                name="GGM tree PRF",
                inputs={"k": k, "x_bits": "".join(str(b) for b in bits)},
                outputs={"F_k(x)": s, "path": [p.hex() for p in path]},
                theorem="PRG ==> PRF (GGM)",
                pa_number=2,
            )
        return s


# ============== PA#2b backward: PRF ==> PRG ==============


class PRFAsPRG(PRG):
    """
    Backward reduction:  G(s) = F_s(0) || F_s(1).

    Length-doubling: input s of size key_size, output 2 * block_size.
    Distinguishability of G would yield a PRF distinguisher.
    """

    def __init__(self, prf: PRF):
        self._prf = prf
        self._seed = None
        # We use the PRF block size as the input-domain size.
        self._block_size = prf.block_size
        self._key_size = prf.key_size

    @property
    def seed_length(self) -> int:
        return self._key_size

    def seed(self, s: bytes) -> None:
        if len(s) != self._key_size:
            raise ValueError(f"seed length must be {self._key_size}")
        self._seed = s

    def next_bits(self, n_bytes: int, *, trace=None) -> bytes:
        if self._seed is None:
            raise RuntimeError("PRFAsPRG: seed not set")
        out = b""
        ctr = 0
        while len(out) < n_bytes:
            x = ctr.to_bytes(self._block_size, "big")
            block = self._prf.evaluate(self._seed, x)
            out += block
            ctr += 1
        out = out[:n_bytes]
        if trace is not None:
            trace.record(
                name="PRF-as-PRG  G(s) = F_s(0) || F_s(1) || ...",
                inputs={"seed": self._seed, "n_bytes": n_bytes},
                outputs={"G(s)": out},
                theorem="PRF ==> PRG (length-doubling and beyond by counter)",
                pa_number=2,
            )
        return out


def prf_as_prg(prf: PRF) -> PRG:
    """Backward reduction: wrap a PRF as a length-doubling PRG."""
    return PRFAsPRG(prf)
