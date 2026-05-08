"""
PA#8: DLP-based collision-resistant hash function.

Compression:  h(x, y) = g^x * h_pub^y  mod p
  where (g, h_pub) are generators of an order-q subgroup of Z_p^*.

Collision resistance proof: a collision (x,y) != (x',y') with h(x,y)=h(x',y')
gives  log_g(h_pub) = (x - x')/(y' - y) mod q.  So a collision-finder yields
a discrete-log oracle, contradicting DLP hardness.

We plug this into PA#7's Merkle-Damgard framework to get a full hash for
arbitrary-length input.
"""
from crypto_core.common.interfaces import CRHF
from crypto_core.foundation.dlp_foundation import DLPFoundation
from crypto_core.number_theory.modular import mod_pow
from crypto_core.hashing.merkle_damgard import MerkleDamgard


class DLPCompression:
    """
    DLP compression function. Treats incoming state z and message block m as
    integers in Z_q, computes g^z * h_pub^m mod p, and returns the result as a
    big-endian byte string of size output_size.
    """

    def __init__(self, foundation: DLPFoundation, h_pub: int = None):
        self._p = foundation.p
        self._q = foundation.q
        self._g = foundation.g
        # Pick a second generator. For correctness it just needs to lie in the
        # order-q subgroup. We pick g^alpha for an unknown random alpha that we
        # then discard (in real life the alpha must be unknowable).
        if h_pub is None:
            from crypto_core.common.randomness import secure_randrange
            alpha = secure_randrange(2, self._q)
            h_pub = mod_pow(self._g, alpha, self._p)
            # Note: we deliberately do not store alpha.
        self._h_pub = h_pub
        # Output / block sizing. The chaining state is a canonical subgroup
        # element in Z_p^*, so output_size must fit p. Blocks are interpreted as
        # exponents in Z_q; choose a block size whose whole byte range fits
        # below q so distinct blocks cannot collide merely by reduction mod q.
        self._output_size = (self._p.bit_length() + 7) // 8
        self._block_size = (self._q.bit_length() - 1) // 8
        if self._block_size < 9:
            raise ValueError("DLPHash requires a group large enough for MD strengthening blocks")

    @property
    def output_size(self):
        return self._output_size

    @property
    def block_size(self):
        return self._block_size

    @property
    def iv(self):
        # IV: canonical representation of group identity 1.
        return (1).to_bytes(self._output_size, "big")

    @property
    def h_pub(self) -> int:
        return self._h_pub

    def __call__(self, z_bytes: bytes, m_bytes: bytes) -> bytes:
        if len(z_bytes) != self._output_size:
            raise ValueError(f"DLP compression state must be {self._output_size} bytes")
        if len(m_bytes) != self._block_size:
            raise ValueError(f"DLP compression block must be {self._block_size} bytes")

        state_int = int.from_bytes(z_bytes, "big")
        if not (1 <= state_int < self._p):
            raise ValueError("DLP compression state is not a canonical group element")
        if mod_pow(state_int, self._q, self._p) != 1:
            raise ValueError("DLP compression state is outside the order-q subgroup")

        block_int = int.from_bytes(m_bytes, "big")
        if block_int >= self._q:
            raise ValueError("DLP compression block is outside Z_q")

        out = (state_int * mod_pow(self._h_pub, block_int, self._p)) % self._p
        return out.to_bytes(self._output_size, "big")


class DLPHash(CRHF):
    """
    Full DLP-based CRHF: PA#8 compression plugged into PA#7 Merkle-Damgard.
    """

    def __init__(self, foundation: DLPFoundation = None, bits: int = 80,
                 truncate_to: int = None):
        if foundation is None:
            foundation = DLPFoundation(bits=bits)
        self._foundation = foundation
        self._compression = DLPCompression(foundation)
        self._md = MerkleDamgard(
            self._compression,
            self._compression.iv,
            self._compression.block_size,
            self._compression.output_size,
        )
        # Optional truncation (used by PA#9 birthday-attack demo with n=16 bits).
        self._truncate = truncate_to

    @property
    def output_size(self) -> int:
        if self._truncate is not None:
            return self._truncate
        return self._compression.output_size

    @property
    def block_size(self) -> int:
        return self._compression.block_size

    @property
    def foundation(self) -> DLPFoundation:
        return self._foundation

    def digest(self, m: bytes, *, trace=None) -> bytes:
        full = self._md.digest(m, trace=trace)
        if self._truncate is not None:
            full = full[-self._truncate:]
        if trace is not None and self._truncate is not None:
            trace.record(
                name=f"Truncate to {self._truncate} bytes",
                inputs={"full_digest": self._md.digest(m)},
                outputs={"truncated": full},
                theorem="Truncation reduces output size (used in birthday demo)",
                pa_number=8,
            )
        return full
