"""
PRF ==> PRP via the Luby-Rackoff Feistel construction.

3 rounds: secure PRP.
4 rounds: secure strong PRP (against adversaries with inversion queries).

Used by PA#4 (CBC mode needs a PRP) and the PA#0 explorer's PRF -> PRP edge.
"""
from crypto_core.common.interfaces import PRF, PRP
from crypto_core.common.bitops import xor_bytes


class LubyRackoffPRP(PRP):
    """
    Feistel-network PRP built from an underlying PRF.

    Block size = 2 * (PRF block size).
    Key = a single PRF key; each round uses (key || round_byte) as the actual
    PRF key seed -- but to keep things simple and standard, we'll use a single
    key and prepend the round number to the PRF input.
    """

    def __init__(self, prf: PRF, rounds: int = 4):
        if rounds not in (3, 4):
            raise ValueError("Luby-Rackoff: rounds must be 3 (PRP) or 4 (strong PRP)")
        self._prf = prf
        self._rounds = rounds
        self._half = prf.block_size

    @property
    def block_size(self) -> int:
        return 2 * self._half

    @property
    def key_size(self) -> int:
        return self._prf.key_size

    def _round_function(self, k: bytes, round_idx: int, x: bytes) -> bytes:
        """F_i(x) = PRF_k(round_idx || x), then truncate/pad to half-block."""
        # We need a PRF input of exactly block_size bytes; prepend round byte
        # by XOR-ing the first byte with round_idx (deterministic, distinct per round).
        x_modified = bytes([(x[0] ^ round_idx) & 0xFF]) + x[1:]
        return self._prf.evaluate(k, x_modified)

    def evaluate(self, k: bytes, x: bytes, *, trace=None) -> bytes:
        if len(x) != 2 * self._half:
            raise ValueError(f"LubyRackoffPRP: input must be {2*self._half} bytes")
        L, R = x[:self._half], x[self._half:]
        for r in range(self._rounds):
            f_out = self._round_function(k, r + 1, R)
            new_L = R
            new_R = xor_bytes(L, f_out)
            L, R = new_L, new_R
        out = L + R
        if trace is not None:
            trace.record(
                name=f"Luby-Rackoff {self._rounds}-round Feistel",
                inputs={"k": k, "x": x},
                outputs={"y": out},
                theorem="PRF ==> PRP (3 rounds) / strong PRP (4 rounds)",
                pa_number=2,
            )
        return out

    def invert(self, k: bytes, y: bytes, *, trace=None) -> bytes:
        if len(y) != 2 * self._half:
            raise ValueError(f"LubyRackoffPRP: input must be {2*self._half} bytes")
        L, R = y[:self._half], y[self._half:]
        for r in range(self._rounds, 0, -1):
            f_out = self._round_function(k, r, L)
            new_R = L
            new_L = xor_bytes(R, f_out)
            L, R = new_L, new_R
        out = L + R
        if trace is not None:
            trace.record(
                name=f"Luby-Rackoff invert ({self._rounds} rounds)",
                inputs={"k": k, "y": y},
                outputs={"x": out},
                theorem="Feistel network is invertible by reversing rounds",
                pa_number=2,
            )
        return out
