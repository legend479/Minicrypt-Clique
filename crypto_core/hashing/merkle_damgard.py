"""
PA#7: Merkle-Damgard domain extension.

Given a fixed-length compression function h : {0,1}^{n+b} -> {0,1}^n, build a
hash function H for arbitrary-length inputs.

Algorithm:
  1. Pad message with MD-strengthening: append 0x80, zero-pad, then 64-bit
     big-endian length field.
  2. Parse into b-byte blocks M_1, ..., M_l.
  3. z_0 = IV.   z_i = h(z_{i-1} || M_i).
  4. Output z_l.

Theorem: If h is collision-resistant, so is H.
"""
from typing import Callable
from crypto_core.common.interfaces import Hash, CRHF
from crypto_core.common.bitops import md_strengthening_pad


class MerkleDamgard(Hash):
    """
    Generic Merkle-Damgard hash builder.

    compression_fn(z, block) -> z'   takes (state, block) and returns new state.
    iv: initial state (n bytes).
    block_size: block length in bytes.
    output_size: state length in bytes.
    """

    def __init__(self, compression_fn: Callable[[bytes, bytes], bytes],
                 iv: bytes, block_size: int, output_size: int):
        self._h = compression_fn
        self._iv = iv
        self._block = block_size
        self._out = output_size
        if len(iv) != output_size:
            raise ValueError(f"IV length {len(iv)} != output_size {output_size}")

    @property
    def output_size(self) -> int:
        return self._out

    @property
    def block_size(self) -> int:
        return self._block

    def digest(self, m: bytes, *, trace=None) -> bytes:
        padded = md_strengthening_pad(m, self._block)
        z = self._iv
        chain = [z]
        for i in range(0, len(padded), self._block):
            block = padded[i:i + self._block]
            z = self._h(z, block)
            chain.append(z)
        if trace is not None:
            trace.record(
                name="Merkle-Damgard hash",
                inputs={"m": m, "padded": padded},
                outputs={"H(m)": z, "chain": [c.hex() for c in chain]},
                theorem="MD: CRHF compression ==> CRHF hash",
                pa_number=7,
            )
        return z


class XorToyCompression:
    """
    Toy compression function for testing the MD framework in isolation.

    h(z, block) = z XOR block_first_state_bytes XOR rotate(block_rest, ...)

    NOT collision-resistant; used purely to verify MD plumbing.
    """

    def __init__(self, output_size: int = 4, block_size: int = 8):
        self._out = output_size
        self._block = block_size

    def __call__(self, z: bytes, block: bytes) -> bytes:
        if len(z) != self._out:
            raise ValueError(f"toy compression: z must be {self._out} bytes")
        if len(block) != self._block:
            raise ValueError(f"toy compression: block must be {self._block} bytes")
        out = bytearray(z)
        for i, b in enumerate(block):
            out[i % self._out] ^= b
            # Light mixing: rotate one bit
            out[i % self._out] = ((out[i % self._out] << 1) | (out[i % self._out] >> 7)) & 0xFF
        return bytes(out)
