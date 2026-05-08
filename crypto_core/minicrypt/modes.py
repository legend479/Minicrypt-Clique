"""
PA#4: Block cipher modes of operation.

Three modes:
  CBC: C_i = E_k(C_{i-1} XOR M_i)        (PRP needed for invertibility)
  OFB: keystream Z_i = E_k(Z_{i-1});  C_i = M_i XOR Z_i
  CTR: keystream Z_i = E_k(r + i);    C_i = M_i XOR Z_i

Each mode also has a documented attack demo (IV reuse, keystream reuse, etc.).
"""
from typing import Tuple
from crypto_core.common.interfaces import PRP, PRF
from crypto_core.common.bitops import xor_bytes, pkcs7_pad, pkcs7_unpad
from crypto_core.common.randomness import secure_random_bytes


def _split_blocks(data: bytes, block_size: int):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


# ---------- CBC ----------

class CBC:
    """CBC mode using a PRP (block cipher)."""

    def __init__(self, prp: PRP):
        self._prp = prp
        self._b = prp.block_size

    def encrypt(self, k: bytes, m: bytes, iv: bytes = None, *, trace=None) -> Tuple[bytes, bytes]:
        """Returns (iv, c)."""
        if iv is None:
            iv = secure_random_bytes(self._b)
        if len(iv) != self._b:
            raise ValueError(f"IV must be {self._b} bytes")
        padded = pkcs7_pad(m, self._b)
        prev = iv
        c_blocks = []
        for blk in _split_blocks(padded, self._b):
            xored = xor_bytes(prev, blk)
            ct = self._prp.evaluate(k, xored)
            c_blocks.append(ct)
            prev = ct
        c = b"".join(c_blocks)
        if trace is not None:
            trace.record(
                name="CBC encrypt",
                inputs={"k": k, "iv": iv, "m": m},
                outputs={"c": c},
                theorem="C_i = E_k(C_{i-1} XOR M_i)",
                pa_number=4,
            )
        return iv, c

    def decrypt(self, k: bytes, ciphertext: Tuple[bytes, bytes], *, trace=None) -> bytes:
        iv, c = ciphertext
        if len(c) % self._b != 0:
            raise ValueError("CBC ciphertext not block-aligned")
        prev = iv
        m_blocks = []
        for blk in _split_blocks(c, self._b):
            inv = self._prp.invert(k, blk)
            m_blocks.append(xor_bytes(prev, inv))
            prev = blk
        padded = b"".join(m_blocks)
        return pkcs7_unpad(padded, self._b)


# ---------- OFB ----------

class OFB:
    """
    OFB mode. Only needs a PRF (no inversion); we accept either PRF or PRP.
    Encryption and decryption are identical.
    """

    def __init__(self, prf: PRF):
        self._prf = prf
        self._b = prf.block_size

    def _keystream(self, k: bytes, iv: bytes, n_blocks: int):
        z = iv
        out = []
        for _ in range(n_blocks):
            z = self._prf.evaluate(k, z)
            out.append(z)
        return b"".join(out)

    def encrypt(self, k: bytes, m: bytes, iv: bytes = None, *, trace=None):
        if iv is None:
            iv = secure_random_bytes(self._b)
        # OFB does NOT need padding (it's a stream cipher), but we still
        # pad for consistency with the PA#4 spec (block-cipher modes).
        padded = pkcs7_pad(m, self._b)
        n_blocks = len(padded) // self._b
        ks = self._keystream(k, iv, n_blocks)
        c = xor_bytes(padded, ks)
        if trace is not None:
            trace.record(
                name="OFB encrypt",
                inputs={"k": k, "iv": iv, "m": m},
                outputs={"c": c, "keystream": ks},
                theorem="Z_i = E_k(Z_{i-1});  C_i = M_i XOR Z_i",
                pa_number=4,
            )
        return iv, c

    def decrypt(self, k: bytes, ciphertext, *, trace=None):
        iv, c = ciphertext
        n_blocks = len(c) // self._b
        ks = self._keystream(k, iv, n_blocks)
        padded = xor_bytes(c, ks)
        return pkcs7_unpad(padded, self._b)

    def precompute_keystream(self, k: bytes, iv: bytes, n_blocks: int) -> bytes:
        """Demonstrates that OFB keystream can be generated before plaintext is known."""
        return self._keystream(k, iv, n_blocks)


# ---------- Randomized CTR ----------

class CTR:
    """Randomized CTR mode. Fully parallelizable, no padding required."""

    def __init__(self, prf: PRF):
        self._prf = prf
        self._b = prf.block_size

    def _keystream(self, k: bytes, r_int: int, n_blocks: int):
        out = []
        for i in range(n_blocks):
            ctr = (r_int + i) % (1 << (self._b * 8))
            out.append(self._prf.evaluate(k, ctr.to_bytes(self._b, "big")))
        return b"".join(out)

    def encrypt(self, k: bytes, m: bytes, r: bytes = None, *, trace=None):
        if r is None:
            r = secure_random_bytes(self._b)
        # CTR doesn't need padding, but we keep messages length-preserving by
        # generating just enough keystream and truncating.
        n_blocks = (len(m) + self._b - 1) // self._b
        r_int = int.from_bytes(r, "big")
        ks = self._keystream(k, r_int, n_blocks)[:len(m)]
        c = xor_bytes(m, ks)
        if trace is not None:
            trace.record(
                name="CTR encrypt",
                inputs={"k": k, "r": r, "m": m},
                outputs={"c": c},
                theorem="Z_i = F_k(r+i);  C_i = M_i XOR Z_i",
                pa_number=4,
            )
        return r, c

    def decrypt(self, k: bytes, ciphertext, *, trace=None):
        r, c = ciphertext
        n_blocks = (len(c) + self._b - 1) // self._b
        r_int = int.from_bytes(r, "big")
        ks = self._keystream(k, r_int, n_blocks)[:len(c)]
        return xor_bytes(c, ks)


# ---------- Unified mode selector ----------

def encrypt(mode: str, k: bytes, m: bytes, primitive, **kwargs):
    """Unified API. mode in {'CBC', 'OFB', 'CTR'}."""
    if mode == "CBC":
        return CBC(primitive).encrypt(k, m, **kwargs)
    if mode == "OFB":
        return OFB(primitive).encrypt(k, m, **kwargs)
    if mode == "CTR":
        return CTR(primitive).encrypt(k, m, **kwargs)
    raise ValueError(f"unknown mode {mode}")


def decrypt(mode: str, k: bytes, ciphertext, primitive, **kwargs):
    if mode == "CBC":
        return CBC(primitive).decrypt(k, ciphertext, **kwargs)
    if mode == "OFB":
        return OFB(primitive).decrypt(k, ciphertext, **kwargs)
    if mode == "CTR":
        return CTR(primitive).decrypt(k, ciphertext, **kwargs)
    raise ValueError(f"unknown mode {mode}")
