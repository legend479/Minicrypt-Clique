"""
PA#5: Message Authentication Codes.

Three constructions:
  PRFMAC: t = F_k(m)              (fixed-length messages only)
  CBCMAC: chain F_k over message blocks   (variable-length messages)
  HMAC:   defined here as a STUB (see hashing/hmac.py for full PA#10)

Includes:
  - EUF-CMA game simulator
  - Length-extension attack demo on naive H(k || m)
"""
from typing import List
from crypto_core.common.interfaces import PRF, PRP, MAC
from crypto_core.common.bitops import xor_bytes
from crypto_core.common.exceptions import StubNotImplemented, MacVerificationFailure


# ---------- helpers ----------

def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time byte comparison."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


# ---------- PRF-MAC (PA#5) ----------

class PRFMAC(MAC):
    """
    Mac_k(m) = F_k(m)  for messages of exactly one PRF block.

    Forgery would distinguish F_k from random; security reduces to PRF.
    """

    def __init__(self, prf: PRF):
        self._prf = prf

    @property
    def key_size(self) -> int:
        return self._prf.key_size

    @property
    def tag_size(self) -> int:
        return self._prf.block_size

    def mac(self, k: bytes, m: bytes, *, trace=None) -> bytes:
        if len(m) != self._prf.block_size:
            raise ValueError(f"PRFMAC expects exactly {self._prf.block_size}-byte message")
        t = self._prf.evaluate(k, m)
        if trace is not None:
            trace.record(
                name="PRF-MAC: t = F_k(m)",
                inputs={"k": k, "m": m},
                outputs={"t": t},
                theorem="PRF ==> EUF-CMA secure MAC",
                pa_number=5,
            )
        return t

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        try:
            expected = self.mac(k, m)
        except ValueError:
            return False
        return constant_time_eq(expected, t)


# ---------- CBC-MAC (PA#5) ----------

class CBCMAC(MAC):
    """
    CBC-MAC for variable-length messages.

    Iterate F_k starting from a zero IV, chaining blocks; output the final
    chaining value as the tag.

    Note: textbook CBC-MAC is secure only for fixed-length messages. For
    variable lengths we MUST length-prefix or use ECBC-MAC. We do the simple
    fixed-length-prefix variant here.
    """

    def __init__(self, prp: PRP):
        if not isinstance(prp, PRP):
            # Allow PRF too; CBC-MAC works with either.
            if not isinstance(prp, PRF):
                raise TypeError("CBCMAC requires a PRF or PRP")
        self._prp = prp
        self._b = prp.block_size

    @property
    def key_size(self) -> int:
        return self._prp.key_size

    @property
    def tag_size(self) -> int:
        return self._b

    def _pad(self, m: bytes) -> bytes:
        # Length-prefix to make the scheme secure for variable-length messages.
        # Format: 8-byte big-endian length || m || zero-pad to block boundary.
        prefix = len(m).to_bytes(8, "big")
        full = prefix + m
        rem = len(full) % self._b
        if rem:
            full += b"\x00" * (self._b - rem)
        return full

    def mac(self, k: bytes, m: bytes, *, trace=None) -> bytes:
        padded = self._pad(m)
        chain = b"\x00" * self._b
        for i in range(0, len(padded), self._b):
            blk = padded[i:i + self._b]
            chain = self._prp.evaluate(k, xor_bytes(chain, blk))
        if trace is not None:
            trace.record(
                name="CBC-MAC",
                inputs={"k": k, "m": m},
                outputs={"t": chain},
                theorem="Iterated PRP gives variable-length MAC (with length prefix)",
                pa_number=5,
            )
        return chain

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        return constant_time_eq(self.mac(k, m), t)


# ---------- HMAC stub (full impl in hashing/hmac.py for PA#10) ----------

class HMACStub(MAC):
    """Placeholder HMAC. PA#10 fills this in via hashing/hmac.py."""

    @property
    def key_size(self): return 16
    @property
    def tag_size(self): return 16

    def mac(self, k, m, *, trace=None):
        raise StubNotImplemented("Stub: HMAC implemented in PA#10 (hashing/hmac.py)")

    def verify(self, k, m, t):
        raise StubNotImplemented("Stub: HMAC implemented in PA#10")


# ---------- Length-extension attack on naive H(k||m) ----------

class NaiveHashMAC:
    """
    Naive 'MAC' t = H(k || m). BROKEN by length-extension on Merkle-Damgard
    hashes. We use this to motivate HMAC's two-hash structure (PA#10).
    """
    def __init__(self, hash_fn):
        self._H = hash_fn

    def mac(self, k: bytes, m: bytes) -> bytes:
        return self._H(k + m)

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        return constant_time_eq(self._H(k + m), t)


# ---------- EUF-CMA game ----------

def euf_cma_game(mac: MAC, k: bytes, n_queries: int, adversary_fn) -> dict:
    """
    Simulate the EUF-CMA game.

    adversary_fn(oracle) is called with a lambda that returns (m_i, t_i) and
    must return a forgery candidate (m*, t*) where m* was not queried.

    Returns {'queried': list, 'attempt': (m*, t*), 'forged': bool}.
    """
    queried = []

    def oracle(m: bytes) -> bytes:
        if len(queried) >= n_queries:
            raise RuntimeError("query budget exhausted")
        t = mac.mac(k, m)
        queried.append((m, t))
        return t

    forgery = adversary_fn(oracle)
    if forgery is None:
        return {"queried": queried, "attempt": None, "forged": False}
    m_star, t_star = forgery
    if any(m_star == m for m, _ in queried):
        return {"queried": queried, "attempt": forgery, "forged": False, "reason": "replay"}
    forged = mac.verify(k, m_star, t_star)
    return {"queried": queried, "attempt": forgery, "forged": forged}


# ---------- MAC ==> PRF backward demo ----------

def mac_as_prf(mac: MAC):
    """
    Backward reduction: a secure MAC (on uniform random inputs) is a PRF.

    Returns a callable F(k, x) = mac.mac(k, x).
    """
    def F(k: bytes, x: bytes) -> bytes:
        return mac.mac(k, x)
    return F
