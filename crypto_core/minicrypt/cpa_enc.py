"""
PA#3: CPA-secure symmetric encryption.

Construction: Enc-then-PRF.
  Enc(k, m) = (r, F_k(r) XOR m)   where r is freshly random per encryption.

For multi-block messages: extend by counter, F_k(r), F_k(r+1), F_k(r+2), ...

Security: CPA-secure under PRF security of F.

Also includes a deliberately broken variant (DeterministicCPAEncryption) that
reuses r -- used in the IND-CPA attack demo.
"""
from typing import Tuple
from crypto_core.common.interfaces import PRF, SymEncryption
from crypto_core.common.bitops import xor_bytes, pkcs7_pad, pkcs7_unpad
from crypto_core.common.randomness import secure_random_bytes


class CPAEncryption(SymEncryption):
    """
    CPA-secure encryption from a PRF.

    Ciphertext: (r, c)  where  c = F_k(r) || F_k(r+1) || ... XOR padded(m).
    The fresh r per encryption is what gives CPA security.
    """

    def __init__(self, prf: PRF):
        self._prf = prf
        self._block = prf.block_size

    @property
    def key_size(self) -> int:
        return self._prf.key_size

    @property
    def block_size(self) -> int:
        return self._block

    def _keystream(self, k: bytes, r_int: int, n_blocks: int) -> bytes:
        out = b""
        for i in range(n_blocks):
            ctr = (r_int + i) % (1 << (self._block * 8))
            x = ctr.to_bytes(self._block, "big")
            out += self._prf.evaluate(k, x)
        return out

    def encrypt(self, k: bytes, m: bytes, *, trace=None) -> Tuple[bytes, bytes]:
        """Returns (r, c)."""
        if len(k) != self.key_size:
            raise ValueError(f"key must be {self.key_size} bytes")
        # Pad m to block boundary
        padded = pkcs7_pad(m, self._block)
        n_blocks = len(padded) // self._block
        # Fresh random nonce r
        r = secure_random_bytes(self._block)
        r_int = int.from_bytes(r, "big")
        ks = self._keystream(k, r_int, n_blocks)
        c = xor_bytes(padded, ks)
        if trace is not None:
            trace.record(
                name="CPA encrypt: Enc(k,m) = (r, F_k(r,r+1,...) XOR pad(m))",
                inputs={"k": k, "m": m, "r": r},
                outputs={"c": c},
                theorem="PRF ==> CPA-secure encryption",
                pa_number=3,
            )
        return r, c

    def decrypt(self, k: bytes, ciphertext: Tuple[bytes, bytes], *, trace=None) -> bytes:
        r, c = ciphertext
        if len(c) % self._block != 0:
            raise ValueError("ciphertext not block-aligned")
        n_blocks = len(c) // self._block
        r_int = int.from_bytes(r, "big")
        ks = self._keystream(k, r_int, n_blocks)
        padded = xor_bytes(c, ks)
        m = pkcs7_unpad(padded, self._block)
        if trace is not None:
            trace.record(
                name="CPA decrypt",
                inputs={"k": k, "r": r, "c": c},
                outputs={"m": m},
                theorem="Inversion of XOR keystream",
                pa_number=3,
            )
        return m


class DeterministicCPAEncryption(SymEncryption):
    """
    Deliberately broken: reuses a fixed r. Used in the PA#3 IND-CPA attack demo
    to prove that nonce reuse breaks CPA security catastrophically.

    NEVER use this for anything except the demo.
    """

    def __init__(self, prf: PRF):
        self._prf = prf
        self._block = prf.block_size
        self._fixed_r = b"\x00" * self._block  # Identical r every time

    @property
    def key_size(self) -> int:
        return self._prf.key_size

    @property
    def block_size(self) -> int:
        return self._block

    def encrypt(self, k: bytes, m: bytes, *, trace=None):
        padded = pkcs7_pad(m, self._block)
        n_blocks = len(padded) // self._block
        ks = b""
        r_int = int.from_bytes(self._fixed_r, "big")
        for i in range(n_blocks):
            ctr = (r_int + i) % (1 << (self._block * 8))
            ks += self._prf.evaluate(k, ctr.to_bytes(self._block, "big"))
        c = xor_bytes(padded, ks)
        if trace is not None:
            trace.record(
                name="Deterministic CPA encrypt (BROKEN: reused r)",
                inputs={"k": k, "m": m, "r (FIXED)": self._fixed_r},
                outputs={"c": c},
                theorem="Nonce reuse: same plaintext -> same ciphertext, breaks IND-CPA",
                pa_number=3,
            )
        return self._fixed_r, c

    def decrypt(self, k, ciphertext, *, trace=None):
        r, c = ciphertext
        n_blocks = len(c) // self._block
        ks = b""
        r_int = int.from_bytes(r, "big")
        for i in range(n_blocks):
            ctr = (r_int + i) % (1 << (self._block * 8))
            ks += self._prf.evaluate(k, ctr.to_bytes(self._block, "big"))
        padded = xor_bytes(c, ks)
        return pkcs7_unpad(padded, self._block)


# ---------- IND-CPA game simulator ----------

def ind_cpa_game(scheme: SymEncryption, k: bytes,
                 m0: bytes, m1: bytes,
                 adversary_guess_fn=None) -> dict:
    """
    Single round of the IND-CPA game.

    Challenger picks bit b uniformly, encrypts m_b. Adversary guesses b.
    Returns {'b': true_bit, 'guess': adversary_guess, 'correct': bool}.

    If adversary_guess_fn is None, we use a "random guess" baseline (advantage 0).
    """
    b = secure_random_bytes(1)[0] & 1
    target = m1 if b else m0
    ct = scheme.encrypt(k, target)
    if adversary_guess_fn is None:
        guess = secure_random_bytes(1)[0] & 1
    else:
        guess = adversary_guess_fn(ct, m0, m1)
    return {"b": b, "guess": guess, "correct": (guess == b), "ciphertext": ct}
