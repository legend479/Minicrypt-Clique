"""
PA#6: CCA-secure symmetric encryption via Encrypt-then-MAC.

Paradigm: independent keys (k_E, k_M).
  Enc(k_E, k_M, m):
    c_E = CPA_Enc(k_E, m)
    t   = MAC(k_M, encode(c_E))
    return (c_E, t)

  Dec(k_E, k_M, (c_E, t)):
    if not MAC_verify(k_M, encode(c_E), t): return BOTTOM
    return CPA_Dec(k_E, c_E)

CCA2-secure under CPA security of Enc and EUF-CMA security of MAC.
"""
from typing import Tuple
from crypto_core.common.interfaces import SymEncryption, MAC
from crypto_core.common.exceptions import MacVerificationFailure
from crypto_core.minicrypt.mac import constant_time_eq


def _encode_ciphertext(ct) -> bytes:
    """
    Serialize a CPA ciphertext (r, c) into a single byte string for MACing.
    Format: 4-byte length of r (big-endian) || r || c.
    """
    if isinstance(ct, tuple) and len(ct) == 2:
        r, c = ct
        return len(r).to_bytes(4, "big") + r + c
    if isinstance(ct, bytes):
        return ct
    raise TypeError(f"unsupported ciphertext type: {type(ct)}")


class EncryptThenMAC(SymEncryption):
    """
    CCA2-secure encryption scheme: Encrypt-then-MAC.

    Holds independent encryption and MAC keys k_E, k_M (provided to the
    encrypt/decrypt methods bundled as a tuple).

    The decryption MUST verify the MAC before invoking the decryption oracle
    of the underlying CPA scheme. Failure yields a "bottom" reject.
    """

    def __init__(self, cpa: SymEncryption, mac: MAC):
        self._cpa = cpa
        self._mac = mac

    @property
    def key_size(self) -> int:
        # Composed key: (k_E, k_M)
        return self._cpa.key_size + self._mac.key_size

    def encrypt(self, k: Tuple[bytes, bytes], m: bytes, *, trace=None):
        k_E, k_M = k
        ct = self._cpa.encrypt(k_E, m, trace=trace)
        encoded = _encode_ciphertext(ct)
        t = self._mac.mac(k_M, encoded, trace=trace)
        if trace is not None:
            trace.record(
                name="Encrypt-then-MAC",
                inputs={"k_E": k_E, "k_M": k_M, "m": m},
                outputs={"c_E": ct, "tag": t},
                theorem="CPA + EUF-CMA MAC ==> CCA2-secure encryption",
                pa_number=6,
            )
        return ct, t

    def decrypt(self, k: Tuple[bytes, bytes], ct_and_tag, *, trace=None) -> bytes:
        k_E, k_M = k
        ct, t = ct_and_tag
        encoded = _encode_ciphertext(ct)
        if not self._mac.verify(k_M, encoded, t):
            if trace is not None:
                trace.record(
                    name="Encrypt-then-MAC: MAC verify FAILED -> reject",
                    inputs={"k_M": k_M, "tag": t},
                    outputs={"result": "BOTTOM"},
                    theorem="MAC failure ==> reject ciphertext (no decryption oracle leak)",
                    pa_number=6,
                )
            raise MacVerificationFailure("MAC failed; ciphertext rejected")
        m = self._cpa.decrypt(k_E, ct, trace=trace)
        if trace is not None:
            trace.record(
                name="Encrypt-then-MAC: tag verified, decrypt CPA",
                inputs={"k_E": k_E},
                outputs={"m": m},
                theorem="MAC verification gates CPA decryption",
                pa_number=6,
            )
        return m


# ---------- IND-CCA2 game ----------

def ind_cca2_game(scheme: EncryptThenMAC, key, m0: bytes, m1: bytes,
                  adversary_decrypt_calls=()) -> dict:
    """
    Simplified IND-CCA2 game:
      - Adversary can ask the decryption oracle for any ciphertext other than
        the challenge.
      - Challenger picks b, encrypts m_b.
      - Adversary may continue to query decrypt oracle on non-challenge ct.

    adversary_decrypt_calls: list of ciphertexts (each (ct, tag)) the adversary
      will submit to the decryption oracle. Returns oracle responses (None if
      rejected).

    For testing: this is the "scheme correctly rejects modified ciphertexts"
    deliverable from PA#6.
    """
    from crypto_core.common.randomness import secure_random_bytes
    b = secure_random_bytes(1)[0] & 1
    target = m1 if b else m0
    challenge = scheme.encrypt(key, target)
    oracle_responses = []
    for ct in adversary_decrypt_calls:
        if ct == challenge:
            oracle_responses.append(("REJECTED_CHALLENGE", None))
            continue
        try:
            pt = scheme.decrypt(key, ct)
            oracle_responses.append(("OK", pt))
        except MacVerificationFailure:
            oracle_responses.append(("BOTTOM", None))
    return {"b": b, "challenge": challenge, "oracle_responses": oracle_responses}
