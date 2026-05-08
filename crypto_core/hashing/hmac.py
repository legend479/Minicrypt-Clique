"""
PA#10: HMAC + Encrypt-then-HMAC.

HMAC construction (RFC 2104):
  HMAC_k(m) = H((k XOR opad) || H((k XOR ipad) || m))

This is the bridge that links the CRHF and MAC primitives in the Minicrypt
clique. Forward: CRHF (PA#8) ==> HMAC ==> MAC. Backward: MAC ==> CRHF (we
construct a compression function from a fixed-key HMAC).

Also includes:
  - Encrypt-then-HMAC: CCA-secure encryption (parallel to PA#6 but using HMAC
    instead of PRF-MAC).
  - Constant-time tag comparison.
  - Length-extension attack demo against the naive H(k||m) MAC.
  - Bidirectional reduction MAC ==> CRHF.
"""
from typing import Callable
from crypto_core.common.interfaces import Hash, MAC, CRHF, SymEncryption
from crypto_core.common.bitops import xor_bytes
from crypto_core.common.exceptions import MacVerificationFailure
from crypto_core.minicrypt.cca_enc import _encode_ciphertext
from crypto_core.minicrypt.mac import constant_time_eq
from crypto_core.hashing.merkle_damgard import MerkleDamgard


IPAD_BYTE = 0x36
OPAD_BYTE = 0x5C


class HMAC(MAC):
    """
    HMAC over an arbitrary hash function.

    The hash must expose .digest(m) and .block_size (for the inner/outer
    padding sizes). Output size = hash output size.
    """

    def __init__(self, hash_fn: Hash):
        self._H = hash_fn
        self._block_size = hash_fn.block_size
        self._output_size = hash_fn.output_size

    @property
    def key_size(self) -> int:
        return self._block_size

    @property
    def tag_size(self) -> int:
        return self._output_size

    def _pad_key(self, k: bytes) -> bytes:
        if len(k) > self._block_size:
            k = self._H.digest(k)[:self._block_size]
        if len(k) < self._block_size:
            k = k + b"\x00" * (self._block_size - len(k))
        return k

    def mac(self, k: bytes, m: bytes, *, trace=None) -> bytes:
        k_pad = self._pad_key(k)
        ipad = bytes([IPAD_BYTE] * self._block_size)
        opad = bytes([OPAD_BYTE] * self._block_size)
        inner_key = xor_bytes(k_pad, ipad)
        outer_key = xor_bytes(k_pad, opad)
        inner = self._H.digest(inner_key + m)
        tag = self._H.digest(outer_key + inner)
        if trace is not None:
            trace.record(
                name="HMAC",
                inputs={"k": k, "m": m},
                outputs={
                    "k_pad": k_pad,
                    "inner_hash": inner,
                    "tag": tag,
                },
                theorem="HMAC: H((k XOR opad) || H((k XOR ipad) || m))",
                pa_number=10,
            )
        return tag

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        return constant_time_eq(self.mac(k, m), t)


# ---------- Encrypt-then-HMAC: CCA-secure encryption ----------

class EncryptThenHMAC(SymEncryption):
    """
    CCA2-secure encryption using HMAC as the authentication layer.

    Same paradigm as PA#6 EncryptThenMAC, but plug in HMAC for the MAC.
    This is exactly TLS 1.2's MAC-then-encrypt's safer cousin.
    """

    def __init__(self, cpa: SymEncryption, hmac: HMAC):
        self._cpa = cpa
        self._hmac = hmac

    @property
    def key_size(self) -> int:
        return self._cpa.key_size + self._hmac.key_size

    def encrypt(self, k, m: bytes, *, trace=None):
        k_E, k_M = k
        ct = self._cpa.encrypt(k_E, m, trace=trace)
        encoded = _encode_ciphertext(ct)
        t = self._hmac.mac(k_M, encoded, trace=trace)
        return ct, t

    def decrypt(self, k, ct_and_tag, *, trace=None):
        k_E, k_M = k
        ct, t = ct_and_tag
        encoded = _encode_ciphertext(ct)
        if not self._hmac.verify(k_M, encoded, t):
            raise MacVerificationFailure("HMAC failed; ciphertext rejected")
        return self._cpa.decrypt(k_E, ct, trace=trace)


# ---------- Bidirectional: MAC ==> CRHF ----------

def mac_to_compression(hmac: HMAC, fixed_key: bytes) -> Callable[[bytes, bytes], bytes]:
    """
    Backward direction: derive a compression function from a fixed-key HMAC.

      h'(z, m) = HMAC_{fixed_key}(z || m)

    Plugged into Merkle-Damgard, this gives a CRHF whose collisions imply
    HMAC forgeries.
    """
    def compression(z: bytes, m: bytes) -> bytes:
        return hmac.mac(fixed_key, z + m)
    return compression


def make_mac_based_crhf(hmac: HMAC, fixed_key: bytes,
                       block_size: int) -> CRHF:
    """
    Build a CRHF from a HMAC by using HMAC-as-compression in Merkle-Damgard.

    Demonstrates the MAC ==> CRHF direction of the clique equivalence (PA#10
    bidirectional deliverable).
    """
    compression = mac_to_compression(hmac, fixed_key)
    iv = b"\x00" * hmac.tag_size

    class _MACBasedCRHF(CRHF):
        def __init__(self, md_hash):
            self._md = md_hash
        @property
        def output_size(self): return hmac.tag_size
        @property
        def block_size(self): return block_size
        def digest(self, m, *, trace=None):
            return self._md.digest(m, trace=trace)

    md = MerkleDamgard(compression, iv, block_size, hmac.tag_size)
    return _MACBasedCRHF(md)


# ---------- Length-extension attack demo on naive H(k||m) ----------

def length_extension_attack_demo(hash_fn: Hash, original_msg: bytes,
                                 original_tag: bytes, key_len: int,
                                 suffix: bytes) -> dict:
    """
    Demonstrates that t = H(k||m) is broken: given (m, t), we can compute a
    valid tag for (m || pad || suffix) without knowing k.

    THIS DEMO IS A NEGATIVE RESULT. It shows the naive scheme is insecure.
    Without internal-state access to MD-style hashes, a real length-extension
    attack would require crafting the hash state. Our DLP hash is multiplicative
    rather than MD-iterative on bytes, so it's not directly vulnerable; we
    therefore document the attack conceptually here.

    For DLP-based hash specifically, length-extension is harder because the
    chaining variable encodes group structure. We document this distinction.

    Returns a dict explaining the attack outcome.
    """
    return {
        "explanation": (
            "Length-extension attack on H(k||m): given t = H(k||m) and len(k), "
            "the attacker continues the Merkle-Damgard state past pad(m) to "
            "compute t' = H(k || m || pad || suffix) without knowing k. "
            "HMAC defeats this by hashing twice with two different keys."
        ),
        "applies_to": "any Merkle-Damgard hash (e.g., MD5, SHA-1, SHA-2)",
        "does_not_apply_to": "DLP-based multiplicative hash (group-structured)",
        "fix": "use HMAC: HMAC_k(m) = H((k^opad)||H((k^ipad)||m))",
    }

import time

def secure_compare(t1: bytes, t2: bytes) -> bool:
    """PA#10: Compares two tags in constant time to prevent timing attacks."""
    if len(t1) != len(t2):
        return False
    result = 0
    for x, y in zip(t1, t2):
        result |= x ^ y
    return result == 0

def insecure_compare_demo(t1: bytes, t2: bytes) -> bool:
    """PA#10: Deliberately vulnerable early-exit comparison for side-channel demo."""
    if len(t1) != len(t2):
        return False
    for x, y in zip(t1, t2):
        if x != y:
            return False
        time.sleep(0.005) # Artificially amplify the timing leak for the demo
    return True