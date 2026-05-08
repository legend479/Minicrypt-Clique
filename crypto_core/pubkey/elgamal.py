"""
PA#16: ElGamal public-key cryptosystem.

Setup: cyclic group G of prime order q with generator g (DLP foundation).

Key generation:
  sk = x in Z_q (random)
  pk = h = g^x mod p

Encryption of m in G (m must be a group element):
  r in Z_q (random)
  c1 = g^r mod p
  c2 = m * h^r mod p
  return (c1, c2)

Decryption of (c1, c2):
  m = c2 / c1^x mod p = m * g^{xr} / g^{xr} = m

Security: CPA-secure under Decisional Diffie-Hellman.
NOT CCA-secure: malleable. Given (c1, c2), (c1, k*c2) decrypts to k*m.
"""
from typing import Tuple
from dataclasses import dataclass
from crypto_core.common.interfaces import PKC
from crypto_core.common.randomness import secure_randrange
from crypto_core.number_theory.modular import mod_pow, mod_inverse
from crypto_core.foundation.dlp_foundation import DLPFoundation


@dataclass
class ElGamalPublicKey:
    p: int
    q: int
    g: int
    h: int  # g^x mod p


@dataclass
class ElGamalPrivateKey:
    p: int
    q: int
    g: int
    x: int


class ElGamal(PKC):
    """ElGamal PKC over a DLP-based foundation."""

    def __init__(self, bits: int = 256, foundation: DLPFoundation = None):
        if foundation is None:
            foundation = DLPFoundation(bits=bits)
        self._f = foundation

    @property
    def foundation(self):
        return self._f

    def keygen(self, *, trace=None) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
        x = secure_randrange(2, self._f.q)
        h = mod_pow(self._f.g, x, self._f.p)
        pk = ElGamalPublicKey(p=self._f.p, q=self._f.q, g=self._f.g, h=h)
        sk = ElGamalPrivateKey(p=self._f.p, q=self._f.q, g=self._f.g, x=x)
        if trace is not None:
            trace.record(name="ElGamal keygen",
                         inputs={"p": pk.p, "q": pk.q, "g": pk.g},
                         outputs={"h": h},
                         theorem="ElGamal CPA-secure under DDH",
                         pa_number=16)
        return pk, sk

    def encrypt(self, pk: ElGamalPublicKey, m, *, trace=None) -> Tuple[int, int]:
        """m must be an integer in (0, p) representing a group element."""
        if isinstance(m, bytes):
            m_int = int.from_bytes(m, "big")
        else:
            m_int = m
        if not (0 < m_int < pk.p):
            raise ValueError(f"ElGamal: m must be in (0, p={pk.p})")
        r = secure_randrange(2, pk.q)
        c1 = mod_pow(pk.g, r, pk.p)
        c2 = (m_int * mod_pow(pk.h, r, pk.p)) % pk.p
        if trace is not None:
            trace.record(name="ElGamal encrypt",
                         inputs={"m": m_int, "r (random)": r},
                         outputs={"c1": c1, "c2": c2},
                         pa_number=16)
        return c1, c2

    def decrypt(self, sk: ElGamalPrivateKey, ciphertext, *, trace=None):
        c1, c2 = ciphertext
        s = mod_pow(c1, sk.x, sk.p)
        s_inv = mod_inverse(s, sk.p)
        m = (c2 * s_inv) % sk.p
        if trace is not None:
            trace.record(name="ElGamal decrypt: m = c2 / c1^x",
                         inputs={"c1": c1, "c2": c2},
                         outputs={"m": m},
                         pa_number=16)
        return m


# ---------- Malleability attack (PA#16 demo) ----------

def elgamal_malleability_attack(ciphertext, multiplier: int, p: int):
    """
    Given (c1, c2) for unknown m, return a fresh ciphertext for k*m without
    knowing m or x:
      (c1, k * c2 mod p)  decrypts to k * m.
    """
    c1, c2 = ciphertext
    return c1, (multiplier * c2) % p
