"""
PA#12: Textbook RSA + PKCS#1 v1.5.

Key generation:
  1. p, q distinct primes (Miller-Rabin via PA#13).
  2. N = pq;  phi(N) = (p-1)(q-1)
  3. e = 65537 (commonly).  d = e^{-1} mod phi(N).
  4. Public key: (N, e).  Private key: (N, d, p, q, dp, dq, q_inv).
     [The CRT components dp, dq, q_inv are stored so PA#14's Garner can use them.]

Textbook: c = m^e mod N;  m = c^d mod N.  DETERMINISTIC, hence not CPA-secure.

PKCS#1 v1.5 padded:  EM = 00 || 02 || PS (random nonzero, >= 8 bytes) || 00 || m
Then encrypt EM under textbook RSA. CPA-secure but NOT CCA-secure (Bleichenbacher).
"""
from typing import Tuple
from dataclasses import dataclass
from crypto_core.common.interfaces import PKC
from crypto_core.common.exceptions import PaddingError
from crypto_core.common.randomness import secure_random_bytes, secure_randrange
from crypto_core.number_theory.modular import mod_pow, mod_inverse
from crypto_core.number_theory.prime_gen import gen_prime
from crypto_core.number_theory.crt import garner_recombine


@dataclass
class RSAPublicKey:
    N: int
    e: int

    @property
    def byte_length(self) -> int:
        return (self.N.bit_length() + 7) // 8


@dataclass
class RSAPrivateKey:
    N: int
    d: int
    p: int
    q: int
    dp: int   # d mod (p-1)
    dq: int   # d mod (q-1)
    q_inv: int  # q^{-1} mod p


class RSA(PKC):
    """Textbook RSA. NOT CPA-secure on its own; use PKCS1v15 wrapper for that."""

    def __init__(self, bits: int = 1024, e: int = 65537):
        self._bits = bits
        self._e = e

    def keygen(self, *, trace=None) -> Tuple[RSAPublicKey, RSAPrivateKey]:
        half = self._bits // 2
        # Generate two distinct primes p, q with gcd(e, p-1) = gcd(e, q-1) = 1.
        while True:
            p = gen_prime(half)
            if (p - 1) % self._e != 0:
                break
        while True:
            q = gen_prime(half)
            if q != p and (q - 1) % self._e != 0:
                break
        N = p * q
        phi = (p - 1) * (q - 1)
        d = mod_inverse(self._e, phi)
        dp = d % (p - 1)
        dq = d % (q - 1)
        q_inv = mod_inverse(q, p)
        pk = RSAPublicKey(N=N, e=self._e)
        sk = RSAPrivateKey(N=N, d=d, p=p, q=q, dp=dp, dq=dq, q_inv=q_inv)
        if trace is not None:
            trace.record(name="RSA keygen", inputs={"bits": self._bits},
                         outputs={"N": N, "e": self._e},
                         theorem="RSA: factoring assumption", pa_number=12)
        return pk, sk

    def encrypt(self, pk: RSAPublicKey, m, *, trace=None) -> int:
        """Textbook RSA: c = m^e mod N. Accepts int or bytes."""
        if isinstance(m, bytes):
            m_int = int.from_bytes(m, "big")
        else:
            m_int = m
        if not (0 <= m_int < pk.N):
            raise ValueError("RSA: message integer out of range [0, N)")
        c = mod_pow(m_int, pk.e, pk.N)
        if trace is not None:
            trace.record(name="RSA encrypt: c = m^e mod N",
                         inputs={"m": m_int, "e": pk.e, "N": pk.N},
                         outputs={"c": c}, pa_number=12)
        return c

    def decrypt(self, sk: RSAPrivateKey, c, *, trace=None):
        """Standard RSA decryption: m = c^d mod N."""
        if isinstance(c, bytes):
            c_int = int.from_bytes(c, "big")
        else:
            c_int = c
        m = mod_pow(c_int, sk.d, sk.N)
        if trace is not None:
            trace.record(name="RSA decrypt: m = c^d mod N",
                         inputs={"c": c_int, "d": "[private]", "N": sk.N},
                         outputs={"m": m}, pa_number=12)
        return m

    def decrypt_crt(self, sk: RSAPrivateKey, c, *, trace=None):
        """PA#14: Garner-style CRT-based decryption (~3-4x faster)."""
        if isinstance(c, bytes):
            c_int = int.from_bytes(c, "big")
        else:
            c_int = c
        mp = mod_pow(c_int, sk.dp, sk.p)
        mq = mod_pow(c_int, sk.dq, sk.q)
        m = garner_recombine(mp, mq, sk.p, sk.q, sk.q_inv)
        if trace is not None:
            trace.record(name="RSA-CRT decrypt (Garner)",
                         inputs={"c": c_int},
                         outputs={"mp": mp, "mq": mq, "m": m},
                         theorem="CRT speedup: ~4x faster than standard decrypt",
                         pa_number=14)
        return m


# ---------- PKCS#1 v1.5 ----------

class PKCS1v15:
    """PKCS#1 v1.5 padding wrapping textbook RSA. CPA-secure, not CCA-secure."""

    def __init__(self, rsa: RSA):
        self._rsa = rsa

    def _pad_encrypt(self, pk: RSAPublicKey, m: bytes) -> bytes:
        """EM = 00 || 02 || PS (random nonzero, >= 8 bytes) || 00 || m"""
        k = pk.byte_length
        if len(m) > k - 11:
            raise ValueError(f"PKCS#1 v1.5: message too long ({len(m)} > {k-11})")
        ps_len = k - len(m) - 3
        # Generate ps_len random NONZERO bytes
        ps = bytearray()
        while len(ps) < ps_len:
            cand = secure_random_bytes(ps_len - len(ps) + 16)
            for byte in cand:
                if byte != 0:
                    ps.append(byte)
                if len(ps) == ps_len:
                    break
        return b"\x00\x02" + bytes(ps) + b"\x00" + m

    def _unpad(self, em: bytes, k: int) -> bytes:
        if len(em) != k:
            raise PaddingError("PKCS#1 v1.5: bad EM length")
        if em[0] != 0x00 or em[1] != 0x02:
            raise PaddingError("PKCS#1 v1.5: bad header")
        # Find the 0x00 separator after PS (which must be >= 8 bytes long).
        idx = em.find(b"\x00", 2)
        if idx == -1 or idx < 10:  # 2 header + 8 PS = at least position 10
            raise PaddingError("PKCS#1 v1.5: no separator or PS too short")
        return em[idx + 1:]

    def encrypt(self, pk: RSAPublicKey, m: bytes, *, trace=None) -> int:
        em = self._pad_encrypt(pk, m)
        if trace is not None:
            trace.record(name="PKCS#1 v1.5 pad",
                         inputs={"m": m},
                         outputs={"EM": em},
                         theorem="Random PS gives CPA security",
                         pa_number=12)
        return self._rsa.encrypt(pk, em, trace=trace)

    def decrypt(self, sk: RSAPrivateKey, c, *, trace=None) -> bytes:
        m_int = self._rsa.decrypt(sk, c, trace=trace)
        k = (sk.N.bit_length() + 7) // 8
        em = m_int.to_bytes(k, "big")
        return self._unpad(em, k)
