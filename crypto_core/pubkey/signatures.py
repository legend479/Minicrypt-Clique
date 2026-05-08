"""
PA#15: Digital signatures.

Hash-then-sign with RSA:
  Sign(sk, m) = H(m)^d mod N
  Verify(vk, m, sigma) = (sigma^e mod N) == H(m)?

Hashing is essential. Without it, raw RSA signatures are forgeable:
  given sig(m1), sig(m2), forge sig(m1*m2) = sig(m1) * sig(m2) mod N.

EUF-CMA secure assuming H is collision-resistant (PA#8).
"""
from typing import Tuple
from crypto_core.common.interfaces import Signature, Hash
from crypto_core.common.exceptions import CryptoError
from crypto_core.minicrypt.mac import constant_time_eq
from crypto_core.pubkey.rsa import RSA, RSAPublicKey, RSAPrivateKey


class RSASignature(Signature):
    """RSA hash-then-sign."""

    def __init__(self, rsa: RSA, hash_fn: Hash):
        self._rsa = rsa
        self._H = hash_fn

    def keygen(self, *, trace=None):
        """Returns (vk, sk) where vk is the public RSA key."""
        return self._rsa.keygen(trace=trace)

    def _hash_to_int(self, m: bytes, N: int) -> int:
        h = self._H.digest(m)
        h_int = int.from_bytes(h, "big")
        # Reduce modulo N to ensure h_int < N
        return h_int % N

    def sign(self, sk: RSAPrivateKey, m: bytes, *, trace=None) -> int:
        """sigma = H(m)^d mod N."""
        h_int = self._hash_to_int(m, sk.N)
        from crypto_core.number_theory.modular import mod_pow
        sigma = mod_pow(h_int, sk.d, sk.N)
        if trace is not None:
            trace.record(name="RSA sign: sigma = H(m)^d mod N",
                         inputs={"m": m, "H(m)": h_int},
                         outputs={"sigma": sigma},
                         theorem="Hash-then-sign EUF-CMA",
                         pa_number=15)
        return sigma

    def verify(self, vk: RSAPublicKey, m: bytes, sigma: int) -> bool:
        try:
            from crypto_core.number_theory.modular import mod_pow
            h_int = self._hash_to_int(m, vk.N)
            check = mod_pow(sigma, vk.e, vk.N)
            return check == h_int
        except Exception:
            return False


class RawRSASignature:
    """
    INSECURE: signs the message integer directly without hashing. Used to
    demonstrate the multiplicative-homomorphism forgery (PA#15 attack demo).
    """

    def __init__(self, rsa: RSA):
        self._rsa = rsa

    def keygen(self):
        return self._rsa.keygen()

    def sign(self, sk: RSAPrivateKey, m_int: int) -> int:
        from crypto_core.number_theory.modular import mod_pow
        return mod_pow(m_int, sk.d, sk.N)

    def verify(self, vk: RSAPublicKey, m_int: int, sigma: int) -> bool:
        from crypto_core.number_theory.modular import mod_pow
        return mod_pow(sigma, vk.e, vk.N) == m_int
