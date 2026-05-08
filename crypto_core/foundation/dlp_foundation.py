"""
DLP-based cryptographic foundation.

The Discrete Logarithm Problem in a prime-order group gives us a concrete
one-way permutation:  f(x) = g^x mod p  on  Z_q  where q is the order of <g>.

This module exposes:
  - DLPFoundation: holds a safe-prime group (p, q, g)
  - DLPOWF: a closed OWP view over Z_p^*, exposing f(x) = G^(x+1)-1 mod p

This foundation is required by:
  - PA#1 (OWF/PRG with hard-core bit)
  - PA#8 (DLP-based collision-resistant hash)
  - PA#11 (Diffie-Hellman key exchange)
  - PA#16 (ElGamal)
"""
from crypto_core.common.interfaces import Foundation, OWF, OWP, PRF, PRP
from crypto_core.common.exceptions import NotSupported, InvalidGroupParam
from crypto_core.number_theory.modular import mod_pow
from crypto_core.number_theory.prime_gen import gen_safe_prime


class DLPOWF(OWP):
    """
    Closed DLP-style one-way permutation over Z_p^*.

    The public API indexes the non-zero residues as integers x in [0, p-2],
    representing the group element x+1. A full-group generator G maps:

      f(x) = G^(x+1) mod p - 1

    This is a permutation on the same encoded domain because G generates
    Z_p^*. Inverting f requires computing a discrete logarithm in Z_p^*.

    Hard-core predicate: lsb(x). (Blum-Micali style; provably hard-core for
    DLP under standard assumptions.)
    """

    def __init__(self, p: int, q: int, full_generator: int):
        self._p = p
        self._q = q
        self._g = full_generator
        self._domain_size = p - 1
        self._domain_bits = (self._domain_size - 1).bit_length()

    @property
    def p(self) -> int: return self._p
    @property
    def q(self) -> int: return self._q
    @property
    def g(self) -> int: return self._g
    @property
    def domain_size(self) -> int: return self._domain_size
    @property
    def domain_bits(self) -> int: return self._domain_bits

    def evaluate(self, x: int, *, trace=None) -> int:
        if not (0 <= x < self._domain_size):
            raise ValueError(f"DLPOWF: x={x} out of domain [0, {self._domain_size})")
        group_element = x + 1
        y = mod_pow(self._g, group_element, self._p) - 1
        if trace is not None:
            trace.record(
                name="DLP-OWP f(x)=G^(x+1)-1 mod p",
                inputs={"x": x, "G": self._g, "p": self._p},
                outputs={"y": y},
                theorem="DLP hardness",
                pa_number=1,
            )
        return y

    def hard_core_predicate(self, x: int) -> int:
        """LSB hard-core bit b(x) = x mod 2."""
        return x & 1

    def is_permutation(self) -> bool:
        return True


class DLPFoundation(Foundation):
    """
    A concrete DLP-based foundation. Constructs (p, q, g) once at instantiation.

    bits: bit-length of safe prime p. For tests/demos use small bits (e.g. 64);
          for real security use >= 2048.
    """

    def __init__(self, bits: int = 64, p: int = None, q: int = None, g: int = None):
        if p is not None and q is not None and g is not None:
            self._p, self._q, self._g = p, q, g
        else:
            self._p, self._q = gen_safe_prime(bits)
            # Find a generator of the order-q subgroup.
            # In Z_p^* with p = 2q+1, the QR subgroup has order q.
            # Any h^2 mod p with h != 1, p-1 generates the QR subgroup.
            self._g = self._find_generator()
        self._full_g = self._find_full_group_generator()
        # Sanity checks
        if mod_pow(self._g, self._q, self._p) != 1:
            raise InvalidGroupParam("g does not have order dividing q")
        if self._g == 1:
            raise InvalidGroupParam("g is the identity")
        if mod_pow(self._full_g, 2, self._p) == 1 or mod_pow(self._full_g, self._q, self._p) == 1:
            raise InvalidGroupParam("full generator does not generate Z_p^*")

    def _find_generator(self) -> int:
        for cand in range(2, 1000):
            g = mod_pow(cand, 2, self._p)  # square forces into QR subgroup
            if g != 1 and mod_pow(g, self._q, self._p) == 1:
                return g
        raise InvalidGroupParam("could not find generator")

    def _find_full_group_generator(self) -> int:
        # p is safe: |Z_p^*| = 2q. A primitive root G must fail both
        # G^2 = 1 and G^q = 1.
        for cand in range(2, 1000):
            if mod_pow(cand, 2, self._p) != 1 and mod_pow(cand, self._q, self._p) != 1:
                return cand
        raise InvalidGroupParam("could not find full-group generator")

    @property
    def name(self) -> str:
        return "DLP"

    @property
    def p(self) -> int: return self._p
    @property
    def q(self) -> int: return self._q
    @property
    def g(self) -> int: return self._g
    @property
    def full_generator(self) -> int: return self._full_g

    def as_owf(self) -> OWF:
        return DLPOWF(self._p, self._q, self._full_g)

    def as_owp(self) -> OWP:
        return DLPOWF(self._p, self._q, self._full_g)

    def as_prf(self) -> PRF:
        # DLP doesn't natively give a PRF; you must compose OWP -> PRG -> PRF
        # via PA#1 (HILL) and PA#2 (GGM). The architecture forbids skipping.
        raise NotSupported(
            "DLPFoundation does not expose PRF directly. "
            "Compose: as_owf() -> HILLPRG (PA#1) -> GGMTreePRF (PA#2)."
        )

    def as_prp(self) -> PRP:
        raise NotSupported(
            "DLPFoundation does not expose PRP. Build via PA#2 (GGM PRF) "
            "then PA#4 / Luby-Rackoff."
        )
