"""
PA#11: Diffie-Hellman key exchange.

Public params: safe prime p = 2q+1, generator g of order-q subgroup.

Protocol:
  Alice: a in Z_q,  A = g^a mod p
  Bob:   b in Z_q,  B = g^b mod p
  Both:  K = g^{ab} = B^a = A^b
"""
from crypto_core.common.randomness import secure_randrange
from crypto_core.number_theory.modular import mod_pow
from crypto_core.foundation.dlp_foundation import DLPFoundation


class DiffieHellman:
    """Diffie-Hellman key exchange over a DLP foundation."""

    def __init__(self, bits: int = 256, foundation: DLPFoundation = None):
        if foundation is None:
            foundation = DLPFoundation(bits=bits)
        self._f = foundation

    @property
    def p(self) -> int: return self._f.p
    @property
    def q(self) -> int: return self._f.q
    @property
    def g(self) -> int: return self._f.g
    @property
    def foundation(self) -> DLPFoundation: return self._f

    def alice_step1(self, *, trace=None):
        """Returns (a_private, A_public)."""
        a = secure_randrange(2, self.q)
        A = mod_pow(self.g, a, self.p)
        if trace is not None:
            trace.record(name="DH Alice step 1",
                         inputs={"q": self.q},
                         outputs={"a (private)": a, "A = g^a": A},
                         pa_number=11)
        return a, A

    def bob_step1(self, *, trace=None):
        b = secure_randrange(2, self.q)
        B = mod_pow(self.g, b, self.p)
        if trace is not None:
            trace.record(name="DH Bob step 1",
                         inputs={"q": self.q},
                         outputs={"b (private)": b, "B = g^b": B},
                         pa_number=11)
        return b, B

    def alice_step2(self, a: int, B: int, *, trace=None) -> int:
        K = mod_pow(B, a, self.p)
        if trace is not None:
            trace.record(name="DH Alice step 2",
                         inputs={"a": a, "B": B},
                         outputs={"K = B^a = g^{ab}": K},
                         pa_number=11)
        return K

    def bob_step2(self, b: int, A: int, *, trace=None) -> int:
        K = mod_pow(A, b, self.p)
        if trace is not None:
            trace.record(name="DH Bob step 2",
                         inputs={"b": b, "A": A},
                         outputs={"K = A^b = g^{ab}": K},
                         pa_number=11)
        return K


# ---------- MITM attack demo ----------

class MITMAdversary:
    """
    Active man-in-the-middle attacker against unauthenticated DH.

    Eve intercepts A and B, substitutes her own public values, and ends up
    sharing a separate key with each of Alice and Bob.

    Demonstrates why DH alone is NOT sufficient -- you need authenticated DH
    (via signatures, PA#15).
    """

    def __init__(self, dh: DiffieHellman):
        self._dh = dh
        self._e_a = None  # Eve's secret with Alice
        self._e_b = None  # Eve's secret with Bob

    def intercept_alice(self, A_real: int) -> int:
        """Eve receives A from Alice, sends a fake A' = g^{e_a} to Bob."""
        self._e_a = secure_randrange(2, self._dh.q)
        A_fake = mod_pow(self._dh.g, self._e_a, self._dh.p)
        self._A_real = A_real  # remember Alice's real public value
        return A_fake

    def intercept_bob(self, B_real: int) -> int:
        """Eve receives B from Bob, sends fake B' = g^{e_b} to Alice."""
        self._e_b = secure_randrange(2, self._dh.q)
        B_fake = mod_pow(self._dh.g, self._e_b, self._dh.p)
        self._B_real = B_real
        return B_fake

    def shared_with_alice(self) -> int:
        """Eve computes K_alice = A_real^{e_b}; matches what Alice computes."""
        return mod_pow(self._A_real, self._e_b, self._dh.p)

    def shared_with_bob(self) -> int:
        return mod_pow(self._B_real, self._e_a, self._dh.p)
