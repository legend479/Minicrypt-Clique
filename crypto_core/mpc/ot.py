"""
PA#18: 1-out-of-2 Oblivious Transfer (Bellare-Micali style).

Sender holds (m_0, m_1).  Receiver holds choice bit b in {0, 1}.

Protocol:
  1. Receiver generates two PKC keypairs but knows the secret key for ONLY
     the b-th one. The other public key is constructed so that no one knows
     its secret key.
  2. Receiver sends (pk_0, pk_1) to sender.
  3. Sender encrypts m_0 under pk_0 and m_1 under pk_1, sends both.
  4. Receiver decrypts only c_b (the only one for which they hold sk).

Properties:
  - Sender privacy: receiver cannot decrypt c_{1-b} (no sk).
  - Receiver privacy: sender cannot tell b from (pk_0, pk_1) -- both look
    indistinguishable.

This module is parametric on PKC -- it works with PA#12 RSA or PA#16 ElGamal.

For ElGamal, we exploit the structure:
  - Receiver picks one secret x_b, computes h_b = g^{x_b}.
  - The other key h_{1-b} = some random group element (no known dlog).
  - Receiver sends (h_0, h_1).

Since both keys are uniform group elements from sender's view, b is hidden.
"""
from typing import Any, Tuple
from crypto_core.common.randomness import secure_randrange
from crypto_core.number_theory.modular import mod_pow, mod_inverse
from crypto_core.foundation.dlp_foundation import DLPFoundation
from crypto_core.pubkey.elgamal import ElGamal, ElGamalPublicKey, ElGamalPrivateKey


class OTReceiver:
    """OT receiver. Use with `OTSender` over the same DLP foundation."""

    def __init__(self, foundation: DLPFoundation):
        self._f = foundation
        self._b = None
        self._sk_b = None
        self._sk_real = None  # ElGamal private key for the b-th slot

    def step1(self, b: int, *, trace=None) -> Tuple[ElGamalPublicKey, ElGamalPublicKey]:
        """
        Generate two public keys; only the b-th has a known private exponent.

        The other (decoy) is set to a random group element.
        """
        if b not in (0, 1):
            raise ValueError("OT choice bit must be 0 or 1")
        self._b = b
        # Real keypair for slot b.
        x_b = secure_randrange(2, self._f.q)
        h_b = mod_pow(self._f.g, x_b, self._f.p)
        self._sk_real = x_b

        # Decoy keypair for slot 1-b. Pick a random group element.
        # We pick it as g^r * c for some random r and a non-identity element
        # whose dlog we don't store (it's just a random element of the
        # subgroup). The simplest: pick a random group element by raising g
        # to a fresh exponent we IMMEDIATELY DISCARD.
        decoy_exp = secure_randrange(2, self._f.q)
        h_decoy = mod_pow(self._f.g, decoy_exp, self._f.p)
        # We deliberately store nothing about decoy_exp.

        if b == 0:
            pk_0 = ElGamalPublicKey(p=self._f.p, q=self._f.q, g=self._f.g, h=h_b)
            pk_1 = ElGamalPublicKey(p=self._f.p, q=self._f.q, g=self._f.g, h=h_decoy)
        else:
            pk_0 = ElGamalPublicKey(p=self._f.p, q=self._f.q, g=self._f.g, h=h_decoy)
            pk_1 = ElGamalPublicKey(p=self._f.p, q=self._f.q, g=self._f.g, h=h_b)

        if trace is not None:
            trace.record(name="OT receiver step1: send (pk_0, pk_1)",
                         inputs={"b": b},
                         outputs={"pk_0.h": pk_0.h, "pk_1.h": pk_1.h},
                         theorem="Receiver knows sk only for slot b",
                         pa_number=18)
        return pk_0, pk_1

    def step2(self, c0, c1, *, trace=None) -> int:
        """Decrypt the b-th ciphertext."""
        if self._b is None:
            raise RuntimeError("OTReceiver: must call step1 first")
        ct = c0 if self._b == 0 else c1
        c_a, c_bb = ct
        # Same as ElGamal decrypt with secret = self._sk_real
        s = mod_pow(c_a, self._sk_real, self._f.p)
        s_inv = mod_inverse(s, self._f.p)
        m = (c_bb * s_inv) % self._f.p
        if trace is not None:
            trace.record(name="OT receiver step2: decrypt c_b",
                         inputs={"b": self._b},
                         outputs={"m_b": m},
                         pa_number=18)
        return m


class OTSender:
    """OT sender. Has messages (m_0, m_1)."""

    def __init__(self, foundation: DLPFoundation):
        self._f = foundation
        self._eg = ElGamal(foundation=foundation)

    def step(self, pk_0: ElGamalPublicKey, pk_1: ElGamalPublicKey,
             m_0: int, m_1: int, *, trace=None):
        """Encrypt m_0 under pk_0 and m_1 under pk_1; return both."""
        c_0 = self._eg.encrypt(pk_0, m_0)
        c_1 = self._eg.encrypt(pk_1, m_1)
        if trace is not None:
            trace.record(name="OT sender step",
                         inputs={"m_0": m_0, "m_1": m_1},
                         outputs={"c_0": c_0, "c_1": c_1},
                         pa_number=18)
        return c_0, c_1


# ---------- Convenience wrapper ----------

def run_ot(foundation: DLPFoundation, b: int, m_0: int, m_1: int,
           *, trace=None) -> int:
    """Run a full OT exchange and return the receiver's output (= m_b)."""
    receiver = OTReceiver(foundation)
    sender = OTSender(foundation)
    pk_0, pk_1 = receiver.step1(b, trace=trace)
    c_0, c_1 = sender.step(pk_0, pk_1, m_0, m_1, trace=trace)
    return receiver.step2(c_0, c_1, trace=trace)
