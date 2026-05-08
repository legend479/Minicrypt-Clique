"""
PA#14: Chinese Remainder Theorem and Garner's algorithm for fast RSA decryption.

Two roles in RSA:
  1. Honest party: 4x speedup of decryption via per-prime modular exponentiation.
  2. Adversary: Hastad's broadcast attack (in pubkey/rsa_attacks.py) uses the
     basic CRT solver here to recover m from m^e mod N1, ..., m^e mod Ne.
"""
from typing import List, Tuple
from crypto_core.number_theory.modular import mod_inverse


def crt(residues: List[int], moduli: List[int]) -> int:
    """
    Solve the system  x = residues[i] (mod moduli[i])  for pairwise coprime moduli.

    Returns the unique solution x in [0, prod(moduli)).
    """
    if len(residues) != len(moduli):
        raise ValueError("crt: residues and moduli length mismatch")
    if len(residues) == 0:
        raise ValueError("crt: empty input")

    # Compute product N = n1 * n2 * ... * nk
    N = 1
    for n in moduli:
        if n <= 0:
            raise ValueError("crt: moduli must be positive")
        N *= n

    x = 0
    for ai, ni in zip(residues, moduli):
        Mi = N // ni
        Mi_inv = mod_inverse(Mi, ni)
        x = (x + ai * Mi * Mi_inv) % N
    return x


def garner_recombine(mp: int, mq: int, p: int, q: int, q_inv_mod_p: int) -> int:
    """
    Garner's CRT recombination for RSA decryption.

    Given:
      mp = c^{dp} mod p
      mq = c^{dq} mod q
      q_inv_mod_p = q^{-1} mod p

    Returns m = c^d mod N where N = p*q.
    """
    h = (q_inv_mod_p * (mp - mq)) % p
    return mq + h * q
