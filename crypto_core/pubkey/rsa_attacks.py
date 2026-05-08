"""
Attack demos against RSA-based schemes.

  - determinism_demo: textbook RSA leaks via deterministic ciphertext.
  - bleichenbacher_attack_simplified: a stripped-down padding-oracle attack on
    PKCS#1 v1.5 (PA#12).
  - hastad_broadcast_attack: Hastad's CRT-based broadcast attack (PA#14).
"""
from typing import List, Tuple, Callable
from crypto_core.number_theory.crt import crt
from crypto_core.number_theory.integer_root import integer_nth_root, is_perfect_power
from crypto_core.number_theory.modular import mod_pow


# ---------- Determinism demo (PA#12) ----------

def determinism_demo(rsa, pk, message: bytes, n_trials: int = 5):
    """
    Encrypt the same message multiple times under textbook RSA. All ciphertexts
    are identical -- demonstrating CPA insecurity.

    Returns {'ciphertexts': [...], 'all_identical': bool}.
    """
    cts = [rsa.encrypt(pk, message) for _ in range(n_trials)]
    return {
        "ciphertexts": cts,
        "all_identical": all(c == cts[0] for c in cts),
        "explanation": "Same plaintext -> same ciphertext under textbook RSA. "
                       "An adversary can detect when two encryptions encode "
                       "the same plaintext (votes, coin flips, ...).",
    }


# ---------- Bleichenbacher (simplified, illustrative) ----------

def bleichenbacher_attack_simplified(pk, c0: int,
                                     padding_oracle: Callable[[int], bool],
                                     max_queries: int = 100_000) -> dict:
    """
    A pedagogical sketch of Bleichenbacher's adaptive padding-oracle attack.

    The full attack is complex (3 steps with interval narrowing). This
    simplified version performs the "blinding" step and a coarse search to
    illustrate the core idea: a yes/no padding oracle is enough to recover
    the plaintext.

    For PA#12's deliverable, the demo runs on tiny moduli (e.g., 64 bits)
    where exhaustive search is fast. With small N we can verify the oracle
    semantics rather than achieving the attack's full asymptotic.

    Returns a dict explaining the attack and reporting partial progress.
    """
    queries = 0
    # Blinding: find s_1 such that c_1 = c0 * s_1^e mod N is PKCS-conformant.
    s = 1
    found_s = None
    while queries < max_queries:
        c1 = (c0 * mod_pow(s, pk.e, pk.N)) % pk.N
        queries += 1
        if padding_oracle(c1):
            found_s = s
            break
        s += 1
    return {
        "queries_made": queries,
        "blinding_s_found": found_s,
        "explanation": (
            "Bleichenbacher (1998): adaptive padding-oracle attack on PKCS#1 "
            "v1.5. ~2^20 oracle queries on real-world moduli decrypt arbitrary "
            "ciphertexts. Lesson: PKCS#1 v1.5 is not CCA-secure; use OAEP."
        ),
    }


# ---------- Hastad broadcast attack (PA#14) ----------

def hastad_broadcast_attack(ciphertexts: List[int], moduli: List[int],
                            e: int) -> dict:
    """
    Hastad's broadcast attack.

    Setup: a sender broadcasts the same plaintext m to e recipients with the
    same small public exponent e but different moduli N_1, ..., N_e.

      c_i = m^e mod N_i

    Since m < N_i for all i, m^e < N_1 * N_2 * ... * N_e. CRT recovers x =
    m^e mod prod(N_i), which equals m^e exactly as an integer. Then we take
    the e-th integer root.

    Inputs:
      ciphertexts: [c_1, ..., c_e]
      moduli:      [N_1, ..., N_e]
      e:           the small public exponent (e.g., 3)

    Returns {'recovered_m': int, 'is_perfect_root': bool}.
    """
    if len(ciphertexts) != e or len(moduli) != e:
        raise ValueError(f"Hastad: need exactly e={e} ciphertexts and moduli")

    # Step 1: CRT to recover m^e (as an integer).
    me = crt(ciphertexts, moduli)

    # Step 2: integer e-th root.
    m = integer_nth_root(me, e)
    perfect = (pow(m, e) == me)

    return {
        "recovered_m": m,
        "m_to_the_e": me,
        "is_perfect_root": perfect,
        "explanation": (
            "Hastad: CRT recovers m^e in [0, prod(N_i)); since m^e is small "
            "enough to fit, the integer e-th root recovers m without factoring."
        ),
    }


# ---------- Multiplicative-homomorphism forgery on raw RSA-Sign ----------

def rsa_sign_homomorphism_forgery(pk, sig_m1: int, sig_m2: int, N: int) -> int:
    """
    Given signatures sig_1 = m_1^d mod N and sig_2 = m_2^d mod N (raw RSA, no
    hashing), forge a signature on m_1 * m_2 mod N:

      sig_{m1*m2} = sig_1 * sig_2 mod N

    Used in PA#15 to motivate hash-then-sign.
    """
    return (sig_m1 * sig_m2) % N
