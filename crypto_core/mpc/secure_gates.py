"""
PA#19: Secure boolean gates from OT.

Secure AND from OT:
  Alice holds a in {0,1}; Bob holds b in {0,1}.
  Alice acts as OT sender with messages (m_0, m_1) = (0, a).
  Bob acts as OT receiver with choice bit b.
  Bob receives m_b = a * b = a AND b.
  Alice locally outputs (a AND b) by waiting for Bob to share, OR by computing
  it from her side -- but to keep both parties symmetric, the convention is
  that Bob sends the result back to Alice over an authenticated channel after
  the gate evaluation. For our circuit evaluator we just return the value.

Secure XOR (free):
  No OT needed. Use additive secret sharing: Alice and Bob each hold a share,
  XORing locally produces a share of the result. For our higher-level circuit
  framework we simply compute a XOR b directly when both inputs are known to
  the same party (which after gate evaluation becomes the case).

Secure NOT (free):
  Locally flip the bit on the holder's share.

Privacy:
  AND: Bob learns a*b but not a (OT receiver privacy of the slot 1-b).
       Alice learns nothing about b (OT sender privacy).
  XOR: each party's share is one-time-padded to the other party's view.
"""
from crypto_core.foundation.dlp_foundation import DLPFoundation
from crypto_core.mpc.ot import OTSender, OTReceiver


def secure_and(a: int, b: int, foundation: DLPFoundation, *, trace=None) -> int:
    """
    Secure AND of a (held by Alice) and b (held by Bob), via OT.

    For our simplified circuit model, both inputs are accessible at evaluation
    time and the function returns the result. This is the canonical 2-party
    AND gate construction.
    """
    if a not in (0, 1) or b not in (0, 1):
        raise ValueError("secure_and: inputs must be bits")
    receiver = OTReceiver(foundation)
    sender = OTSender(foundation)
    # Alice's OT messages: (m_0, m_1) = (0, a). Encoded as small group elements.
    # We use small integers 1 and (1 + a) to keep them inside (0, p).
    # Specifically: encode 0 -> 1, 1 -> 2 in the group element space.
    #   m_0 = 1 (representing 0)
    #   m_1 = 2 if a==1 else 1 (representing a)
    msg_for_b0 = 1            # = 0 (bit) encoded as group element 1
    msg_for_b1 = 2 if a == 1 else 1  # = a encoded
    pk0, pk1 = receiver.step1(b, trace=trace)
    c0, c1 = sender.step(pk0, pk1, msg_for_b0, msg_for_b1, trace=trace)
    received_group_elem = receiver.step2(c0, c1, trace=trace)
    # Decode: 1 -> 0, 2 -> 1
    bit_received = 0 if received_group_elem == 1 else 1
    if trace is not None:
        trace.record(name="Secure AND result",
                     inputs={"a": a, "b": b},
                     outputs={"a AND b": bit_received},
                     theorem="OT-based secure AND",
                     pa_number=19)
    return bit_received


def secure_xor(a: int, b: int, *, trace=None) -> int:
    """Secure XOR: free (additive over Z_2). No OT call required."""
    out = a ^ b
    if trace is not None:
        trace.record(name="Secure XOR (free)",
                     inputs={"a": a, "b": b},
                     outputs={"a XOR b": out},
                     theorem="XOR is linear; additive secret sharing is free",
                     pa_number=19)
    return out


def secure_not(a: int, *, trace=None) -> int:
    """Secure NOT: free (local share flip)."""
    out = 1 ^ (a & 1)
    if trace is not None:
        trace.record(name="Secure NOT (free)",
                     inputs={"a": a},
                     outputs={"NOT a": out},
                     pa_number=19)
    return out
