"""
PA#17: CCA-secure public-key encryption via signcryption.

Construction: Encrypt-then-Sign.
  Sender has signing key sk_S; receiver has decryption key sk_R, sig vk_S.
  Encrypt(pk_R, sk_S, m):
    c_E = PKC.Encrypt(pk_R, m)
    sigma = Signature.Sign(sk_S, encode(c_E))
    return (c_E, sigma)
  Decrypt(sk_R, vk_S, (c_E, sigma)):
    if not Signature.Verify(vk_S, encode(c_E), sigma): return BOTTOM
    return PKC.Decrypt(sk_R, c_E)

Security: CCA2-secure. Any tampering with c_E invalidates sigma, so the
decryption oracle is useless to the adversary.
"""
from typing import Tuple
from crypto_core.common.exceptions import MacVerificationFailure
from crypto_core.pubkey.pkc_interface import PKC, Signature


def _encode_pkc_ciphertext(ct) -> bytes:
    """Encode a PKC ciphertext into bytes for signing."""
    if isinstance(ct, int):
        # RSA: single integer
        bit_len = ct.bit_length()
        byte_len = (bit_len + 7) // 8 or 1
        return ct.to_bytes(byte_len, "big")
    if isinstance(ct, tuple):
        # ElGamal: (c1, c2) pair
        parts = []
        for x in ct:
            if isinstance(x, int):
                bl = x.bit_length()
                bb = (bl + 7) // 8 or 1
                parts.append(len(parts).to_bytes(2, "big"))
                parts.append(bb.to_bytes(4, "big"))
                parts.append(x.to_bytes(bb, "big"))
            elif isinstance(x, bytes):
                parts.append(len(x).to_bytes(4, "big"))
                parts.append(x)
        return b"".join(parts)
    if isinstance(ct, bytes):
        return ct
    raise TypeError(f"unsupported PKC ciphertext type: {type(ct)}")


class Signcryption(PKC):
    """
    CCA2-secure PKC = PKC + signature applied after encryption.

    Note: the keygen here returns ((pk_pkc, vk_sig), (sk_pkc, sk_sig)).
    Encryption requires both sk_sig (sender signs) and pk_pkc (recipient).
    Decryption requires both vk_sig (verify sender) and sk_pkc (recipient).
    """

    def __init__(self, pkc: PKC, signer: Signature):
        self._pkc = pkc
        self._sig = signer

    def keygen(self, *, trace=None):
        """Returns ((pk_pkc, vk_sig), (sk_pkc, sk_sig))."""
        pk_pkc, sk_pkc = self._pkc.keygen(trace=trace)
        vk_sig, sk_sig = self._sig.keygen(trace=trace)
        return (pk_pkc, vk_sig), (sk_pkc, sk_sig)

    def encrypt(self, pk_combined, m: bytes, *, sender_sk_sig=None, trace=None):
        """
        pk_combined: (pk_pkc, vk_sig) of the receiver/sender pair.
        sender_sk_sig: the sender's signing key (provided separately because
                       it doesn't belong to the receiver's public key bundle).

        Frame: 0x01 || len(m, 2 bytes) || m.  The leading 0x01 sentinel ensures
        round-tripping through an int (which strips leading zero bytes) does
        not lose alignment.
        """
        if sender_sk_sig is None:
            raise ValueError("Signcryption.encrypt: sender_sk_sig required")
        pk_pkc, vk_sig = pk_combined
        if len(m) > 0xFFFF:
            raise ValueError("message too long for length-prefix")
        framed = b"\x01" + len(m).to_bytes(2, "big") + m
        c_E = self._pkc.encrypt(pk_pkc, framed, trace=trace)
        encoded = _encode_pkc_ciphertext(c_E)
        sigma = self._sig.sign(sender_sk_sig, encoded, trace=trace)
        if trace is not None:
            trace.record(name="Signcryption: PKC.Encrypt then Sign",
                         inputs={"m": m},
                         outputs={"c_E": c_E, "sigma": sigma},
                         theorem="Encrypt-then-Sign achieves CCA2-PKC",
                         pa_number=17)
        return c_E, sigma

    def decrypt(self, sk_combined, ct_with_sig, *, sender_vk_sig=None, trace=None):
        if sender_vk_sig is None:
            raise ValueError("Signcryption.decrypt: sender_vk_sig required")
        sk_pkc, _ = sk_combined
        c_E, sigma = ct_with_sig
        encoded = _encode_pkc_ciphertext(c_E)
        if not self._sig.verify(sender_vk_sig, encoded, sigma):
            if trace is not None:
                trace.record(name="Signcryption decrypt: SIGNATURE INVALID",
                             inputs={"c_E": c_E, "sigma": sigma},
                             outputs={"result": "BOTTOM"},
                             pa_number=17)
            raise MacVerificationFailure("signature invalid; ciphertext rejected")
        m_raw = self._pkc.decrypt(sk_pkc, c_E, trace=trace)
        if isinstance(m_raw, int):
            byte_len = (m_raw.bit_length() + 7) // 8 or 1
            framed = m_raw.to_bytes(byte_len, "big")
        else:
            framed = m_raw
        if len(framed) < 3 or framed[0] != 0x01:
            raise MacVerificationFailure("decoded plaintext: bad framing")
        msg_len = int.from_bytes(framed[1:3], "big")
        if 3 + msg_len > len(framed):
            raise MacVerificationFailure("decoded plaintext: length overflow")
        m = framed[3:3 + msg_len]
        if trace is not None:
            trace.record(name="Signcryption decrypt: signature verified, decrypt",
                         inputs={},
                         outputs={"m": m},
                         pa_number=17)
        return m
