"""
AES-128 implementation from scratch.

This is a clean-room implementation of FIPS-197 AES-128:
  - 128-bit block size, 128-bit key
  - 10 rounds
  - Standard S-box (Rijndael S-box derived from GF(2^8) inverse + affine)

Implemented directly to honor the "no library crypto" rule. The OS-randomness
exception does not extend to AES.

Wrapped as AESFoundation exposing PRF, PRP, and OWF views.
"""
from crypto_core.common.interfaces import Foundation, OWF, PRF, PRP
from crypto_core.common.exceptions import NotSupported
from crypto_core.common.bitops import xor_bytes


# ----------- Rijndael S-box and inverse -----------

S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_S_BOX = [0] * 256
for _i, _v in enumerate(S_BOX):
    INV_S_BOX[_v] = _i

R_CON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
]


def _xtime(a: int) -> int:
    """Multiply by x (=0x02) in GF(2^8) with reduction polynomial 0x11b."""
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff


def _gmul(a: int, b: int) -> int:
    """Multiplication in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


def _key_expansion(key: bytes) -> list:
    """
    AES-128 key expansion. Returns 11 round keys (each a 16-byte bytes object).
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    Nk = 4   # 4 32-bit words in key
    Nb = 4   # 4 32-bit words per block
    Nr = 10  # 10 rounds

    # Words: list of 4-byte tuples
    w = [tuple(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            # RotWord + SubWord + Rcon
            temp = (temp[1], temp[2], temp[3], temp[0])
            temp = tuple(S_BOX[b] for b in temp)
            temp = (temp[0] ^ R_CON[i // Nk - 1], temp[1], temp[2], temp[3])
        w.append(tuple(a ^ b for a, b in zip(w[i - Nk], temp)))

    # Group every 4 words into a 16-byte round key.
    round_keys = []
    for r in range(Nr + 1):
        rk = bytes(b for word in w[4*r:4*r+4] for b in word)
        round_keys.append(rk)
    return round_keys


def _sub_bytes(state: list) -> None:
    for i in range(16):
        state[i] = S_BOX[state[i]]


def _inv_sub_bytes(state: list) -> None:
    for i in range(16):
        state[i] = INV_S_BOX[state[i]]


def _shift_rows(state: list) -> None:
    # State is column-major: state[col*4 + row]
    # Row 1: shift left by 1
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    # Row 2: shift left by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift left by 3
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _inv_shift_rows(state: list) -> None:
    state[5], state[9], state[13], state[1] = state[1], state[5], state[9], state[13]
    state[10], state[14], state[2], state[6] = state[2], state[6], state[10], state[14]
    state[15], state[3], state[7], state[11] = state[3], state[7], state[11], state[15]


def _mix_columns(state: list) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[4*c], state[4*c+1], state[4*c+2], state[4*c+3]
        state[4*c] = _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3
        state[4*c+1] = a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3
        state[4*c+2] = a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3)
        state[4*c+3] = _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2)


def _inv_mix_columns(state: list) -> None:
    for c in range(4):
        a0, a1, a2, a3 = state[4*c], state[4*c+1], state[4*c+2], state[4*c+3]
        state[4*c]   = _gmul(a0, 0x0e) ^ _gmul(a1, 0x0b) ^ _gmul(a2, 0x0d) ^ _gmul(a3, 0x09)
        state[4*c+1] = _gmul(a0, 0x09) ^ _gmul(a1, 0x0e) ^ _gmul(a2, 0x0b) ^ _gmul(a3, 0x0d)
        state[4*c+2] = _gmul(a0, 0x0d) ^ _gmul(a1, 0x09) ^ _gmul(a2, 0x0e) ^ _gmul(a3, 0x0b)
        state[4*c+3] = _gmul(a0, 0x0b) ^ _gmul(a1, 0x0d) ^ _gmul(a2, 0x09) ^ _gmul(a3, 0x0e)


def _add_round_key(state: list, round_key: bytes) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block under a 16-byte key."""
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys = _key_expansion(key)
    state = list(block)
    _add_round_key(state, round_keys[0])
    for r in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return bytes(state)


def aes128_decrypt_block(key: bytes, block: bytes) -> bytes:
    """Decrypt one 16-byte block."""
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys = _key_expansion(key)
    state = list(block)
    _add_round_key(state, round_keys[10])
    for r in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)


# ============ Wrappers as PRF / PRP / OWF ============


class AESPRF(PRF):
    """AES-128 wrapped as a PRF (which it is, by the PRP/PRF switching lemma)."""

    @property
    def block_size(self) -> int:
        return 16

    @property
    def key_size(self) -> int:
        return 16

    def evaluate(self, k: bytes, x: bytes, *, trace=None) -> bytes:
        if len(x) != 16:
            raise ValueError("AESPRF input must be 16 bytes")
        y = aes128_encrypt_block(k, x)
        if trace is not None:
            trace.record(
                name="AES-128 F_k(x)",
                inputs={"k": k, "x": x},
                outputs={"y": y},
                theorem="AES (concrete PRP/PRF)",
                pa_number=2,
            )
        return y


class AESPRP(PRP):
    """AES-128 wrapped as a PRP (invertible via the decrypt path)."""

    @property
    def block_size(self) -> int:
        return 16

    @property
    def key_size(self) -> int:
        return 16

    def evaluate(self, k: bytes, x: bytes, *, trace=None) -> bytes:
        if len(x) != 16:
            raise ValueError("AESPRP input must be 16 bytes")
        y = aes128_encrypt_block(k, x)
        if trace is not None:
            trace.record(name="AES-128 encrypt", inputs={"k": k, "x": x},
                         outputs={"y": y}, theorem="AES PRP", pa_number=2)
        return y

    def invert(self, k: bytes, y: bytes, *, trace=None) -> bytes:
        if len(y) != 16:
            raise ValueError("AESPRP input must be 16 bytes")
        x = aes128_decrypt_block(k, y)
        if trace is not None:
            trace.record(name="AES-128 decrypt", inputs={"k": k, "y": y},
                         outputs={"x": x}, theorem="AES PRP^{-1}", pa_number=2)
        return x


class AESCompressionOWF(OWF):
    """
    Davies-Meyer-style OWF from AES:  f(k) = AES_k(0^128) XOR k.

    This is a length-preserving OWF on 128-bit inputs. Used as an alternative
    OWF foundation (PA#1 alternative).
    """

    @property
    def domain_bits(self) -> int:
        return 128

    def evaluate(self, x, *, trace=None):
        # Accept either bytes or int
        if isinstance(x, int):
            if not (0 <= x < (1 << 128)):
                raise ValueError("input must fit in 128 bits")
            k = x.to_bytes(16, "big")
        else:
            k = x
            if len(k) != 16:
                raise ValueError("AESCompressionOWF input must be 16 bytes / 128 bits")
        zero = b"\x00" * 16
        y = xor_bytes(aes128_encrypt_block(k, zero), k)
        if trace is not None:
            trace.record(
                name="AES Davies-Meyer OWF",
                inputs={"k": k},
                outputs={"f(k)": y},
                theorem="OWF from PRP (Davies-Meyer construction)",
                pa_number=1,
            )
        return y if not isinstance(x, int) else int.from_bytes(y, "big")

    def hard_core_predicate(self, x) -> int:
        """LSB of x."""
        if isinstance(x, int):
            return x & 1
        return x[-1] & 1


class AESFoundation(Foundation):
    """
    AES-based foundation. Exposes:
      - as_prf(): AES as a PRF
      - as_prp(): AES as a PRP
      - as_owf(): Davies-Meyer-style OWF derived from AES
      - as_owp(): NotSupported (Davies-Meyer is not bijective on its full input)
    """

    @property
    def name(self) -> str:
        return "AES-128"

    def as_owf(self) -> OWF:
        return AESCompressionOWF()

    def as_owp(self):
        raise NotSupported("AES Davies-Meyer is not a permutation; use DLPFoundation for OWP.")

    def as_prf(self) -> PRF:
        return AESPRF()

    def as_prp(self) -> PRP:
        return AESPRP()
