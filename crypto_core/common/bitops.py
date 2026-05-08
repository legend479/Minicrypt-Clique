"""
Bit, byte, integer conversion helpers + padding schemes.

Pure functions, no crypto state. Used everywhere.
"""
from typing import List


# ---------- int <-> bytes ----------

def int_to_bytes(n: int, length: int) -> bytes:
    """Big-endian fixed-length encoding of a non-negative integer."""
    if n < 0:
        raise ValueError("int_to_bytes requires non-negative input")
    return n.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    """Big-endian decoding."""
    return int.from_bytes(b, "big")


# ---------- bytes <-> bits ----------

def bytes_to_bits(b: bytes) -> List[int]:
    """MSB-first bit decomposition."""
    out = []
    for byte in b:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def bits_to_bytes(bits: List[int]) -> bytes:
    """MSB-first bit composition. Length must be multiple of 8."""
    if len(bits) % 8 != 0:
        raise ValueError(f"bit-list length {len(bits)} not multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (bits[i + j] & 1)
        out.append(byte)
    return bytes(out)


def int_to_bits(n: int, width: int) -> List[int]:
    """Big-endian (MSB-first) `width`-bit decomposition."""
    if n < 0:
        raise ValueError("int_to_bits requires non-negative input")
    if n >= (1 << width):
        raise ValueError(f"int {n} does not fit in {width} bits")
    return [(n >> (width - 1 - i)) & 1 for i in range(width)]


def bits_to_int(bits: List[int]) -> int:
    n = 0
    for b in bits:
        n = (n << 1) | (b & 1)
    return n


# ---------- XOR ----------

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(a) != len(b):
        raise ValueError(f"xor_bytes length mismatch: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


# ---------- PKCS#7 padding (used by CBC mode) ----------

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Append PKCS#7 padding to make data a multiple of block_size."""
    if not 1 <= block_size <= 255:
        raise ValueError("block_size must be in [1, 255]")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    """Strip PKCS#7 padding; raise PaddingError on malformed input."""
    from crypto_core.common.exceptions import PaddingError
    if len(data) == 0 or len(data) % block_size != 0:
        raise PaddingError("pkcs7_unpad: invalid length")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise PaddingError(f"pkcs7_unpad: invalid pad byte {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise PaddingError("pkcs7_unpad: malformed padding")
    return data[:-pad_len]


# ---------- Merkle-Damgard strengthening (PA#7) ----------

def md_strengthening_pad(message: bytes, block_size: int) -> bytes:
    """
    MD strengthening: append 0x80 (the '1' bit + 7 zero bits), then enough zero
    bytes, then a 64-bit big-endian length field, so the result is a multiple
    of `block_size` bytes.
    """
    if block_size < 9:
        raise ValueError("block_size must be >= 9 for 1-byte tag + 8-byte length")
    msg_len_bits = len(message) * 8
    # We need at least 1 byte for the 0x80 tag and 8 bytes for the length field.
    # Pad with zeros so total length is a multiple of block_size.
    padded = message + b"\x80"
    while (len(padded) + 8) % block_size != 0:
        padded += b"\x00"
    padded += msg_len_bits.to_bytes(8, "big")
    assert len(padded) % block_size == 0
    return padded
