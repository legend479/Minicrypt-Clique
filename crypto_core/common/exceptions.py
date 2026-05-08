"""
Exception hierarchy for the cryptographic codebase.
"""


class CryptoError(Exception):
    """Base for all cryptographic errors."""


class MacVerificationFailure(CryptoError):
    """Raised when a MAC tag fails to verify (CCA decrypt rejects ciphertext)."""


class PaddingError(CryptoError):
    """Raised by PKCS#1 v1.5 / PKCS#7 unpadding when format is malformed."""


class InvalidGroupParam(CryptoError):
    """Raised when a DH/DLP/ElGamal parameter set is malformed."""


class OTSenderError(CryptoError):
    """Raised when OT sender detects misbehavior."""


class NotSupported(CryptoError):
    """A foundation/primitive does not support a requested view."""


class StubNotImplemented(CryptoError):
    """Stub placeholder; raised by unimplemented PA modules."""
