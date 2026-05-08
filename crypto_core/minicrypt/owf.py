"""
PA#1a: One-Way Function instantiations.

Re-exports the OWF interface and provides convenience constructors:
  - DLP-based OWF (from foundation)
  - AES Davies-Meyer OWF (from foundation)
"""
from crypto_core.common.interfaces import OWF, OWP
from crypto_core.foundation.dlp_foundation import DLPOWF, DLPFoundation
from crypto_core.foundation.aes_foundation import AESCompressionOWF


def dlp_owf(bits: int = 64) -> OWP:
    """Convenience: return a fresh DLP-based OWP."""
    return DLPFoundation(bits=bits).as_owp()


def aes_owf() -> OWF:
    """Convenience: return an AES-based Davies-Meyer OWF."""
    return AESCompressionOWF()


__all__ = ["OWF", "OWP", "DLPOWF", "AESCompressionOWF", "dlp_owf", "aes_owf"]
