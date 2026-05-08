"""
Base for cryptographic foundations. Re-exports the Foundation ABC.
"""
from crypto_core.common.interfaces import Foundation, OWF, OWP, PRF, PRP

__all__ = ["Foundation", "OWF", "OWP", "PRF", "PRP"]
