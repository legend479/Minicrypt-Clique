"""
Abstract base classes for every cryptographic primitive in the codebase.

These ABCs are the contract between layers. Every concrete implementation
subclasses one of these; every consumer accepts an instance of the ABC, never
a concrete class. This is what makes the PA#0 foundation toggle and routing
table work polymorphically.
"""
from abc import ABC, abstractmethod
from typing import Optional, Tuple, Any


class OWF(ABC):
    """One-way function f: domain -> range."""

    @abstractmethod
    def evaluate(self, x: int, *, trace=None) -> int: ...

    @abstractmethod
    def hard_core_predicate(self, x: int) -> int:
        """Goldreich-Levin / Blum-Micali style hard-core bit b(x) in {0,1}."""

    @property
    @abstractmethod
    def domain_bits(self) -> int: ...

    @property
    def name(self) -> str:
        return self.__class__.__name__


class OWP(OWF):
    """One-way permutation. evaluate must be a bijection on the domain."""

    @abstractmethod
    def is_permutation(self) -> bool: ...


class PRG(ABC):
    """Pseudorandom generator: short seed -> long pseudorandom output."""

    @abstractmethod
    def seed(self, s: bytes) -> None: ...

    @abstractmethod
    def next_bits(self, n_bytes: int, *, trace=None) -> bytes: ...

    @property
    @abstractmethod
    def seed_length(self) -> int: ...


class PRF(ABC):
    """Keyed pseudorandom function F_k(x)."""

    @abstractmethod
    def evaluate(self, k: bytes, x: bytes, *, trace=None) -> bytes: ...

    @property
    @abstractmethod
    def block_size(self) -> int:
        """Output (and typical input) length in bytes."""

    @property
    @abstractmethod
    def key_size(self) -> int: ...


class PRP(PRF):
    """Pseudorandom permutation: a PRF that is also invertible."""

    @abstractmethod
    def invert(self, k: bytes, y: bytes, *, trace=None) -> bytes: ...


class MAC(ABC):
    """Message authentication code."""

    @abstractmethod
    def mac(self, k: bytes, m: bytes, *, trace=None) -> bytes: ...

    @abstractmethod
    def verify(self, k: bytes, m: bytes, t: bytes) -> bool: ...

    @property
    @abstractmethod
    def key_size(self) -> int: ...

    @property
    @abstractmethod
    def tag_size(self) -> int: ...


class Hash(ABC):
    """Unkeyed hash function."""

    @abstractmethod
    def digest(self, m: bytes, *, trace=None) -> bytes: ...

    @property
    @abstractmethod
    def output_size(self) -> int: ...

    @property
    @abstractmethod
    def block_size(self) -> int: ...


class CRHF(Hash):
    """Marker subclass: collision-resistant hash."""


class SymEncryption(ABC):
    """Symmetric encryption (CPA or CCA)."""

    @abstractmethod
    def encrypt(self, k, m: bytes, *, trace=None): ...

    @abstractmethod
    def decrypt(self, k, c, *, trace=None) -> bytes: ...

    @property
    @abstractmethod
    def key_size(self) -> int: ...


class PKC(ABC):
    """Public-key encryption."""

    @abstractmethod
    def keygen(self, *, trace=None) -> Tuple[Any, Any]:
        """Returns (pk, sk)."""

    @abstractmethod
    def encrypt(self, pk, m: bytes, *, trace=None): ...

    @abstractmethod
    def decrypt(self, sk, c, *, trace=None) -> bytes: ...


class Signature(ABC):
    """Public-key signature scheme."""

    @abstractmethod
    def keygen(self, *, trace=None) -> Tuple[Any, Any]:
        """Returns (vk, sk)."""

    @abstractmethod
    def sign(self, sk, m: bytes, *, trace=None): ...

    @abstractmethod
    def verify(self, vk, m: bytes, sigma) -> bool: ...


class Foundation(ABC):
    """
    A concrete cryptographic foundation (AES or DLP). Exposes views as the
    various Minicrypt primitives. Views may raise NotSupported if the
    foundation cannot natively serve as that primitive.
    """

    @abstractmethod
    def as_owf(self) -> OWF: ...

    @abstractmethod
    def as_owp(self) -> OWP: ...

    @abstractmethod
    def as_prf(self) -> PRF: ...

    @abstractmethod
    def as_prp(self) -> PRP: ...

    @property
    @abstractmethod
    def name(self) -> str: ...
