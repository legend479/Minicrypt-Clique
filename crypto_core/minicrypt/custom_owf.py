"""User-configurable OWF-style functions for PA#0 demonstrations.

These functions are intentionally small and bounded so the web demo can let a
student define a deterministic closed map and then feed it through the existing
OWF -> PRG -> PRF -> PRP -> MAC pipeline. They are not security claims.
"""
from dataclasses import dataclass
from crypto_core.common.interfaces import OWF


@dataclass
class UserOWFConfig:
    name: str = "User OWF"
    kind: str = "quadratic"
    domain_bits: int = 16
    a: int = 5
    b: int = 3
    c: int = 7
    xor_mask: int = 0xA5A5
    hc_bit: int = 0


class UserDefinedOWF(OWF):
    """Small closed map over {0,1}^n configured by demo inputs."""

    def __init__(self, config: UserOWFConfig):
        if not (4 <= int(config.domain_bits) <= 32):
            raise ValueError("domain_bits must be between 4 and 32")
        self.config = config
        self._domain_bits = int(config.domain_bits)
        self.domain_size = 1 << self._domain_bits
        self._mask = self.domain_size - 1
        self._kind = config.kind
        if self._kind not in ("quadratic", "affine", "xorshift"):
            raise ValueError("kind must be quadratic, affine, or xorshift")

    @property
    def domain_bits(self) -> int:
        return self._domain_bits

    @property
    def name(self) -> str:
        return self.config.name or "User OWF"

    def evaluate(self, x: int, *, trace=None) -> int:
        x &= self._mask
        a = int(self.config.a) & self._mask
        b = int(self.config.b) & self._mask
        c = int(self.config.c) & self._mask
        xor_mask = int(self.config.xor_mask) & self._mask
        if self._kind == "affine":
            y = (a * x + b) & self._mask
        elif self._kind == "xorshift":
            y = x ^ ((x << max(1, a % self._domain_bits)) & self._mask)
            y ^= y >> max(1, b % self._domain_bits)
            y = (y ^ xor_mask ^ c) & self._mask
        else:
            y = (a * x * x + b * x + c) & self._mask
            y ^= xor_mask
            y &= self._mask
        if trace is not None:
            trace.record(
                name=f"{self.name} evaluate",
                inputs={"x": x, "kind": self._kind},
                outputs={"f(x)": y},
                theorem="User-supplied OWF-style foundation for demo pipeline",
                pa_number=0,
            )
        return y

    def hard_core_predicate(self, x: int) -> int:
        bit = int(self.config.hc_bit) % self._domain_bits
        return (int(x) >> bit) & 1

    def diagnostics(self, sample_limit: int = 4096) -> dict:
        count = min(self.domain_size, sample_limit)
        values = [self.evaluate(x) for x in range(count)]
        unique = len(set(values))
        collisions = count - unique
        return {
            "name": self.name,
            "kind": self._kind,
            "domain_bits": self._domain_bits,
            "sampled": count,
            "unique_outputs": unique,
            "collisions": collisions,
            "closed": all(0 <= y < self.domain_size for y in values),
            "hc_bit": int(self.config.hc_bit) % self._domain_bits,
        }


def user_owf_from_payload(data: dict) -> UserDefinedOWF:
    return UserDefinedOWF(UserOWFConfig(
        name=data.get("name", "User OWF"),
        kind=data.get("kind", "quadratic"),
        domain_bits=int(data.get("domain_bits", 16)),
        a=int(data.get("a", 5)),
        b=int(data.get("b", 3)),
        c=int(data.get("c", 7)),
        xor_mask=int(data.get("xor_mask", 0xA5A5)),
        hc_bit=int(data.get("hc_bit", 0)),
    ))
