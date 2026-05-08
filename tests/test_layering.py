"""
Architectural test: layer encapsulation.

Higher modules may only import from strictly lower layers:
  common < number_theory < foundation < minicrypt < hashing < pubkey < mpc

Routing/api are top-level consumers; they may import from any crypto_core layer
but not vice versa.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LAYER_ORDER = [
    "common",
    "number_theory",
    "foundation",
    "minicrypt",
    "hashing",
    "pubkey",
    "mpc",
]

LAYER_RANK = {name: i for i, name in enumerate(LAYER_ORDER)}


def _file_layer(path: Path) -> str:
    rel = path.relative_to(ROOT / "crypto_core").parts
    return rel[0] if rel else None


def test_layers_respect_order():
    violations = []
    for py in (ROOT / "crypto_core").rglob("*.py"):
        layer = _file_layer(py)
        if layer not in LAYER_RANK:
            continue
        rank = LAYER_RANK[layer]
        text = py.read_text()
        for line in text.splitlines():
            m = re.match(r"^\s*from\s+crypto_core\.(\w+)", line)
            if not m:
                continue
            other_layer = m.group(1)
            if other_layer not in LAYER_RANK:
                continue
            other_rank = LAYER_RANK[other_layer]
            if other_rank > rank:
                violations.append(
                    f"{py.relative_to(ROOT)}: imports from higher layer "
                    f"crypto_core.{other_layer} (line: {line.strip()})"
                )
    assert not violations, "Layer-encapsulation violations:\n" + "\n".join(violations)


def test_crypto_core_does_not_import_routing_or_api():
    bad = []
    for py in (ROOT / "crypto_core").rglob("*.py"):
        text = py.read_text()
        for line in text.splitlines():
            if re.match(r"^\s*(from|import)\s+(routing|api)\b", line):
                bad.append(f"{py.relative_to(ROOT)}: {line.strip()}")
    assert not bad, "crypto_core/ must not import from routing or api:\n" + "\n".join(bad)
