"""
StepTrace: a small append-only log of intermediate values that the React web
app can display. Every primitive's evaluate/encrypt/mac/digest/sign accepts an
optional `trace=None` argument; when given a StepTrace, it appends labelled
steps with hex-encoded inputs and outputs.

This is what makes the PA#0 explorer's "show me the intermediate values" UI
work without bolting visualization concerns into each primitive.
"""
from dataclasses import dataclass, field, asdict
from typing import Any, List, Optional


def _to_hex(v: Any) -> str:
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, int):
        # int has no fixed width; render compactly
        return hex(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return "[" + ", ".join(_to_hex(x) for x in v) + "]"
    if isinstance(v, tuple):
        return "(" + ", ".join(_to_hex(x) for x in v) + ")"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{k}: {_to_hex(val)}" for k, val in v.items()) + "}"
    return str(v)


@dataclass
class TraceStep:
    name: str
    inputs: dict
    outputs: dict
    theorem: Optional[str] = None
    pa_number: Optional[int] = None

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "inputs": {k: _to_hex(v) for k, v in self.inputs.items()},
            "outputs": {k: _to_hex(v) for k, v in self.outputs.items()},
            "theorem": self.theorem,
            "pa_number": self.pa_number,
        }


@dataclass
class StepTrace:
    """Append-only sequence of computation steps."""
    steps: List[TraceStep] = field(default_factory=list)

    def record(self, name: str, inputs: dict, outputs: dict,
               theorem: Optional[str] = None,
               pa_number: Optional[int] = None) -> None:
        self.steps.append(TraceStep(name, inputs, outputs, theorem, pa_number))

    def to_json(self) -> List[dict]:
        return [s.to_json() for s in self.steps]

    def __len__(self) -> int:
        return len(self.steps)

    def __iter__(self):
        return iter(self.steps)
