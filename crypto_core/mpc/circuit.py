"""
PA#20: All 2-party secure computation via boolean circuits.

A Circuit is a DAG of gates over a set of input wires. Each gate has type
(AND, XOR, NOT) and references its input wires. Output wires are designated
explicitly.

secure_eval(circuit, x_alice, y_bob, foundation):
  For each gate in topological order, call the secure gate primitive from
  PA#19. AND uses OT (PA#18). XOR/NOT are free. Final output wires are
  returned to both parties.

Three mandatory test circuits:
  millionaires(n): n-bit comparison x > y.
  equality(n):     n-bit equality test x == y.
  bit_add(n):      n-bit addition x + y mod 2^n.
"""
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass, field
from crypto_core.foundation.dlp_foundation import DLPFoundation
from crypto_core.mpc.secure_gates import secure_and, secure_xor, secure_not


# ---------- Wire and Gate model ----------

@dataclass
class Gate:
    """A gate in the circuit. Inputs are wire indices; output is a wire index."""
    type: str           # "AND", "XOR", "NOT", "INPUT_A", "INPUT_B", "CONST"
    output: int         # output wire id
    inputs: List[int] = field(default_factory=list)
    const_val: Optional[int] = None  # for CONST gates


class Circuit:
    """Boolean circuit DAG with input/output wire designations."""

    def __init__(self, n_alice_inputs: int, n_bob_inputs: int):
        self.n_alice = n_alice_inputs
        self.n_bob = n_bob_inputs
        self.gates: List[Gate] = []
        self._next_wire = 0
        # Reserve wires 0..n_alice-1 for Alice's input bits;
        # then n_alice..n_alice+n_bob-1 for Bob's.
        self.alice_input_wires = []
        for i in range(n_alice_inputs):
            w = self._next_wire
            self._next_wire += 1
            self.alice_input_wires.append(w)
            self.gates.append(Gate(type="INPUT_A", output=w))
        self.bob_input_wires = []
        for i in range(n_bob_inputs):
            w = self._next_wire
            self._next_wire += 1
            self.bob_input_wires.append(w)
            self.gates.append(Gate(type="INPUT_B", output=w))
        self.output_wires: List[int] = []

    def _new_wire(self) -> int:
        w = self._next_wire
        self._next_wire += 1
        return w

    def AND(self, a: int, b: int) -> int:
        out = self._new_wire()
        self.gates.append(Gate(type="AND", output=out, inputs=[a, b]))
        return out

    def XOR(self, a: int, b: int) -> int:
        out = self._new_wire()
        self.gates.append(Gate(type="XOR", output=out, inputs=[a, b]))
        return out

    def NOT(self, a: int) -> int:
        out = self._new_wire()
        self.gates.append(Gate(type="NOT", output=out, inputs=[a]))
        return out

    def CONST(self, val: int) -> int:
        out = self._new_wire()
        self.gates.append(Gate(type="CONST", output=out, const_val=val))
        return out

    def OR(self, a: int, b: int) -> int:
        # a OR b = NOT( (NOT a) AND (NOT b) ) = a XOR b XOR (a AND b)
        return self.XOR(self.XOR(a, b), self.AND(a, b))

    def set_outputs(self, wires: List[int]):
        self.output_wires = list(wires)


# ---------- Secure evaluation ----------

def secure_eval(circuit: Circuit, x_alice: List[int], y_bob: List[int],
                foundation: DLPFoundation, *, trace=None) -> Tuple[List[int], dict]:
    """
    Evaluate the circuit securely. Returns (output_bits, stats).

    stats includes 'and_gates' (= number of OT calls).
    """
    if len(x_alice) != circuit.n_alice:
        raise ValueError(f"need {circuit.n_alice} Alice bits, got {len(x_alice)}")
    if len(y_bob) != circuit.n_bob:
        raise ValueError(f"need {circuit.n_bob} Bob bits, got {len(y_bob)}")

    wire_values: Dict[int, int] = {}
    a_idx = 0
    b_idx = 0
    n_ots = 0
    for g in circuit.gates:
        if g.type == "INPUT_A":
            wire_values[g.output] = x_alice[a_idx] & 1
            a_idx += 1
        elif g.type == "INPUT_B":
            wire_values[g.output] = y_bob[b_idx] & 1
            b_idx += 1
        elif g.type == "CONST":
            wire_values[g.output] = g.const_val & 1
        elif g.type == "AND":
            a = wire_values[g.inputs[0]]
            b = wire_values[g.inputs[1]]
            wire_values[g.output] = secure_and(a, b, foundation, trace=trace)
            n_ots += 1
        elif g.type == "XOR":
            a = wire_values[g.inputs[0]]
            b = wire_values[g.inputs[1]]
            wire_values[g.output] = secure_xor(a, b, trace=trace)
        elif g.type == "NOT":
            a = wire_values[g.inputs[0]]
            wire_values[g.output] = secure_not(a, trace=trace)
        else:
            raise ValueError(f"unknown gate type: {g.type}")

    output_bits = [wire_values[w] for w in circuit.output_wires]
    stats = {
        "and_gates": n_ots,
        "total_gates": len([g for g in circuit.gates
                            if g.type in ("AND", "XOR", "NOT")]),
    }
    if trace is not None:
        trace.record(name=f"Circuit evaluated ({stats['and_gates']} OT calls)",
                     inputs={"x_alice": x_alice, "y_bob": y_bob},
                     outputs={"out": output_bits},
                     pa_number=20)
    return output_bits, stats


# ---------- Three mandatory test circuits ----------

def equality_circuit(n: int) -> Circuit:
    """
    n-bit equality test: returns 1 iff x == y.

    NOT(OR over bits of (x_i XOR y_i))
    """
    c = Circuit(n_alice_inputs=n, n_bob_inputs=n)
    diff_bits = [c.XOR(c.alice_input_wires[i], c.bob_input_wires[i])
                 for i in range(n)]
    # OR-reduce diff_bits
    or_acc = diff_bits[0]
    for i in range(1, n):
        or_acc = c.OR(or_acc, diff_bits[i])
    out = c.NOT(or_acc)
    c.set_outputs([out])
    return c


def bit_add_circuit(n: int) -> Circuit:
    """
    n-bit ripple-carry adder (mod 2^n). Returns sum bits low-to-high.

    For each bit i:  s_i = a_i XOR b_i XOR carry_in
                     carry_out = (a_i AND b_i) XOR (carry_in AND (a_i XOR b_i))
    """
    c = Circuit(n_alice_inputs=n, n_bob_inputs=n)
    sum_bits = []
    carry = c.CONST(0)
    for i in range(n):
        a = c.alice_input_wires[i]
        b = c.bob_input_wires[i]
        ab_xor = c.XOR(a, b)
        s_i = c.XOR(ab_xor, carry)
        sum_bits.append(s_i)
        # Compute next carry
        ab_and = c.AND(a, b)
        carry_and = c.AND(carry, ab_xor)
        carry = c.XOR(ab_and, carry_and)
    c.set_outputs(sum_bits)
    return c


def millionaires_circuit(n: int) -> Circuit:
    """
    Millionaire's problem: n-bit comparison x > y.

    Standard approach: compute (x - y) mod 2^{n+1}; the high bit determines
    sign. We instead compute the comparison directly via:

      x > y  iff  there exists an i (highest where x_i != y_i) such that
                  x_i = 1 and y_i = 0.

    For inputs given LSB-first, process from MSB down:
      gt = 0; eq = 1
      for i = n-1 downto 0:
        bit_gt = x_i AND (NOT y_i)
        bit_eq = NOT (x_i XOR y_i)
        gt = gt OR (eq AND bit_gt)
        eq = eq AND bit_eq
      output: gt
    """
    c = Circuit(n_alice_inputs=n, n_bob_inputs=n)
    gt = c.CONST(0)
    eq = c.CONST(1)
    for i in range(n - 1, -1, -1):
        a = c.alice_input_wires[i]
        b = c.bob_input_wires[i]
        not_b = c.NOT(b)
        bit_gt = c.AND(a, not_b)
        bit_eq = c.NOT(c.XOR(a, b))
        eq_and_gt = c.AND(eq, bit_gt)
        gt = c.OR(gt, eq_and_gt)
        eq = c.AND(eq, bit_eq)
    c.set_outputs([gt])
    return c
