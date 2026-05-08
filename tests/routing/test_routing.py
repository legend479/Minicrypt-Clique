"""Tests for the clique routing graph."""
from routing.clique_graph import EDGES, PRIMITIVES
from routing.reducer import reduce, describe_chain


def test_edges_reference_known_primitives():
    for e in EDGES:
        assert e.src in PRIMITIVES, f"edge src {e.src} not in PRIMITIVES"
        assert e.dst in PRIMITIVES, f"edge dst {e.dst} not in PRIMITIVES"


def test_reduce_owf_to_prf():
    """A canonical multi-step path."""
    chain = reduce("OWF", "PRF", direction="forward")
    assert chain is not None
    # Final destination must be PRF
    assert chain[-1].dst == "PRF"


def test_reduce_prg_to_prf_one_step():
    chain = reduce("PRG", "PRF", direction="forward")
    assert len(chain) == 1
    assert chain[0].theorem.startswith("GGM")


def test_reduce_self_is_empty():
    chain = reduce("OWF", "OWF")
    assert chain == []


def test_describe_chain_runs():
    chain = reduce("PRF", "MAC", direction="forward")
    s = describe_chain(chain)
    assert "MAC" in s


def test_no_path_for_disjoint_primitives_returns_none_or_chain():
    # OT to OWF (going backwards through clique) under forward-only direction
    # may not exist; should not crash.
    chain = reduce("MPC", "OWF", direction="forward")
    # forward only -> probably None
    assert chain is None or all(e.direction == "forward" for e in chain)
