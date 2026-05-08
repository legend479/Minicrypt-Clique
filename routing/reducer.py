"""
Reducer: given primitives A and B and a foundation, return the chain of
reduction steps to convert A into B.

This is what powers the PA#0 web app's routing table.
"""
from typing import List, Optional
from collections import deque
from routing.clique_graph import EDGES, Edge, adjacency


def reduce(A: str, B: str, foundation: str = "AES",
           direction: str = "forward") -> Optional[List[Edge]]:
    """
    Find a shortest path from A to B in the clique graph (BFS).

    direction: "forward" (default) uses only forward edges; "any" allows
    backward edges (for the bidirectional toggle).

    Returns a list of Edges, or None if no path exists.
    """
    adj = adjacency()
    if A not in adj or B not in adj:
        return None
    if A == B:
        return []

    # BFS
    queue = deque([(A, [])])
    visited = {A}
    while queue:
        node, path = queue.popleft()
        for e in adj.get(node, []):
            if direction == "forward" and e.direction != "forward":
                continue
            new_path = path + [e]
            if e.dst == B:
                return new_path
            if e.dst not in visited:
                visited.add(e.dst)
                queue.append((e.dst, new_path))
    return None


def describe_chain(chain: List[Edge]) -> str:
    """Pretty-print a reduction chain for the proof panel."""
    if chain is None:
        return "(no reduction path found)"
    if len(chain) == 0:
        return "(identity: A = B)"
    parts = [chain[0].src]
    for e in chain:
        parts.append(f"-- {e.theorem} (PA#{e.pa_number}) -->  {e.dst}")
    return "  ".join(parts)
