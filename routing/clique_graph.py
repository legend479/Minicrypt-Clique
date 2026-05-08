"""
The Minicrypt clique encoded as a labelled directed graph.

Each edge stores:
  - theorem name
  - PA number where it's implemented
  - direction (forward / backward)
  - security claim summary

Used by the PA#0 web app to route between any (A, B) pair and explain the
chain of reductions.
"""
from dataclasses import dataclass
from typing import Dict, List, Tuple


# Primitive nodes
PRIMITIVES = [
    "OWF", "OWP", "PRG", "PRF", "PRP",
    "MAC", "CRHF", "HMAC",
    "CPA-Enc", "CCA-Enc",
    "PKC", "DigitalSig", "CCA-PKC",
    "OT", "SecureAND", "MPC",
]


@dataclass
class Edge:
    src: str
    dst: str
    theorem: str
    pa_number: int
    direction: str        # "forward" or "backward"
    security_claim: str


# All known reductions in the clique (forward) and their backward partners.
EDGES: List[Edge] = [
    # OWF <-> PRG  (PA#1)
    Edge("OWF", "PRG", "HILL hard-core-bit construction", 1, "forward",
         "PRG security reduces to OWF + hard-core bit"),
    Edge("PRG", "OWF", "Trivial: f(s) = G(s)", 1, "backward",
         "Inverting f recovers the seed, breaking pseudorandomness"),

    # OWF <-> OWP
    Edge("OWF", "OWP", "DLP is already a OWP on Z_q", 1, "forward",
         "DLP foundation gives OWP directly"),
    Edge("OWP", "OWF", "Trivial inclusion", 1, "backward",
         "OWP is a special case of OWF"),

    # PRG <-> PRF (PA#2)
    Edge("PRG", "PRF", "GGM tree", 2, "forward",
         "Tree of length-doubling PRG calls; GGM thm"),
    Edge("PRF", "PRG", "G(s) = F_s(0) || F_s(1)", 2, "backward",
         "Distinguishing G implies distinguishing F"),

    # OWP -> PRG (HILL one-bit-per-app)
    Edge("OWP", "PRG", "HILL hard-core-bit (Blum-Micali for OWP)", 1, "forward",
         "PRG security ~ DLP hardness"),

    # PRF <-> PRP (Luby-Rackoff)
    Edge("PRF", "PRP", "Luby-Rackoff Feistel network", 2, "forward",
         "3-round Feistel = PRP, 4-round = strong PRP"),
    Edge("PRP", "PRF", "PRP/PRF switching lemma", 2, "backward",
         "PRP indistinguishable from PRF for poly-many queries"),

    # PRF -> MAC (PA#5)
    Edge("PRF", "MAC", "Mac_k(m) = F_k(m)", 5, "forward",
         "MAC EUF-CMA reduces to PRF security"),
    Edge("MAC", "PRF", "MAC on uniform inputs is a PRF", 5, "backward",
         "Distinguish MAC from random implies forgery"),

    # PRP -> MAC (via PRF)
    Edge("PRP", "MAC", "PRP -> PRF (switching lemma) -> MAC", 5, "forward",
         "Composition through PRF"),

    # CRHF <-> HMAC (PA#10)
    Edge("CRHF", "HMAC", "HMAC construction over hash", 10, "forward",
         "Inner+outer hash with key XOR"),
    Edge("HMAC", "CRHF", "HMAC-as-compression in MD", 10, "backward",
         "Fixed-key HMAC plugs into Merkle-Damgard"),

    # HMAC -> MAC
    Edge("HMAC", "MAC", "HMAC IS a MAC", 10, "forward",
         "EUF-CMA from PRF property of compression"),
    Edge("MAC", "HMAC", "Recast MAC in HMAC structure", 10, "backward",
         "Treat MAC as inner compression step"),

    # CRHF <-> MAC (via HMAC)
    Edge("CRHF", "MAC", "CRHF -> HMAC -> MAC", 10, "forward",
         "Two-step composition"),
    Edge("MAC", "CRHF", "MAC as compression in MD", 10, "backward",
         "Collision in MD -> collision in MAC -> forgery"),

    # CPA-Enc and CCA-Enc
    Edge("PRF", "CPA-Enc", "Enc(k,m) = (r, F_k(r) XOR m)", 3, "forward",
         "CPA security from PRF + fresh nonce"),
    Edge("CPA-Enc", "CCA-Enc", "Encrypt-then-MAC", 6, "forward",
         "CPA + EUF-CMA -> CCA2"),

    # Public key (Cryptomania)
    Edge("OWP", "PKC", "RSA / ElGamal trapdoor structure", 12, "forward",
         "Factoring or DDH gives trapdoor"),
    Edge("PKC", "DigitalSig", "Hash-then-sign", 15, "forward",
         "EUF-CMA from CRHF + RSA"),
    Edge("PKC", "CCA-PKC", "Encrypt-then-Sign (signcryption)", 17, "forward",
         "CCA2 from CPA-PKC + EUF-CMA Sig"),

    # MPC
    Edge("PKC", "OT", "Bellare-Micali OT", 18, "forward",
         "OT from PKC's IND-CPA security"),
    Edge("OT", "SecureAND", "AND from OT (m_0=0, m_1=a)", 19, "forward",
         "Receiver gets a*b only"),
    Edge("SecureAND", "MPC", "Yao / GMW: AND + XOR completes", 20, "forward",
         "All boolean circuits"),
]


def adjacency() -> Dict[str, List[Edge]]:
    """Build outgoing-edge adjacency map."""
    adj: Dict[str, List[Edge]] = {p: [] for p in PRIMITIVES}
    for e in EDGES:
        adj.setdefault(e.src, []).append(e)
    return adj
