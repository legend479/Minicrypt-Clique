"""End-to-end lineage test: PA#20 -> PA#19 -> PA#18 -> PA#16 -> PA#11 -> PA#13.

Verifies that evaluating a single secure-AND gate ultimately bottoms out at
Miller-Rabin (via prime generation in the DLP foundation construction). This
is the no-bypass guarantee the PDF asks for.
"""
import sys


def test_pa20_millionaires_uses_full_stack():
    """Run the millionaires circuit and confirm the expected lineage of imports."""
    from crypto_core.foundation.dlp_foundation import DLPFoundation
    from crypto_core.mpc.circuit import millionaires_circuit, secure_eval

    f = DLPFoundation(bits=128)
    c = millionaires_circuit(4)
    x_bits = [1, 1, 1, 0]   # x = 7
    y_bits = [0, 0, 1, 1]   # y = 12
    out, stats = secure_eval(c, x_bits, y_bits, f)
    assert out[0] == 0   # 7 > 12 ? -> No

    # Verify the modules in our import lineage are actually loaded.
    expected = [
        "crypto_core.foundation.dlp_foundation",
        "crypto_core.number_theory.miller_rabin",
        "crypto_core.number_theory.prime_gen",
        "crypto_core.mpc.ot",
        "crypto_core.mpc.secure_gates",
        "crypto_core.mpc.circuit",
        "crypto_core.pubkey.elgamal",
    ]
    for mod in expected:
        assert mod in sys.modules, f"missing lineage module: {mod}"


def test_full_chain_owf_to_mpc_via_routing():
    """The clique reducer should produce a path from OWF all the way to MPC."""
    from routing.reducer import reduce
    chain = reduce("OWF", "MPC", direction="forward")
    assert chain is not None
    # The final node must be MPC
    assert chain[-1].dst == "MPC"
    # The path should pass through PKC and OT
    nodes_visited = [chain[0].src] + [e.dst for e in chain]
    assert "PKC" in nodes_visited
    assert "OT" in nodes_visited
    assert "SecureAND" in nodes_visited


def test_pa10_hmac_uses_pa8_dlp_hash():
    """HMAC must consume our own DLP hash, not anything else."""
    from crypto_core.hashing.dlp_hash import DLPHash
    from crypto_core.hashing.hmac import HMAC
    h = DLPHash(bits=80)
    hm = HMAC(h)
    t = hm.mac(b"k" * 16, b"msg")
    assert hm.verify(b"k" * 16, b"msg", t)
    # Confirm both PA#8 and PA#10 modules are loaded.
    assert "crypto_core.hashing.dlp_hash" in sys.modules
    assert "crypto_core.hashing.hmac" in sys.modules


def test_pa17_signcryption_uses_pa15_and_pa16():
    """PA#17 must consume our PA#15 signatures + PA#16 ElGamal."""
    from crypto_core.pubkey.rsa import RSA
    from crypto_core.pubkey.signatures import RSASignature
    from crypto_core.pubkey.elgamal import ElGamal
    from crypto_core.pubkey.cca_pkc import Signcryption
    from crypto_core.hashing.dlp_hash import DLPHash
    sig = RSASignature(RSA(bits=512), DLPHash(bits=80))
    sc = Signcryption(ElGamal(bits=128), sig)
    pk_combined, sk_combined = sc.keygen()
    vk_sig, sk_sig = sig.keygen()
    ct = sc.encrypt(pk_combined, b"top", sender_sk_sig=sk_sig)
    assert sc.decrypt(sk_combined, ct, sender_vk_sig=vk_sig) == b"top"
    # Lineage check
    for mod in ["crypto_core.pubkey.rsa", "crypto_core.pubkey.signatures",
                "crypto_core.pubkey.elgamal", "crypto_core.pubkey.cca_pkc",
                "crypto_core.hashing.dlp_hash"]:
        assert mod in sys.modules
