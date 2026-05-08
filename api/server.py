"""
Flask backend for the PA#0 React web app.

Exposes endpoints for every PA's interactive demo, plus the clique routing
endpoints that power the foundation/source/target dropdowns.

Start with:  python -m api.server
The frontend (frontend/) connects to http://localhost:5000 by default.
"""
from flask import Flask, request, jsonify
from flask_cors import CORS

from crypto_core.common.trace import StepTrace
from routing.reducer import reduce, describe_chain


def create_app():
    app = Flask(__name__)
    CORS(app)

    # ------------ Health and metadata ------------

    @app.route("/api/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/api/clique")
    def clique():
        from routing.clique_graph import EDGES, PRIMITIVES
        return jsonify({
            "primitives": PRIMITIVES,
            "edges": [
                {"src": e.src, "dst": e.dst, "theorem": e.theorem,
                 "pa": e.pa_number, "direction": e.direction,
                 "claim": e.security_claim}
                for e in EDGES
            ],
        })

    @app.route("/api/reduce", methods=["POST"])
    def reduce_endpoint():
        data = request.get_json(force=True)
        A = data["from"]; B = data["to"]
        direction = data.get("direction", "forward")
        chain = reduce(A, B, direction=direction)
        if chain is None:
            return jsonify({"path": None, "summary": "(no path found)"})
        return jsonify({
            "path": [
                {"src": e.src, "dst": e.dst, "theorem": e.theorem,
                 "pa": e.pa_number, "direction": e.direction,
                 "claim": e.security_claim}
                for e in chain
            ],
            "summary": describe_chain(chain),
        })

    # ------------ PA#1: PRG ------------

    @app.route("/api/pa1/prg", methods=["POST"])
    def pa1_prg():
        from crypto_core.foundation.dlp_foundation import DLPFoundation
        from crypto_core.minicrypt.prg import (
            HILLPRG, monobit_frequency_test, runs_test, serial_test_lite,
        )
        data = request.get_json(force=True)
        seed_hex = data.get("seed", "00" * 16)
        out_bytes = int(data.get("output_bytes", 32))
        bits = int(data.get("bits", 80))
        seed = bytes.fromhex(seed_hex)
        f = DLPFoundation(bits=bits)
        prg = HILLPRG(f.as_owp())
        prg.seed(seed)
        trace = StepTrace()
        out = prg.next_bits(out_bytes, trace=trace)
        long_out = HILLPRG(f.as_owp())
        long_out.seed(seed)
        sample = long_out.next_bits(max(out_bytes, 64))
        p_freq, ok_freq = monobit_frequency_test(sample)
        p_runs, ok_runs = runs_test(sample)
        chi, ok_serial = serial_test_lite(sample)
        return jsonify({
            "output_hex": out.hex(),
            "trace": trace.to_json(),
            "tests": {
                "monobit_frequency": {"p_value": p_freq, "passed": ok_freq},
                "runs": {"p_value": p_runs, "passed": ok_runs},
                "serial_chi": {"chi": chi, "passed": ok_serial},
            },
        })

    # ------------ PA#2: GGM PRF ------------

    @app.route("/api/pa2/ggm", methods=["POST"])
    def pa2_ggm():
        from crypto_core.foundation.dlp_foundation import DLPFoundation
        from crypto_core.minicrypt.prg import HILLPRG
        from crypto_core.minicrypt.prf_ggm import GGMTreePRF
        data = request.get_json(force=True)
        key_hex = data.get("key", "00" * 16)
        x_int = int(data.get("x", 0))
        input_bits = int(data.get("input_bits", 4))
        key = bytes.fromhex(key_hex)[:16].ljust(16, b"\x00")
        f = DLPFoundation(bits=80)
        prg = HILLPRG(f.as_owp())
        prf = GGMTreePRF(prg, input_bits=input_bits, key_bytes=16)
        trace = StepTrace()
        out = prf.evaluate(key, x_int.to_bytes(16, "big"), trace=trace)
        return jsonify({"output_hex": out.hex(), "trace": trace.to_json()})

    # ------------ PA#3: CPA ------------

    @app.route("/api/pa3/cpa", methods=["POST"])
    def pa3_cpa():
        from crypto_core.foundation.aes_foundation import AESFoundation
        from crypto_core.minicrypt.cpa_enc import CPAEncryption
        data = request.get_json(force=True)
        key = bytes.fromhex(data.get("key", "00" * 16))
        m = data.get("message", "hello").encode("utf-8")
        cpa = CPAEncryption(AESFoundation().as_prf())
        trace = StepTrace()
        r, c = cpa.encrypt(key, m, trace=trace)
        recovered = cpa.decrypt(key, (r, c))
        return jsonify({
            "r_hex": r.hex(), "c_hex": c.hex(),
            "recovered": recovered.decode("utf-8", errors="replace"),
            "trace": trace.to_json(),
        })

    # ------------ PA#4: modes ------------

    @app.route("/api/pa4/modes", methods=["POST"])
    def pa4_modes():
        from crypto_core.foundation.aes_foundation import AESFoundation
        from crypto_core.minicrypt.modes import CBC, OFB, CTR
        data = request.get_json(force=True)
        mode = data.get("mode", "CBC")
        key = bytes.fromhex(data.get("key", "00" * 16))
        m = data.get("message", "Hello, world!").encode("utf-8")
        aes = AESFoundation()
        prp, prf = aes.as_prp(), aes.as_prf()
        trace = StepTrace()
        if mode == "CBC":
            iv, c = CBC(prp).encrypt(key, m, trace=trace)
            recovered = CBC(prp).decrypt(key, (iv, c))
        elif mode == "OFB":
            iv, c = OFB(prf).encrypt(key, m, trace=trace)
            recovered = OFB(prf).decrypt(key, (iv, c))
        elif mode == "CTR":
            iv, c = CTR(prf).encrypt(key, m, trace=trace)
            recovered = CTR(prf).decrypt(key, (iv, c))
        else:
            return jsonify({"error": f"unknown mode {mode}"}), 400
        return jsonify({
            "iv_hex": iv.hex(), "c_hex": c.hex(),
            "recovered": recovered.decode("utf-8", errors="replace"),
            "trace": trace.to_json(),
        })

    # ------------ PA#5: MAC ------------

    @app.route("/api/pa5/mac", methods=["POST"])
    def pa5_mac():
        from crypto_core.foundation.aes_foundation import AESFoundation
        from crypto_core.minicrypt.mac import PRFMAC, CBCMAC
        data = request.get_json(force=True)
        kind = data.get("kind", "CBCMAC")
        key = bytes.fromhex(data.get("key", "00" * 16))
        m = data.get("message", "auth me").encode("utf-8")
        aes = AESFoundation()
        if kind == "PRFMAC":
            mac = PRFMAC(aes.as_prf())
            target = m[:16].ljust(16, b"\x00")
        else:
            mac = CBCMAC(aes.as_prp())
            target = m
        trace = StepTrace()
        t = mac.mac(key, target, trace=trace)
        return jsonify({"tag_hex": t.hex(),
                        "verify": mac.verify(key, target, t),
                        "trace": trace.to_json()})

    # ------------ PA#6: CCA ------------

    @app.route("/api/pa6/cca", methods=["POST"])
    def pa6_cca():
        from crypto_core.foundation.aes_foundation import AESFoundation
        from crypto_core.minicrypt.cpa_enc import CPAEncryption
        from crypto_core.minicrypt.mac import CBCMAC
        from crypto_core.minicrypt.cca_enc import EncryptThenMAC
        from crypto_core.common.exceptions import MacVerificationFailure
        data = request.get_json(force=True)
        k_E = bytes.fromhex(data.get("k_E", "11" * 16))
        k_M = bytes.fromhex(data.get("k_M", "22" * 16))
        m = data.get("message", "secret").encode("utf-8")
        tamper = bool(data.get("tamper", False))
        aes = AESFoundation()
        cca = EncryptThenMAC(CPAEncryption(aes.as_prf()), CBCMAC(aes.as_prp()))
        trace = StepTrace()
        ct = cca.encrypt((k_E, k_M), m, trace=trace)
        if tamper:
            (r, c), t = ct
            tampered_c = bytes([c[0] ^ 0xff]) + c[1:]
            ct = ((r, tampered_c), t)
        try:
            recovered = cca.decrypt((k_E, k_M), ct, trace=trace)
            return jsonify({"recovered": recovered.decode("utf-8", errors="replace"),
                            "rejected": False, "trace": trace.to_json()})
        except MacVerificationFailure:
            return jsonify({"recovered": None, "rejected": True,
                            "trace": trace.to_json()})

    # ------------ PA#7: Merkle-Damgard ------------

    @app.route("/api/pa7/md", methods=["POST"])
    def pa7_md():
        from crypto_core.hashing.merkle_damgard import MerkleDamgard, XorToyCompression
        data = request.get_json(force=True)
        m = data.get("message", "hello").encode("utf-8")
        block_size = int(data.get("block_size", 16))
        out_size = int(data.get("output_size", 8))
        toy = XorToyCompression(output_size=out_size, block_size=block_size)
        md = MerkleDamgard(toy, b"\x00" * out_size, block_size, out_size)
        trace = StepTrace()
        d = md.digest(m, trace=trace)
        return jsonify({"digest_hex": d.hex(), "trace": trace.to_json()})

    # ------------ PA#8: DLP hash ------------

    @app.route("/api/pa8/hash", methods=["POST"])
    def pa8_hash():
        from crypto_core.hashing.dlp_hash import DLPHash
        data = request.get_json(force=True)
        m = data.get("message", "hello").encode("utf-8")
        bits = int(data.get("bits", 80))
        h = DLPHash(bits=bits)
        trace = StepTrace()
        d = h.digest(m, trace=trace)
        return jsonify({"digest_hex": d.hex(), "trace": trace.to_json()})

    # ------------ PA#9: birthday ------------

    @app.route("/api/pa9/birthday", methods=["POST"])
    def pa9_birthday():
        from crypto_core.hashing.dlp_hash import DLPHash
        from crypto_core.hashing.birthday import birthday_attack_naive
        data = request.get_json(force=True)
        n_bits = int(data.get("n_bits", 16))
        bits = int(data.get("dlp_bits", 80))
        n_bytes = max(1, n_bits // 8)
        h = DLPHash(bits=bits, truncate_to=n_bytes)
        result = birthday_attack_naive(h.digest, input_bytes=8, max_queries=100_000)
        if result is None:
            return jsonify({"found": False, "queries": 100_000})
        return jsonify({"found": True,
                        "x1_hex": result["x1"].hex(),
                        "x2_hex": result["x2"].hex(),
                        "h_hex": result["h"].hex(),
                        "queries": result["queries"],
                        "expected_2_to_n_over_2": 2 ** (n_bits // 2)})

    # ------------ PA#10: HMAC ------------

    @app.route("/api/pa10/hmac", methods=["POST"])
    def pa10_hmac():
        from crypto_core.hashing.dlp_hash import DLPHash
        from crypto_core.hashing.hmac import HMAC
        data = request.get_json(force=True)
        k = bytes.fromhex(data.get("key", "00" * 16))
        m = data.get("message", "hi").encode("utf-8")
        hm = HMAC(DLPHash(bits=80))
        trace = StepTrace()
        t = hm.mac(k, m, trace=trace)
        return jsonify({"tag_hex": t.hex(),
                        "verify": hm.verify(k, m, t),
                        "trace": trace.to_json()})

    # ------------ PA#11: DH ------------

    @app.route("/api/pa11/dh", methods=["POST"])
    def pa11_dh():
        from crypto_core.pubkey.diffie_hellman import DiffieHellman, MITMAdversary
        data = request.get_json(force=True)
        bits = int(data.get("bits", 128))
        mitm = bool(data.get("mitm", False))
        dh = DiffieHellman(bits=bits)
        a, A = dh.alice_step1()
        b, B = dh.bob_step1()
        if not mitm:
            return jsonify({"p": dh.p, "g": dh.g, "A": A, "B": B,
                            "K_alice": dh.alice_step2(a, B),
                            "K_bob": dh.bob_step2(b, A)})
        eve = MITMAdversary(dh)
        A_fake = eve.intercept_alice(A)
        B_fake = eve.intercept_bob(B)
        return jsonify({
            "p": dh.p, "g": dh.g,
            "K_alice": dh.alice_step2(a, B_fake),
            "K_bob": dh.bob_step2(b, A_fake),
            "K_eve_alice": eve.shared_with_alice(),
            "K_eve_bob": eve.shared_with_bob(),
        })

    # ------------ PA#12: RSA ------------

    @app.route("/api/pa12/rsa", methods=["POST"])
    def pa12_rsa():
        from crypto_core.pubkey.rsa import RSA, PKCS1v15
        from crypto_core.pubkey.rsa_attacks import determinism_demo
        data = request.get_json(force=True)
        bits = int(data.get("bits", 512))
        m = data.get("message", "hi").encode("utf-8")
        mode = data.get("mode", "textbook")
        rsa = RSA(bits=bits)
        pk, sk = rsa.keygen()
        if mode == "pkcs":
            pkcs = PKCS1v15(rsa)
            c1 = pkcs.encrypt(pk, m); c2 = pkcs.encrypt(pk, m)
            return jsonify({"N": pk.N, "e": pk.e, "c1": c1, "c2": c2,
                            "different": c1 != c2,
                            "recovered": pkcs.decrypt(sk, c1).decode("utf-8", errors="replace")})
        res = determinism_demo(rsa, pk, m, n_trials=3)
        return jsonify({"N": pk.N, "e": pk.e,
                        "ciphertexts": [int(c) for c in res["ciphertexts"]],
                        "all_identical": res["all_identical"]})

    # ------------ PA#13: Miller-Rabin ------------

    @app.route("/api/pa13/miller_rabin", methods=["POST"])
    def pa13_mr():
        from crypto_core.number_theory.miller_rabin import miller_rabin, fermat_test
        data = request.get_json(force=True)
        n = int(data.get("n", 561))
        rounds = int(data.get("rounds", 20))
        return jsonify({"n": n,
                        "miller_rabin": miller_rabin(n, rounds),
                        "fermat": fermat_test(n, rounds),
                        "is_carmichael_561_demo": (n == 561)})

    # ------------ PA#14: Hastad ------------

    @app.route("/api/pa14/hastad", methods=["POST"])
    def pa14_hastad():
        from crypto_core.pubkey.rsa import RSA
        from crypto_core.pubkey.rsa_attacks import hastad_broadcast_attack
        from crypto_core.number_theory.modular import mod_pow
        data = request.get_json(force=True)
        m_int = int(data.get("m", 0x1234))
        e = 3
        keys = []
        for _ in range(3):
            while True:
                rsa = RSA(bits=256, e=e)
                try:
                    pk, _ = rsa.keygen()
                    keys.append(pk); break
                except Exception:
                    continue
        cts = [mod_pow(m_int, e, k.N) for k in keys]
        moduli = [k.N for k in keys]
        result = hastad_broadcast_attack(cts, moduli, e)
        return jsonify({"recovered_m": result["recovered_m"],
                        "is_perfect_root": result["is_perfect_root"],
                        "moduli": moduli, "ciphertexts": cts,
                        "match_original": result["recovered_m"] == m_int})

    # ------------ PA#15: signatures ------------

    @app.route("/api/pa15/sign", methods=["POST"])
    def pa15_sign():
        from crypto_core.pubkey.rsa import RSA
        from crypto_core.pubkey.signatures import RSASignature
        from crypto_core.hashing.dlp_hash import DLPHash
        data = request.get_json(force=True)
        m = data.get("message", "I agree").encode("utf-8")
        tamper = bool(data.get("tamper", False))
        sig = RSASignature(RSA(bits=512), DLPHash(bits=80))
        vk, sk = sig.keygen()
        sigma = sig.sign(sk, m)
        check = m + b"!" if tamper else m
        return jsonify({"sigma": sigma,
                        "verify": sig.verify(vk, check, sigma),
                        "tamper": tamper})

    # ------------ PA#16: ElGamal ------------

    @app.route("/api/pa16/elgamal", methods=["POST"])
    def pa16_eg():
        from crypto_core.pubkey.elgamal import ElGamal, elgamal_malleability_attack
        data = request.get_json(force=True)
        m_int = int(data.get("m", 42))
        k_mult = int(data.get("multiplier", 3))
        eg = ElGamal(bits=128)
        pk, sk = eg.keygen()
        ct = eg.encrypt(pk, m_int)
        c_attacked = elgamal_malleability_attack(ct, k_mult, pk.p)
        return jsonify({"p": pk.p,
                        "ct": list(ct),
                        "recovered": eg.decrypt(sk, ct),
                        "malleability": {
                            "multiplier": k_mult,
                            "attacked_ct": list(c_attacked),
                            "decrypts_to": eg.decrypt(sk, c_attacked),
                            "expected": (k_mult * m_int) % pk.p,
                        }})

    # ------------ PA#17: Signcryption ------------

    @app.route("/api/pa17/signcrypt", methods=["POST"])
    def pa17_sc():
        from crypto_core.pubkey.rsa import RSA
        from crypto_core.pubkey.signatures import RSASignature
        from crypto_core.pubkey.elgamal import ElGamal
        from crypto_core.pubkey.cca_pkc import Signcryption
        from crypto_core.hashing.dlp_hash import DLPHash
        from crypto_core.common.exceptions import MacVerificationFailure
        data = request.get_json(force=True)
        m_int = int(data.get("m", 12345))
        tamper = bool(data.get("tamper", False))
        sig = RSASignature(RSA(bits=512), DLPHash(bits=80))
        sc = Signcryption(ElGamal(bits=128), sig)
        (pk_combined, sk_combined) = sc.keygen()
        vk_sig, sk_sig = sig.keygen()
        ct = sc.encrypt(pk_combined, m_int.to_bytes(8, "big"),
                        sender_sk_sig=sk_sig)
        if tamper:
            (c1, c2), sigma = ct
            ct = ((c1, (c2 * 2) % pk_combined[0].p), sigma)
        try:
            r = sc.decrypt(sk_combined, ct, sender_vk_sig=vk_sig)
            return jsonify({"recovered": int.from_bytes(r, "big"),
                            "rejected": False})
        except MacVerificationFailure:
            return jsonify({"recovered": None, "rejected": True})

    # ------------ PA#18: OT ------------

    @app.route("/api/pa18/ot", methods=["POST"])
    def pa18_ot():
        from crypto_core.foundation.dlp_foundation import DLPFoundation
        from crypto_core.mpc.ot import run_ot
        data = request.get_json(force=True)
        b = int(data.get("b", 0))
        m0 = int(data.get("m0", 11))
        m1 = int(data.get("m1", 22))
        out = run_ot(DLPFoundation(bits=128), b, m0, m1)
        return jsonify({"received": out, "expected": m0 if b == 0 else m1})

    # ------------ PA#19: secure AND ------------

    @app.route("/api/pa19/and", methods=["POST"])
    def pa19_and():
        from crypto_core.foundation.dlp_foundation import DLPFoundation
        from crypto_core.mpc.secure_gates import secure_and
        data = request.get_json(force=True)
        a = int(data.get("a", 0)) & 1
        b = int(data.get("b", 0)) & 1
        return jsonify({"a": a, "b": b,
                        "result": secure_and(a, b, DLPFoundation(bits=128)),
                        "expected": a & b})

    # ------------ PA#20: MPC ------------

    @app.route("/api/pa20/mpc", methods=["POST"])
    def pa20_mpc():
        from crypto_core.foundation.dlp_foundation import DLPFoundation
        from crypto_core.mpc.circuit import (
            equality_circuit, bit_add_circuit, millionaires_circuit, secure_eval,
        )
        data = request.get_json(force=True)
        circuit_name = data.get("circuit", "millionaires")
        n = int(data.get("n", 4))
        x_int = int(data.get("x", 7))
        y_int = int(data.get("y", 12))
        x_bits = [(x_int >> i) & 1 for i in range(n)]
        y_bits = [(y_int >> i) & 1 for i in range(n)]
        c = {"millionaires": millionaires_circuit,
             "equality": equality_circuit,
             "bit_add": bit_add_circuit}[circuit_name](n)
        out, stats = secure_eval(c, x_bits, y_bits, DLPFoundation(bits=128))
        return jsonify({
            "circuit": circuit_name, "x": x_int, "y": y_int,
            "out_bits": out,
            "result": sum(b << i for i, b in enumerate(out)),
            "and_gates": stats["and_gates"],
            "total_gates": stats["total_gates"],
        })

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5000, debug=True)
