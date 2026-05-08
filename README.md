# CS8.401: Principles of Information Security — Programming Assignments

A modular, from-scratch cryptographic codebase implementing the entire
Minicrypt → Cryptomania → MPC reduction chain. Built to the project
specification: every primitive is implemented from raw integers and
`os.urandom`, with no external cryptographic libraries.

## What's in here

| PA | Topic | Module |
|---|---|---|
| #1 | OWF + PRG (HILL) | `crypto_core/minicrypt/{owf, prg}.py` |
| #2 | PRF (GGM tree) + PRP (Luby-Rackoff) | `crypto_core/minicrypt/{prf_ggm, prp_feistel}.py` |
| #3 | CPA-secure encryption | `crypto_core/minicrypt/cpa_enc.py` |
| #4 | CBC, OFB, CTR modes | `crypto_core/minicrypt/modes.py` |
| #5 | PRF-MAC, CBC-MAC | `crypto_core/minicrypt/mac.py` |
| #6 | CCA-secure (Encrypt-then-MAC) | `crypto_core/minicrypt/cca_enc.py` |
| #7 | Merkle-Damgård | `crypto_core/hashing/merkle_damgard.py` |
| #8 | DLP-based CRHF | `crypto_core/hashing/dlp_hash.py` |
| #9 | Birthday attack | `crypto_core/hashing/birthday.py` |
| #10 | HMAC + Encrypt-then-HMAC | `crypto_core/hashing/hmac.py` |
| #11 | Diffie-Hellman + MITM demo | `crypto_core/pubkey/diffie_hellman.py` |
| #12 | RSA + PKCS#1 v1.5 | `crypto_core/pubkey/rsa.py` |
| #13 | Miller-Rabin | `crypto_core/number_theory/miller_rabin.py` |
| #14 | CRT + Garner + Håstad | `crypto_core/number_theory/crt.py` + `pubkey/rsa_attacks.py` |
| #15 | Digital signatures (RSA) | `crypto_core/pubkey/signatures.py` |
| #16 | ElGamal + malleability demo | `crypto_core/pubkey/elgamal.py` |
| #17 | CCA-secure PKC (Signcryption) | `crypto_core/pubkey/cca_pkc.py` |
| #18 | Oblivious Transfer | `crypto_core/mpc/ot.py` |
| #19 | Secure AND/XOR/NOT | `crypto_core/mpc/secure_gates.py` |
| #20 | All 2-party MPC | `crypto_core/mpc/circuit.py` |
| #0 | Web explorer | `api/` (Flask backend) + `frontend/` (React) |

## Architecture

Strict layering, enforced by `tests/test_no_libs.py`:

```
common  <  number_theory  <  foundation  <  minicrypt  <  hashing  <  pubkey  <  mpc
```

- No higher layer ever bypasses a lower one.
- Every primitive subclasses an ABC in `common/interfaces.py` and accepts
  dependencies via constructor injection.
- `os.urandom` is permitted only inside `common/randomness.py`. All other
  modules use the wrapper functions there.

## Running

### Tests

```bash
pip install -r requirements.txt
pytest -q
```

The suite has 101 tests covering every PA, the no-libs architectural rule,
the os.urandom chokepoint, FIPS-197 AES vectors, Carmichael 561, RSA-CRT
correctness, Håstad's attack, ElGamal malleability, signcryption tamper-
rejection, MPC truth tables, and end-to-end lineage from PA#20 down to PA#13.

### Backend (PA#0 explorer API)

```bash
python -m api.server
```

Serves on `http://localhost:5000`. Endpoints: `/api/health`, `/api/clique`,
`/api/reduce`, plus `/api/paN/...` for each PA.

### Frontend (PA#0 React app)

```bash
cd frontend
npm install
npm run dev
```

Opens on `http://localhost:3000` and proxies `/api` to the Python backend.

## The No-Library Rule

`tests/test_no_libs.py` greps `crypto_core/` for any forbidden import
(`Crypto`, `cryptography`, `hashlib`, `hmac`, `secrets`, etc.) and fails the
build if any is found. A second test enforces that `os.urandom` is called
only from the single chokepoint module.

## Folder structure

```
crypto_core/             core cryptographic implementations
├── common/              interfaces, bitops, randomness, trace, exceptions
├── number_theory/       modular, Miller-Rabin, CRT, integer roots
├── foundation/          AES (own impl), DLP foundation
├── minicrypt/           PA#1-#6
├── hashing/             PA#7-#10
├── pubkey/              PA#11, #12, #14-#17
└── mpc/                 PA#18-#20
routing/                 clique graph + reducer for PA#0
api/                     Flask backend exposing /api/* endpoints
frontend/                React + Vite app for the PA#0 explorer
tests/                   pytest suite (mirrors crypto_core/ + integration)
```

## What this project demonstrates

- The Minicrypt clique: every primitive (OWF, PRG, PRF, PRP, MAC, CRHF,
  HMAC) is reachable from any other via implemented reductions, with
  bidirectional reductions for the PA#1, PA#2, and PA#10 pairs.
- Cryptomania: DLP and factoring trapdoors give DH, RSA, ElGamal, signatures,
  and CCA-secure PKC.
- MPC: from oblivious transfer up to Yao-style 2-party secure computation,
  demonstrated on the Millionaire's problem, equality test, and bit-addition.
- Concrete attack demos: CPA nonce reuse, IV/keystream reuse, length
  extension, RSA determinism, Håstad broadcast, ElGamal malleability,
  DH MITM, raw-RSA homomorphism forgery, birthday attack on truncated DLP
  hash. Each demonstrates *why* the corresponding hardening exists.
