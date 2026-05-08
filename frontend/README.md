# PA#0 — Minicrypt Clique Web Explorer (frontend)

Vite + React app for the PA#0 deliverable.

## Run

In one terminal, start the Python backend:
```bash
cd ..
python -m api.server
```

In another terminal, start the dev server:
```bash
npm install
npm run dev
```

Then open http://localhost:3000.

## Layout

The app implements the PA#0 three-tier layout from the spec:

1. **Top bar** — Foundation toggle (AES-128 / DLP) and direction toggle.
2. **Two-column main area:**
   - Column 1 — Build source primitive A from foundation. Each step is logged
     and shown in the trace.
   - Column 2 — Reduce source A to target primitive B. Receives A as a black box.
3. **Bottom proof panel** — Shows the formal reduction chain
   (Foundation → A → B), theorem citations (HILL, GGM, Luby-Rackoff, etc.),
   and the security claim at each step.

The dropdowns let the student pick any pair (A, B). The clique routing
endpoint at `/api/reduce` computes the shortest chain through the graph.

## Data flow

All cryptographic computation runs on the Python backend. The frontend is
purely UI: it sends parameters via `fetch('/api/...')` and renders the JSON
response (including the StepTrace from `crypto_core.common.trace`).

This keeps the architectural rule intact: the React side never re-implements
any primitive — it only displays values produced by your own implementations.
