import { useState, useEffect } from 'react'

const PRIMITIVES = [
  'OWF', 'OWP', 'PRG', 'PRF', 'PRP',
  'MAC', 'CRHF', 'HMAC',
  'CPA-Enc', 'CCA-Enc',
  'PKC', 'DigitalSig', 'CCA-PKC',
  'OT', 'SecureAND', 'MPC',
]

// Map each primitive to the PA endpoint that demonstrates it.
const PA_ENDPOINTS = {
  'OWF':       { name: 'PA#1 - DLP OWP',     path: '/api/pa1/owp',     pa: 1 },
  'OWP':       { name: 'PA#1 - DLP OWP',     path: '/api/pa1/owp',     pa: 1 },
  'PRG':       { name: 'PA#1 - PRG (HILL)',  path: '/api/pa1/prg',     pa: 1 },
  'PRF':       { name: 'PA#2 - GGM tree',    path: '/api/pa2/ggm',     pa: 2 },
  'PRP':       { name: 'PA#4 - modes',       path: '/api/pa4/modes',   pa: 4 },
  'CPA-Enc':   { name: 'PA#3 - CPA-Enc',     path: '/api/pa3/cpa',     pa: 3 },
  'MAC':       { name: 'PA#5 - MAC',         path: '/api/pa5/mac',     pa: 5 },
  'CCA-Enc':   { name: 'PA#6 - CCA-Enc',     path: '/api/pa6/cca',     pa: 6 },
  'CRHF':      { name: 'PA#8 - DLP hash',    path: '/api/pa8/hash',    pa: 8 },
  'HMAC':      { name: 'PA#10 - HMAC',       path: '/api/pa10/hmac',   pa: 10 },
  'PKC':       { name: 'PA#12 - RSA',        path: '/api/pa12/rsa',    pa: 12 },
  'DigitalSig':{ name: 'PA#15 - signatures', path: '/api/pa15/sign',   pa: 15 },
  'CCA-PKC':   { name: 'PA#17 - signcrypt',  path: '/api/pa17/signcrypt', pa: 17 },
  'OT':        { name: 'PA#18 - OT',         path: '/api/pa18/ot',     pa: 18 },
  'SecureAND': { name: 'PA#19 - secure AND', path: '/api/pa19/and',    pa: 19 },
  'MPC':       { name: 'PA#20 - MPC',        path: '/api/pa20/mpc',    pa: 20 },
}

function defaultPayload(foundation) {
  return {
    foundation,
    seed: '00112233445566778899aabbccddeeff',
    output_bytes: 32,
    key: '00112233445566778899aabbccddeeff',
    message: 'hello world',
    bits: 80,
  }
}

async function postJson(path, payload) {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  const data = await resp.json()
  if (!resp.ok) {
    throw new Error(data?.error || `${path} failed with HTTP ${resp.status}`)
  }
  return data
}

function hex(bytes) {
  if (bytes == null) return ''
  return String(bytes)
}

function StepTrace({ steps }) {
  if (!steps || steps.length === 0) return null
  return (
    <div className="trace">
      <h3>Step trace</h3>
      <ol>
        {steps.map((s, i) => (
          <li key={i}>
            <div className="step-name">{s.name}</div>
            {s.theorem && <div className="step-theorem">[{s.theorem}, PA#{s.pa_number}]</div>}
            <div className="step-io">
              <strong>in:</strong>{' '}
              {Object.entries(s.inputs).map(([k, v]) => (
                <span key={k}><code>{k}</code>={hex(v).slice(0, 60)}{hex(v).length > 60 ? '…' : ''} </span>
              ))}
            </div>
            <div className="step-io">
              <strong>out:</strong>{' '}
              {Object.entries(s.outputs).map(([k, v]) => (
                <span key={k}><code>{k}</code>={hex(v).slice(0, 60)}{hex(v).length > 60 ? '…' : ''} </span>
              ))}
            </div>
          </li>
        ))}
      </ol>
    </div>
  )
}

function ColumnBuild({ foundation, primA, output, onUpdate }) {
  const [seedHex, setSeedHex] = useState('00112233445566778899aabbccddeeff')
  const [outBytes, setOutBytes] = useState(32)

  async function run() {
    const ep = PA_ENDPOINTS[primA]
    if (!ep || !ep.path) {
      onUpdate({ note: `${primA}: no demo endpoint (foundation-direct view)` })
      return
    }
    try {
      const data = await postJson(ep.path, {
        ...defaultPayload(foundation),
        seed: seedHex,
        key: seedHex,
        output_bytes: parseInt(outBytes),
      })
      onUpdate(data)
    } catch (e) {
      onUpdate({ error: String(e) })
    }
  }

  return (
    <div className="column">
      <h2>Column 1: Build {primA}</h2>
      <p className="subtitle">Foundation → {primA} ({foundation})</p>
      <div className="form">
        <label>Seed/Key (hex)</label>
        <input value={seedHex} onChange={(e) => setSeedHex(e.target.value)} />
        <label>Output bytes</label>
        <input type="number" value={outBytes} onChange={(e) => setOutBytes(e.target.value)} />
        <button onClick={run}>Build</button>
      </div>
      {output && <pre className="result">{JSON.stringify(output, null, 2).slice(0, 2000)}</pre>}
      {output?.trace && <StepTrace steps={output.trace} />}
    </div>
  )
}

function ColumnReduce({ foundation, primA, primB, chain, buildOutput, output, onUpdate }) {
  async function run() {
    if (!chain) {
      onUpdate({ error: 'Reduction chain has not loaded yet' })
      return
    }
    if (!chain.path) {
      onUpdate({ chain, demos: [], note: 'No reducer path is available for this pair' })
      return
    }
    try {
      const demos = []
      if (chain.path.length === 0) {
        const ep = PA_ENDPOINTS[primB]
        if (ep?.path) {
          demos.push({ primitive: primB, endpoint: ep.path, result: await postJson(ep.path, defaultPayload(foundation)) })
        }
      } else {
        for (const edge of chain.path) {
          const ep = PA_ENDPOINTS[edge.dst]
          if (!ep?.path) {
            demos.push({ primitive: edge.dst, skipped: true, reason: 'No demo endpoint' })
            continue
          }
          const result = await postJson(ep.path, {
            ...defaultPayload(foundation),
            source: primA,
            target: primB,
            theorem: edge.theorem,
            black_box_from_column_1: buildOutput ? 'available' : 'not_built',
          })
          demos.push({ primitive: edge.dst, theorem: edge.theorem, endpoint: ep.path, result })
        }
      }
      onUpdate({ chain, black_box_input: buildOutput || null, demos })
    } catch (e) {
      onUpdate({ error: String(e) })
    }
  }

  return (
    <div className="column">
      <h2>Column 2: Reduce to {primB}</h2>
      <p className="subtitle">{primA} → {primB}</p>
      <button onClick={run}>Reduce</button>
      {output && <pre className="result">{JSON.stringify(output, null, 2).slice(0, 2000)}</pre>}
      {output?.trace && <StepTrace steps={output.trace} />}
    </div>
  )
}

function ProofPanel({ chain }) {
  if (!chain) return null
  return (
    <div className="proof">
      <h3>Reduction chain summary</h3>
      <p>{chain.summary}</p>
      {chain.path && (
        <ol>
          {chain.path.map((edge, i) => (
            <li key={i}>
              <strong>{edge.src} → {edge.dst}</strong> via {edge.theorem} (PA#{edge.pa})
              <div className="claim">{edge.claim}</div>
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

export default function App() {
  const [foundation, setFoundation] = useState('AES')
  const [primA, setPrimA] = useState('PRG')
  const [primB, setPrimB] = useState('PRF')
  const [direction, setDirection] = useState('forward')
  const [build1, setBuild1] = useState(null)
  const [build2, setBuild2] = useState(null)
  const [chain, setChain] = useState(null)

  useEffect(() => {
    fetch('/api/reduce', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: primA, to: primB, direction }),
    })
      .then((r) => r.json())
      .then(setChain)
      .catch(() => setChain({ path: null, summary: '(server unreachable)' }))
  }, [primA, primB, direction])

  return (
    <div className="app">
      <header>
        <h1>CS8.401 Minicrypt Clique Explorer</h1>
        <div className="controls">
          <label>
            Foundation:
            <select value={foundation} onChange={(e) => setFoundation(e.target.value)}>
              <option value="AES">AES-128 (PRP)</option>
              <option value="DLP">DLP (g^x mod p)</option>
            </select>
          </label>
          <label>
            Direction:
            <select value={direction} onChange={(e) => setDirection(e.target.value)}>
              <option value="forward">Forward (A → B)</option>
              <option value="any">Any (allow B → A)</option>
            </select>
          </label>
        </div>
      </header>

      <main>
        <div className="dropdowns">
          <label>
            Source A:
            <select value={primA} onChange={(e) => setPrimA(e.target.value)}>
              {PRIMITIVES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
          <label>
            Target B:
            <select value={primB} onChange={(e) => setPrimB(e.target.value)}>
              {PRIMITIVES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
        </div>

        <div className="columns">
          <ColumnBuild
            foundation={foundation}
            primA={primA}
            output={build1}
            onUpdate={setBuild1}
          />
          <ColumnReduce
            foundation={foundation}
            primA={primA}
            primB={primB}
            chain={chain}
            buildOutput={build1}
            output={build2}
            onUpdate={setBuild2}
          />
        </div>

        <ProofPanel chain={chain} />
      </main>

      <footer>
        <small>
          PA#0 web explorer — backend: <code>localhost:5000</code>.
          All intermediate values are real outputs from the PA#1–#20 implementations.
        </small>
      </footer>
    </div>
  )
}
