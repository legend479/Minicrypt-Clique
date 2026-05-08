import { useEffect, useMemo, useRef, useState } from 'react'

const FALLBACK_PRIMITIVES = [
  'OWF', 'OWP', 'PRG', 'PRF', 'PRP',
  'MAC', 'CRHF', 'HMAC',
  'CPA-Enc', 'CCA-Enc',
  'PKC', 'DigitalSig', 'CCA-PKC',
  'OT', 'SecureAND', 'MPC',
]

// Legacy primitive-to-demo map kept as an explicit reducer contract.
const PA_ENDPOINTS = {
  'OWF': { name: 'PA#1 - DLP OWP', path: '/api/pa1/owp', pa: 1 },
  'OWP': { name: 'PA#1 - DLP OWP', path: '/api/pa1/owp', pa: 1 },
  'PRG': { name: 'PA#1 - PRG (HILL)', path: '/api/pa1/prg', pa: 1 },
  'PRF': { name: 'PA#2 - GGM tree', path: '/api/pa2/ggm', pa: 2 },
  'PRP': { name: 'PA#4 - modes', path: '/api/pa4/modes', pa: 4 },
  'CPA-Enc': { name: 'PA#3 - CPA-Enc', path: '/api/pa3/cpa', pa: 3 },
  'MAC': { name: 'PA#5 - MAC', path: '/api/pa5/mac', pa: 5 },
  'CCA-Enc': { name: 'PA#6 - CCA-Enc', path: '/api/pa6/cca', pa: 6 },
  'CRHF': { name: 'PA#8 - DLP hash', path: '/api/pa8/hash', pa: 8 },
  'HMAC': { name: 'PA#10 - HMAC', path: '/api/pa10/hmac', pa: 10 },
  'PKC': { name: 'PA#12 - RSA', path: '/api/pa12/rsa', pa: 12 },
  'DigitalSig': { name: 'PA#15 - signatures', path: '/api/pa15/sign', pa: 15 },
  'CCA-PKC': { name: 'PA#17 - signcrypt', path: '/api/pa17/signcrypt', pa: 17 },
  'OT': { name: 'PA#18 - OT', path: '/api/pa18/ot', pa: 18 },
  'SecureAND': { name: 'PA#19 - secure AND', path: '/api/pa19/and', pa: 19 },
  'MPC': { name: 'PA#20 - MPC', path: '/api/pa20/mpc', pa: 20 },
}

const GUIDED_PRESETS = [
  {
    id: 'minicrypt-chain',
    shortTitle: 'Minicrypt',
    title: 'Minicrypt Chain',
    pathLabel: 'OWF → PRG → PRF → PRP → MAC',
    from: 'OWF',
    to: 'MAC',
    foundation: 'DLP',
    direction: 'forward',
    demoIds: ['pa1-owp', 'pa1-prg', 'pa2-ggm', 'pa4-modes', 'pa5-mac'],
    hint: 'One-wayness becomes pseudorandomness, permutations, and authentication.',
  },
  {
    id: 'encryption-hardening',
    shortTitle: 'CCA',
    title: 'Encryption Hardening',
    pathLabel: 'PRF → CPA-Enc → CCA-Enc',
    from: 'PRF',
    to: 'CCA-Enc',
    foundation: 'AES',
    direction: 'forward',
    demoIds: ['pa2-ggm', 'pa3-cpa', 'pa6-cca'],
    hint: 'Run this to see tampering rejected by authentication.',
  },
  {
    id: 'hash-auth',
    shortTitle: 'Hash/MAC',
    title: 'Hash/Auth Path',
    pathLabel: 'CRHF → HMAC → MAC',
    from: 'CRHF',
    to: 'MAC',
    foundation: 'DLP',
    direction: 'forward',
    demoIds: ['pa8-hash', 'pa10-hmac', 'pa5-mac', 'pa9-birthday'],
    hint: 'Collision resistance, keyed hashing, and the birthday bound in one pass.',
  },
  {
    id: 'public-key',
    shortTitle: 'PKC',
    title: 'Public-Key Path',
    pathLabel: 'OWP → PKC → DigitalSig → CCA-PKC',
    from: 'OWP',
    to: 'CCA-PKC',
    foundation: 'DLP',
    direction: 'forward',
    demoIds: ['pa1-owp', 'pa12-rsa', 'pa15-sign', 'pa17-signcrypt'],
    hint: 'Trapdoors, signatures, and public-key tamper rejection.',
  },
  {
    id: 'mpc-stack',
    shortTitle: 'MPC',
    title: 'MPC Stack',
    pathLabel: 'PKC → OT → SecureAND → MPC',
    from: 'PKC',
    to: 'MPC',
    foundation: 'DLP',
    direction: 'forward',
    demoIds: ['pa12-rsa', 'pa18-ot', 'pa19-and', 'pa20-mpc'],
    hint: 'Public-key assumptions lift into secure two-party computation.',
  },
]

const CATEGORY_ORDER = ['Minicrypt', 'Hashing', 'Public Key', 'MPC', 'Attack', 'Number Theory']

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

async function getJson(path) {
  const resp = await fetch(path)
  const data = await resp.json()
  if (!resp.ok) {
    throw new Error(data?.error || `${path} failed with HTTP ${resp.status}`)
  }
  return data
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

function shortText(value, max = 42) {
  if (value == null) return 'none'
  const text = String(value)
  return text.length > max ? `${text.slice(0, max)}...` : text
}

function describeValue(value) {
  if (value == null) return 'none'
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (typeof value === 'number') return String(value)
  if (typeof value === 'string') return shortText(value, 64)
  if (Array.isArray(value)) return value.slice(0, 3).map((item) => shortText(item, 24)).join(' / ')
  if (typeof value === 'object') {
    return Object.entries(value)
      .slice(0, 3)
      .map(([key, item]) => `${key}: ${shortText(item, 28)}`)
      .join(' | ')
  }
  return shortText(value, 64)
}

function fieldLabel(field) {
  return field
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function theoremLabel(theorem = '') {
  const compact = theorem
    .replace('HILL hard-core-bit construction', 'HILL')
    .replace('HILL hard-core-bit (Blum-Micali for OWP)', 'HILL')
    .replace('Luby-Rackoff Feistel network', 'Luby-Rackoff')
    .replace('PRP/PRF switching lemma', 'Switching')
    .replace('Encrypt-then-MAC', 'EtM')
    .replace('Mac_k(m) = F_k(m)', 'PRF-MAC')
    .replace('Hash-then-sign', 'Hash-sign')
    .replace('Bellare-Micali OT', 'BM OT')
  return shortText(compact, 22)
}

function statusFor(demo, result) {
  if (!result) return { label: 'Ready', tone: 'neutral' }
  if (result.error) return { label: 'Error', tone: 'bad' }
  if (result.rejected) return { label: 'Rejected', tone: 'good' }
  if (result.verify === false) return { label: 'Tamper failed', tone: 'good' }
  if (result.found) return { label: 'Collision found', tone: 'bad' }
  if (result.K_eve_alice || result.K_eve_bob) return { label: 'MITM active', tone: 'bad' }
  if (result.match_original || result.all_identical || result.malleability) return { label: 'Attack works', tone: 'bad' }
  if (result.mac_verify || result.prp_round_trip) return { label: 'Built', tone: 'good' }
  if (result.different || result.verify === true) return { label: 'Verified', tone: 'good' }
  if (demo?.tags?.includes('attack')) return { label: 'Attack', tone: 'bad' }
  return { label: 'OK', tone: 'good' }
}

function formatResult(demo, result) {
  if (!result) return []
  if (result.error) return [{ label: 'Error', value: result.error, copy: result.error }]

  const preferred = [
    'rejected', 'verify', 'recovered', 'result', 'output_hex', 'digest_hex', 'tag_hex',
    'found', 'queries', 'expected_2_to_n_over_2', 'match_original', 'different',
    'all_identical', 'K_alice', 'K_bob', 'K_eve_alice', 'K_eve_bob',
    'built', 'owf_output', 'prg_output_hex', 'prf_output_hex', 'prp_round_trip',
    'mac_tag_hex', 'mac_verify', 'and_gates', 'total_gates', 'malleability',
  ]
  const fields = [...new Set([...(demo?.result_fields || []), ...preferred])]
  return fields
    .filter((field) => Object.prototype.hasOwnProperty.call(result, field))
    .slice(0, 6)
    .map((field) => ({
      label: fieldLabel(field),
      value: describeValue(result[field]),
      copy: describeValue(result[field]),
    }))
}

function isInteractiveDemo(demo) {
  return (demo?.controls || []).length > 0
}

function isAttackDemo(demo) {
  return demo?.tags?.includes('attack') || demo?.tags?.includes('hardening')
}

function Hint({ text, children }) {
  return (
    <span className="hint" tabIndex="0">
      {children || '?'}
      <span className="hint-bubble">{text}</span>
    </span>
  )
}

function Pill({ children, tone = 'neutral', hint }) {
  const pill = <span className={`pill pill-${tone}`}>{children}</span>
  return hint ? <Hint text={hint}>{pill}</Hint> : pill
}

function CopyButton({ value }) {
  if (!value) return null
  return (
    <Hint text="Copy value">
      <button
        type="button"
        className="copy-button"
        onClick={() => navigator.clipboard?.writeText(value)}
        aria-label="Copy value"
      >
        copy
      </button>
    </Hint>
  )
}

function TraceTimeline({ steps }) {
  if (!steps || steps.length === 0) return null
  return (
    <details className="trace" open={steps.length <= 3}>
      <summary>Trace <span>{steps.length}</span></summary>
      <div className="trace-rows">
        {steps.slice(0, 8).map((step, index) => (
          <div className="trace-row" key={`${step.name}-${index}`}>
            <strong>{shortText(step.name, 28)}</strong>
            <Pill tone="accent" hint={step.theorem || `PA#${step.pa_number}`}>
              PA#{step.pa_number || '-'}
            </Pill>
            <code>{describeValue(step.outputs || step.inputs || {})}</code>
          </div>
        ))}
      </div>
    </details>
  )
}

function EvidenceCard({ demo, result, label }) {
  if (!result) return null
  const status = statusFor(demo, result)
  const rows = formatResult(demo, result)
  return (
    <section className="evidence-card">
      <div className="card-head">
        <div>
          <span className="micro">PA#{demo?.pa || '-'} · {demo?.primitive || label}</span>
          <h3>{label || demo?.title}</h3>
        </div>
        <Pill tone={status.tone} hint={demo?.claim}>{status.label}</Pill>
      </div>
      <div className="evidence-rows">
        {rows.map((row) => (
          <div className="evidence-row" key={row.label}>
            <span>{row.label}</span>
            <code>{row.value}</code>
            <CopyButton value={row.copy} />
          </div>
        ))}
      </div>
      <TraceTimeline steps={result.trace} />
    </section>
  )
}

function ErrorBanner({ message }) {
  if (!message) return null
  return <div className="error-banner">{message}</div>
}

function buildLineage(chain, fallbackFrom, fallbackTo) {
  if (!chain?.path) return { nodes: [fallbackFrom, fallbackTo].filter(Boolean), edges: [] }
  if (chain.path.length === 0) return { nodes: [fallbackFrom || fallbackTo].filter(Boolean), edges: [] }
  const nodes = [chain.path[0].src]
  for (const edge of chain.path) nodes.push(edge.dst)
  return { nodes, edges: chain.path }
}

function LineageRail({ chain, from, to, active }) {
  const { nodes, edges } = buildLineage(chain, from, to)
  if (!nodes.length) return <section className="lineage empty">No path</section>
  return (
    <section className="lineage">
      <div className="section-head">
        <h2>Lineage</h2>
        <Pill hint="Shortest path returned by /api/reduce">
          {edges.length ? `${edges.length} hops` : 'identity'}
        </Pill>
      </div>
      <div className="lineage-rail" aria-label="Reduction lineage">
        {nodes.map((node, index) => {
          const edge = edges[index]
          return (
            <div className="lineage-step" key={`${node}-${index}`}>
              <div className={`node ${active ? 'active' : ''}`}>{node}</div>
              {edge && (
                <div className="edge">
                  <div className="connector" />
                  <Hint text={`${edge.theorem}. ${edge.claim}`}>
                    <span className="theorem-chip">{theoremLabel(edge.theorem)}</span>
                  </Hint>
                  <Pill tone={edge.direction === 'forward' ? 'good' : 'accent'} hint={edge.claim}>
                    PA#{edge.pa}
                  </Pill>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </section>
  )
}

function ControlInput({ control, value, onChange }) {
  if (control.type === 'boolean') {
    return (
      <label className="check-row">
        <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
        <span>{control.label}</span>
        <Hint text="Toggle the demo condition" />
      </label>
    )
  }
  if (control.type === 'select') {
    return (
      <label>
        {control.label}
        <select value={value} onChange={(e) => onChange(normalizeControlValue(e.target.value, control))}>
          {control.options.map((option) => <option key={option} value={option}>{String(option)}</option>)}
        </select>
      </label>
    )
  }
  return (
    <label>
      {control.label}
      <input
        type={control.type === 'number' ? 'number' : 'text'}
        min={control.min}
        max={control.max}
        value={value ?? ''}
        onChange={(e) => onChange(normalizeControlValue(e.target.value, control))}
      />
    </label>
  )
}

function normalizeControlValue(value, control) {
  if (control.type === 'number') return Number(value)
  if (control.type === 'select' && control.options?.every((option) => typeof option === 'number')) return Number(value)
  return value
}

function DemoRunnerTile({ demo, payload, result, busy, onPayloadChange, onRun, expanded = false }) {
  const controls = demo.controls || []
  const showControls = expanded || controls.length <= 3
  return (
    <section className={`demo-tile ${isAttackDemo(demo) ? 'interactive-tile' : ''}`}>
      <div className="tile-head">
        <span className="micro">PA#{demo.pa}</span>
        <Pill tone={demo.tags.includes('attack') ? 'bad' : demo.tags.includes('hardening') ? 'good' : 'neutral'} hint={demo.claim}>
          {demo.primitive}
        </Pill>
      </div>
      <h3>{demo.title}</h3>
      {controls.length > 0 && showControls && (
        <div className="mini-form visible">
          {controls.map((control) => (
            <ControlInput
              key={control.name}
              control={control}
              value={payload[control.name]}
              onChange={(value) => onPayloadChange(demo, control.name, value)}
            />
          ))}
        </div>
      )}
      <div className="tile-actions">
        <button type="button" onClick={() => onRun(demo)} disabled={busy}>
          {busy ? 'Running' : 'Run'}
        </button>
        {controls.length > 3 && !expanded && (
          <details>
            <summary>Inputs</summary>
            <div className="mini-form">
              {controls.map((control) => (
                <ControlInput
                  key={control.name}
                  control={control}
                  value={payload[control.name]}
                  onChange={(value) => onPayloadChange(demo, control.name, value)}
                />
              ))}
            </div>
          </details>
        )}
      </div>
      <EvidenceCard demo={demo} result={result} label={demo.title} />
    </section>
  )
}

function PresetRail({ selectedId, onSelect }) {
  return (
    <aside className="preset-rail">
      <span className="micro">Paths</span>
      {GUIDED_PRESETS.map((preset) => (
        <button
          type="button"
          key={preset.id}
          className={preset.id === selectedId ? 'selected' : ''}
          onClick={() => onSelect(preset.id)}
        >
          <strong>{preset.shortTitle}</strong>
          <small>{preset.pathLabel}</small>
          <Hint text={preset.hint} />
        </button>
      ))}
    </aside>
  )
}

function PanelTabs({ activePanel, onChange }) {
  const tabs = [
    ['guided', 'Guided'],
    ['custom-owf', 'Custom OWF'],
    ['attacks', 'Attacks'],
    ['catalog', 'Catalog'],
    ['custom-path', 'Custom Path'],
  ]
  return (
    <nav className="panel-tabs" aria-label="Demo panels">
      {tabs.map(([id, label]) => (
        <button
          type="button"
          key={id}
          className={activePanel === id ? 'selected' : ''}
          onClick={() => onChange(id)}
        >
          {label}
        </button>
      ))}
    </nav>
  )
}

function CustomPath({ primitives, state, setters, onRun, busy, expanded = false }) {
  const { foundation, primA, primB, direction } = state
  const content = (
      <div className="custom-grid">
        <label>
          Foundation
          <select value={foundation} onChange={(e) => setters.setFoundation(e.target.value)}>
            <option value="AES">AES-128</option>
            <option value="DLP">DLP</option>
          </select>
        </label>
        <label>
          From
          <select value={primA} onChange={(e) => setters.setPrimA(e.target.value)}>
            {primitives.map((primitive) => <option key={primitive} value={primitive}>{primitive}</option>)}
          </select>
        </label>
        <label>
          To
          <select value={primB} onChange={(e) => setters.setPrimB(e.target.value)}>
            {primitives.map((primitive) => <option key={primitive} value={primitive}>{primitive}</option>)}
          </select>
        </label>
        <label>
          Direction <Hint text="Forward follows construction arrows; any can use reverse reductions." />
          <select value={direction} onChange={(e) => setters.setDirection(e.target.value)}>
            <option value="forward">Forward</option>
            <option value="any">Any</option>
          </select>
        </label>
        <button type="button" onClick={onRun} disabled={busy}>Run</button>
      </div>
  )
  if (expanded) {
    return (
      <section className="custom-path custom-path-panel">
        <div className="section-head">
          <h2>Custom path</h2>
          <Pill hint="Pick any source and target primitive, then run the reducer.">Reducer</Pill>
        </div>
        {content}
      </section>
    )
  }
  return (
    <details className="custom-path">
      <summary>Custom path</summary>
      {content}
    </details>
  )
}

function CustomOWFWorkspace({ demo, payload, result, busy, onPayloadChange, onRun }) {
  if (!demo) return null
  const core = ['name', 'kind', 'domain_bits', 'a', 'b', 'c', 'xor_mask', 'hc_bit']
  const run = ['seed', 'output_bytes', 'input_bits', 'prf_input', 'message']
  const controls = new Map((demo.controls || []).map((control) => [control.name, control]))
  return (
    <section className="custom-owf">
      <div className="section-head">
        <div>
          <h2>Custom OWF</h2>
          <code>OWF → PRG → PRF → PRP → MAC</code>
        </div>
        <Pill tone="accent" hint="Define a bounded deterministic map that implements the OWF interface.">
          Foundation
        </Pill>
      </div>
      <div className="owf-grid">
        <div className="owf-controls">
          <span className="micro">Map</span>
          <div className="mini-form visible">
            {core.map((name) => controls.get(name)).filter(Boolean).map((control) => (
              <ControlInput
                key={control.name}
                control={control}
                value={payload[control.name]}
                onChange={(value) => onPayloadChange(demo, control.name, value)}
              />
            ))}
          </div>
          <details>
            <summary>Run inputs</summary>
            <div className="mini-form">
              {run.map((name) => controls.get(name)).filter(Boolean).map((control) => (
                <ControlInput
                  key={control.name}
                  control={control}
                  value={payload[control.name]}
                  onChange={(value) => onPayloadChange(demo, control.name, value)}
                />
              ))}
            </div>
          </details>
          <button type="button" className="primary-action" onClick={() => onRun(demo)} disabled={busy}>
            {busy ? 'Building' : 'Use foundation'}
          </button>
        </div>
        <EvidenceCard demo={demo} result={result} label="Custom OWF build" />
        {!result && <div className="empty-panel">Tune the map, then build.</div>}
      </div>
    </section>
  )
}

function useDemoRunner() {
  const [payloads, setPayloads] = useState({})
  const [results, setResults] = useState({})
  const [busyId, setBusyId] = useState('')

  function payloadFor(demo) {
    return payloads[demo.id] || demo.default_payload || {}
  }

  function setPayloadField(demo, name, value) {
    setPayloads((current) => ({
      ...current,
      [demo.id]: { ...payloadFor(demo), [name]: value },
    }))
  }

  async function runDemo(demo) {
    setBusyId(demo.id)
    try {
      const data = await postJson(demo.path, payloadFor(demo))
      setResults((current) => ({ ...current, [demo.id]: data }))
    } catch (err) {
      setResults((current) => ({ ...current, [demo.id]: { error: String(err) } }))
    } finally {
      setBusyId('')
    }
  }

  return { payloadFor, setPayloadField, runDemo, results, busyId }
}

function AttackLab({ catalog }) {
  const demos = catalog.filter((demo) => isAttackDemo(demo) && isInteractiveDemo(demo))
  const { payloadFor, setPayloadField, runDemo, results, busyId } = useDemoRunner()

  if (demos.length === 0) return null
  return (
    <section className="attack-lab">
      <div className="section-head">
        <h2>Interactive attacks</h2>
        <Pill tone="bad" hint="Edit inputs, toggle tamper/MITM modes, then rerun.">
          {demos.length} demos
        </Pill>
      </div>
      <div className="demo-grid attack-grid">
        {demos.map((demo) => (
          <DemoRunnerTile
            key={demo.id}
            demo={demo}
            payload={payloadFor(demo)}
            result={results[demo.id]}
            busy={busyId === demo.id}
            onPayloadChange={setPayloadField}
            onRun={runDemo}
            expanded
          />
        ))}
      </div>
    </section>
  )
}

function AllDemos({ catalog }) {
  const [filter, setFilter] = useState('All')
  const { payloadFor, setPayloadField, runDemo, results, busyId } = useDemoRunner()
  const categories = useMemo(() => ['All', ...CATEGORY_ORDER.filter((cat) => catalog.some((demo) => demo.category === cat))], [catalog])
  const visibleCatalog = catalog.filter((demo) => filter === 'All' || demo.category === filter)

  return (
    <section className="all-demos">
      <div className="section-head">
        <h2>All demos</h2>
        <div className="filter-row">
          {categories.map((category) => (
            <button
              type="button"
              key={category}
              className={filter === category ? 'selected' : ''}
              onClick={() => setFilter(category)}
            >
              {category}
            </button>
          ))}
        </div>
      </div>
      <div className="demo-grid">
        {visibleCatalog.map((demo) => (
          <DemoRunnerTile
            key={demo.id}
            demo={demo}
            payload={payloadFor(demo)}
            result={results[demo.id]}
            busy={busyId === demo.id}
            onPayloadChange={setPayloadField}
            onRun={runDemo}
            expanded={isAttackDemo(demo)}
          />
        ))}
      </div>
    </section>
  )
}

function DemoBoard({ catalog, catalogById, catalogByPrimitive, primitives, health, loadError }) {
  const [activePanel, setActivePanel] = useState('guided')
  const [selectedId, setSelectedId] = useState(GUIDED_PRESETS[0].id)
  const [chain, setChain] = useState(null)
  const [evidence, setEvidence] = useState([])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [foundation, setFoundation] = useState('AES')
  const [primA, setPrimA] = useState('PRG')
  const [primB, setPrimB] = useState('PRF')
  const [direction, setDirection] = useState('forward')
  const customRunner = useDemoRunner()
  const didAutoRun = useRef(false)
  const preset = GUIDED_PRESETS.find((item) => item.id === selectedId) || GUIDED_PRESETS[0]
  const customOWFDemo = catalogById.get('custom-owf-chain')

  async function runPreset(nextPreset = preset) {
    setBusy(true)
    setError('')
    setEvidence([])
    try {
      const nextChain = await postJson('/api/reduce', {
        from: nextPreset.from,
        to: nextPreset.to,
        direction: nextPreset.direction,
      })
      setChain(nextChain)
      const nextEvidence = []
      for (const demoId of nextPreset.demoIds) {
        const demo = catalogById.get(demoId)
        if (!demo) continue
        const data = await postJson(demo.path, {
          ...demo.default_payload,
          foundation: demo.default_payload?.foundation || nextPreset.foundation,
        })
        nextEvidence.push({ demo, result: data })
      }
      setEvidence(nextEvidence)
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  async function runCustom() {
    setBusy(true)
    setError('')
    setEvidence([])
    try {
      const nextChain = await postJson('/api/reduce', { from: primA, to: primB, direction })
      setChain(nextChain)
      const customEvidence = []
      const sourceEndpoint = PA_ENDPOINTS[primA]
      let sourceResult = null
      if (sourceEndpoint?.path) {
        sourceResult = await postJson(sourceEndpoint.path, defaultPayload(foundation))
        customEvidence.push({
          demo: catalogByPrimitive.get(primA) || sourceEndpoint,
          result: sourceResult,
        })
      }

      if (nextChain.path) {
        const edges = nextChain.path.length === 0 ? [{ dst: primB, theorem: 'identity' }] : nextChain.path
        for (const edge of edges) {
          const endpoint = PA_ENDPOINTS[edge.dst]
          if (!endpoint?.path) continue
          const result = await postJson(endpoint.path, {
            ...defaultPayload(foundation),
            source: primA,
            target: primB,
            theorem: edge.theorem,
            black_box_from_column_1: sourceResult ? 'available' : 'not_built',
          })
          customEvidence.push({
            demo: catalogByPrimitive.get(edge.dst) || endpoint,
            result,
          })
        }
      }
      setEvidence(customEvidence)
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  async function runCustomOWF(demo) {
    setBusy(true)
    setError('')
    setEvidence([])
    try {
      const nextChain = await postJson('/api/reduce', { from: 'OWF', to: 'MAC', direction: 'forward' })
      setChain(nextChain)
      await customRunner.runDemo(demo)
    } catch (err) {
      setError(String(err))
    } finally {
      setBusy(false)
    }
  }

  function reset() {
    setChain(null)
    setEvidence([])
    setError('')
  }

  function choosePreset(id) {
    const nextPreset = GUIDED_PRESETS.find((item) => item.id === id)
    setSelectedId(id)
    if (nextPreset) runPreset(nextPreset)
  }

  useEffect(() => {
    if (catalog.length > 0 && !didAutoRun.current) {
      didAutoRun.current = true
      runPreset(preset)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [catalog.length])

  return (
    <main className="demo-board">
      <section className="run-panel">
        <div className="topbar">
          <div>
            <span className="micro">CS8.401 PA#0</span>
            <h1>Minicrypt Clique</h1>
          </div>
          <div className="status-strip">
            <Pill tone={health === 'ok' ? 'good' : health === 'error' ? 'bad' : 'neutral'} hint="Flask API health">
              API {health}
            </Pill>
            <Pill hint="Runnable catalog entries">{catalog.length} demos</Pill>
          </div>
        </div>

        <PanelTabs activePanel={activePanel} onChange={setActivePanel} />
        <ErrorBanner message={loadError || error} />

        {activePanel === 'guided' && (
          <section className="panel-surface guided-panel">
            <PresetRail selectedId={selectedId} onSelect={choosePreset} />
            <div className="guided-workspace">
              <section className="run-hero">
                <div>
                  <h2>{preset.shortTitle}</h2>
                  <code>{preset.pathLabel}</code>
                </div>
                <div className="run-actions">
                  <button type="button" className="primary-action" onClick={() => runPreset()} disabled={busy}>
                    {busy ? 'Running' : 'Run'}
                  </button>
                  <button type="button" onClick={reset}>Reset</button>
                </div>
              </section>

              <LineageRail chain={chain} from={preset.from} to={preset.to} active={evidence.length > 0} />

              <section className="evidence">
                <div className="section-head">
                  <h2>Evidence</h2>
                  <Pill hint="Formatted backend outputs; no raw JSON is displayed">
                    {evidence.length || 0} cards
                  </Pill>
                </div>
                {evidence.length === 0 && <div className="empty-panel">Run a path.</div>}
                <div className="evidence-grid">
                  {evidence.map(({ demo, result }, index) => (
                    <EvidenceCard
                      key={`${demo?.id || demo?.path}-${index}`}
                      demo={demo}
                      result={result}
                      label={demo?.title || demo?.name}
                    />
                  ))}
                </div>
              </section>
            </div>
          </section>
        )}

        {activePanel === 'custom-owf' && (
          <section className="panel-surface">
            <LineageRail chain={chain} from="OWF" to="MAC" active={Boolean(customOWFDemo && customRunner.results[customOWFDemo.id])} />
            <CustomOWFWorkspace
              demo={customOWFDemo}
              payload={customOWFDemo ? customRunner.payloadFor(customOWFDemo) : {}}
              result={customOWFDemo ? customRunner.results[customOWFDemo.id] : null}
              busy={busy || customRunner.busyId === customOWFDemo?.id}
              onPayloadChange={customRunner.setPayloadField}
              onRun={runCustomOWF}
            />
          </section>
        )}

        {activePanel === 'attacks' && (
          <section className="panel-surface">
            <AttackLab catalog={catalog} />
          </section>
        )}

        {activePanel === 'catalog' && (
          <section className="panel-surface">
            <AllDemos catalog={catalog} />
          </section>
        )}

        {activePanel === 'custom-path' && (
          <section className="panel-surface">
            <CustomPath
              primitives={primitives}
              state={{ foundation, primA, primB, direction }}
              setters={{ setFoundation, setPrimA, setPrimB, setDirection }}
              onRun={runCustom}
              busy={busy}
              expanded
            />
            <LineageRail chain={chain} from={primA} to={primB} active={evidence.length > 0} />
            <section className="evidence">
              <div className="section-head">
                <h2>Evidence</h2>
                <Pill hint="Outputs from the selected custom reduction.">{evidence.length || 0} cards</Pill>
              </div>
              {evidence.length === 0 && <div className="empty-panel">Run a custom path.</div>}
              <div className="evidence-grid">
                {evidence.map(({ demo, result }, index) => (
                  <EvidenceCard
                    key={`${demo?.id || demo?.path}-${index}`}
                    demo={demo}
                    result={result}
                    label={demo?.title || demo?.name}
                  />
                ))}
              </div>
            </section>
          </section>
        )}
      </section>
    </main>
  )
}

export default function App() {
  const [health, setHealth] = useState('checking')
  const [catalog, setCatalog] = useState([])
  const [clique, setClique] = useState({ primitives: FALLBACK_PRIMITIVES, edges: [] })
  const [loadError, setLoadError] = useState('')

  useEffect(() => {
    getJson('/api/health')
      .then(() => setHealth('ok'))
      .catch(() => setHealth('error'))

    getJson('/api/catalog')
      .then((data) => setCatalog(data.demos || []))
      .catch((err) => setLoadError(String(err)))

    getJson('/api/clique')
      .then(setClique)
      .catch(() => setClique({ primitives: FALLBACK_PRIMITIVES, edges: [] }))
  }, [])

  const catalogById = useMemo(() => new Map(catalog.map((demo) => [demo.id, demo])), [catalog])
  const catalogByPrimitive = useMemo(() => {
    const map = new Map()
    for (const demo of catalog) {
      if (!map.has(demo.primitive)) map.set(demo.primitive, demo)
    }
    return map
  }, [catalog])

  return (
    <DemoBoard
      catalog={catalog}
      catalogById={catalogById}
      catalogByPrimitive={catalogByPrimitive}
      primitives={clique.primitives || FALLBACK_PRIMITIVES}
      health={health}
      loadError={loadError}
    />
  )
}
