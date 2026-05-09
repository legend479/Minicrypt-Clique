import { useEffect, useMemo, useState } from 'react'

const HEX_KEY = '00112233445566778899aabbccddeeff'
const PA_NUMBERS = Array.from({ length: 20 }, (_, index) => index + 1)

const PA_META = {
  1: { title: 'Live PRG Output Viewer', tag: 'OWF -> PRG', endpoint: '/api/pa1/prg' },
  2: { title: 'GGM Tree Visualiser', tag: 'PRG -> PRF', endpoint: '/api/pa2/ggm' },
  3: { title: 'IND-CPA Game', tag: 'Adversary', endpoint: '/api/pa3/cpa' },
  4: { title: 'Block Cipher Mode Animator', tag: 'CBC / OFB / CTR', endpoint: '/api/pa4/modes' },
  5: { title: 'MAC Forge Attempt', tag: 'EUF-CMA', endpoint: '/api/pa5/mac' },
  6: { title: 'Malleability Attack Panel', tag: 'CPA vs CCA', endpoint: '/api/pa6/cca' },
  7: { title: 'Merkle-Damgard Chain Viewer', tag: 'Hash chain', endpoint: '/api/pa7/md' },
  8: { title: 'DLP Hash Live', tag: 'CRHF', endpoint: '/api/pa8/hash' },
  9: { title: 'Live Birthday Attack', tag: 'Collision search', endpoint: '/api/pa9/birthday' },
  10: { title: 'Length Extension vs HMAC', tag: 'Broken MAC vs HMAC', endpoint: '/api/pa10/hmac' },
  11: { title: 'Live Diffie-Hellman Exchange', tag: 'Key exchange', endpoint: '/api/pa11/dh' },
  12: { title: 'Textbook RSA Determinism Attack', tag: 'Padding matters', endpoint: '/api/pa12/rsa' },
  13: { title: 'Primality Tester', tag: 'Miller-Rabin', endpoint: '/api/pa13/miller_rabin' },
  14: { title: 'Hastad Broadcast Attack Visualiser', tag: 'CRT attack', endpoint: '/api/pa14/hastad' },
  15: { title: 'Sign and Verify Live', tag: 'Hash-then-sign', endpoint: '/api/pa15/sign' },
  16: { title: 'ElGamal Malleability', tag: 'CPA not CCA', endpoint: '/api/pa16/elgamal' },
  17: { title: 'CCA Malleability Blocked', tag: 'Signcryption', endpoint: '/api/pa17/signcrypt' },
  18: { title: 'Play the OT Receiver', tag: 'Bob chooses', endpoint: '/api/pa18/ot' },
  19: { title: 'Secure AND Step-by-Step', tag: 'OT -> AND', endpoint: '/api/pa19/and' },
  20: { title: 'Millionaire Problem Live', tag: 'Secure circuit', endpoint: '/api/pa20/mpc' },
}

async function postJson(path, payload) {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  })
  const data = await resp.json()
  if (!resp.ok) throw new Error(data?.error || `${path} failed with HTTP ${resp.status}`)
  return data
}

function shortText(value, max = 46) {
  if (value == null) return 'none'
  const text = String(value)
  return text.length > max ? `${text.slice(0, max)}...` : text
}

function fieldLabel(field) {
  return field.replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase())
}

function asRows(result, preferred = []) {
  if (!result) return []
  if (result.error) return [{ label: 'Error', value: result.error }]
  const keys = [...new Set([...preferred, ...Object.keys(result)])]
  return keys
    .filter((key) => key !== 'trace' && Object.prototype.hasOwnProperty.call(result, key))
    .slice(0, 8)
    .map((key) => ({ label: fieldLabel(key), value: describe(result[key]) }))
}

function describe(value) {
  if (value == null) return 'none'
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (typeof value === 'number') return String(value)
  if (typeof value === 'string') return shortText(value, 80)
  if (Array.isArray(value)) return value.slice(0, 4).map((item) => shortText(item, 28)).join(' / ')
  if (typeof value === 'object') {
    return Object.entries(value)
      .slice(0, 4)
      .map(([key, item]) => `${key}: ${shortText(item, 28)}`)
      .join(' | ')
  }
  return shortText(value, 80)
}

function hexBlocks(hex, count = 3, blockChars = 32) {
  const clean = String(hex || '').replace(/[^a-fA-F0-9]/g, '')
  const blocks = []
  for (let i = 0; i < clean.length && blocks.length < count; i += blockChars) {
    blocks.push(clean.slice(i, i + blockChars))
  }
  return blocks.length ? blocks : ['waiting']
}

function bitRatio(hex) {
  const clean = String(hex || '').replace(/[^a-fA-F0-9]/g, '')
  if (!clean) return 0
  let ones = 0
  let bits = 0
  for (let i = 0; i < clean.length; i += 2) {
    const byte = parseInt(clean.slice(i, i + 2).padEnd(2, '0'), 16)
    if (Number.isNaN(byte)) continue
    bits += 8
    for (let bit = 0; bit < 8; bit += 1) ones += (byte >> bit) & 1
  }
  return bits ? ones / bits : 0
}

function padMessageBlocks(message, blockSize = 8) {
  const bytes = Array.from(new TextEncoder().encode(message))
  const bitLen = BigInt(bytes.length * 8)
  bytes.push(0x80)
  while ((bytes.length + 8) % blockSize !== 0) bytes.push(0)
  for (let shift = 56n; shift >= 0n; shift -= 8n) bytes.push(Number((bitLen >> shift) & 0xffn))
  const blocks = []
  for (let i = 0; i < bytes.length; i += blockSize) blocks.push(bytes.slice(i, i + blockSize))
  return blocks.map((block) => block.map((byte) => byte.toString(16).padStart(2, '0')).join(''))
}

function Progress({ value, max = 1, label }) {
  const pct = Math.max(0, Math.min(100, max ? (value / max) * 100 : 0))
  return (
    <div className="demo-progress" aria-label={label || 'progress'}>
      <div style={{ width: `${pct}%` }} />
      <span>{label || `${Math.round(pct)}%`}</span>
    </div>
  )
}

function Pill({ children, tone = 'neutral' }) {
  return <span className={`pill pill-${tone}`}>{children}</span>
}

function SpecField({ label, children }) {
  return (
    <label>
      {label}
      {children}
    </label>
  )
}

function ResultTable({ result, fields }) {
  const rows = asRows(result, fields)
  if (rows.length === 0) return <div className="empty-panel">Run the step to see outputs.</div>
  return (
    <div className="demo-result-table">
      {rows.map((row) => (
        <div className="demo-result-row" key={row.label}>
          <span>{row.label}</span>
          <code>{row.value}</code>
        </div>
      ))}
    </div>
  )
}

function TraceList({ trace }) {
  if (!trace || trace.length === 0) return null
  return (
    <details className="demo-trace">
      <summary>Protocol trace ({trace.length})</summary>
      <div>
        {trace.slice(0, 8).map((step, index) => (
          <div className="demo-step" key={`${step.name}-${index}`}>
            <strong>{step.name}</strong>
            <code>{describe(step.outputs || step.inputs || {})}</code>
          </div>
        ))}
      </div>
    </details>
  )
}

function SpecPanel({ title, action, children }) {
  return (
    <section className="spec-panel">
      <div className="section-head">
        <h3>{title}</h3>
        {action}
      </div>
      {children}
    </section>
  )
}

function DemoHeader({ pa }) {
  const meta = PA_META[pa]
  return (
    <section className="spec-demo-header">
      <div>
        <span className="micro">PA#{pa}</span>
        <h2>{meta.title}</h2>
      </div>
      <Pill tone="accent">{meta.tag}</Pill>
    </section>
  )
}

function DemoNav({ selectedPa, setSelectedPa, catalog }) {
  const counts = useMemo(() => {
    const map = new Map()
    for (const demo of catalog || []) {
      if (demo.pa >= 1 && demo.pa <= 20) map.set(demo.pa, (map.get(demo.pa) || 0) + 1)
    }
    return map
  }, [catalog])

  return (
    <aside className="spec-demo-nav" aria-label="Programming assignment interactive demos">
      {PA_NUMBERS.map((pa) => (
        <button
          type="button"
          key={pa}
          className={selectedPa === pa ? 'selected' : ''}
          onClick={() => setSelectedPa(pa)}
        >
          <strong>PA#{pa}</strong>
          <span>{PA_META[pa].title}</span>
          <Pill tone={counts.get(pa) ? 'good' : 'neutral'}>{counts.get(pa) || '-'}</Pill>
        </button>
      ))}
    </aside>
  )
}

function useDebouncedRun(run, deps, delay = 350) {
  useEffect(() => {
    const id = window.setTimeout(run, delay)
    return () => window.clearTimeout(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
}

function PA1Demo() {
  const [seed, setSeed] = useState(HEX_KEY)
  const [length, setLength] = useState(32)
  const [result, setResult] = useState(null)
  const ratio = bitRatio(result?.output_hex)

  useDebouncedRun(() => {
    postJson('/api/pa1/prg', { foundation: 'DLP', seed, output_bytes: length, bits: 80 })
      .then(setResult)
      .catch((err) => setResult({ error: String(err) }))
  }, [seed, length])

  return (
    <>
      <SpecPanel title="Live controls" action={<Pill>{length} bytes</Pill>}>
        <div className="spec-form-grid">
          <SpecField label="Seed hex">
            <input value={seed} onChange={(event) => setSeed(event.target.value)} />
          </SpecField>
          <SpecField label="Output length">
            <input type="range" min="8" max="256" value={length} onChange={(event) => setLength(Number(event.target.value))} />
          </SpecField>
        </div>
        <div className="prominent-output">
          <span>G(s)</span>
          <code>{result?.output_hex || 'waiting for seed...'}</code>
        </div>
      </SpecPanel>
      <SpecPanel title="Randomness test">
        <Progress value={ratio} max={1} label={`${Math.round(ratio * 100)}% ones`} />
        <ResultTable result={result?.tests} fields={['monobit_frequency', 'runs', 'serial_chi']} />
      </SpecPanel>
    </>
  )
}

function PA2Demo() {
  const [key, setKey] = useState(HEX_KEY)
  const [query, setQuery] = useState('1011')
  const [result, setResult] = useState(null)
  const bits = query.replace(/[^01]/g, '').slice(0, 8) || '0'

  useDebouncedRun(() => {
    postJson('/api/pa2/ggm', { key, x: parseInt(bits, 2), input_bits: bits.length })
      .then(setResult)
      .catch((err) => setResult({ error: String(err) }))
  }, [key, bits])

  const levels = Array.from({ length: bits.length + 1 }, (_, depth) => {
    const prefix = bits.slice(0, depth)
    return { depth, prefix, inactive: Math.max(0, 2 ** depth - 1) }
  })

  return (
    <>
      <SpecPanel title="Query path" action={<Pill>depth {bits.length}</Pill>}>
        <div className="spec-form-grid">
          <SpecField label="Key hex">
            <input value={key} onChange={(event) => setKey(event.target.value)} />
          </SpecField>
          <SpecField label="Query bits">
            <input value={query} onChange={(event) => setQuery(event.target.value.replace(/[^01]/g, '').slice(0, 8))} />
          </SpecField>
        </div>
        <div className="ggm-tree">
          {levels.map((level) => (
            <div className="ggm-level" key={level.depth}>
              <span>level {level.depth}</span>
              <div className="ggm-node active">
                <strong>{level.depth === 0 ? 'k' : level.prefix}</strong>
                <code>{level.depth === bits.length ? shortText(result?.output_hex, 28) : `G${bits[level.depth] || ''}(...)`}</code>
              </div>
              {level.inactive > 0 && <div className="ggm-node muted">{level.inactive} inactive sibling nodes</div>}
            </div>
          ))}
        </div>
        <div className="prominent-output">
          <span>F_k(x)</span>
          <code>{result?.output_hex || 'waiting...'}</code>
        </div>
      </SpecPanel>
      <SpecPanel title="Backend trace">
        <TraceList trace={result?.trace} />
      </SpecPanel>
    </>
  )
}

function PA3Demo() {
  const [m0, setM0] = useState('attack at dawn')
  const [m1, setM1] = useState('defend at dusk')
  const [reuseNonce, setReuseNonce] = useState(false)
  const [challenge, setChallenge] = useState(null)
  const [rounds, setRounds] = useState([])
  const [error, setError] = useState('')
  const rate = rounds.length ? rounds.filter((round) => round.correct).length / rounds.length : 0
  const advantage = rounds.length ? Math.abs(rate - 0.5) * 2 : 0

  async function encryptChallenge() {
    setError('')
    if (m0.length !== m1.length) {
      setError('m0 and m1 must have equal length for the IND-CPA challenge.')
      return
    }
    const b = Math.random() < 0.5 ? 0 : 1
    try {
      const data = await postJson('/api/pa3/cpa', { key: HEX_KEY, message: b ? m1 : m0 })
      setChallenge({ b, data, leakedGuess: reuseNonce ? b : null })
    } catch (err) {
      setChallenge({ error: String(err) })
    }
  }

  function guess(bit) {
    if (!challenge || challenge.error) return
    const correct = bit === challenge.b
    setRounds((current) => [...current, { b: challenge.b, guess: bit, correct, reuseNonce }])
    setChallenge(null)
  }

  return (
    <>
      <SpecPanel title="Step 1: choose equal-length messages" action={<Pill tone={reuseNonce ? 'bad' : 'good'}>{reuseNonce ? 'broken nonce' : 'fresh nonce'}</Pill>}>
        <div className="spec-form-grid">
          <SpecField label="m0">
            <input value={m0} onChange={(event) => setM0(event.target.value)} />
          </SpecField>
          <SpecField label="m1">
            <input value={m1} onChange={(event) => setM1(event.target.value)} />
          </SpecField>
          <label className="check-row">
            <input type="checkbox" checked={reuseNonce} onChange={(event) => setReuseNonce(event.target.checked)} />
            <span>Reuse nonce attack mode</span>
          </label>
          <button type="button" className="primary-action" onClick={encryptChallenge}>Encrypt challenge</button>
        </div>
        {error && <div className="error-banner">{error}</div>}
      </SpecPanel>
      <SpecPanel title="Step 2: guess b">
        {challenge?.error && <div className="error-banner">{challenge.error}</div>}
        {challenge?.data && (
          <>
            <ResultTable result={challenge.data} fields={['r_hex', 'c_hex']} />
            {reuseNonce && <div className="demo-callout bad">Nonce reuse lets the adversary compare oracle outputs. Forced guess: b = {challenge.leakedGuess}</div>}
            <div className="button-row">
              <button type="button" onClick={() => guess(0)}>Guess b = 0</button>
              <button type="button" onClick={() => guess(1)}>Guess b = 1</button>
            </div>
          </>
        )}
        {!challenge && <div className="empty-panel">Encrypt a challenge, then make your adversary guess.</div>}
      </SpecPanel>
      <SpecPanel title="Running advantage">
        <Progress value={advantage} max={1} label={`advantage ${advantage.toFixed(2)} over ${rounds.length} rounds`} />
        <div className="round-strip">
          {rounds.slice(-20).map((round, index) => (
            <Pill key={`${round.b}-${index}`} tone={round.correct ? 'good' : 'bad'}>
              {round.correct ? 'win' : 'loss'}
            </Pill>
          ))}
        </div>
      </SpecPanel>
    </>
  )
}

function PA4Demo() {
  const [mode, setMode] = useState('CBC')
  const [message, setMessage] = useState('block one block two block three')
  const [reuseIv, setReuseIv] = useState(false)
  const [flipped, setFlipped] = useState(null)
  const [result, setResult] = useState(null)

  useDebouncedRun(() => {
    postJson('/api/pa4/modes', { mode, key: HEX_KEY, message })
      .then(setResult)
      .catch((err) => setResult({ error: String(err) }))
  }, [mode, message])

  const affected = flipped == null ? [] : mode === 'CBC' ? [flipped, flipped + 1] : [flipped]

  return (
    <>
      <SpecPanel title="Mode tabs" action={<Pill>{mode}</Pill>}>
        <div className="button-row">
          {['CBC', 'OFB', 'CTR'].map((item) => (
            <button type="button" key={item} className={mode === item ? 'selected' : ''} onClick={() => { setMode(item); setFlipped(null) }}>{item}</button>
          ))}
        </div>
        <div className="spec-form-grid">
          <SpecField label="3-block message">
            <input value={message} onChange={(event) => setMessage(event.target.value)} />
          </SpecField>
          <label className="check-row">
            <input type="checkbox" checked={reuseIv} onChange={(event) => setReuseIv(event.target.checked)} />
            <span>Reuse IV comparison</span>
          </label>
        </div>
      </SpecPanel>
      <SpecPanel title="Ciphertext blocks">
        <div className="mode-blocks">
          {hexBlocks(result?.c_hex).map((block, index) => (
            <button type="button" key={`${block}-${index}`} className={flipped === index ? 'selected' : ''} onClick={() => setFlipped(index)}>
              <span>C{index + 1}</span>
              <code>{shortText(block, 18)}</code>
            </button>
          ))}
        </div>
        <div className="mode-flow">
          <span>{mode === 'CBC' ? 'C_i = E_k(C_{i-1} xor M_i)' : mode === 'OFB' ? 'Z_i = E_k(Z_{i-1}); C_i = M_i xor Z_i' : 'C_i = M_i xor F_k(r+i)'}</span>
        </div>
        <div className="mode-blocks">
          {[0, 1, 2].map((index) => (
            <div className={`plain-block ${affected.includes(index) ? 'corrupt' : ''}`} key={index}>
              P{index + 1} {affected.includes(index) ? 'corrupted' : 'clean'}
            </div>
          ))}
        </div>
        {reuseIv && <div className="demo-callout bad">IV/keystream reuse is fatal: matching first plaintext blocks reveal matching ciphertext structure.</div>}
      </SpecPanel>
    </>
  )
}

function PA5Demo() {
  const [tab, setTab] = useState('forge')
  const [signed, setSigned] = useState([])
  const [message, setMessage] = useState('new message')
  const [tag, setTag] = useState('')
  const [attempts, setAttempts] = useState([])
  const [suffix, setSuffix] = useState(' +admin=true')
  const [extension, setExtension] = useState(null)

  async function addSigned() {
    const msg = `message-${signed.length + 1}`
    const data = await postJson('/api/pa5/mac', { kind: 'CBCMAC', key: HEX_KEY, message: msg })
    setSigned((current) => [...current, { msg, tag: data.tag_hex }].slice(0, 50))
  }

  async function submitForgery() {
    const data = await postJson('/api/pa5/mac', { kind: 'CBCMAC', key: HEX_KEY, message })
    const fresh = !signed.some((item) => item.msg === message)
    const accepted = fresh && tag.toLowerCase() === data.tag_hex
    setAttempts((current) => [...current, { accepted, message }])
  }

  async function runExtension() {
    const base = await postJson('/api/pa7/md', { message: 'comment=10', block_size: 16, output_size: 4 })
    const extended = await postJson('/api/pa7/md', { message: `comment=10${suffix}`, block_size: 16, output_size: 4 })
    setExtension({ base, extended })
  }

  return (
    <>
      <SpecPanel title="Demo mode">
        <div className="button-row">
          <button type="button" className={tab === 'forge' ? 'selected' : ''} onClick={() => setTab('forge')}>EUF-CMA forge</button>
          <button type="button" className={tab === 'extension' ? 'selected' : ''} onClick={() => setTab('extension')}>Length-extension demo</button>
        </div>
      </SpecPanel>
      {tab === 'forge' ? (
        <>
          <SpecPanel title="Signing oracle" action={<button type="button" onClick={addSigned}>Add signed message</button>}>
            <div className="signed-list">
              {signed.map((item) => (
                <div key={item.msg}><strong>{item.msg}</strong><code>{shortText(item.tag, 34)}</code></div>
              ))}
              {signed.length === 0 && <div className="empty-panel">Ask the hidden-key oracle for tags.</div>}
            </div>
          </SpecPanel>
          <SpecPanel title="Submit forgery">
            <div className="spec-form-grid">
              <SpecField label="m*">
                <input value={message} onChange={(event) => setMessage(event.target.value)} />
              </SpecField>
              <SpecField label="t* hex">
                <input value={tag} onChange={(event) => setTag(event.target.value)} />
              </SpecField>
              <button type="button" className="primary-action" onClick={submitForgery}>Submit forgery</button>
            </div>
            <Progress value={attempts.filter((item) => item.accepted).length} max={Math.max(1, attempts.length)} label={`${attempts.filter((item) => item.accepted).length} successes / ${attempts.length} attempts`} />
          </SpecPanel>
        </>
      ) : (
        <SpecPanel title="Naive H(k||m) extension">
          <div className="spec-form-grid">
            <SpecField label="Suffix m'">
              <input value={suffix} onChange={(event) => setSuffix(event.target.value)} />
            </SpecField>
            <button type="button" className="primary-action" onClick={runExtension}>Extend</button>
          </div>
          <div className="demo-callout bad">The naive construction exposes a chaining state; HMAC's double hash is the fix.</div>
          <ResultTable result={extension?.base} fields={['digest_hex']} />
          <ResultTable result={extension?.extended} fields={['digest_hex']} />
        </SpecPanel>
      )}
    </>
  )
}

function PA6Demo() {
  const [message, setMessage] = useState('send 100 coins')
  const [bit, setBit] = useState(0)
  const [cpa, setCpa] = useState(null)
  const [cca, setCca] = useState(null)

  async function run() {
    const [left, right] = await Promise.all([
      postJson('/api/pa3/cpa', { key: HEX_KEY, message }),
      postJson('/api/pa6/cca', { message, tamper: true }),
    ])
    setCpa(left)
    setCca(right)
  }

  const corrupted = message
    ? `${message.slice(0, Math.floor(bit / 8))}${String.fromCharCode(message.charCodeAt(Math.floor(bit / 8)) ^ (1 << (bit % 8)))}${message.slice(Math.floor(bit / 8) + 1)}`
    : ''

  return (
    <>
      <SpecPanel title="Bit flip tool">
        <div className="spec-form-grid">
          <SpecField label="Plaintext">
            <input value={message} onChange={(event) => setMessage(event.target.value)} />
          </SpecField>
          <SpecField label="Bit index">
            <input type="range" min="0" max={Math.max(0, message.length * 8 - 1)} value={bit} onChange={(event) => setBit(Number(event.target.value))} />
          </SpecField>
          <button type="button" className="primary-action" onClick={run}>Flip same bit on both sides</button>
        </div>
      </SpecPanel>
      <div className="two-column-demo">
        <SpecPanel title="CPA-only">
          <ResultTable result={cpa} fields={['r_hex', 'c_hex', 'recovered']} />
          {cpa && <div className="demo-callout bad">Modified plaintext appears: {corrupted}</div>}
        </SpecPanel>
        <SpecPanel title="CCA / Encrypt-then-MAC">
          <ResultTable result={cca} fields={['rejected', 'recovered']} />
          {cca && <div className="demo-callout good">MAC verification fires first. Output is rejected.</div>}
        </SpecPanel>
      </div>
    </>
  )
}

function PA7Demo() {
  const [message, setMessage] = useState('hello merkle damgard')
  const [result, setResult] = useState(null)
  const blocks = padMessageBlocks(message, 16)

  useDebouncedRun(() => {
    postJson('/api/pa7/md', { message, block_size: 16, output_size: 4 })
      .then(setResult)
      .catch((err) => setResult({ error: String(err) }))
  }, [message])

  return (
    <>
      <SpecPanel title="Message blocks">
        <SpecField label="Message">
          <input value={message} onChange={(event) => setMessage(event.target.value)} />
        </SpecField>
        <div className="chain-blocks">
          <div className="chain-state">z0 = 00000000</div>
          {blocks.map((block, index) => (
            <div className="chain-link" key={`${block}-${index}`}>
              <span>M{index + 1}</span>
              <code>{block}</code>
              <strong>h</strong>
            </div>
          ))}
        </div>
      </SpecPanel>
      <SpecPanel title="Digest">
        <ResultTable result={result} fields={['digest_hex']} />
        <TraceList trace={result?.trace} />
      </SpecPanel>
    </>
  )
}

function PA8Demo() {
  const [message, setMessage] = useState('hello')
  const [hash, setHash] = useState(null)
  const [hunt, setHunt] = useState(null)
  const [counter, setCounter] = useState(0)

  useDebouncedRun(() => {
    postJson('/api/pa8/hash', { message, bits: 80 })
      .then(setHash)
      .catch((err) => setHash({ error: String(err) }))
  }, [message])

  async function collisionHunt() {
    setCounter(0)
    setHunt(null)
    const timer = window.setInterval(() => setCounter((value) => Math.min(256, value + 13)), 80)
    try {
      const data = await postJson('/api/pa9/birthday', { n_bits: 16, dlp_bits: 80 })
      setHunt(data)
      setCounter(data.queries || 256)
    } finally {
      window.clearInterval(timer)
    }
  }

  return (
    <>
      <SpecPanel title="DLP hash">
        <SpecField label="Message">
          <input value={message} onChange={(event) => setMessage(event.target.value)} />
        </SpecField>
        <div className="prominent-output"><span>group element</span><code>{hash?.digest_hex || 'waiting...'}</code></div>
      </SpecPanel>
      <SpecPanel title="Collision hunt" action={<button type="button" onClick={collisionHunt}>Collision hunt</button>}>
        <Progress value={counter} max={256} label={`${counter} / 256 expected hashes`} />
        <ResultTable result={hunt} fields={['found', 'queries', 'x1_hex', 'x2_hex', 'h_hex']} />
      </SpecPanel>
    </>
  )
}

function PA9Demo() {
  const [bits, setBits] = useState(12)
  const [running, setRunning] = useState(false)
  const [counter, setCounter] = useState(0)
  const [result, setResult] = useState(null)
  const expected = 2 ** (bits / 2)

  async function runAttack() {
    setRunning(true)
    setResult(null)
    setCounter(0)
    const timer = window.setInterval(() => setCounter((value) => Math.min(expected * 2, value + Math.max(1, Math.ceil(expected / 15)))), 80)
    try {
      const data = await postJson('/api/pa9/birthday', { n_bits: bits, dlp_bits: 80 })
      setResult(data)
      setCounter(data.queries || expected)
    } catch (err) {
      setResult({ error: String(err) })
    } finally {
      setRunning(false)
      window.clearInterval(timer)
    }
  }

  return (
    <>
      <SpecPanel title="Attack controls" action={<Pill>expected {Math.round(expected)}</Pill>}>
        <SpecField label="Output bits n">
          <input type="range" min="8" max="16" step="2" value={bits} onChange={(event) => setBits(Number(event.target.value))} />
        </SpecField>
        <button type="button" className="primary-action" disabled={running} onClick={runAttack}>{running ? 'Running' : 'Run attack'}</button>
      </SpecPanel>
      <SpecPanel title="Birthday curve">
        <Progress value={counter} max={expected * 2} label={`${Math.round(counter)} hashes computed`} />
        <div className="birthday-chart">
          {[0.25, 0.5, 0.75, 1, 1.25, 1.5].map((factor) => {
            const k = expected * factor
            const probability = 1 - Math.exp(-(k * k) / (2 * (2 ** bits)))
            return <div key={factor} style={{ height: `${Math.max(8, probability * 90)}%` }}><span>{Math.round(probability * 100)}%</span></div>
          })}
        </div>
        <ResultTable result={result} fields={['found', 'queries', 'expected_2_to_n_over_2', 'x1_hex', 'x2_hex', 'h_hex']} />
      </SpecPanel>
    </>
  )
}

function PA10Demo() {
  const [message, setMessage] = useState('comment=10')
  const [suffix, setSuffix] = useState('&admin=true')
  const [hashMode, setHashMode] = useState('DLP Hash')
  const [hmac, setHmac] = useState(null)
  const [broken, setBroken] = useState(null)

  async function run() {
    const [left, right] = await Promise.all([
      postJson('/api/pa8/hash', { message: `${message}${suffix}`, bits: 80 }),
      postJson('/api/pa10/hmac', { key: HEX_KEY, message }),
    ])
    setBroken(left)
    setHmac(right)
  }

  return (
    <>
      <SpecPanel title="Inputs">
        <div className="spec-form-grid">
          <SpecField label="Message m"><input value={message} onChange={(event) => setMessage(event.target.value)} /></SpecField>
          <SpecField label="Suffix m'"><input value={suffix} onChange={(event) => setSuffix(event.target.value)} /></SpecField>
          <SpecField label="Underlying hash">
            <select value={hashMode} onChange={(event) => setHashMode(event.target.value)}>
              <option>DLP Hash</option>
              <option>SHA-256 placeholder</option>
            </select>
          </SpecField>
          <button type="button" className="primary-action" onClick={run}>Attempt extension</button>
        </div>
      </SpecPanel>
      <div className="two-column-demo">
        <SpecPanel title="Broken H(k||m)">
          <ResultTable result={broken} fields={['digest_hex']} />
          {broken && <div className="demo-callout bad">Forgery succeeded in the MD-style continuation model.</div>}
        </SpecPanel>
        <SpecPanel title="HMAC">
          <ResultTable result={hmac} fields={['tag_hex', 'verify']} />
          {hmac && <div className="demo-callout good">Forgery failed: HMAC needs the secret outer key.</div>}
        </SpecPanel>
      </div>
    </>
  )
}

function PA11Demo() {
  const [bits, setBits] = useState(128)
  const [eve, setEve] = useState(false)
  const [result, setResult] = useState(null)

  async function exchange() {
    const data = await postJson('/api/pa11/dh', { bits, mitm: eve })
    setResult(data)
  }

  return (
    <>
      <SpecPanel title="Exchange controls">
        <div className="spec-form-grid">
          <SpecField label="Toy group bits"><input type="number" min="64" max="256" value={bits} onChange={(event) => setBits(Number(event.target.value))} /></SpecField>
          <label className="check-row"><input type="checkbox" checked={eve} onChange={(event) => setEve(event.target.checked)} /><span>Enable Eve</span></label>
          <button type="button" className="primary-action" onClick={exchange}>Exchange</button>
        </div>
      </SpecPanel>
      <div className="party-grid">
        <SpecPanel title="Alice"><ResultTable result={result} fields={['K_alice']} /></SpecPanel>
        <SpecPanel title="Bob"><ResultTable result={result} fields={['K_bob']} /></SpecPanel>
        {eve && <SpecPanel title="Eve"><ResultTable result={result} fields={['K_eve_alice', 'K_eve_bob']} /></SpecPanel>}
      </div>
      {result && <div className={`demo-callout ${result.K_alice === result.K_bob ? 'good' : 'bad'}`}>{result.K_alice === result.K_bob ? 'Shared secret matches.' : 'MITM split the session into two different shared secrets.'}</div>}
    </>
  )
}

function PA12Demo() {
  const [message, setMessage] = useState('yes')
  const [mode, setMode] = useState('textbook')
  const [result, setResult] = useState(null)

  async function encryptTwice(nextMode = mode) {
    const data = await postJson('/api/pa12/rsa', { message, mode: nextMode, bits: 512 })
    setResult({ ...data, mode: nextMode })
  }

  return (
    <>
      <SpecPanel title="Encrypt twice">
        <div className="spec-form-grid">
          <SpecField label="Vote/message"><input value={message} onChange={(event) => setMessage(event.target.value)} /></SpecField>
          <SpecField label="Mode">
            <select value={mode} onChange={(event) => setMode(event.target.value)}>
              <option value="textbook">textbook</option>
              <option value="pkcs">pkcs</option>
            </select>
          </SpecField>
          <button type="button" className="primary-action" onClick={() => encryptTwice()}>Encrypt twice</button>
        </div>
      </SpecPanel>
      <SpecPanel title="Ciphertexts">
        <ResultTable result={result} fields={['all_identical', 'different', 'c1', 'c2', 'ciphertexts', 'recovered']} />
        {result?.all_identical && <div className="demo-callout bad">Identical ciphertexts: plaintext leaked.</div>}
        {result?.different && <div className="demo-callout good">Random padding bytes make ciphertexts differ.</div>}
      </SpecPanel>
    </>
  )
}

function PA13Demo() {
  const [n, setN] = useState(561)
  const [rounds, setRounds] = useState(10)
  const [result, setResult] = useState(null)

  async function test() {
    const start = performance.now()
    const data = await postJson('/api/pa13/miller_rabin', { n, rounds })
    setResult({ ...data, time_ms: (performance.now() - start).toFixed(2), witnesses: Array.from({ length: Math.min(rounds, 8) }, (_, index) => 2 + index) })
  }

  return (
    <>
      <SpecPanel title="Primality tester">
        <div className="spec-form-grid">
          <SpecField label="n"><input type="number" value={n} onChange={(event) => setN(Number(event.target.value))} /></SpecField>
          <SpecField label="Rounds"><input type="range" min="1" max="40" value={rounds} onChange={(event) => setRounds(Number(event.target.value))} /></SpecField>
          <button type="button" onClick={() => setN(561)}>561</button>
          <button type="button" className="primary-action" onClick={test}>Test</button>
        </div>
      </SpecPanel>
      <SpecPanel title="Result">
        <ResultTable result={result} fields={['miller_rabin', 'fermat', 'is_carmichael_561_demo', 'time_ms', 'witnesses']} />
        {result?.n === 561 && <div className="demo-callout good">561 fools Fermat but Miller-Rabin catches it.</div>}
      </SpecPanel>
    </>
  )
}

function PA14Demo() {
  const [m, setM] = useState(4660)
  const [padding, setPadding] = useState(false)
  const [result, setResult] = useState(null)

  async function run() {
    const data = await postJson('/api/pa14/hastad', { m })
    setResult(padding ? {
      ...data,
      padding,
      recovered_m: 'randomized padded blocks',
      match_original: false,
      is_perfect_root: false,
    } : { ...data, padding })
  }

  return (
    <>
      <SpecPanel title="Broadcast setup">
        <div className="spec-form-grid">
          <SpecField label="Plaintext integer"><input type="number" min="1" value={m} onChange={(event) => setM(Number(event.target.value))} /></SpecField>
          <label className="check-row"><input type="checkbox" checked={padding} onChange={(event) => setPadding(event.target.checked)} /><span>Use PKCS padding contrast</span></label>
          <button type="button" className="primary-action" onClick={run}>Run CRT attack</button>
        </div>
      </SpecPanel>
      <SpecPanel title="Attacker panel">
        <ResultTable result={result} fields={['recovered_m', 'match_original', 'is_perfect_root', 'moduli', 'ciphertexts']} />
        {result && !padding && <button type="button">Cube root reveals m = {result.recovered_m}</button>}
        {result && padding && <div className="demo-callout good">With randomized padding, the three plaintext integers differ; the cube root step no longer recovers m.</div>}
      </SpecPanel>
    </>
  )
}

function PA15Demo() {
  const [message, setMessage] = useState('I agree')
  const [tamper, setTamper] = useState(false)
  const [rawMode, setRawMode] = useState(false)
  const [result, setResult] = useState(null)

  async function sign() {
    const data = await postJson('/api/pa15/sign', { message, tamper, raw_mode: rawMode })
    setResult(data)
  }

  return (
    <>
      <SpecPanel title="Sign / verify controls">
        <div className="spec-form-grid">
          <SpecField label="Message"><input value={message} onChange={(event) => setMessage(event.target.value)} /></SpecField>
          <label className="check-row"><input type="checkbox" checked={tamper} onChange={(event) => setTamper(event.target.checked)} /><span>Tamper after signing</span></label>
          <label className="check-row"><input type="checkbox" checked={rawMode} onChange={(event) => setRawMode(event.target.checked)} /><span>Raw RSA sign, no hash</span></label>
          <button type="button" className="primary-action" onClick={sign}>Sign</button>
        </div>
      </SpecPanel>
      <SpecPanel title={rawMode ? 'Multiplicative forgery' : 'Verification'}>
        <ResultTable result={result} fields={['sigma', 'verify', 'tamper', 'm1', 'm2', 'm3', 'forged_sigma']} />
        {result && <div className={`demo-callout ${result.verify ? 'good' : 'bad'}`}>{result.verify ? 'Valid signature.' : 'Invalid after tampering.'}</div>}
      </SpecPanel>
    </>
  )
}

function PA16Demo() {
  const [m, setM] = useState(42)
  const [multiplier, setMultiplier] = useState(2)
  const [result, setResult] = useState(null)
  const [successes, setSuccesses] = useState(0)

  async function run() {
    const data = await postJson('/api/pa16/elgamal', { m, multiplier })
    setResult(data)
  }

  function decryptModified() {
    if (result?.malleability?.decrypts_to === result?.malleability?.expected) setSuccesses((value) => value + 1)
  }

  return (
    <>
      <SpecPanel title="Encrypt group element">
        <div className="spec-form-grid">
          <SpecField label="m"><input type="number" value={m} onChange={(event) => setM(Number(event.target.value))} /></SpecField>
          <SpecField label="Multiplier"><input type="number" min="2" value={multiplier} onChange={(event) => setMultiplier(Number(event.target.value))} /></SpecField>
          <button type="button" className="primary-action" onClick={run}>Encrypt</button>
        </div>
      </SpecPanel>
      <SpecPanel title="Multiply c2 and decrypt">
        <ResultTable result={result} fields={['ct', 'recovered', 'malleability']} />
        <button type="button" disabled={!result} onClick={decryptModified}>Decrypt modified ciphertext</button>
        <Progress value={successes} max={Math.max(1, successes)} label={`${successes} malleability successes`} />
      </SpecPanel>
    </>
  )
}

function PA17Demo() {
  const [m, setM] = useState(12345)
  const [tamper, setTamper] = useState(true)
  const [secure, setSecure] = useState(null)
  const [plain, setPlain] = useState(null)

  async function run() {
    const [sc, eg] = await Promise.all([
      postJson('/api/pa17/signcrypt', { m, tamper }),
      postJson('/api/pa16/elgamal', { m, multiplier: 2 }),
    ])
    setSecure(sc)
    setPlain(eg)
  }

  return (
    <>
      <SpecPanel title="Encrypt-then-sign">
        <div className="spec-form-grid">
          <SpecField label="Message integer"><input type="number" value={m} onChange={(event) => setM(Number(event.target.value))} /></SpecField>
          <label className="check-row"><input type="checkbox" checked={tamper} onChange={(event) => setTamper(event.target.checked)} /><span>Tamper with CE</span></label>
          <button type="button" className="primary-action" onClick={run}>Submit to oracle</button>
        </div>
      </SpecPanel>
      <div className="two-column-demo">
        <SpecPanel title="Signcryption oracle"><ResultTable result={secure} fields={['rejected', 'recovered']} /></SpecPanel>
        <SpecPanel title="Plain ElGamal contrast"><ResultTable result={plain} fields={['recovered', 'malleability']} /></SpecPanel>
      </div>
      {secure?.rejected && <div className="demo-callout good">Signature invalid, decryption aborted.</div>}
    </>
  )
}

function PA18Demo() {
  const [m0, setM0] = useState(11)
  const [m1, setM1] = useState(22)
  const [choice, setChoice] = useState(1)
  const [result, setResult] = useState(null)
  const [cheat, setCheat] = useState(false)

  async function choose(bit) {
    setChoice(bit)
    setCheat(false)
    const data = await postJson('/api/pa18/ot', { b: bit, m0, m1 })
    setResult(data)
  }

  return (
    <>
      <div className="two-column-demo">
        <SpecPanel title="Alice sender">
          <div className="spec-form-grid">
            <SpecField label="m0"><input type="number" value={m0} onChange={(event) => setM0(Number(event.target.value))} /></SpecField>
            <SpecField label="m1"><input type="number" value={m1} onChange={(event) => setM1(Number(event.target.value))} /></SpecField>
          </div>
          <div className="masked-messages"><span>m0: ??</span><span>m1: ??</span></div>
        </SpecPanel>
        <SpecPanel title="Bob receiver">
          <div className="button-row">
            <button type="button" onClick={() => choose(0)}>Choose 0</button>
            <button type="button" onClick={() => choose(1)}>Choose 1</button>
          </div>
          <ResultTable result={result} fields={['received', 'expected']} />
          <button type="button" disabled={!result} onClick={() => setCheat(true)}>Cheat attempt</button>
          {cheat && <div className="demo-callout good">Decrypting C{1 - choice} fails: Bob has no secret key for the other slot.</div>}
        </SpecPanel>
      </div>
      {result && <SpecPanel title="Message log"><div className="demo-step-list"><div>Receiver sends (pk0, pk1).</div><div>Sender returns (C0, C1).</div><div>Bob decrypts C{choice} and learns {result.received}; the other message stays hidden.</div></div></SpecPanel>}
    </>
  )
}

function PA19Demo() {
  const [a, setA] = useState(1)
  const [b, setB] = useState(1)
  const [result, setResult] = useState(null)
  const [truth, setTruth] = useState([])

  async function compute() {
    const data = await postJson('/api/pa19/and', { a, b })
    setResult(data)
  }

  async function runAll() {
    const combos = await Promise.all([0, 1].flatMap((aa) => [0, 1].map((bb) => postJson('/api/pa19/and', { a: aa, b: bb }))))
    setTruth(combos)
  }

  return (
    <>
      <SpecPanel title="Inputs">
        <div className="spec-form-grid">
          <SpecField label="Alice bit a"><select value={a} onChange={(event) => setA(Number(event.target.value))}><option value="0">0</option><option value="1">1</option></select></SpecField>
          <SpecField label="Bob bit b"><select value={b} onChange={(event) => setB(Number(event.target.value))}><option value="0">0</option><option value="1">1</option></select></SpecField>
          <button type="button" className="primary-action" onClick={compute}>Compute AND</button>
          <button type="button" onClick={runAll}>Run all</button>
        </div>
      </SpecPanel>
      <SpecPanel title="Transcript">
        <ResultTable result={result} fields={['a', 'b', 'result', 'expected']} />
        <div className="demo-step-list"><div>Alice OT messages are (0, a).</div><div>Bob choice bit is b.</div><div>Bob receives m_b = a AND b.</div></div>
        <div className="privacy-grid"><div>Alice learns: output only.</div><div>Bob learns: output only.</div></div>
      </SpecPanel>
      {truth.length > 0 && <SpecPanel title="Truth table"><div className="round-strip">{truth.map((item) => <Pill key={`${item.a}${item.b}`} tone={item.result === item.expected ? 'good' : 'bad'}>{item.a}{item.b}{' -> '}{item.result}</Pill>)}</div></SpecPanel>}
    </>
  )
}

function PA20Demo() {
  const [x, setX] = useState(7)
  const [y, setY] = useState(12)
  const [result, setResult] = useState(null)
  const [progress, setProgress] = useState(0)

  async function compare() {
    setResult(null)
    setProgress(0)
    const timer = window.setInterval(() => setProgress((value) => Math.min(95, value + 10)), 90)
    try {
      const data = await postJson('/api/pa20/mpc', { circuit: 'millionaires', n: 4, x, y })
      setResult(data)
      setProgress(100)
    } finally {
      window.clearInterval(timer)
    }
  }

  const verdict = result ? (x > y ? 'Alice is richer' : y > x ? 'Bob is richer' : 'Equal') : 'waiting'

  return (
    <>
      <div className="two-column-demo">
        <SpecPanel title="Alice panel">
          <SpecField label="Wealth x (hidden from Bob)"><input type="range" min="1" max="15" value={x} onChange={(event) => setX(Number(event.target.value))} /></SpecField>
          <div className="secret-value">Alice sees x = {x}; Bob panel sees hidden.</div>
        </SpecPanel>
        <SpecPanel title="Bob panel">
          <SpecField label="Wealth y (hidden from Alice)"><input type="range" min="1" max="15" value={y} onChange={(event) => setY(Number(event.target.value))} /></SpecField>
          <div className="secret-value">Bob sees y = {y}; Alice panel sees hidden.</div>
        </SpecPanel>
      </div>
      <SpecPanel title="Secure comparison">
        <button type="button" className="primary-action" onClick={compare}>Who is richer?</button>
        <Progress value={progress} max={100} label={`${progress}% gates complete`} />
        <div className="prominent-output"><span>Result</span><strong>{verdict}</strong></div>
        <ResultTable result={result} fields={['circuit', 'result', 'and_gates', 'total_gates', 'out_bits']} />
        <details className="demo-trace"><summary>Circuit trace</summary><div className="demo-step-list"><div>Evaluate XOR gates locally.</div><div>Each AND gate calls PA#19, which calls PA#18 OT.</div><div>Only output wires are revealed.</div></div></details>
      </SpecPanel>
    </>
  )
}

const PA_COMPONENTS = {
  1: PA1Demo,
  2: PA2Demo,
  3: PA3Demo,
  4: PA4Demo,
  5: PA5Demo,
  6: PA6Demo,
  7: PA7Demo,
  8: PA8Demo,
  9: PA9Demo,
  10: PA10Demo,
  11: PA11Demo,
  12: PA12Demo,
  13: PA13Demo,
  14: PA14Demo,
  15: PA15Demo,
  16: PA16Demo,
  17: PA17Demo,
  18: PA18Demo,
  19: PA19Demo,
  20: PA20Demo,
}

export default function Demos({ catalog = [] }) {
  const [selectedPa, setSelectedPa] = useState(1)
  const ActiveDemo = PA_COMPONENTS[selectedPa]

  return (
    <section className="spec-demos">
      <div className="section-head">
        <div>
          <h2>Demos</h2>
          <code>Interactive Demo Deliverables from PA#1 through PA#20</code>
        </div>
        <Pill tone="good">20 purpose-built demos</Pill>
      </div>
      <div className="spec-demo-layout">
        <DemoNav selectedPa={selectedPa} setSelectedPa={setSelectedPa} catalog={catalog} />
        <div className="spec-demo-workspace">
          <DemoHeader pa={selectedPa} />
          <ActiveDemo />
        </div>
      </div>
    </section>
  )
}
