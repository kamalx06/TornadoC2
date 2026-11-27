import { useEffect, useState } from 'react'
import { invoke } from '../hooks'

export default function Settings(props: {
  paletteKey: string
  onPaletteKey: (k: string) => void
  config: string
  theme: 'dark' | 'light'
  density: 'cozy' | 'compact' | 'dense'
  onTheme: (t: 'dark' | 'light') => void
  onDensity: (d: 'cozy' | 'compact' | 'dense') => void
}): JSX.Element {
  return (
    <div className="view">
      <div className="pane-head"><span className="pane-title">SETTINGS</span></div>
      <div className="settings">
        <h3>Appearance</h3>
        <div className="quick" role="group" aria-label="Theme">
          {(['dark', 'light'] as const).map((t) => (
            <button key={t} className="btn" aria-pressed={props.theme === t}
              onClick={() => props.onTheme(t)}>{t}</button>
          ))}
        </div>
        <div className="quick" role="group" aria-label="Density">
          {(['cozy', 'compact', 'dense'] as const).map((d) => (
            <button key={d} className="btn" aria-pressed={props.density === d}
              onClick={() => props.onDensity(d)}>{d}</button>
          ))}
        </div>
        <h3>Connection</h3>
        <p className="mono small">{props.config || 'no config'}</p>
        <p className="muted small">
          Certificates, password HMAC and all HTTP live in the Python
          bridge. The renderer never holds PEM material.
        </p>
        <h3>AI provider</h3>
        <AiForm />

        <h3>Shortcuts</h3>
        <label className="small muted">Palette key (⌘/Ctrl + key)
          <input className="field" style={{ width: 60 }} maxLength={1}
            defaultValue={props.paletteKey}
            onChange={(e) => props.onPaletteKey(e.target.value)} />
        </label>
        <dl className="keys">
          <dt>⌘/Ctrl + {props.paletteKey.toUpperCase()}</dt><dd>Command palette</dd>
          <dt>Enter</dt><dd>Attach to selection</dd>
          <dt>Esc</dt><dd>Close dialog / restore pane</dd>
          <dt>Alt + ←/→</dt><dd>Move active tab between panes</dd>
          <dt>Alt + 1–4</dt><dd>Move active tab to pane 1–4</dd>
          <dt>Alt + Shift + M</dt><dd>Maximise / restore pane</dd>
          <dt>Delete</dt><dd>Close active tab</dd>
        </dl>
      </div>
    </div>
  )
}


function AiForm(): JSX.Element {
  const [f, setF] = useState<Record<string, string>>({})
  const [keySet, setKeySet] = useState(false)
  const [msg, setMsg] = useState('')

  useEffect(() => {
    void invoke('ai.config.get').then((r) => {
      const c = r as { provider?: string; model?: string; base_url?: string; key_set?: boolean }
      setF({ provider: c.provider ?? '', model: c.model ?? '', base_url: c.base_url ?? '' })
      setKeySet(Boolean(c.key_set))
    }).catch(() => undefined)
  }, [])

  return (
    <div className="ai-form">
      <label>Provider
        <select value={f.provider ?? ''} onChange={(e) => setF({ ...f, provider: e.target.value })}>
          <option value="">—</option>
          {['anthropic', 'claude_code', 'gemini', 'groq', 'ollama', 'openai', 'openrouter']
            .map((p) => <option key={p}>{p}</option>)}
        </select>
      </label>
      <label>Model
        <input className="field" value={f.model ?? ''} onChange={(e) => setF({ ...f, model: e.target.value })} />
      </label>
      <label>API key {keySet ? '(set)' : ''}
        <input className="field" type="password" placeholder={keySet ? 'unchanged' : ''}
          onChange={(e) => setF({ ...f, api_key: e.target.value })} />
      </label>
      <label>Base URL
        <input className="field" value={f.base_url ?? ''} onChange={(e) => setF({ ...f, base_url: e.target.value })} />
      </label>
      <div className="quick">
        <button className="btn primary" onClick={async () => {
          try {
            await invoke('ai.config.set', f)
            setMsg('saved')
          } catch (e) { setMsg((e as Error).message) }
        }}>Save AI settings</button>
        {msg && <span className="small muted">{msg}</span>}
      </div>
    </div>
  )
}
