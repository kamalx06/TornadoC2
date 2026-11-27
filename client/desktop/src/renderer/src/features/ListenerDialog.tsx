import { useEffect, useState } from 'react'
import type { Listener } from '../../../shared/ipc'
import { invoke } from '../hooks'

type Certs = { certs: string[]; keys: string[]; cas: string[] }
type Profiles = Array<{ name: string; description?: string }>

const TYPES = ['http', 'quic', 'websocket', 'dns', 'icmp', 'wireguard']

export default function ListenerDialog(props: {
  editing: Listener | null
  onClose: () => void
  onDone: (msg: string) => void
  variant?: 'modal' | 'sheet'
  onDelete?: () => void
}): JSX.Element {
  const sheet = props.variant === 'sheet'
  const e = props.editing
  const [type, setType] = useState(e?.type ?? 'http')
  const [name, setName] = useState(e?.name ?? '')
  const [host, setHost] = useState(e?.host ?? '0.0.0.0')
  const [port, setPort] = useState(String(e?.port ?? 443))
  const [publicHost, setPublicHost] = useState('')
  const [tlsMode, setTlsMode] = useState('server')
  const [cert, setCert] = useState('')
  const [key, setKey] = useState('')
  const [ca, setCa] = useState('')
  const [profiles, setProfiles] = useState<string[]>([])
  const [domain, setDomain] = useState('')
  const [certs, setCerts] = useState<Certs>({ certs: [], keys: [], cas: [] })
  const [prof, setProf] = useState<Profiles>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    void invoke<Certs>('listeners.certs').then(setCerts).catch(() => undefined)
    void invoke<{ profiles: Profiles }>('listeners.profiles')
      .then((r) => setProf(r.profiles)).catch(() => undefined)
  }, [])

  useEffect(() => {
    if (type === 'dns') setPort('53')
    if (type === 'icmp') setPort('0')
    if (type === 'wireguard') setPort('51820')
  }, [type])

  const submit = async (): Promise<void> => {
    setBusy(true)
    setErr('')
    const spec: Record<string, unknown> = {
      type, name: name.trim(), host: host.trim(), port, profiles,
      enabled: true
    }
    if (publicHost.trim()) spec.public_host = publicHost.trim()
    if (type === 'dns') spec.domain = domain.trim()
    if (type === 'http' || type === 'quic' || type === 'websocket') {
      spec.tls = { mode: tlsMode }
      if (tlsMode !== 'none') {
        if (cert) spec.tls = { ...(spec.tls as object), cert_path: cert }
        if (key) spec.tls = { ...(spec.tls as object), key_path: key }
      }
      if (ca) spec.tls = { ...(spec.tls as object), ca_path: ca }
    }
    try {
      if (e) await invoke('listener.update', { id: e.id, patch: spec }, 60_000)
      else await invoke('listener.create', { spec }, 60_000)
      props.onDone(e ? `updated ${name}` : `created ${name}`)
    } catch (ex) {
      setErr((ex as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className={sheet ? 'listener-sheet-wrap' : 'modal'}
      onMouseDown={(ev) => ev.target === ev.currentTarget && props.onClose()}>
      <form className={sheet ? 'listener-sheet' : 'modal-card'}
        role={sheet ? 'region' : 'dialog'} aria-modal={sheet ? undefined : true}
        aria-label={e ? 'Edit listener' : 'Create listener'}
        onSubmit={(ev) => { ev.preventDefault(); void submit() }}>
        <header className="sheet-head">
          <h2>{e ? `Edit ${e.name}` : 'New listener'}</h2>
          <button type="button" className="icon-btn" aria-label="Close form"
            onClick={props.onClose}>×</button>
        </header>
        <div className="modal-body grid2">
          <label>Type
            <select value={type} disabled={Boolean(e)} onChange={(ev) => setType(ev.target.value)}>
              {TYPES.map((t) => <option key={t}>{t}</option>)}
            </select>
          </label>
          <label>Name
            <input className="field" value={name} autoFocus
              onChange={(ev) => setName(ev.target.value)} required />
          </label>
          <label>Bind host
            <input className="field" value={host} onChange={(ev) => setHost(ev.target.value)} />
          </label>
          <label>Port
            <input className="field" type="number" value={port}
              onChange={(ev) => setPort(ev.target.value)} />
          </label>
          <label>Public host (redirector)
            <input className="field" value={publicHost}
              onChange={(ev) => setPublicHost(ev.target.value)} />
          </label>
          {type === 'dns' && (
            <label>Domain
              <input className="field" value={domain} onChange={(ev) => setDomain(ev.target.value)} required />
            </label>
          )}
          {(type === 'http' || type === 'quic' || type === 'websocket') && (
            <>
              <label>TLS
                <select value={tlsMode} onChange={(ev) => setTlsMode(ev.target.value)}>
                  <option value="server">server (self-signed)</option>
                  <option value="mtls">mTLS</option>
                  <option value="none">none</option>
                </select>
              </label>
              <label>Certificate
                <select value={cert} onChange={(ev) => setCert(ev.target.value)}>
                  <option value="">—</option>
                  {certs.certs.map((c) => <option key={c}>{c}</option>)}
                </select>
              </label>
              <label>Key
                <select value={key} onChange={(ev) => setKey(ev.target.value)}>
                  <option value="">—</option>
                  {certs.keys.map((c) => <option key={c}>{c}</option>)}
                </select>
              </label>
              <label>CA
                <select value={ca} onChange={(ev) => setCa(ev.target.value)}>
                  <option value="">—</option>
                  {certs.cas.map((c) => <option key={c}>{c}</option>)}
                </select>
              </label>
            </>
          )}
          <label className="span2">Profiles
            <div className="chips">
              {prof.length === 0 && <span className="muted small">none</span>}
              {prof.map((p) => (
                <label key={p.name} className="chip" title={p.description}>
                  <input type="checkbox" checked={profiles.includes(p.name)}
                    onChange={(ev) => setProfiles(ev.target.checked
                      ? [...profiles, p.name]
                      : profiles.filter((x) => x !== p.name))} />
                  {p.name}
                </label>
              ))}
            </div>
          </label>
        </div>
        {err && <div className="err-line">{err}</div>}
        <div className="modal-foot">
          {e && props.onDelete && (
            <button type="button" className="btn" onClick={props.onDelete}>Delete</button>
          )}
          <span className="grow" />
          <button type="button" className="btn" onClick={props.onClose}>Cancel</button>
          <button className="btn primary" disabled={busy || !name.trim()}>
            {busy ? 'saving…' : e ? 'Save' : 'Create'}
          </button>
        </div>
      </form>
    </div>
  )
}
