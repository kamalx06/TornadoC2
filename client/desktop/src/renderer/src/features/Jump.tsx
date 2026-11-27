import { useState } from 'react'
import type { Beacon, HealthRow } from '../../../shared/ipc'
import { invoke } from '../hooks'

export default function Jump(props: {
  beacons: Beacon[]
  listeners: HealthRow[]
  onClose: () => void
  onToast: (t: string, k?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const [method, setMethod] = useState('psexec')
  const [target, setTarget] = useState('')
  const [beacon, setBeacon] = useState<number>(props.beacons[0]?.id ?? 0)
  const [listener, setListener] = useState(props.listeners[0]?.id ?? '')
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [service, setService] = useState('')
  const [cleanup, setCleanup] = useState(true)
  const [busy, setBusy] = useState(false)

  const go = async (): Promise<void> => {
    setBusy(true)
    try {
      const r = (await invoke('jump', {
        id: beacon, method, target, listener, user, pass, service,
        noCleanup: !cleanup
      })) as { stage: { url: string } }
      props.onToast(`jump queued via ${r.stage.url}`, 'ok')
      props.onClose()
    } catch (e) {
      props.onToast((e as Error).message, 'err')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="modal" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <form
        className="modal-card"
        role="dialog"
        aria-modal="true"
        aria-label="Jump"
        onSubmit={(e) => {
          e.preventDefault()
          void go()
        }}
      >
        <h2>Lateral movement</h2>
        <div className="modal-body grid2">
          <label>Method
            <select value={method} onChange={(e) => setMethod(e.target.value)}>
              {['psexec', 'winrm', 'wmi', 'scshell'].map((m) => <option key={m}>{m}</option>)}
            </select>
          </label>
          <label>From beacon
            <select value={beacon} onChange={(e) => setBeacon(Number(e.target.value))}>
              {props.beacons.map((b) => (
                <option key={b.id} value={b.id}>#{b.id} {b.display_name}</option>
              ))}
            </select>
          </label>
          <label>Target host
            <input className="field" value={target} onChange={(e) => setTarget(e.target.value)} required />
          </label>
          <label>Listener
            <select value={listener} onChange={(e) => setListener(e.target.value)}>
              {props.listeners.filter((l) => l.status === 'running').map((l) => (
                <option key={l.id} value={l.id}>{l.name}</option>
              ))}
            </select>
          </label>
          <label>User (blank = token)
            <input className="field" value={user} onChange={(e) => setUser(e.target.value)} />
          </label>
          <label>Password
            <input className="field" type="password" value={pass} onChange={(e) => setPass(e.target.value)} />
          </label>
          <label>Service
            <input className="field" value={service} onChange={(e) => setService(e.target.value)} placeholder="default" />
          </label>
          <label className="check">
            <input type="checkbox" checked={cleanup} onChange={(e) => setCleanup(e.target.checked)} />
            Clean up service and payload
          </label>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn" onClick={props.onClose}>Cancel</button>
          <button className="btn primary" disabled={busy || !target || !beacon}>
            {busy ? 'staging…' : 'Run jump'}
          </button>
        </div>
      </form>
    </div>
  )
}
