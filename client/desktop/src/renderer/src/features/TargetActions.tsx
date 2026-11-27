import { useCallback, useState } from 'react'
import type { Beacon } from '../../../shared/ipc'
import { invoke } from '../hooks'
import IconButton from '../ui/IconButton'
import StatusPill from '../ui/StatusPill'
import { Toolbar, ToolbarGroup, ToolbarSpacer } from '../ui/Toolbar'
import Prompt, { Confirm } from '../ui/Prompt'
import { append } from '../lib/transcripts'

function b64decode(s: string): string {
  try {
    const raw = atob(s)
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  } catch {
    return s
  }
}

function Fact(props: {
  label: string
  value?: string | number
  mono?: boolean
  onCopy?: () => void
}): JSX.Element {
  const text = props.value === undefined || props.value === '' ? '—' : String(props.value)
  return (
    <div className="fact">
      <span className="fact-k">{props.label}</span>
      <span className={`fact-v${props.mono ? ' mono' : ''}`}>{text}</span>
      {props.onCopy && text !== '—' && (
        <IconButton label={`Copy ${props.label}`} onClick={props.onCopy}>⧉</IconButton>
      )}
    </div>
  )
}

export default function TargetActions(props: {
  caps?: string[]
  beacon: Beacon
  onToast: (text: string, kind?: 'ok' | 'err' | 'info') => void
  onChanged: () => void
  onConsole: (command?: string) => void
}): JSX.Element {
  const { beacon, onToast, onChanged } = props
  const [prompt, setPrompt] = useState<null | 'alias' | 'tag' | 'note' | 'upload' | 'download' | 'bof'>(null)
  const [confirmForget, setConfirmForget] = useState(false)
  const [uploadLocal, setUploadLocal] = useState('')
  const [assembly, setAssembly] = useState('')
  const [socksPort, setSocksPort] = useState('1080')
  const [socksOn, setSocksOn] = useState(false)
  const [notes, setNotes] = useState<string[]>([])
  const can = (c: string): boolean => (props.caps ?? []).includes(c)

  const copy = useCallback((value: unknown, label: string) => {
    const text = String(value ?? '')
    if (!text) return
    void window.t2.clipboard(text, 30_000).then(
      () => onToast(`${label} copied (clears in 30s)`, 'ok'),
      () => onToast('clipboard unavailable', 'err'))
  }, [onToast])

  const simple = useCallback(
    async (method: string, params: Record<string, unknown>, ok: string) => {
      try {
        await invoke(method, params)
        onToast(ok, 'ok')
        onChanged()
      } catch (e) {
        onToast((e as Error).message, 'err')
      }
    },
    [onToast, onChanged]
  )

  const who = beacon.display_name || 'unknown'

  return (
    <div className="view inspector">
      <Toolbar label={`Target ${beacon.id}`}>
        <span className="insp-id mono">#{beacon.id}</span>
        <span className="insp-who ellipsis" title={who}>{who}</span>
        <StatusPill tone={beacon.alive ? 'ok' : 'idle'}>
          {beacon.alive ? 'live' : 'stale'}
        </StatusPill>
        <ToolbarSpacer />
        <IconButton label="Copy beacon id"
          onClick={() => copy(beacon.id, 'beacon id')}>⧉</IconButton>
      </Toolbar>

      <div className="inspector-body selectable">
        <details className="insp" open>
          <summary>Identity</summary>
          <div className="facts">
            <Fact label="Host" value={beacon.display_name}
              onCopy={() => copy(beacon.display_name, 'host')} />
            <Fact label="OS" value={beacon.os && `${beacon.os}/${beacon.arch}`} />
            <Fact label="Privilege"
              value={`${beacon.privilege || 'user'}${beacon.elevated ? ' (elevated)' : ''}`} />
            <Fact label="Integrity" value={beacon.integrity} />
            <Fact label="Parent" value={beacon.parent_name} />
            <Fact label="Fingerprint" value={beacon.fingerprint} mono
              onCopy={() => copy(beacon.fingerprint, 'fingerprint')} />
            <Fact label="Alias" value={beacon.alias} />
          </div>
          <ToolbarGroup>
            <button className="btn" onClick={() => setPrompt('alias')}>Alias…</button>
            <button className="btn" onClick={() => setPrompt('tag')}>Tag…</button>
            <button className="btn" onClick={() => setPrompt('note')}>Note…</button>
          </ToolbarGroup>
        </details>

        <details className="insp" open>
          <summary>Session</summary>
          <div className="facts">
            <Fact label="Last seen" value={`${beacon.last_seen_age ?? 0}s`} />
            <Fact label="Check-ins" value={beacon.checkins} mono />
            <Fact label="Sleep" value={beacon.sleep_interval && `${beacon.sleep_interval}s`} />
            <Fact label="Last address" value={beacon.last_addr} mono
              onCopy={() => copy(beacon.last_addr, 'address')} />
            <Fact label="Viewers"
              value={beacon.viewers?.map((v) => v.name).join(', ')} />
          </div>
        </details>

        <details className="insp" open>
          <summary>Execution</summary>
          <p className="insp-note">
            Task and shell output live in the console and its per-target
            transcript.
          </p>
          <div className="quick">
            <button className="btn tiny" onClick={() => props.onConsole()}>
              Open console
            </button>
            {['whoami', 'pwd', 'ls', 'info', 'ps', 'netstat', 'screenshot'].map((v) => (
              <button key={v} className="btn tiny"
                onClick={() => props.onConsole(v)}>{v}</button>
            ))}
          </div>
        </details>

        <details className="insp">
          <summary>Payloads</summary>
          <div className="quick">
            <button className="btn" onClick={() => setPrompt('bof')}>Run BOF…</button>
            <button className="btn" onClick={async () => {
              const path = await window.t2.pickOpen()
              if (path) setAssembly(path)
            }}>Assembly…</button>
          </div>
          {assembly && <p className="mono small">{assembly.split('/').pop()}</p>}
        </details>

        <details className="insp">
          <summary>Notes ({notes.length})</summary>
          <div className="quick">
            <button className="btn tiny" onClick={() => setPrompt('note')}>Add note</button>
            <button className="btn tiny" onClick={async () => {
              await invoke('beacon.note', { id: beacon.id, op: 'list' }).then((r) => {
                const n = (r as { notes?: Array<{ text: string }> }).notes ?? []
                setNotes(n.map((x) => x.text))
              }).catch((e) => onToast((e as Error).message, 'err'))
            }}>Load notes</button>
            <button className="btn tiny" disabled={notes.length === 0} onClick={async () => {
              await invoke('beacon.note', { id: beacon.id, op: 'clear' }).catch(() => undefined)
              setNotes([])
            }}>Clear</button>
          </div>
          {notes.length > 0 && <pre className="output" tabIndex={0}>{notes.join('\n---\n')}</pre>}
        </details>

        <details className="insp">
          <summary>Transfer</summary>
          <div className="quick">
            <button className="btn" onClick={async () => {
              const local = await window.t2.pickOpen()
              if (local) {
                setUploadLocal(local)
                setPrompt('upload')
              }
            }}>Upload…</button>
            <button className="btn" onClick={() => setPrompt('download')}>Download…</button>
          </div>
        </details>

        {can('beacon.socks') && (
          <details className="insp">
            <summary>Pivot</summary>
            <div className="quick">
              <input className="ui-input" style={{ width: 78 }} value={socksPort}
                onChange={(e) => setSocksPort(e.target.value)} aria-label="SOCKS port" />
              <button className="btn tiny" disabled={socksOn} onClick={async () => {
                try {
                  await invoke('socks', { id: beacon.id, action: 'start', port: Number(socksPort) })
                  setSocksOn(true)
                  onToast(`socks on 127.0.0.1:${socksPort}`, 'ok')
                } catch (e) { onToast((e as Error).message, 'err') }
              }}>Start SOCKS</button>
              <button className="btn tiny" disabled={!socksOn} onClick={async () => {
                await invoke('socks', { action: 'stop' }).catch(() => undefined)
                setSocksOn(false)
              }}>Stop</button>
            </div>
          </details>
        )}

        <details className="insp">
          <summary>Danger</summary>
          <div className="quick">
            <button className="btn" onClick={() => props.onConsole('kill')}>Kill</button>
            <button className="btn" onClick={() => setConfirmForget(true)}>Forget…</button>
          </div>
        </details>
      </div>

      {prompt === 'alias' && (
        <Prompt title="Set alias" label="alias" initial={beacon.alias}
          onClose={() => setPrompt(null)}
          onDone={(v) => { setPrompt(null); void simple('beacon.alias', { id: beacon.id, alias: v }, 'alias set') }} />
      )}
      {prompt === 'tag' && (
        <Prompt title="Add tag" label="tag" onClose={() => setPrompt(null)}
          onDone={(v) => { setPrompt(null); void simple('beacon.tag', { id: beacon.id, tag: v }, 'tagged') }} />
      )}
      {prompt === 'upload' && (
        <Prompt title="Remote path" label="/tmp/file" initial={uploadLocal.split('/').pop()}
          onClose={() => setPrompt(null)}
          onDone={(remote) => {
            setPrompt(null)
            void invoke('upload.start', { id: beacon.id, local: uploadLocal, remote })
              .then(() => onToast('upload queued', 'ok'))
              .catch((e) => onToast((e as Error).message, 'err'))
          }} />
      )}
      {prompt === 'bof' && (
        <Prompt title="Installed BOF" label="name [args]" onClose={() => setPrompt(null)}
          onDone={async (v) => {
            setPrompt(null)
            const parts = v.split(/\s+/)
            try {
              const r = (await invoke('bof.run', {
                id: beacon.id, name: parts[0], args: parts.slice(1)
              }, 180_000)) as { output?: string; error?: string }
              props.onConsole()
              append(beacon.id, {
                kind: r.error ? 'err' : 'out',
                text: r.error ?? b64decode(r.output ?? '')
              })
              onToast('bof finished', r.error ? 'err' : 'ok')
            } catch (e) { onToast((e as Error).message, 'err') }
          }} />
      )}
      {assembly && (
        <Prompt title={`Assembly args for ${assembly.split('/').pop()}`} label="args" initial=""
          onClose={() => setAssembly('')}
          onDone={async (args) => {
            try {
              const r = (await invoke('assembly.run', {
                id: beacon.id, path: assembly,
                args: args.split(/\s+/).filter(Boolean)
              }, 180_000)) as { output?: string; error?: string }
              props.onConsole()
              append(beacon.id, {
                kind: r.error ? 'err' : 'out',
                text: r.error ?? b64decode(r.output ?? '')
              })
              onToast('assembly finished', r.error ? 'err' : 'ok')
            } catch (e) { onToast((e as Error).message, 'err') }
            setAssembly('')
          }} />
      )}
      {prompt === 'download' && (
        <Prompt title="Remote path" label="/etc/passwd" onClose={() => setPrompt(null)}
          onDone={(remote) => {
            setPrompt(null)
            void invoke('download.start', { id: beacon.id, remote })
              .then(() => onToast('download queued', 'ok'))
              .catch((e) => onToast((e as Error).message, 'err'))
          }} />
      )}
      {prompt === 'note' && (
        <Prompt title="Add note" label="note" onClose={() => setPrompt(null)}
          onDone={(v) => { setPrompt(null); void simple('beacon.note', { id: beacon.id, op: 'add', text: v }, 'note added') }} />
      )}
      {confirmForget && (
        <Confirm title="Forget beacon" body={`Remove #${beacon.id} from the session list?`}
          yes="Forget" onClose={() => setConfirmForget(false)}
          onYes={() => { setConfirmForget(false); void simple('beacon.forget', { id: beacon.id }, 'forgotten') }} />
      )}
    </div>
  )
}
