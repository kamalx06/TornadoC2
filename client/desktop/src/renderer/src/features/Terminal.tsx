import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import type { Beacon } from '../../../shared/ipc'
import { invoke } from '../hooks'
import {
  append, clearTranscript, getTranscript, subscribe, transcriptText, type Line
} from '../lib/transcripts'
import { matchVerbs, verbsFor } from '../lib/verbs'
import EmptyState from '../ui/EmptyState'
import IconButton from '../ui/IconButton'
import { Toolbar, ToolbarSpacer, ToolbarTitle } from '../ui/Toolbar'

function decode(s: string): string {
  try {
    const raw = atob(s)
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  } catch {
    return s
  }
}

const stamp = (ts: number): string =>
  new Date(ts).toLocaleTimeString([], { hour12: false })

export default function Terminal(props: {
  beacon: Beacon | null
  onToast: (text: string, kind?: 'ok' | 'err' | 'info') => void
  prefill?: { text: string; n: number } | null
  onPrefillUsed?: () => void
}): JSX.Element {
  const id = props.beacon?.id ?? 0
  const [lines, setLines] = useState<Line[]>([])
  const [cmd, setCmd] = useState('')
  const [busy, setBusy] = useState(false)
  const [shellOn, setShellOn] = useState(false)
  const [raw, setRaw] = useState(false)
  const [menu, setMenu] = useState<string[]>([])
  const [active, setActive] = useState(0)
  const [verbs, setVerbs] = useState<string[]>([])
  const [histAt, setHistAt] = useState(-1)
  const [draft, setDraft] = useState('')
  const scroller = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const abort = useRef(false)
  const liveId = useRef(id)

  const history = useMemo(
    () => lines.filter((l) => l.kind === 'in').map((l) => l.text).slice(-100),
    [lines])

  const push = useCallback((line: Omit<Line, 'id' | 'ts'>) => {
    if (!id) return
    append(id, line)
    if (liveId.current === id) setLines(getTranscript(id))
  }, [id])

  useEffect(() => {
    if (!id) return
    return subscribe(id, () => setLines(getTranscript(id)))
  }, [id])

  useEffect(() => {
    liveId.current = id
    if (!id) { setLines([]); return }
    setLines(getTranscript(id))
    setCmd('')
    setShellOn(false)
    setBusy(false)
    setMenu([])
    setActive(0)
    setHistAt(-1)
  }, [id])

  useEffect(() => {
    if (!props.prefill?.n || !id) return
    setCmd(props.prefill.text)
    setMenu([])
    props.onPrefillUsed?.()
    input.current?.focus()
  }, [props.prefill?.n]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!props.beacon) return
    let live = true
    void verbsFor(props.beacon.os).then((v) => { if (live) setVerbs(v) })
    return () => { live = false }
  }, [props.beacon?.os])

  useEffect(() => {
    if (cmd) setMenu(matchVerbs(verbs, cmd))
  }, [verbs]) // eslint-disable-line react-hooks/exhaustive-deps

  const virt = useVirtualizer({
    count: lines.length,
    getScrollElement: () => scroller.current,
    estimateSize: () => 22,
    getItemKey: (i) => lines[i]?.id ?? i,
    overscan: 24,
    anchorTo: 'end',
    followOnAppend: true
  })

  const suggest = useCallback((value: string) => {
    if (!value || value.includes(' ')) { setMenu([]); return }
    setMenu(matchVerbs(verbs, value))
    setActive(0)
  }, [verbs])

  const complete = (v: string): void => {
    setCmd(`${v} `)
    setMenu([])
    setHistAt(-1)
    input.current?.focus()
  }

  const poll = async (taskId: string): Promise<void> => {
    for (let i = 0; i < 120; i++) {
      if (abort.current) {
        push({ kind: 'sys', text: `wait aborted — task ${taskId} continues` })
        return
      }
      const r = (await invoke('task.result', {
        id, taskId, wait: 2
      })) as { ready?: boolean; output?: string; error?: string }
      if (r.ready) {
        if (r.output) {
          const b64 = r.output
          push({ kind: 'out', text: decode(b64), raw: b64 })
        }
        if (r.error) push({ kind: 'err', text: r.error })
        return
      }
    }
    push({ kind: 'sys', text: `task ${taskId} queued; no result yet` })
  }

  const send = async (): Promise<void> => {
    const value = cmd.trim()
    if (!id || !value || busy) return
    push({ kind: 'in', text: value })
    setCmd('')
    setMenu([])
    setHistAt(-1)
    setBusy(true)
    abort.current = false
    try {
      if (shellOn) {
        const r = (await invoke('shell', {
          id, action: 'exec', command: value
        }, 90_000)) as { output?: string; error?: string }
        if (r.output) {
          const b64 = r.output
          push({ kind: 'out', text: decode(b64), raw: b64 })
        }
        if (r.error) push({ kind: 'err', text: r.error })
      } else {
        const [verb, ...args] = value.split(/\s+/)
        const r = (await invoke('task', { id, verb, args })) as { task_id?: string }
        if (!r.task_id) throw new Error('not queued')
        await poll(r.task_id)
      }
    } catch (e) {
      push({ kind: 'err', text: (e as Error).message })
    } finally {
      setBusy(false)
    }
  }

  const startShell = async (): Promise<void> => {
    try {
      await invoke('shell', { id, action: 'start' })
      setShellOn(true)
      push({ kind: 'sys', text: 'shell started' })
    } catch (e) { props.onToast((e as Error).message, 'err') }
  }

  const stopShell = async (): Promise<void> => {
    abort.current = true
    await invoke('shell', { id, action: 'stop' }).catch(() => undefined)
    setShellOn(false)
    push({ kind: 'sys', text: 'shell stopped' })
  }

  const onKey = (e: React.KeyboardEvent<HTMLInputElement>): void => {
    if (menu.length) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setActive((a) => (a + 1) % menu.length)
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setActive((a) => (a - 1 + menu.length) % menu.length)
        return
      }
      if (e.key === 'Tab' || (e.key === 'Enter' && menu[active])) {
        e.preventDefault()
        if (e.key === 'Enter' &&
            menu[active]!.toLowerCase() === cmd.trim().toLowerCase()) {
          setMenu([])
          void send()
        } else {
          complete(menu[active]!)
        }
        return
      }
      if (e.key === 'Escape') { e.preventDefault(); setMenu([]); return }
    }
    if (e.key === 'ArrowUp' && !menu.length && history.length) {
      e.preventDefault()
      const next = Math.min(history.length - 1, histAt + 1)
      if (histAt === -1) setDraft(cmd)
      setHistAt(next)
      setCmd(history[history.length - 1 - next] ?? '')
      return
    }
    if (e.key === 'ArrowDown' && !menu.length && histAt >= 0) {
      e.preventDefault()
      const next = histAt - 1
      setHistAt(next)
      setCmd(next < 0 ? draft : (history[history.length - 1 - next] ?? ''))
      return
    }
    if (e.key === 'Tab' && !cmd.includes(' ')) {
      e.preventDefault()
      const first = matchVerbs(verbs, cmd)[0]
      if (first) complete(first)
      return
    }
    if (e.key === 'Enter') {
      e.preventDefault()
      void send()
    }
    if (e.key === 'l' && e.ctrlKey) {
      e.preventDefault()
      clearTranscript(id)
      setLines([])
    }
  }

  if (!props.beacon) {
    return <EmptyState glyph="⌨" title="No target selected"
      hint="pick a beacon in Targets to open its console" />
  }

  return (
    <div className="view terminal">
      <Toolbar label="Terminal">
        <ToolbarTitle>Terminal</ToolbarTitle>
        <span className="mono muted">#{props.beacon.id}</span>
        <span className={`transport ${shellOn ? 'shell' : ''}`}>
          {shellOn ? 'SHELL' : 'TASK'}
        </span>
        <ToolbarSpacer />
        <IconButton label={raw ? 'Show decoded text' : 'Show raw base64'}
          on={raw} onClick={() => setRaw((r) => !r)}>◫</IconButton>
        <IconButton label="Save transcript" onClick={() => {
          const name = `transcript-${props.beacon?.id}.txt`
          void window.t2.saveFile(name, transcriptText(id))
            .then((p) => { if (p) props.onToast(`saved ${p}`, 'ok') })
            .catch((e) => props.onToast((e as Error).message, 'err'))
        }}>⤓</IconButton>
        <IconButton label="Clear transcript" onClick={() => {
          clearTranscript(id)
          setLines([])
        }}>⌫</IconButton>
      </Toolbar>

      <div className="term-bar">
        {shellOn
          ? <button className="btn tiny" onClick={() => void stopShell()}>Stop shell</button>
          : <button className="btn tiny" onClick={() => void startShell()}>Start shell</button>}
        {busy && (
          <button className="btn tiny" onClick={() => { abort.current = true }}>
            Interrupt wait
          </button>
        )}
        <span className="grow" />
        <span className="muted small mono">
          {lines.length} lines · ↑ history · Tab complete
        </span>
      </div>

      <div className="term-scroll" ref={scroller} role="log" aria-live="polite"
        aria-label={`Terminal for ${props.beacon.display_name ?? props.beacon.id}`}
        tabIndex={0} onMouseDown={() => input.current?.focus()}>
        {lines.length === 0 && (
          <EmptyState glyph="›_" title="Console ready"
            hint="type a verb, or start a shell for a persistent prompt" />
        )}
        <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
          {virt.getVirtualItems().map((v) => {
            const l = lines[v.index]
            if (!l) return null
            return (
              <div key={l.id} className={`term-line ${l.kind}`}
                data-index={v.index}
                style={{
                  position: 'absolute', left: 0, right: 0,
                  transform: `translateY(${v.start}px)`
                }}>
                <time className="mono term-time" dateTime={new Date(l.ts).toISOString()}>
                  {stamp(l.ts)}
                </time>
                <span className="term-mark" aria-hidden="true">
                  {l.kind === 'in' ? '$' : l.kind === 'err' ? '!' : l.kind === 'sys' ? '·' : ' '}
                </span>
                <span className="term-text">{raw && l.raw ? l.raw : l.text}</span>
              </div>
            )
          })}
        </div>
      </div>

      <div className="term-prompt">
        <span className="term-ps1" aria-hidden="true">{shellOn ? '>' : '$'}</span>
        <input ref={input} className="term-input" value={cmd} autoFocus
          role="combobox" aria-label="Command" aria-autocomplete="list"
          aria-haspopup="listbox"
          aria-expanded={menu.length > 0}
          aria-controls="term-menu" disabled={busy && !shellOn}
          placeholder={shellOn ? 'shell command' : 'verb args'}
          onChange={(e) => { setCmd(e.target.value); suggest(e.target.value) }}
          onKeyDown={onKey} />
        <button className="btn tiny" disabled={!cmd.trim() || busy}
          onClick={() => void send()}>Run</button>
        {menu.length > 0 && (
          <ul className="term-menu" id="term-menu" role="listbox"
            aria-label="Verb suggestions">
            {menu.map((m, i) => (
              <li key={m} role="option" aria-selected={i === active}
                onMouseDown={(e) => { e.preventDefault(); complete(m) }}>
                {m}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
