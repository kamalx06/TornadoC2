import { useCallback, useEffect, useRef, useState } from 'react'
import type { Beacon } from '../../../shared/ipc'
import { crumbs, parentPath, parseEntries, type Entry } from '../lib/data'
import { runVerb } from '../lib/tasks'
import { invoke } from '../hooks'
import DataGrid, { type Column } from '../ui/DataGrid'
import IconButton from '../ui/IconButton'

export default function Files(props: {
  beacon: Beacon | null
  caps: string[]
  onToast: (text: string, kind?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const [path, setPath] = useState('')
  const [draft, setDraft] = useState('')
  const [rows, setRows] = useState<Entry[]>([])
  const [raw, setRaw] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [rawMode, setRawMode] = useState(false)
  const abort = useRef<AbortController | null>(null)
  const id = props.beacon?.id ?? 0
  const canUse = props.caps.includes('beacon.use')

  const load = useCallback(async (target: string, silent = false) => {
    if (!id || !target) return
    abort.current?.abort()
    const ac = new AbortController()
    abort.current = ac
    setBusy(true)
    if (!silent) setErr('')
    try {
      const [dirs, files] = await Promise.all([
        runVerb(id, 'find', [target, '-type', 'd'], ac.signal),
        runVerb(id, 'find', [target, '-type', 'f'], ac.signal)
      ])
      if (dirs.error) throw new Error(dirs.error)
      setRaw(`${dirs.output}${files.output}`)
      setRows(parseEntries(dirs.output, files.output, target))
      setPath(target)
      setDraft(target)
      setErr('')
    } catch (e) {
      if ((e as Error).name === 'AbortError') return
      setErr((e as Error).message)
    } finally {
      if (!ac.signal.aborted) setBusy(false)
    }
  }, [id, canUse])

  useEffect(() => {
    setRows([])
    setRaw('')
    setErr('')
    setPath('')
    if (!id) return
    abort.current?.abort()
    const ac = new AbortController()
    abort.current = ac
    void (async () => {
      try {
        const pwd = await runVerb(id, 'pwd', [], ac.signal)
        const start = pwd.output.trim() || '/'
        if (!ac.signal.aborted) await load(start)
      } catch {
        if (!ac.signal.aborted) await load(props.beacon?.os && /win/i.test(props.beacon.os) ? 'C:\\' : '/')
      }
    })()
    return () => abort.current?.abort()
  }, [id]) // eslint-disable-line react-hooks/exhaustive-deps

  const columns: Array<Column<Entry>> = [
    { key: 'name', label: 'NAME', width: 'minmax(180px, 2fr)',
      sort: (a, b) => a.name.localeCompare(b.name), mono: true,
      render: (e) => (
        <button className={`file-name${e.dir ? ' dir' : ''}`}
          onClick={() => { if (e.dir) void load(e.path) }}>
          {e.dir ? '▸ ' : '· '}{e.name}
        </button>
      ) },
    { key: 'type', label: 'TYPE', width: '70px',
      render: (e) => (e.dir ? 'dir' : 'file') },
    { key: 'path', label: 'PATH', width: 'minmax(180px, 1fr)',
      render: (e) => e.path }
  ]

  const head = (
    <div className="files-bar">
      <IconButton label="Parent directory" disabled={!path || busy}
        onClick={() => void load(parentPath(path))}>↑</IconButton>
      <nav className="crumbs" aria-label="Path">
        {crumbs(path).map((c) => (
          <button key={c.path} type="button" className="crumb"
            onClick={() => void load(c.path)}>{c.label}</button>
        ))}
      </nav>
      <form className="files-go" onSubmit={(e) => {
        e.preventDefault()
        if (draft.trim()) void load(draft.trim())
      }}>
        <input className="ui-input" value={draft} onChange={(e) => setDraft(e.target.value)}
          aria-label="Directory path" placeholder="absolute path" />
        <button className="btn tiny" disabled={busy || !draft.trim()}>Go</button>
      </form>
    </div>
  )

  if (!props.beacon) {
    return (
      <>
        {head}
        <DataGrid<Entry> label="Files" rows={[]} columns={columns}
          getKey={(e) => e.path} rowText={(e) => e.path}
          onRefresh={() => undefined} emptyTitle="No target selected"
          emptyHint="pick a beacon in Targets" />
      </>
    )
  }

  return (
    <>
      {head}
      <DataGrid<Entry> label="Files" rows={rows} columns={columns}
        getKey={(e) => e.path} rowText={(e) => e.path}
        actions={[
          { id: 'open', label: 'Open', onSelect: (e) => { if (e.dir) void load(e.path) },
            disabled: (e) => !e.dir },
          { id: 'get', label: 'Download', onSelect: (e) => {
            void invoke('download.start', { id, remote: e.path })
              .then(() => props.onToast(`download ${e.name} queued`, 'ok'))
              .catch((x) => props.onToast((x as Error).message, 'err'))
          }, disabled: (e) => e.dir || !canUse },
          { id: 'copy', label: 'Copy', onSelect: (e) => {
            void window.t2.clipboard(e.path, 30_000)
            props.onToast('path copied', 'ok')
          } }
        ]}
        onActivate={(e) => { if (e.dir) void load(e.path) }}
        onRefresh={() => void load(path)} busy={busy} error={err}
        raw={raw} rawMode={rawMode} onRaw={() => setRawMode((r) => !r)}
        emptyTitle="Empty or unreadable directory"
        emptyHint="check the path, or use the raw view"
        hint={canUse ? 'find -type d / -type f, direct children only' : 'beacon.use is required'} />
    </>
  )
}
