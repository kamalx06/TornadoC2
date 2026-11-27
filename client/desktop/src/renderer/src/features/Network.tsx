import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Beacon } from '../../../shared/ipc'
import { parseConnections, parseProcesses, type Conn, type Process } from '../lib/data'
import { runVerb } from '../lib/tasks'
import { Confirm } from '../ui/Prompt'
import DataGrid, { type Column } from '../ui/DataGrid'

export default function Network(props: {
  beacon: Beacon | null
  caps: string[]
  onToast: (text: string, kind?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const [rows, setRows] = useState<Conn[]>([])
  const [procs, setProcs] = useState<Map<number, Process>>(new Map())
  const [raw, setRaw] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [auto, setAuto] = useState(false)
  const [rawMode, setRawMode] = useState(false)
  const [kill, setKill] = useState<Process | null>(null)
  const abort = useRef<AbortController | null>(null)
  const id = props.beacon?.id ?? 0
  const canUse = props.caps.includes('beacon.use')

  const collect = useCallback(async (silent = false) => {
    if (!id) return
    abort.current?.abort()
    const ac = new AbortController()
    abort.current = ac
    setBusy(true)
    if (!silent) setErr('')
    try {
      const [net, ps] = await Promise.all([
        runVerb(id, 'netstat', [], ac.signal),
        runVerb(id, 'ps', [], ac.signal).catch(() => ({ output: '' }))
      ])
      if (net.error) throw new Error(net.error)
      setRaw(net.output)
      setRows(parseConnections(net.output))
      const map = new Map<number, Process>()
      for (const p of parseProcesses(ps.output ?? '')) map.set(p.pid, p)
      setProcs(map)
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
    setProcs(new Map())
    setRaw('')
    setErr('')
    if (id) void collect()
    return () => abort.current?.abort()
  }, [id]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!auto || !id) return
    const t = setInterval(() => void collect(true), 10_000)
    return () => clearInterval(t)
  }, [auto, id, collect])

  const columns: Array<Column<Conn>> = useMemo(() => [
    { key: 'proto', label: 'PROTO', width: '62px', mono: true,
      sort: (a, b) => a.proto.localeCompare(b.proto), render: (c) => c.proto },
    { key: 'local', label: 'LOCAL', width: 'minmax(140px, 1fr)', mono: true,
      render: (c) => c.local },
    { key: 'remote', label: 'REMOTE', width: 'minmax(140px, 1fr)', mono: true,
      render: (c) => c.remote },
    { key: 'state', label: 'STATE', width: '100px',
      render: (c) => <span className="state">{c.state}</span> },
    { key: 'pid', label: 'PID', width: '66px', mono: true,
      render: (c) => c.pid ?? '—' },
    { key: 'proc', label: 'PROCESS', width: 'minmax(110px, 0.7fr)',
      render: (c) => (c.pid ? procs.get(c.pid)?.name ?? '?' : '—') }
  ], [procs])

  const killPid = async (p: Process): Promise<void> => {
    setKill(null)
    try {
      const args = props.beacon?.os && /win/i.test(props.beacon.os)
        ? ['taskkill', '/PID', String(p.pid), '/F']
        : ['kill', '-9', String(p.pid)]
      const r = await runVerb(id, 'exec', args)
      if (r.error) throw new Error(r.error)
      props.onToast(`kill ${p.pid} queued`, 'ok')
      void collect(true)
    } catch (e) {
      props.onToast((e as Error).message, 'err')
    }
  }

  if (!props.beacon) {
    return <DataGrid<Conn> label="Network" rows={[]} columns={columns}
      getKey={(c) => `${c.proto}${c.local}${c.remote}${c.pid ?? ''}`}
      rowText={() => ''} onRefresh={() => undefined}
      emptyTitle="No target selected" emptyHint="pick a beacon in Targets" />
  }

  return (
    <>
      <DataGrid<Conn> label="Network" rows={rows} columns={columns}
        getKey={(c) => `${c.proto}${c.local}${c.remote}${c.pid ?? ''}`}
        rowText={(c) => `${c.proto} ${c.local} ${c.remote} ${c.state} ${c.pid ?? ''} ${c.pid ? procs.get(c.pid)?.name ?? '' : ''}`}
        actions={[
          { id: 'copy', label: 'Copy', onSelect: (c) => {
            void window.t2.clipboard(`${c.local} -> ${c.remote}`, 30_000)
            props.onToast('endpoints copied', 'ok')
          } },
          { id: 'kill', label: 'Kill', onSelect: (c) => {
            const p = c.pid ? procs.get(c.pid) : undefined
            if (p) setKill(p)
          }, disabled: (c) => !canUse || !c.pid || !procs.has(c.pid!) }
        ]}
        onRefresh={() => void collect()} busy={busy} error={err}
        raw={raw} rawMode={rawMode} onRaw={() => setRawMode((r) => !r)}
        auto={auto} onAuto={() => setAuto((a) => !a)}
        emptyTitle="No connections" emptyHint="Refresh to collect netstat output"
        hint={props.beacon.os && /win/i.test(props.beacon.os)
          ? 'Windows rows carry an owning PID; Linux rows correlate when available.'
          : 'Linux netstat has no owning PID, so PROCESS stays unknown.'} />
      {kill && (
        <Confirm title="Kill process" yes="Kill"
          body={`Send kill to ${kill.name} (${kill.pid})?`}
          onClose={() => setKill(null)} onYes={() => void killPid(kill)} />
      )}
    </>
  )
}
