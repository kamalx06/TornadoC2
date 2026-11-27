import { useCallback, useEffect, useRef, useState } from 'react'
import type { Beacon } from '../../../shared/ipc'
import { parseProcesses, type Process } from '../lib/data'
import { runVerb } from '../lib/tasks'
import { Confirm } from '../ui/Prompt'
import DataGrid, { type Column } from '../ui/DataGrid'

export default function Processes(props: {
  beacon: Beacon | null
  caps: string[]
  onToast: (text: string, kind?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const [rows, setRows] = useState<Process[]>([])
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
      const r = await runVerb(id, 'ps', [], ac.signal)
      if (r.error) throw new Error(r.error)
      setRaw(r.output)
      setRows(parseProcesses(r.output))
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
    if (id) void collect()
    return () => abort.current?.abort()
  }, [id]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!auto || !id) return
    const t = setInterval(() => void collect(true), 10_000)
    return () => clearInterval(t)
  }, [auto, id, collect])

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

  const columns: Array<Column<Process>> = [
    { key: 'pid', label: 'PID', width: '70px', mono: true,
      sort: (a, b) => a.pid - b.pid, render: (p) => p.pid },
    { key: 'name', label: 'PROCESS', width: 'minmax(120px, 0.7fr)',
      render: (p) => p.name, sort: (a, b) => a.name.localeCompare(b.name) },
    { key: 'cmd', label: 'COMMAND', width: 'minmax(200px, 2fr)',
      render: (p) => p.cmd }
  ]

  if (!props.beacon) {
    return <DataGrid<Process> label="Processes" rows={[]} columns={columns}
      getKey={(p) => p.pid} rowText={(p) => `${p.pid} ${p.name} ${p.cmd}`}
      onRefresh={() => undefined} emptyTitle="No target selected"
      emptyHint="pick a beacon in Targets" />
  }

  const actions = [
    { id: 'copy', label: 'Copy', onSelect: (p: Process) => {
      void window.t2.clipboard(String(p.pid), 30_000)
      props.onToast(`pid ${p.pid} copied`, 'ok')
    } },
    { id: 'kill', label: 'Kill', onSelect: (p: Process) => setKill(p),
      disabled: () => !canUse }
  ]

  return (
    <>
      <DataGrid<Process> label="Processes" rows={rows} columns={columns}
        getKey={(p) => p.pid} rowText={(p) => `${p.pid} ${p.name} ${p.cmd}`}
        actions={actions}
        onRefresh={() => void collect()} busy={busy} error={err}
        raw={raw} rawMode={rawMode} onRaw={() => setRawMode((r) => !r)}
        auto={auto} onAuto={() => setAuto((a) => !a)}
        emptyTitle="No process list"
        emptyHint={canUse ? 'Refresh to collect ps output' : 'beacon.use is required'}
        hint={canUse ? 'Kill uses taskkill /F or kill -9.' : undefined} />
      {kill && (
        <Confirm title="Kill process" yes="Kill"
          body={`Send kill to ${kill.name} (${kill.pid})?`}
          onClose={() => setKill(null)} onYes={() => void killPid(kill)} />
      )}
    </>
  )
}
