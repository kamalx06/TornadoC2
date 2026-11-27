import { useEffect, useMemo, useState } from 'react'
import { usePoll, invoke } from '../hooks'
import EmptyState from '../ui/EmptyState'
import IconButton from '../ui/IconButton'
import StatusPill from '../ui/StatusPill'
import { Confirm } from '../ui/Prompt'
import { Toolbar, ToolbarSpacer, ToolbarTitle } from '../ui/Toolbar'

type Job = {
  id: string; kind: string; state: string; done: number; total: number
  error?: string; local?: string; remote?: string; out?: string
}
type Tracked = Job & { first: number; last: number }

export default function Jobs(props: {
  onToast?: (text: string, kind?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const { data, error } = usePoll<{ jobs: Job[] }>('job.list', {}, 1_000)
  const [seen, setSeen] = useState<Map<string, Tracked>>(new Map())
  const [cancel, setCancel] = useState<Job | null>(null)
  const [updated, setUpdated] = useState(0)
  const [, tick] = useState(0)

  useEffect(() => {
    if (!data?.jobs) return
    setUpdated(Date.now())
    setSeen((prev) => {
      const next = new Map(prev)
      for (const j of data.jobs ?? []) {
        const old = next.get(j.id)
        next.set(j.id, { ...j, first: old?.first ?? Date.now(), last: Date.now() })
      }
      return next
    })
  }, [data?.jobs])

  useEffect(() => {
    const t = setInterval(() => tick((n) => n + 1), 3_000)
    return () => clearInterval(t)
  }, [])

  const jobs = useMemo(() => [...seen.values()].sort((a, b) => {
    const live = Number(b.state === 'running') - Number(a.state === 'running')
    return live || b.last - a.last
  }), [seen])

  const running = jobs.filter((j) => j.state === 'running').length
  const failed = jobs.filter((j) => j.state === 'error').length
  const stale = updated > 0 && Date.now() - updated > 5_000

  const doCancel = async (j: Job): Promise<void> => {
    setCancel(null)
    try {
      await invoke('job.cancel', { id: j.id })
      props.onToast?.(`cancel ${j.kind} ${j.id} requested`, 'ok')
    } catch (e) { props.onToast?.((e as Error).message, 'err') }
  }

  return (
    <div className="view jobs">
      <Toolbar label="Jobs">
        <ToolbarTitle>Jobs</ToolbarTitle>
        <span className="pill">{jobs.length}</span>
        {running > 0 && <StatusPill tone="info">{running} running</StatusPill>}
        {failed > 0 && <StatusPill tone="err">{failed} failed</StatusPill>}
        {stale && <StatusPill tone="warn">stale</StatusPill>}
        <ToolbarSpacer />
        <span className="muted small">finished jobs stay here</span>
      </Toolbar>

      {error && <div className="banner err" role="alert">job stream: {error}</div>}

      <div className="table-wrap">
        {jobs.length === 0 && (
          <EmptyState glyph="⇅" title="No transfers or builds"
            hint="uploads, downloads and builds appear here" />
        )}
        {jobs.map((j) => {
          const pct = j.total ? Math.min(100, (j.done / j.total) * 100) : 0
          return (
            <div key={j.id} className="row job" data-state={j.state}>
              <span className="mono">{j.kind}</span>
              <span className="ellipsis muted" title={j.local || j.remote || j.out}>
                {j.local || j.remote || j.out || '—'}
              </span>
              <span className={j.state === 'error' ? 'errc' : j.state === 'done' ? 'okc' : 'muted'}>
                {j.state}
              </span>
              <div className="progress" role="progressbar" aria-valuenow={Math.round(pct)}
                aria-valuemin={0} aria-valuemax={100}
                aria-label={`${j.kind} progress`}>
                <div style={{ width: `${pct}%` }} />
              </div>
              <span className="muted small">{j.done}/{j.total}</span>
              <span className="mono muted small">{j.id.slice(0, 8)}</span>
              {j.state === 'running' ? (
                <button className="btn tiny" onClick={() => setCancel(j)}>Cancel</button>
              ) : <IconButton label={`Copy ${j.kind} id`} onClick={() => {
                void window.t2.clipboard(j.id, 30_000)
                props.onToast?.(`${j.id} copied`, 'ok')
              }}>⧉</IconButton>}
              {j.error && (
                <span className="err-line small ellipsis" title={j.error}>{j.error}</span>
              )}
            </div>
          )
        })}
      </div>

      {cancel && (
        <Confirm title="Cancel job" yes="Cancel job"
          body={`Abort ${cancel.kind} ${cancel.id}?`}
          onClose={() => setCancel(null)} onYes={() => void doCancel(cancel)} />
      )}
    </div>
  )
}
