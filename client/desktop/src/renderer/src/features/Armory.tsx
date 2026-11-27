import { useCallback, useEffect, useState } from 'react'
import { invoke } from '../hooks'

type Meta = {
  name: string
  format?: string
  description?: string
  version?: string
  installed?: boolean
  installed_version?: string
  sha256?: string
}

type Catalogue = {
  repo: string
  branch: string
  commit?: string
  fetched_at?: number
  stale?: boolean
  error?: string
  catalogue: Meta[]
  installed?: Record<string, unknown>
}

export default function Armory(props: {
  caps?: string[]
  onToast: (t: string, k?: 'ok' | 'err' | 'info') => void
}): JSX.Element {
  const [cat, setCat] = useState<Catalogue | null>(null)
  const [rows, setRows] = useState<Meta[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  const manage = (props.caps ?? []).includes('armory.manage')

  const load = useCallback(async (refresh = false) => {
    try {
      const r = (await invoke('armory.list', { refresh })) as Catalogue
      setCat(r)
      setRows(r.catalogue ?? [])
      setErr(r.error ?? '')
    } catch (e) {
      setErr((e as Error).message)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const act = useCallback(
    async (method: string, row: Meta) => {
      if (method === 'armory.uninstall' &&
          !window.confirm(`Remove ${row.name}?`)) return
      setBusy(row.name)
      try {
        const r = (await invoke(method, {
          names: [row.name], replace: true
        })) as { done?: Array<{ name: string }>; failed?: Array<{ error: string }> }
        const fail = r.failed?.[0]
        if (fail) throw new Error(fail.error)
        props.onToast(
          method === 'armory.uninstall'
            ? `removed ${row.name}`
            : method === 'armory.update'
              ? `updated ${row.name}` : `installed ${row.name}`, 'ok')
        await load()
      } catch (e) {
        props.onToast((e as Error).message, 'err')
        await load()
      } finally {
        setBusy('')
      }
    },
    [load, props]
  )

  const updateIndex = useCallback(async () => {
    setBusy('*')
    try {
      const r = (await invoke('armory.update', {})) as {
        count?: number; error?: string
      }
      props.onToast(`index: ${r.count ?? 0} entries`, 'ok')
      await load()
    } catch (e) {
      props.onToast((e as Error).message, 'err')
    } finally {
      setBusy('')
    }
  }, [load, props])

  const source = cat?.repo ?? 'https://github.com/kamalx06/tornadoc2-armory'

  return (
    <div className="view">
      <div className="pane-head">
        <span className="pane-title">ARMORY</span>
        <span className="pill">{rows.filter((r) => r.installed).length} installed</span>
        <span className="grow" />
        <button className="btn" disabled={Boolean(busy)} onClick={() => void updateIndex()}>
          Update index
        </button>
      </div>
      <div className="armory-source mono small" title="locked backend source">
        <span className="muted">source:</span> {source}
        {cat?.branch ? <span className="muted"> · {cat.branch}</span> : null}
        {cat?.commit ? <span className="muted"> · {cat.commit.slice(0, 12)}</span> : null}
        <span className="muted"> · locked</span>
      </div>
      {err && (
        <div className={`banner ${cat?.stale ? 'warn' : 'err'}`}>
          {cat?.stale ? 'cached index: ' : ''}{err}
        </div>
      )}
      <div className="table-wrap">
        <div className="row head cols-armory">
          <span>NAME</span><span>FORMAT</span><span>VERSION</span>
          <span>DESCRIPTION</span><span />
        </div>
        {rows.length === 0 && !err && <div className="empty">catalogue is empty</div>}
        {rows.map((r) => {
          const current = Boolean(r.installed) &&
            (r.installed_version ?? '') === (r.version ?? '')
          const action = !r.installed ? 'Install'
            : current ? 'Up to date' : 'Update'
          return (
            <div key={r.name} className="row cols-armory">
              <span className="mono">{r.name}</span>
              <span className="muted">{r.format}</span>
              <span className="muted mono">{r.version || '—'}</span>
              <span className="muted ellipsis">{r.description}</span>
              <span className="quick">
                {r.installed && (
                  <button className="btn" disabled={!manage || Boolean(busy)}
                    onClick={() => void act('armory.uninstall', r)}>
                    Remove
                  </button>
                )}
                <button className="btn"
                  disabled={!manage || Boolean(busy) || current}
                  onClick={() => void act(
                    r.installed ? 'armory.update' : 'armory.install', r)}>
                  {busy === r.name ? '…' : action}
                </button>
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
